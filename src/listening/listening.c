#include <libdeflate.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "listening.h"
#include "../motor.h"
#include "../jobs/board.h"
#include "../jobs/scheduler/scheduler.h"
#include "../util/util.h"
#include "../io/logger/logger.h"
#include "../io/io.h"
#include "../io/chat/chat.h"
#include "../io/chat/translation.h"

// packet handlers
#include "phd/handshake.h"
#include "phd/status.h"
#include "phd/login.h"
#include "phd/play.h"
//for test should remove
#include <arpa/inet.h>

#define ID_UNCONNECTED_PING 0x01
#define ID_UNCONNECTED_PONG 0x1C

#define ID_FRAME_SET_0 0x80
#define ID_FRAME_SET_4 0x84

#define ID_FRAME_SET_8 0x88
#define ID_FRAME_SET_C 0x8c

#define ID_GAME 0xFE

void ltg_init(ltg_listener_t* listener) {

	log_info("Starting listener...");

	// generate PKEY keypair
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, OBJ_txt2nid(BEDROCK_SIGNING_KEY_CURVE_NAME)) <= 0) {
        EVP_PKEY_CTX_free(pctx);
	}
    if (EVP_PKEY_keygen(pctx, &listener->keypair) <= 0) {
        EVP_PKEY_CTX_free(pctx);
    }
    EVP_PKEY_CTX_free(pctx);

	// start listening thread
	pthread_create(&listener->thread, NULL, t_ltg_run, listener);

}

void* t_ltg_run(void* args) {

	ltg_listener_t* listener = args;

	// init sockets
	if (sck_init() != SCK_OK) {
		return NULL;
	}

	// create socket
	listener->address.socket = sck_create();

	// set address
	listener->address.addr.sin_family = AF_INET;
	listener->address.addr.sin_addr.s_addr = htonl(INADDR_ANY);
	listener->address.addr.sin_port = io_htons(listener->address.port);

	// bind socket
	if (sck_bind(listener->address.socket, (struct sockaddr*) &listener->address.addr, sizeof(struct sockaddr)) != SCK_OK) {
		return NULL;
	}
	int enable = 1;
    setsockopt(listener->address.socket, SOL_SOCKET, SO_REUSEADDR, (char *) &enable, sizeof(enable));
	setsockopt(listener->address.socket, SOL_SOCKET, SO_BROADCAST, (char *) &enable, sizeof(enable));
	setsockopt(listener->address.socket, SOL_SOCKET, SO_REUSEPORT, (char *) &enable, sizeof(enable));
	struct timespec start;
	clock_gettime(CLOCK_REALTIME, &start);

	log_info("Listening on port %u", listener->address.port);

	char legacy_slp[384];
	PCK_INLINE(pong_packet, 32 + 384, io_big_endian);
	pck_write_int8(pong_packet, ID_UNCONNECTED_PONG);
	pong_packet->cursor += 8;
	pck_write_int64(pong_packet, __SERVER_GUID__);
	pck_write_bytes(pong_packet, (byte_t *) MAGIC, 16);
	size_t length = sprintf(legacy_slp, "MCPE;%s;%d;%s;%d;%d;%ld;%s;Survival;1;19132;0;0;", sky_get_motd()->text.value, __MC_PRO__, __MC_VER__, ltg_get_online_count(sky_get_listener()), ltg_get_online_max(sky_get_listener()), __SERVER_GUID__, "BlueMyth Games");
	pck_write_int16(pong_packet, length);
	pck_write_bytes(pong_packet, (byte_t *) legacy_slp, length);
	size_t size = 65535;
	PCK_INLINE(input, size, io_big_endian);
	struct sockaddr_in address;
	socklen_t address_size = sizeof(struct sockaddr_in);
	for (;;) {
		input->cursor = 0;
		input->length = recvfrom(listener->address.socket, (char*) input->bytes, size, 0, (struct sockaddr *) &address, &address_size);
		if (input->length >= (size_t)3) {// rule out invaild packet
			if(input->bytes[0] == ID_UNCONNECTED_PING){
				if(input->length != (size_t)33) continue;
				pong_packet->cursor = 1;
				pck_write_int64(pong_packet, pck_read_int64(input));
				pong_packet->cursor = 35 + length;
				sendto(listener->address.socket, (char*) pong_packet->bytes, pong_packet->cursor, 0, (struct sockaddr *) &address, sizeof(address));
			}else{
				if(phd_unconnected(input, (struct sockaddr_in *) &address, listener->address.socket)){
					input->cursor = 1;
					pck_cursor_skip(input, 21);//skip magic stuff and type and adress
					if(pck_read_int16(input) == (int16_t)listener->address.port){//same port
						int16_t request_mtu = pck_read_int16(input);
						ltg_client_t* client = calloc(1, sizeof(ltg_client_t));
						client->listener = listener;
						client->socket = listener->address.socket;
						pthread_mutex_init(&client->lock, NULL);
						client->address.addr = address;
						client->address.size = (int) address_size;
						client->rak_time = (int64_t) sky_to_nanos(start);
						client->state = ltg_raknet;
						client->rak_client = pck_read_int64(input);//GUID
						client->rak_mtu = request_mtu > __RAKNET_MTU__ ? __RAKNET_MTU__ : request_mtu;
						client->compound_id = 0;
						client->sender_sequence_number = 0;
						client->sender_reliable_frame_index = 0;
						client->receiver_sequence_number = 0;
						client->sender_order_channel = 0;
						client->sender_sequence_channel = 0;
						client->input_packets = (input_data *) malloc(0);
						client->input_packets_size = 0;
						client->ack_queue = (int32_t *) malloc(0);
						client->ack_queue_size = 0;
						client->nack_queue = (int32_t *) malloc(0);
						client->nack_queue_size = 0;
						client->frame_holder = (frame_data *) malloc(0);
						client->frame_holder_size = 0;
						client->queued_frame_data = (queue_data *) malloc(0);
						client->queued_frame_data_size = 0;
						client->recovery_queue = (frame_full *) malloc(0);
						client->recovery_queue_size = 0;
						client->compression_enabled = false;
						client->encryption.enabled = false;
						// accept the client
						ltg_accept(client);
					}
				}
			}
		}
	}

	return (void*) 1;

}

void ltg_accept(ltg_client_t* client) {

	// lock clients
	with_lock (&client->listener->clients.lock) {
		client->id = utl_id_vector_push(&client->listener->clients.vector, &client);
	}

	// create client listening thread
	pthread_create(&client->thread, NULL, t_ltg_client, client);

}

void* t_ltg_client(void* args) {

	ltg_client_t* client = args;
	for (;;) {
		// // read packet
		if(client->input_packets_size >= 1 && client->input_packets[0].length >= 1){
			input_data *filtered_inputs = (input_data *) malloc(client->input_packets_size - 1 * sizeof(frame_full));
			PCK_INLINE(recvd, client->input_packets[0].length, io_big_endian);
			pck_write_bytes(recvd, client->input_packets[0].bytes, client->input_packets[0].length);
			recvd->cursor = 0;
			phd_packets(client, recvd);	
			size_t new = 0;
			for (size_t i = 1; i < client->input_packets_size; i++){
				filtered_inputs[new] = client->input_packets[i];
				new++;
			}
			memcpy(client->input_packets, filtered_inputs, client->input_packets_size - 1 * sizeof(queue_data));
			free(filtered_inputs);
		}
		// send packet
		ltg_pack_frames(client, client->sender_sequence_number, false);
	}
	ltg_disconnect(client);
	return NULL;
}

void ltg_pack_game_packet(ltg_client_t* client, pck_packet_t** packets, size_t size){
	printf("pack game\n");
	size_t batch_size = 0;
	for (size_t i = 0; i < size; i++){
		size_t pk_len = packets[i]->length;
		batch_size += io_var_int_length(pk_len) + pk_len;
	}
	PCK_INLINE(batch_data, batch_size, io_little_endian);
	for (size_t i = 0; i < size; i++){
		pck_write_string(batch_data, (char *)packets[i]->bytes, packets[i]->length);
	}
	if(!client->compression_enabled){
		bool has_alg = false;
		size_t new_size = batch_size + (has_alg ? 2 : 1);
		PCK_INLINE(batch_packet, new_size, io_little_endian);
		pck_write_int8(batch_packet, ID_GAME);//batch packet
		if(has_alg){
			pck_write_int8(batch_packet, 0xFF);//no alg for testing
		}
		pck_write_bytes(batch_packet, batch_data->bytes, batch_size);
		ltg_frame(client, batch_packet, RELIABILITY_RELIABLE_ORDERED);
		return;
	}
	if(client->compression_enabled){
		with_lock (&client->lock) {
			size_t deflate_size = libdeflate_deflate_compress_bound(client->compression.compressor, batch_size) + 10;
			byte_t *deflate_buffer = (byte_t *) malloc(deflate_size);
			deflate_size = libdeflate_deflate_compress(client->compression.compressor, batch_data->bytes, batch_size, deflate_buffer, deflate_size);
			PCK_INLINE(batch_packet, deflate_size + 2 - client->encryption.enabled, io_little_endian);
			if(!client->encryption.enabled){
				pck_write_int8(batch_packet, ID_GAME);//batch packet
			}
			pck_write_int8(batch_packet, 0x00);//zlib
			pck_write_bytes(batch_packet, deflate_buffer, deflate_size);//write zlib data
			free(deflate_buffer);
			if(client->encryption.enabled){
				//TODO: encryption stuff
				PCK_INLINE(encrypted_batch_packet, 1, io_little_endian);
				pck_write_int8(encrypted_batch_packet, ID_GAME);//batch packet
				// pck_write_bytes(encrypted_batch_packet, , );//write encrypted batch data
				pthread_mutex_unlock(&client->lock);
				ltg_frame(client, encrypted_batch_packet, RELIABILITY_RELIABLE_ORDERED);
				return;
			}
			ltg_frame(client, batch_packet, RELIABILITY_RELIABLE_ORDERED);
			return;
		}
	}
}

void ltg_frame(ltg_client_t* client, pck_packet_t* packet, int8_t reliability) {
	size_t packet_len = packet->length;
	int16_t len = 3;
	if (is_reliable(reliability)){
		len += 3;
		client->sender_reliable_frame_index++;
	}
	if(is_sequenced(reliability)) {
		len += 3;
		client->sender_sequence_channel++;
	} else if (is_ordered(reliability)) {
		len += 4;
		client->sender_order_channel++;
	}
	int16_t max_size = client->rak_mtu - 60;
	if (packet_len > (size_t)max_size) {//not tested
		len += 10;
		int16_t frame_count = (packet_len / max_size) + 1;
		int16_t pad_bytes = (frame_count * max_size) - packet_len;
		int16_t byte = max_size;
		PCK_INLINE(frame, len + byte, io_big_endian);//max buff and only 1 time alloc
		frame->cursor = 3;
		if(is_reliable(reliability)){
			pck_write_int24(frame, client->sender_reliable_frame_index - 1);
		}
		if(is_sequenced(reliability)){
			pck_write_int24(frame, client->sender_sequence_channel - 1);
		}
		if(is_ordered(reliability)){
			pck_write_int24(frame, client->sender_order_channel - 1);
			pck_write_int8(frame, 0);//chanel is always 0
		}
		pck_write_int32(frame, frame_count);
		pck_write_int16(frame, client->compound_id);
		for (int16_t id = 0; id < frame_count; id++){
			frame->cursor = 0;
			if(id + 1 == frame_count){ byte -= pad_bytes; }
			pck_write_int8(frame, (reliability << 5) | 0x10);
			pck_write_int16(frame, byte << 3);
			frame->cursor += len - 7;
			pck_write_int32(frame, id);
			pck_write_bytes(frame, pck_cursor(packet), byte);
			pck_cursor_skip(packet, byte);
			queue_data queue = {.length = frame->cursor, .reliability = reliability, .bytes = (byte_t *) malloc(frame->length), .mode = true};
			memcpy(queue.bytes, frame->bytes, frame->cursor);
			client->queued_frame_data_size++;
			client->queued_frame_data = (queue_data *) realloc(client->queued_frame_data, client->queued_frame_data_size * sizeof(queue_data));
			client->queued_frame_data[client->queued_frame_data_size - 1] = queue;
		}
		client->compound_id++;
	}else{
		PCK_INLINE(frame, len + packet_len, io_big_endian);
		pck_write_int8(frame, reliability << 5);
		pck_write_int16(frame, packet_len << 3);
		if(is_reliable(reliability)){
			pck_write_int24(frame, client->sender_reliable_frame_index - 1);
		}
		if(is_sequenced(reliability)){
			pck_write_int24(frame, client->sender_sequence_channel - 1);
		}
		if(is_ordered(reliability)){
			pck_write_int24(frame, client->sender_order_channel - 1);
			pck_write_int8(frame, 0);//chanel is always 0
		}
		pck_write_bytes(frame, packet->bytes, packet_len);
		queue_data queue = {.length = frame->length, .reliability = reliability, .bytes = (byte_t *) malloc(frame->length), .mode = false};
		memcpy(queue.bytes, frame->bytes, frame->length);
		client->queued_frame_data_size++;
		client->queued_frame_data = (queue_data *) realloc(client->queued_frame_data, client->queued_frame_data_size * sizeof(queue_data));
		client->queued_frame_data[client->queued_frame_data_size - 1] = queue;
	}
}

static inline void ltg_send_e(ltg_client_t* client, byte_t* bytes, size_t length) {
	sendto(client->socket, (char*) bytes, length, 0, (struct sockaddr *) &client->address.addr, sizeof(client->address.addr));
}

void ltg_pack_frames(ltg_client_t* client, int32_t sequence_number, bool mode) {
	if(sequence_number == client->sender_sequence_number){//normal
		size_t client_queue_size = client->queued_frame_data_size;
		if(1 > client_queue_size) return;
		size_t idk = 16, frame_len = 0, loop = (client_queue_size > idk) ? idk : client_queue_size, len = 4, reliabe_len = 0;
		bool have = false;
		for (size_t i = 0; i < loop; i++){
			frame_len = client->queued_frame_data[i].length;
			have |= client->queued_frame_data[i].mode;
			len += frame_len;
			if(is_reliable(client->queued_frame_data[i].reliability)){
				reliabe_len += frame_len;
			}
		}
		PCK_INLINE(frames, len, io_big_endian);
		pck_write_int8(frames, mode ? 0x8b : ID_FRAME_SET_4);
		pck_write_int24(frames, sequence_number);//framesid
		client->sender_sequence_number++;
		bool reliable = reliabe_len != 0;
		frame_full recovery_data = {
			.original_sequence_number = sequence_number,
			.mode = mode,
			.length = reliabe_len,
			.bytes = (byte_t *) malloc(reliabe_len)
		};
		size_t re_len = 0;
		for (size_t i = 0; i < loop; i++){
			pck_write_bytes(frames, client->queued_frame_data[i].bytes, client->queued_frame_data[i].length);
			if(is_reliable(client->queued_frame_data[i].reliability)){
				memcpy(recovery_data.bytes + re_len, client->queued_frame_data[i].bytes, client->queued_frame_data[i].length);
				re_len += client->queued_frame_data[i].length;
			}
		}
		client->recovery_queue_size++;
		client->recovery_queue = (frame_full *) realloc(client->recovery_queue, client->recovery_queue_size * sizeof(frame_full));
		client->recovery_queue[client->recovery_queue_size - 1] = recovery_data;
		size_t new_size = client_queue_size - loop;
		if(new_size > 0){
			queue_data *new_queue = malloc(new_size * sizeof(queue_data));
			for (size_t r = 0; r < new_size; ++r) {
				new_queue[r] = client->queued_frame_data[loop + r];
			}
			memcpy(client->queued_frame_data, new_queue, new_size * sizeof(queue_data));
			free(new_queue);
		}
		client->queued_frame_data_size = new_size;
		ltg_send_e(client, frames->bytes, len);
		ltg_pack_frames(client, client->sender_sequence_number, false);
	}else{//recovery
		frame_full *filtered_recovery_queue = (frame_full *) malloc(client->recovery_queue_size - 1 * sizeof(frame_full));
		size_t new_recovery_queue_size = 0;
		for (size_t r = 0; r < client->recovery_queue_size; ++r){
			if (client->recovery_queue[r].original_sequence_number == sequence_number) {//push back to queue
				queue_data queue = {
					.length = client->recovery_queue[r].length, 
					.reliability = RELIABILITY_RELIABLE_ORDERED, 
					.bytes = (byte_t *) malloc(client->recovery_queue[r].length), 
					.mode = client->recovery_queue[r].mode
				};
				memcpy(queue.bytes, client->recovery_queue[r].bytes, client->recovery_queue[r].length);
				free(client->recovery_queue[r].bytes);
				client->queued_frame_data_size++;
				client->queued_frame_data = (queue_data *) realloc(client->queued_frame_data, client->queued_frame_data_size * sizeof(queue_data));
				client->queued_frame_data[client->queued_frame_data_size - 1] = queue;
			}else{
				filtered_recovery_queue[new_recovery_queue_size++] = client->recovery_queue[r];
			}
		}
		client->recovery_queue_size = new_recovery_queue_size;
		memcpy(client->recovery_queue, filtered_recovery_queue, new_recovery_queue_size * sizeof(frame_full));
		free(filtered_recovery_queue);
	}
}

/*
 * Handle packets
 * If return is false, disconnect the client
 */
bool ltg_handle_packet(ltg_client_t* client, pck_packet_t* packet) {
	do {
		int32_t size = pck_read_var_int(packet);
		pck_packet_t *data_packet = pck_from_bytes(pck_cursor(packet), size, io_little_endian);
		pck_cursor_skip(packet, size);
		// int32_t header = pck_read_var_int(data_packet);
		// int32_t pkid = header & 0x3ff;
		// if((header >> 10) & 0x03) return false; //TODO: split screen support
		switch (client->state) {
			case ltg_first_packet: {
				if (!phd_status(client, data_packet)) {
					return false;
				}
			} break;
			case ltg_login: {
				if (!phd_login(client, data_packet)) {
					return false;
				}
			} break;
			case ltg_play: {
				if (!phd_play(client, data_packet)) {
					return false;
				}
			} break;
			default: {
				log_warn("Client is in an unknown state! (%d)", client->state);
				return false;
			}
		}
	} while (packet->length > packet->cursor);

	return true;

}

// sends the packet to the client specified
void ltg_send(ltg_client_t* client, pck_packet_t* packet) {
	ltg_pack_game_packet(client, &packet, 1);
}

void ltg_disconnect(ltg_client_t* client) {

	if (pthread_self() != client->thread) {
		return;
	}

	switch (client->state) {
		case ltg_play: {
			// cancel keep alive
			sch_cancel(client->keep_alive);

			// remove from online player list
			with_lock (&client->listener->online.lock) {
				utl_id_vector_remove(&client->listener->online.vector, client->online_node);
			}

			// create player leave job
			job_payload_t payload = {
				.player_leave = {
					.username_length = client->username.length
				}
			};
			payload.player_leave.username[payload.player_leave.username_length] = 0;
			memcpy(payload.player_leave.username, client->username.value, client->username.length);
			memcpy(payload.player_leave.uuid, client->uuid, sizeof(ltg_uuid_t));
			uint32_t work = job_new(job_player_leave, payload);
			
			job_add(work);
			
			phd_update_sent_chunks_leave(client);
			ent_free_player(client->entity);
		} break;
		default: {
			// do nothing extra
		} break;
	}
	ltg_pack_frames(client, client->sender_sequence_number, false);
	pthread_mutex_lock(&client->lock);
	pthread_mutex_destroy(&client->lock);

	// remove from client list
	with_lock (&client->listener->clients.lock) {
		utl_id_vector_remove(&client->listener->clients.vector, client->id);
	}

	// free compressors
	libdeflate_free_compressor(client->compression.compressor);
	libdeflate_free_decompressor(client->compression.decompressor);

	// free username
	UTL_FREESTR(client->username);
	// free packets
	free(client->input_packets);
	free(client->ack_queue);
	free(client->nack_queue);
	free(client->frame_holder);
	free(client->queued_frame_data);
	free(client->recovery_queue);
	// free skin
	UTL_FREESTR(client->textures.value);
	UTL_FREESTR(client->textures.signature);

	// free encryption key
	if (client->encryption.enabled) {
		ctr256_done(client->encryption.encrypt, client->encryption.decrypt);
	}

	free(client);

}

void ltg_term(ltg_listener_t* listener) {

	// cancel main thread
	sck_close(listener->address.socket);
	pthread_cancel(listener->thread);

	// disconnect message
	cht_translation_t disconnect_message = cht_translation_new;
	disconnect_message.translate = cht_translation_multiplayer_disconnect_server_shutdown;

	char message[128];
	size_t message_length = cht_write_translation(&disconnect_message, message);

	// disconnect all clients
	with_lock (&listener->clients.lock) {
		for (uint32_t i = 0; i < listener->clients.vector.array.size; ++i) {
			ltg_client_t* client = UTL_ID_VECTOR_GET_AS(ltg_client_t*, &listener->clients.vector, i);
			if (client != NULL) {
				pthread_mutex_unlock(&listener->clients.lock);
				phd_send_disconnect(client, message, message_length);
				ltg_disconnect(client);
				if (pthread_self() != client->thread) {
					pthread_join(client->thread, NULL);
				}
				pthread_mutex_lock(&listener->clients.lock);
			}
		}
	}

	sck_term();

}