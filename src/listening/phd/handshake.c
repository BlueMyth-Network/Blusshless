#include "handshake.h"
#include <time.h>
#include <libdeflate.h>
#include <arpa/inet.h>
#include "../../motor.h"
#include "../../io/logger/logger.h"

#define ID_UNCONNECTED_PING_OPEN_CONNECTIONS 0x02
#define ID_CONNECTED_PING 0x00
#define ID_CONNECTED_PONG 0x03
#define ID_OPEN_CONNECTION_REQUEST_1 0x05
#define ID_OPEN_CONNECTION_REPLY_1 0x06
#define ID_OPEN_CONNECTION_REQUEST_2 0x07
#define ID_OPEN_CONNECTION_REPLY_2 0x08
#define ID_CONNECTION_REQUEST 0x09
#define ID_CONNECTION_REQUEST_ACCEPTED 0x10
#define ID_NEW_INCOMING_CONNECTION 0x13
#define ID_DISCONNECT_NOTIFICATION 0x15
#define ID_INCOMPATIBLE_PROTOCOL_VERSION 0x19
#define ID_FRAME_SET_4 0x84
#define ID_FRAME_SET_C 0x8c
#define ID_NACK 0xA0
#define ID_ACK 0xC0
#define ID_GAME 0xFE

bool phd_unconnected(pck_packet_t* packet, struct sockaddr_in* address, int32_t socket) {
	const uint8_t id = (uint8_t) pck_read_int8(packet);
	size_t len = pck_left_over(packet);
	switch (id) {
		case ID_OPEN_CONNECTION_REQUEST_2: {
			if(len != (size_t)33) break;
			return phd_reply_2(packet, address, socket);
		}
		case ID_OPEN_CONNECTION_REQUEST_1: {
			if(len <= (size_t)17) break;
			phd_reply_1(packet, address, socket);
			return false;
		}
		case ID_ACK:
		case ID_NACK:
		case ID_FRAME_SET_4:
		case ID_FRAME_SET_C: {
			if(packet->length <= 0) break;
			log_info("pk in %02x len %lld", id, len);
			input_data input = {
				.bytes = packet->bytes,
				.length = packet->length
			};
			const uint32_t client_length = ltg_get_client_count(sky_get_listener());
			for (uint32_t i = 0; i < client_length; ++i) {
				ltg_client_t* client = ltg_get_client_by_id(sky_get_listener(), i);
				if (client != NULL) {
					if(address->sin_port != client->address.addr.sin_port && memcmp(&((*address).sin_addr.s_addr), &client->address.addr.sin_addr.s_addr, sizeof(struct in_addr))) continue;
					// memcpy(input.bytes, packet->bytes, packet->length);
					client->input_packets_size++;
					client->input_packets = (input_data *) realloc(client->input_packets, client->input_packets_size * sizeof(input_data));
					client->input_packets[client->input_packets_size - 1] = input;
					log_info("push packet in %lld", client->input_packets_size);
				}
			}
			return false;
		}
	}
	return false;
}

void phd_reply_1(pck_packet_t* packet, struct sockaddr_in* address, int32_t socket) {
	pck_cursor_skip(packet, 16);//magic
	PCK_INLINE(reply_packet, 28, io_big_endian);
	if(pck_read_int8(packet) == __RAKNET_VER__){
		pck_write_int8(reply_packet, ID_OPEN_CONNECTION_REPLY_1);
		pck_write_bytes(reply_packet, (byte_t *) MAGIC, 16);
		pck_write_int64(reply_packet, __SERVER_GUID__);
		pck_write_int8(reply_packet, 0);//has Security
		pck_write_int16(reply_packet, 28 + pck_left_over(packet));//mtu
		sendto(socket, (char*) reply_packet->bytes, 28, 0, (struct sockaddr *) address, sizeof(*address));
		return;
	}
	pck_write_int8(reply_packet, ID_INCOMPATIBLE_PROTOCOL_VERSION);
	pck_write_int8(reply_packet, __RAKNET_VER__);
	pck_write_bytes(reply_packet, (byte_t *) MAGIC, 16);
	pck_write_int64(reply_packet, __SERVER_GUID__);
	sendto(socket, (char*) reply_packet->bytes, 26, 0, (struct sockaddr *) address, sizeof(*address));
}

bool phd_reply_2(pck_packet_t* packet, struct sockaddr_in* address, int32_t socket) {
	pck_cursor_skip(packet, 23);//magic and type and address
	int16_t request_mtu = pck_read_int16(packet);
	PCK_INLINE(reply_packet, 35, io_big_endian);
	pck_write_int8(reply_packet, ID_OPEN_CONNECTION_REPLY_2);
	pck_write_bytes(reply_packet, (byte_t *) MAGIC, 16);
	pck_write_int64(reply_packet, __SERVER_GUID__);
	pck_write_int8(reply_packet, 4);//ipv4
	pck_write_int32(reply_packet, 0xffffffff);//ip
	pck_write_int16(reply_packet, 19132);//port
	pck_write_int16(reply_packet, request_mtu > __RAKNET_MTU__ ? __RAKNET_MTU__ : request_mtu);
	pck_write_int8(reply_packet, 0);//Security layer thing
	sendto(socket, (char*) reply_packet->bytes, reply_packet->cursor, 0, (struct sockaddr *) address, sizeof(*address));
	return true;
}

bool phd_packets(ltg_client_t* client, pck_packet_t* packet) {
	log_warn("hm");
	const uint8_t id = (uint8_t) pck_read_int8(packet);
	log_warn("pkid %02x", id);
	size_t len = pck_left_over(packet);
	switch (id) {
		case ID_ACK:
		case ID_NACK:{
			if(len < 3) break;
			return phd_handle_ack_nack(client, packet, id);
		}
		case ID_FRAME_SET_C:
		case ID_FRAME_SET_4:{
			if(len <= 9) break;
			return phd_handle_frame(client, packet);
		}
	}
	return false;
}

bool phd_handle_ack_nack(ltg_client_t* client, pck_packet_t* packet, uint8_t id) {
	int16_t record_count = pck_read_int16(packet);
	int32_t *sequence_numbers = (int32_t *) malloc(0);
	size_t sequence_numbers_count = 0;
	for (int16_t i4 = 0; i4 < record_count; i4++){
		if(pck_read_int8(packet) != 0){
			sequence_numbers[sequence_numbers_count] = pck_read_int24(packet);
			sequence_numbers_count++;
		}else{
			int32_t index = pck_read_int24(packet);
			int32_t end_index = pck_read_int24(packet);
			sequence_numbers = (int32_t *) realloc(sequence_numbers, (sequence_numbers_count + (end_index - index + 1)) * sizeof(int32_t));
			while (index <= end_index) {
				sequence_numbers[sequence_numbers_count] = index;
				sequence_numbers_count++;
				index++;
			}
		}
	}
	if(id == ID_ACK){
		frame_full *filtered_recovery_queue = (frame_full *) malloc(client->recovery_queue_size - sequence_numbers_count * sizeof(frame_full));
		size_t new_recovery_queue_size = 0;
		for (size_t r = 0; r < client->recovery_queue_size; ++r) {
			bool found = false;
			for (size_t i = 0; i < sequence_numbers_count; ++i) {
				if (client->recovery_queue[r].original_sequence_number == sequence_numbers[i]) {
					free(client->recovery_queue[r].bytes);
					found = true;
					break;
				}
			}
			if(!found){
				filtered_recovery_queue[new_recovery_queue_size++] = client->recovery_queue[r];
			}
		}
		client->recovery_queue_size = new_recovery_queue_size;
		memcpy(client->recovery_queue, filtered_recovery_queue, new_recovery_queue_size * sizeof(frame_full));
		free(filtered_recovery_queue);
	}else{
		for (size_t i = 0; i < sequence_numbers_count; ++i) {
			ltg_pack_frames(client, sequence_numbers[i], false);
		}
	}
	free(sequence_numbers);
	return true;
}


bool phd_handle_frame(ltg_client_t* client, pck_packet_t* packet) {
	int32_t sequence_number = pck_read_int24(packet);
	client->ack_queue_size++;
	client->ack_queue = (int32_t *) realloc(client->ack_queue, client->ack_queue_size * sizeof(int32_t));
	client->ack_queue[client->ack_queue_size - 1] = sequence_number;
	int32_t hole_size = sequence_number - client->receiver_sequence_number;
	log_warn("m0");
	if (hole_size != 0) {
		int32_t sequence_number0;
		for (sequence_number0 = client->receiver_sequence_number + 1; sequence_number < sequence_number0; ++sequence_number0) {
			client->nack_queue_size++;
			client->nack_queue = (int32_t *) realloc(client->nack_queue, client->nack_queue_size * sizeof(int32_t));
			client->nack_queue[client->nack_queue_size - 1] = sequence_number0;
		}
	}
	log_warn("m1");
	client->receiver_sequence_number = sequence_number;
	while (packet->cursor < packet->length){
		log_warn("m2");
		int8_t flags = pck_read_int8(packet);
		int8_t reliability = (flags & 0xE0) >> 5;
		size_t payload_size = pck_read_int16(packet) >> 3;
		if(is_reliable(reliability)) pck_cursor_skip(packet, 3);
		if(is_sequenced(reliability)) pck_cursor_skip(packet, 3);
		if(is_ordered(reliability)) pck_cursor_skip(packet, 4);
		if(flags & 0x10){//segmented
			log_warn("m3 1 %lld", payload_size);
			int32_t compound_size = pck_read_int32(packet);
			int16_t compound_id = pck_read_int16(packet);
			int32_t index = pck_read_int32(packet);
			log_warn("pid: %02x size: %d id: %d index: %d", packet->bytes[0], compound_size, compound_id, index);
			bool found = false;
			for (size_t ia = 0; ia < client->frame_holder_size; ++ia) {
				if (client->frame_holder[ia].compound_id == compound_id && client->frame_holder[ia].index == index) {
					found = true;
					break;
				}
			}
			if(!found){
				frame_data frame = {
					.compound_id = compound_id,
					.index = index,
					.sequence_number = sequence_number,
					.length = payload_size
				};
				frame.bytes = (byte_t *) malloc(payload_size);
				memcpy(frame.bytes, pck_cursor(packet), payload_size);
				client->frame_holder_size++;
				client->frame_holder = (frame_data *) realloc(client->frame_holder, client->frame_holder_size * sizeof(frame_data));
				client->frame_holder[client->frame_holder_size - 1] = frame;
			}
			pck_cursor_skip(packet, payload_size);
			size_t size = 0;
			payload_size = 0;
			for (size_t ai = 0; ai < client->frame_holder_size; ++ai) {
				if (client->frame_holder[ai].compound_id == compound_id) {
					payload_size += client->frame_holder[ai].length;
					size++;
				}
			}
			if((int32_t)size != compound_size) continue;
			size_t new_frame_holder_size = client->frame_holder_size - size;
			frame_data *frame_holder = (frame_data *) malloc(new_frame_holder_size * sizeof(frame_data));
			pck_packet_t *segmented = pck_create(payload_size, io_big_endian);
			size_t count = 0;
			for (size_t ai = 0; ai < client->frame_holder_size; ++ai) {
				for (int32_t i0 = 0; i0 < compound_size; ++i0) {
					if (client->frame_holder[ai].compound_id == compound_id && client->frame_holder[ai].index == i0) {
						pck_write_bytes(segmented, client->frame_holder[ai].bytes, (int32_t)client->frame_holder[ai].length);
						free(client->frame_holder[ai].bytes);
						break;
					}
				}
				if(client->frame_holder[ai].compound_id != compound_id){
					frame_holder[count] = client->frame_holder[ai];
					count++;
				}
			}
			client->frame_holder_size = new_frame_holder_size;
			memcpy(client->frame_holder, frame_holder, new_frame_holder_size * sizeof(frame_data));
			free(frame_holder);
			if (!phd_handle_packet(client, segmented)) return false;
			continue;
		}
		log_warn("m3 2 %lld %lld", payload_size, pck_left_over(packet));
		pck_packet_t *data = pck_from_bytes(pck_cursor(packet), payload_size, io_big_endian);
		pck_cursor_skip(packet, payload_size);
		log_warn("oke");
		if (!phd_handle_packet(client, data)) return false;
	}
	return true;
}

bool phd_handle_packet(ltg_client_t* client, pck_packet_t* packet){
	packet->cursor = 0;
	const uint8_t id = (uint8_t) pck_read_int8(packet);
	log_warn("in %02x", id);
	switch (id) {
		case ID_CONNECTED_PING:{
			return phd_connected_pong(client, packet);
		}
		case ID_CONNECTION_REQUEST:{
			return phd_connection_accepted(client, packet);
		}
		case ID_NEW_INCOMING_CONNECTION:{
			client->compression.decompressor = libdeflate_alloc_decompressor();
			client->compression.compressor = libdeflate_alloc_compressor(7);
			ltg_client_set_state(client, ltg_first_packet);
			return true;
		}
		case ID_GAME:{
			return phd_decode_batch_packets(client, packet);
		}
		case ID_DISCONNECT_NOTIFICATION:{
			log_info("disconnect");
			return false;
		}
	}
	return false;
}

bool phd_decode_batch_packets(ltg_client_t* client, pck_packet_t* packet) {
	if(client->encryption.enabled){
		size_t input_len = pck_left_over(packet);
		PCK_INLINE(decrypted, input_len, io_little_endian);
		int out_size = (int) input_len;
		if (ctr256_decrypt(client->encryption.decrypt, pck_cursor(packet), input_len, decrypted->bytes, &out_size) != 1) {
			log_error("Decryption failed");
			return false;
		}
		client->encryption.decrypt_counter++;
		uint8_t compress = (uint8_t) pck_read_int8(decrypted);
		if(compress != 0x00 && compress != 0xff){
			ctr256_done(client->encryption.encrypt, client->encryption.decrypt);
			log_error("decode error");
			return false;
		}
		if(compress == 0x00){
			size_t decompressed_size;
			byte_t* decompressed_data = (byte_t *) malloc(MAX_BYTE);
			int32_t re = libdeflate_deflate_decompress(client->compression.decompressor, pck_cursor(decrypted), out_size - decrypted->cursor - 8 , decompressed_data, MAX_BYTE, &decompressed_size);
			if (re != 0) {
				log_error("Decompression failed with error %d", re);
				free(decompressed_data);
				return false;
			}
			pck_packet_t *decompressed_packet = pck_from_bytes(decompressed_data, decompressed_size, io_little_endian);
			return ltg_handle_packet(client, decompressed_packet);
		}
		decrypted->length = out_size - 8;
		return ltg_handle_packet(client, decrypted);
	}
	if(client->compression_enabled && pck_read_int8(packet) == 0){
		size_t decompressed_size;
		byte_t* decompressed_data = (byte_t *) malloc(MAX_BYTE);
		int32_t re = libdeflate_deflate_decompress(client->compression.decompressor, pck_cursor(packet), packet->length - packet->cursor, decompressed_data, MAX_BYTE, &decompressed_size);
		if (re != 0) {
			log_error("Decompression failed with error %d", re);
			free(decompressed_data);
			return false;
		}
		pck_packet_t *decompressed_packet = pck_from_bytes(decompressed_data, decompressed_size, io_little_endian);
		return ltg_handle_packet(client, decompressed_packet);
	}
	return ltg_handle_packet(client, packet);
}

bool phd_connected_pong(ltg_client_t* client, pck_packet_t* packet) {
	PCK_INLINE(out_buff, 17, io_big_endian);
	pck_write_int8(out_buff, ID_CONNECTED_PONG);
	pck_write_int64(out_buff, pck_read_int64(packet));
	pck_write_int64(out_buff, (time(NULL) * 1000) - client->rak_time);
	ltg_frame(client, out_buff, RELIABILITY_UNRELIABLE);
	return true;
}

bool phd_connection_accepted(ltg_client_t* client, pck_packet_t* packet) {
	packet->cursor += 8;//skip guid i don't care
	int64_t rq_time = pck_read_int64(packet);
	PCK_INLINE(respond, 26 + 330, io_big_endian);
	pck_write_int8(respond, ID_CONNECTION_REQUEST_ACCEPTED);
	pck_write_int8(respond, 4);
	pck_write_inte32(respond, ~inet_lnaof(client->address.addr.sin_addr), io_little_endian);//ip random nonsense
	pck_write_int16(respond, htons(client->address.addr.sin_port));//port
	pck_write_int16(respond, (uint16_t)client->id);//sys
	for (size_t i = 0; i < 10; i++){
		pck_write_int8(respond, 6);
		pck_write_int16(respond, io_switch_int16(0x17));
		pck_write_int16(respond, 19132);//port
		pck_write_bytes(respond, WEIRD_ADRESS, 16);
		pck_write_int32(respond, i);
	}
	pck_write_int64(respond, rq_time);
	pck_write_int64(respond, (time(NULL) * 1000) - client->rak_time);
	ltg_frame(client, respond, RELIABILITY_UNRELIABLE);
	return true;
}

bool phd_send_ack_nack(ltg_client_t* client, bool is_ack) {
	int16_t sequence_numbers_count = is_ack ? client->ack_queue_size : client->nack_queue_size;
	if(!sequence_numbers_count) return false;
	int32_t *sequence_numbers = is_ack ? client->ack_queue : client->nack_queue;
	PCK_INLINE(ack, 3 + (sequence_numbers_count * 4), io_big_endian);
	pck_write_int8(ack, is_ack ? ID_ACK : ID_NACK);
	pck_write_int16(ack, sequence_numbers_count);
	for (int16_t i = 0; i < sequence_numbers_count; ++i) {
		pck_write_int8(ack, true); //Single Sequence number
		pck_write_int24(ack, sequence_numbers[i]);
	}
	sendto(client->socket, (char*) ack->bytes, ack->length, 0, (struct sockaddr *) &client->address.addr, sizeof(client->address.addr));
	if(is_ack){
		client->ack_queue_size = 0;
		client->ack_queue = realloc(client->ack_queue, 0);
	}else{
		client->nack_queue_size = 0;
		client->nack_queue = realloc(client->nack_queue, 0);
	}
	return true;
}

void phd_send_legacy_slp(ltg_client_t* client) {

	PCK_INLINE(packet, 128, io_big_endian);
	pck_write_int8(packet, 0xFF);
	char legacy_slp[384];
	char motd[256];
	cht_write_old(sky_get_motd(), motd);

	size_t length = sprintf(legacy_slp, "\xa7\x31%c127%cMotor MC " __MC_VER__ "%c%s%c%u%c%u", '\0', '\0', '\0', motd, '\0', ltg_get_online_count(sky_get_listener()), '\0', ltg_get_online_max(sky_get_listener()));
	pck_write_int16(packet, length);
	for (size_t i = 0; i < length; ++i) {
		pck_write_int8(packet, 0);
		pck_write_int8(packet, legacy_slp[i]);
	}

	sck_send(ltg_client_get_socket(client), (char*) packet->bytes, packet->cursor);

}