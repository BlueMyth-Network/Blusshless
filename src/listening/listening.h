#pragma once
#include <pthread.h>

#include "listening.d.h"
#include "../world/entity/living/player/player.d.h"

#include "../main.h"
#include "../util/id_vector.h"
#include "../util/util.h"
#include "../util/lock_util.h"
#include "../util/str_util.h"
#include "../io/packet/packet.h"
#include "../crypt/ctr256.h"
#include "socket/socket.h"

static uint8_t MAGIC[16] = {
	'\x00', '\xff', '\xff', '\x00',
	'\xfe', '\xfe', '\xfe', '\xfe',
	'\xfd', '\xfd', '\xfd', '\xfd',
	'\x12', '\x34', '\x56', '\x78'
};

static uint8_t WEIRD_ADRESS[16] = {
	'\xC0', '\xFF', '\xE6', '\x94',
	'\x20', '\x00', '\x00', '\x00',
	'\x00', '\x00', '\x00', '\x00',
	'\x00', '\x00', '\x00', '\x00'
};

#define BEDROCK_SIGNING_KEY_CURVE_NAME "secp384r1"

#define MAX_BYTE 8 * 1024 * 1024
#define LTG_UUID_UNPACK(uuid) (ltg_uuid_t) { uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7], uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15] }

#define RELIABILITY_UNRELIABLE 0x00
#define RELIABILITY_UNRELIABLE_SEQUENCED 0x01
#define RELIABILITY_RELIABLE 0x02
#define RELIABILITY_RELIABLE_ORDERED 0x03
#define RELIABILITY_RELIABLE_SEQUENCED 0x04
#define RELIABILITY_UNRELIABLE_WITH_ACK_RECEIPT 0x05
#define RELIABILITY_RELIABLE_WITH_ACK_RECEIPT 0x06
#define RELIABILITY_RELIABLE_ORDERED_WITH_ACK_RECEIPT 0x07

struct ltg_listener {

	pthread_t thread;

	// address
	struct {
		int32_t socket;
		struct sockaddr_in addr;
		uint16_t port;
	} address;

	struct {
		pthread_mutex_t lock;
		utl_id_vector_t vector;
	} clients;
	
	struct {
		pthread_mutex_t lock;
		utl_id_vector_t vector;
		_Atomic uint32_t max;
	} online;

	EVP_PKEY* keypair;

};

typedef struct {
	size_t length;
	byte_t* bytes;
} input_data;

typedef struct {
	int16_t compound_id;
	int32_t index;
	int32_t sequence_number;
	size_t length;
	byte_t* bytes;
} frame_data;

typedef struct {
	size_t length;
	byte_t* bytes;
	int8_t reliability;
	bool mode;
} queue_data;

typedef struct {
	int32_t original_sequence_number;
	bool mode;
	size_t length;
	byte_t* bytes;
} frame_full;

struct ltg_client {

	ltg_listener_t* listener;

	// client's thread
	pthread_t thread;
	
	// player entity (only non-null when in PLAY state)
	ent_player_t* entity;

	// compressors and decompressors
	struct {
		struct libdeflate_compressor* compressor;
		struct libdeflate_decompressor* decompressor;
	} compression;

	// textures (only non-null after auth)
	struct {
		string_t value;
		string_t signature;
	} textures;

	string_t username;

	// last recieved packet
	_Atomic int64_t last_recv;

	_Atomic int64_t ping;

	int16_t rak_mtu;

	int64_t rak_time;

	int64_t rak_client;

	int32_t sender_sequence_number;
	int32_t receiver_sequence_number;
	int32_t sender_reliable_frame_index;
	int32_t sender_order_channel;
	int32_t sender_sequence_channel;
	int16_t compound_id;

	size_t input_packets_size;
	input_data* input_packets;

	int32_t *ack_queue;
	int16_t ack_queue_size;

	int32_t *nack_queue;
	int16_t nack_queue_size;

	size_t frame_holder_size;
	frame_data *frame_holder;//client -> server

	size_t queued_frame_data_size;
	queue_data* queued_frame_data;//frames -> frameset

	size_t recovery_queue_size;
	frame_full* recovery_queue;

	ltg_uuid_t uuid;

	struct {
		struct sockaddr_in addr;
		int size;
	} address;

	uint32_t online_node;

	uint32_t id;

	// address
	pthread_mutex_t lock;
	int32_t socket;

	ltg_locale_t locale;

	uint32_t keep_alive;

	struct {
		bool enabled;
		EVP_CIPHER_CTX* encrypt;
		int encrypt_counter;
		EVP_CIPHER_CTX* decrypt;
		int decrypt_counter;
		unsigned char *salt;
	} encryption;

	int32_t protocol;
	uint8_t render_distance : 6;

	enum {
		ltg_chat_enabled = 0,
		ltg_chat_commands_only = 1,
		ltg_chat_hidden = 2
	} chat_mode : 2;

	bool compression_enabled;

	ltg_client_state_t state : 2;
};

extern void ltg_init();
extern void* t_ltg_run(void*);
extern void ltg_accept(ltg_client_t*);
extern void* t_ltg_client(void*);

static inline ltg_client_t* ltg_get_client_by_id(ltg_listener_t* listener, uint32_t id) {
	ltg_client_t* client = NULL;
	with_lock (&listener->clients.lock) {
		client = UTL_ID_VECTOR_GET_AS(ltg_client_t*, &listener->clients.vector, id);
	}
	return client;
}

extern bool ltg_handle_packet(ltg_client_t* client, pck_packet_t* packet);

void ltg_frame(ltg_client_t* client, pck_packet_t* packet, int8_t reliability);

void ltg_pack_frames(ltg_client_t* client, int32_t sequence_number, bool mode);

void itg_ack(ltg_client_t* client, bool is_ack);

extern void ltg_send(ltg_client_t*, pck_packet_t*);

extern void ltg_disconnect(ltg_client_t*);

extern void ltg_term(ltg_listener_t* listener);

static inline bool is_reliable(int reliability){
	return (reliability == RELIABILITY_RELIABLE ||
	    reliability == RELIABILITY_RELIABLE_ORDERED ||
	    reliability == RELIABILITY_RELIABLE_SEQUENCED ||
	    reliability == RELIABILITY_RELIABLE_WITH_ACK_RECEIPT ||
	    reliability == RELIABILITY_RELIABLE_ORDERED_WITH_ACK_RECEIPT
	);
}

static inline bool is_sequenced(int reliability){
	return (reliability == RELIABILITY_UNRELIABLE_SEQUENCED ||
	    reliability == RELIABILITY_RELIABLE_SEQUENCED
	);
}

static inline bool is_ordered(int reliability){
	return (reliability == RELIABILITY_UNRELIABLE_SEQUENCED ||
	    reliability == RELIABILITY_RELIABLE_ORDERED ||
	    reliability == RELIABILITY_RELIABLE_SEQUENCED ||
	    reliability == RELIABILITY_RELIABLE_ORDERED_WITH_ACK_RECEIPT
	);
}

static inline void ltg_uuid_to_string(const ltg_uuid_t uuid, char* out) {
	
	out[0] = utl_hexmap[uuid[0] >> 4];
	out[1] = utl_hexmap[uuid[0] & 0xF];
	out[2] = utl_hexmap[uuid[1] >> 4];
	out[3] = utl_hexmap[uuid[1] & 0xF];
	out[4] = utl_hexmap[uuid[2] >> 4];
	out[5] = utl_hexmap[uuid[2] & 0xF];
	out[6] = utl_hexmap[uuid[3] >> 4];
	out[7] = utl_hexmap[uuid[3] & 0xF];
	out[8] = '-';
	out[9] = utl_hexmap[uuid[4] >> 4];
	out[10] = utl_hexmap[uuid[4] & 0xF];
	out[11] = utl_hexmap[uuid[5] >> 4];
	out[12] = utl_hexmap[uuid[5] & 0xF];
	out[13] = '-';
	out[14] = utl_hexmap[uuid[6] >> 4];
	out[15] = utl_hexmap[uuid[6] & 0xF];
	out[16] = utl_hexmap[uuid[7] >> 4];
	out[17] = utl_hexmap[uuid[7] & 0xF];
	out[18] = '-';
	out[19] = utl_hexmap[uuid[8] >> 4];
	out[20] = utl_hexmap[uuid[8] & 0xF];
	out[21] = utl_hexmap[uuid[9] >> 4];
	out[22] = utl_hexmap[uuid[9] & 0xF];
	out[23] = '-';
	out[24] = utl_hexmap[uuid[10] >> 4];
	out[25] = utl_hexmap[uuid[10] & 0xF];
	out[26] = utl_hexmap[uuid[11] >> 4];
	out[27] = utl_hexmap[uuid[11] & 0xF];
	out[28] = utl_hexmap[uuid[12] >> 4];
	out[29] = utl_hexmap[uuid[12] & 0xF];
	out[30] = utl_hexmap[uuid[13] >> 4];
	out[31] = utl_hexmap[uuid[13] & 0xF];
	out[32] = utl_hexmap[uuid[14] >> 4];
	out[33] = utl_hexmap[uuid[14] & 0xF];
	out[34] = utl_hexmap[uuid[15] >> 4];
	out[35] = utl_hexmap[uuid[15] & 0xF];
	out[36] = 0;

}

// API

static inline uint32_t ltg_client_get_id(const ltg_client_t* client) {
	return client->id;
}

static inline string_t ltg_client_get_username(const ltg_client_t* client) {
	return client->username;
}

static inline void ltg_client_set_username(ltg_client_t* client, string_t username) {
	client->username = username;
}

static inline const byte_t* ltg_client_get_uuid(const ltg_client_t* client) {
	return client->uuid;
}

static inline int32_t ltg_client_get_protocol(const ltg_client_t* client) {
	return client->protocol;
}

static inline void ltg_client_set_protocol(ltg_client_t* client, int32_t protocol) {
	client->protocol = protocol;
}

static inline uint8_t ltg_client_get_render_distance(const ltg_client_t* client) {
	return client->render_distance;
}

static inline void ltg_client_set_render_distance(ltg_client_t* client, uint8_t render_distance) {
	client->render_distance = render_distance;
}

static inline int64_t ltg_client_get_ping(const ltg_client_t* client) {
	return client->ping;
}

static inline void ltg_client_set_ping(ltg_client_t* client, int64_t ping) {
	client->ping = ping;
}

static inline ltg_locale_t ltg_client_get_locale(const ltg_client_t* client) {
	return client->locale;
}

static inline void ltg_client_set_entity(ltg_client_t* client, ent_player_t* player) {
	client->entity = player;
}

static inline void ltg_client_set_chat_mode(ltg_client_t* client, uint8_t chat_mode) {
	client->chat_mode = chat_mode;
}

static inline ent_player_t* ltg_client_get_entity(const ltg_client_t* client) {
	return client->entity;
}

static inline int64_t ltg_client_get_last_receive(const ltg_client_t* client) {
	return client->last_recv;
}

static inline void ltg_client_set_last_receive(ltg_client_t* client, int64_t last_receive) {
	client->last_recv = last_receive;
}

static inline string_t ltg_client_get_textures(const ltg_client_t* client) {
	return client->textures.value;
}

static inline bool ltg_client_has_textures(const ltg_client_t* client) {
	if (UTL_STRTOCSTR(ltg_client_get_textures(client)) != NULL) {
		return true;
	}
	return false;
}

static inline string_t ltg_client_get_textures_signature(const ltg_client_t* client) {
	return client->textures.signature;
}

static inline bool ltg_client_has_textures_signature(const ltg_client_t* client) {
	if (UTL_STRTOCSTR(ltg_client_get_textures_signature(client)) != NULL) {
		return true;
	}
	return false;
}

static inline pthread_t ltg_get_thread(const ltg_listener_t* listener) {
	return listener->thread;
}

static inline uint32_t ltg_get_client_count(ltg_listener_t* listener) {
	
	uint32_t size = 0;
	
	with_lock (&listener->clients.lock) {
		size = utl_id_vector_count(&listener->clients.vector);
	}

	return size;

}

static inline pthread_t ltg_client_get_thread(const ltg_client_t* client) {
	return client->thread;
}

static inline ltg_client_state_t ltg_client_get_state(const ltg_client_t* client) {
	return client->state;
}

static inline void ltg_client_set_state(ltg_client_t* client, ltg_client_state_t state) {
	client->state = state;
}

static inline bool ltg_client_is_encryption_enabled(const ltg_client_t* client) {
	return client->encryption.enabled;
}

static inline int32_t ltg_client_get_socket(const ltg_client_t* client) {
	return client->socket;
}

static inline uint32_t ltg_get_online_max(const ltg_listener_t* listener) {
	return listener->online.max;
}

static inline void ltg_add_online(ltg_listener_t* listener, ltg_client_t* client) {
	
	with_lock (&listener->online.lock) {
		client->online_node = utl_id_vector_push(&listener->online.vector, &client);
	}

}

static inline uint32_t ltg_get_online_count(ltg_listener_t* listener) {

	uint32_t count = 0;

	with_lock (&listener->online.lock) {
		count = utl_id_vector_count(&listener->online.vector);
	}

	return count;
	
}

static inline uint32_t ltg_get_online_length(ltg_listener_t* listener) {

	uint32_t length = 0;

	with_lock (&listener->online.lock) {
		length = utl_id_vector_length(&listener->online.vector);
	}

	return length;

}

static inline ltg_client_t* ltg_get_online_client(ltg_listener_t* listener, uint32_t idx) {
	
	ltg_client_t* client = NULL;

	with_lock (&listener->online.lock) {
		client = UTL_ID_VECTOR_GET_AS(ltg_client_t*, &listener->online.vector, idx);
	}

	return client;

}

static inline EVP_PKEY* ltg_get_keys(ltg_listener_t* listener) {
	return listener->keypair;
}