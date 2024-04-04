#include "status.h"
#include "../../io/logger/logger.h"
#include "../../io/chat/chat.h"

#define ID_PLAY_STATUS 0x02
#define ID_NETWORK_SETTINGS 0x8F
#define ID_REQUEST_NETWORK_SETTINGS 0xC1

#define  LOGIN_FAILED_CLIENT 1
#define  LOGIN_FAILED_SERVER 2

bool phd_status(ltg_client_t* client, pck_packet_t* packet) {

	const int32_t id = pck_read_var_int(packet);

	switch (id) {
		case ID_REQUEST_NETWORK_SETTINGS: {
			return phd_handle_request(client, packet);
		}
		default: {
			log_warn("Received unknown packet %02x in status state!", id);
			return false;
		}
	}

}

bool phd_handle_request(ltg_client_t* client, pck_packet_t* packet) {
	ltg_client_set_protocol(client, pck_read_intb32(packet));
	log_info("req %d %d", ltg_client_get_protocol(client), sky_get_protocol());
    if(ltg_client_get_protocol(client) < sky_get_protocol() && ltg_client_get_protocol(client) > sky_get_max_protocol()){
		if (ltg_client_get_protocol(client) < sky_get_max_protocol()) {
			phd_send_play_status(client, LOGIN_FAILED_CLIENT);
		} else{
			phd_send_play_status(client, LOGIN_FAILED_SERVER);
		}
		return false;
    }else{
		phd_compression_response(client);
    }
	return true;
}

void phd_compression_response(ltg_client_t* client) {
	PCK_INLINE(respond, 12, io_little_endian);
	pck_write_var_int(respond, ID_NETWORK_SETTINGS);
	pck_write_int16(respond, 1);//compress
	pck_write_int16(respond, 0);//zlib
	pck_write_int8(respond, 0);
	pck_write_int8(respond, 0);
	pck_write_float32(respond, 0);
	ltg_send(client, respond);
	ltg_client_set_state(client, ltg_login);
	client->compression_enabled = true;
}

void phd_send_play_status(ltg_client_t* client, int32_t status) {
	PCK_INLINE(respond, 5, io_little_endian);
	pck_write_var_int(respond, ID_PLAY_STATUS);
	pck_write_inte32(respond, status, io_big_endian);
	ltg_send(client, respond);
}