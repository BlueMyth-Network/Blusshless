#pragma once
#include "../../motor.h"
#include "../../main.h"
#include "../../io/packet/packet.h"
#include "../listening.h"

extern bool phd_status(ltg_client_t*, pck_packet_t*);

//inbound
extern bool phd_handle_request(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_ping(ltg_client_t*, pck_packet_t*);

//outbound
extern void phd_compression_response(ltg_client_t*);
extern void phd_send_play_status(ltg_client_t*, int32_t);
