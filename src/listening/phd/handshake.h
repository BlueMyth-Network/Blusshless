#pragma once
#include "../../main.h"
#include "../../io/packet/packet.h"
#include "../listening.h"

extern bool phd_unconnected(pck_packet_t*, struct sockaddr_in*, int32_t);

extern void phd_reply_1(pck_packet_t*, struct sockaddr_in*, int32_t);
extern bool phd_reply_2(pck_packet_t*, struct sockaddr_in*, int32_t);

extern bool phd_packets(ltg_client_t*, pck_packet_t*);

extern bool phd_handle_packet(ltg_client_t*, pck_packet_t*);

//inboud
extern bool phd_handle_ack_nack(ltg_client_t*, pck_packet_t*, uint8_t);
extern bool phd_handle_frame(ltg_client_t*, pck_packet_t*);
extern bool phd_decode_batch_packets(ltg_client_t*, pck_packet_t*);

//outboud
extern bool phd_send_ack_nack(ltg_client_t*, bool);
extern bool phd_connected_pong(ltg_client_t*, pck_packet_t*);
extern bool phd_connection_accepted(ltg_client_t*, pck_packet_t*);
extern void phd_send_legacy_slp(ltg_client_t*);