#pragma once
#include "../../main.h"
#include "../../io/packet/packet.h"
#include "../listening.h"
#include "string.h"
#include "openssl/evp.h"
#include "string.h"

#define MOJANG_ROOT_KEY "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECRXueJeTDqNRRgJi/vlRufByu/2G0i2Ebt6YMar5QX/R0DIIyrJMcUpruK4QveTfJSTp3Shlq4Gk34cD/4GUWwkv0DVuzeuB+tXija7HBxii03NHDbPAD0AKnLr2wdAp"

extern bool phd_login(ltg_client_t*, pck_packet_t*);

//inbound
extern bool phd_handle_login(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_encryption_response(ltg_client_t*, pck_packet_t*);
extern bool phd_handle_resource_pack_response(ltg_client_t*, pck_packet_t*);

typedef struct {
  string_t raw_header;
  string_t raw_payload;
  string_t signature;
} jwt_data_t;

static inline jwt_data_t phd_read_jwt(char *token) {
  jwt_data_t jwt;
  char* header = strtok(token, ".");
  jwt.raw_header = UTL_CSTRTOSTR_STRLEN(header);
  char* payload = strtok(NULL, ".");
  jwt.raw_payload = UTL_CSTRTOSTR_STRLEN(payload);
  char* signature = strtok(NULL, ".");
  jwt.signature = UTL_CSTRTOSTR_STRLEN(signature);
	return jwt;
}

bool phd_verifly_jwt_chain(jwt_data_t *jwtchain, unsigned char **current_public_key, uint8_t chainid);
//outbound
extern void phd_send_disconnect_login(ltg_client_t*, const char*, size_t);
extern bool phd_send_encryption_request(ltg_client_t*);
extern void phd_send_login_success(ltg_client_t*);
extern void phd_set_up_encyption(ltg_client_t*, unsigned char**, size_t);
extern void phd_send_login_plugin_request(ltg_client_t*, const char* identifier, size_t identifier_length, const byte_t* data, size_t data_length);

extern void phd_update_login_success(ltg_client_t* client);