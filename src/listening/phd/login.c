#include <curl/curl.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "login.h"
#include "play.h"
#include "string.h"
#include "../../util/util.h"
#include "../../motor.h"
#include "../../io/logger/logger.h"
#include "../../io/chat/chat.h"
#include "../../io/chat/translation.h"
#include "../../crypt/random.h"
#include "../../util/base64.h"
#include "time.h"

#define ID_LOGIN 0x01
#define ID_PLAY_STATUS 0x02
#define ID_SERVER_TO_CLIENT_HANDSHAKE 0x03
#define ID_CLIENT_TO_SERVER_HANDSHAKE 0x04
#define ID_DISCONNECT 0x05
#define ID_RESOURCE_PACKS_INFO 0x06
#define ID_RESOURCE_PACK_STACK 0x07
#define ID_RESOURCE_PACK_CLIENT_RESPONSE 0x08

#define LOGIN_SUCCESS 0
#define LOGIN_FAILED_EDITOR_VANILLA 8

bool phd_login(ltg_client_t* client, pck_packet_t* packet) {

	const int32_t id = pck_read_var_int(packet);
	log_info("id %d", id);
	switch (id) {
		case ID_LOGIN: {
			return phd_handle_login(client, packet);
		}
		case ID_CLIENT_TO_SERVER_HANDSHAKE: {
			return phd_handle_encryption_response(client, packet);
		}
		case ID_RESOURCE_PACK_CLIENT_RESPONSE: {
			return phd_handle_resource_pack_response(client, packet);
		}
		default: {
			log_warn("Received unknown packet 0x%02x in login state!", id);
			return false;
		}
	}

}

bool phd_handle_login(ltg_client_t* client, pck_packet_t* packet) {
	struct timespec start_time, end_time;
	long long elapsed_nanos;
	packet->cursor += 4;//skip protocol version
    int32_t len = pck_read_var_int(packet);
    pck_packet_t *login = pck_from_bytes(pck_cursor(packet), len, io_little_endian);
    packet->cursor += len;
    int32_t identity_length = pck_read_int32(login);
	mjson_doc* auth = mjson_read((char *)login->bytes + login->cursor, (size_t)identity_length);
	login->cursor += identity_length;
	int32_t client_length = pck_read_int32(login);
	mjson_val* chain = mjson_property_get_value(mjson_obj_get(mjson_get_root(auth), 0));
	if(mjson_get_size(chain) != 3){
		return false;
	}
	jwt_data_t jwt0 = phd_read_jwt(mjson_get_string(mjson_arr_get(chain, 0)));
	jwt_data_t jwt1 = phd_read_jwt(mjson_get_string(mjson_arr_get(chain, 1)));
	jwt_data_t jwt2 = phd_read_jwt(mjson_get_string(mjson_arr_get(chain, 2)));
	unsigned char *current_public_key = NULL;
	bool not_trust = false;
	not_trust |= !phd_verifly_jwt_chain(&jwt0, &current_public_key, 0);
	not_trust |= !phd_verifly_jwt_chain(&jwt1, &current_public_key, 1);
	not_trust |= !phd_verifly_jwt_chain(&jwt2, &current_public_key, 2);
	log_warn("pass %d", !not_trust);
	mjson_free(auth);
	jwt_data_t jwt3 = phd_read_jwt((char *) login->bytes + login->cursor);
	not_trust |= !phd_verifly_jwt_chain(&jwt3, &current_public_key, 3);
	if (sky_is_online_mode()) {
		if(not_trust){
			phd_send_disconnect(client, "kuy", 4);
			return false;
		}
		client->encryption.salt = (unsigned char *) malloc(16 * sizeof(unsigned char));
		cry_random_bytes(client->encryption.salt, 16U);
		phd_set_up_encyption(client, &current_public_key, jwt2.signature.length);
		client->encryption.enabled = phd_send_encryption_request(client);
		client->encryption.encrypt_counter = 0;
		client->encryption.decrypt_counter = 0;
	} else {
		phd_update_login_success(client);
	}
	return true;
}

bool phd_verifly_jwt_chain(jwt_data_t *jwtchain, unsigned char **current_public_key, uint8_t chainid) {//idk
	int64_t timern = (int64_t) time(NULL);
    size_t decoded_len = 0;
	mjson_doc* header_doc = mjson_read((int8_t *) b64url_decode_with_alloc((const uint8_t *) jwtchain->raw_header.value, jwtchain->raw_header.length, &decoded_len), decoded_len);
	size_t combined_len = jwtchain->raw_header.length + jwtchain->raw_payload.length + 2;
	char *combined = (char *) malloc(combined_len);
    snprintf(combined, combined_len, "%s.%s", jwtchain->raw_header.value, jwtchain->raw_payload.value);
	size_t signature_size;//96
	string_t raw_signature = UTL_ARRTOSTR((int8_t *)b64url_decode_with_alloc((const uint8_t *)jwtchain->signature.value, jwtchain->signature.length, &signature_size), signature_size);
	if(signature_size != 96){
		free(combined);
		UTL_FREESTR(raw_signature);
		return false;
	}
	mjson_val* x5u = mjson_property_get_value(mjson_obj_get(mjson_get_root(header_doc), 1));
	if(x5u->type != MJSON_STRING){
		free(combined);
		UTL_FREESTR(raw_signature);
		mjson_free(header_doc);
		return false;
	}
	string_t header_der_key = UTL_ARRTOSTR((int8_t *)b64_decode_with_alloc((const uint8_t *)x5u->value.String.value, x5u->value.String.length, &decoded_len), decoded_len);
	mjson_free(header_doc);
	if(*current_public_key == NULL){
		if(chainid != 0){
			free(combined);
			UTL_FREESTR(raw_signature);
			UTL_FREESTR(header_der_key);
			return false;
		}
	}else if(strcmp(header_der_key.value, (char *)*current_public_key) != 0){
		free(combined);
		UTL_FREESTR(header_der_key);
		UTL_FREESTR(raw_signature);
		return false;
	}
	int nsig_size = (int) signature_size >> 1; //bit shift was faster
    BIGNUM* pr = BN_bin2bn((unsigned char *) raw_signature.value, nsig_size, NULL);
    BIGNUM* ps = BN_bin2bn((unsigned char *) raw_signature.value + nsig_size, nsig_size, NULL);
	UTL_FREESTR(raw_signature);
	ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
	ECDSA_SIG_set0(ecdsa_sig, pr, ps);
	unsigned char *new_sig = NULL;
    int new_sig_len = i2d_ECDSA_SIG(ecdsa_sig, &new_sig);
	BN_free(pr);
	BN_free(ps);
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	EVP_PKEY *public_key = d2i_PUBKEY(NULL, (const unsigned char **)&header_der_key.value, header_der_key.length);
	if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha384(), NULL, public_key) != 1) {
		free(new_sig);
		EVP_PKEY_free(public_key);
		EVP_MD_CTX_free(md_ctx);
		free(combined);
		return false;
	}
	EVP_PKEY_free(public_key);
	if (EVP_DigestVerifyUpdate(md_ctx, combined, combined_len -1) != 1) {
		free(combined);
		free(new_sig);
		EVP_MD_CTX_free(md_ctx);
		return false;
	}
	free(combined);
	int result = EVP_DigestVerifyFinal(md_ctx, new_sig, new_sig_len);
	free(new_sig);
	EVP_MD_CTX_free(md_ctx);
	if(result != 1) return false;
	if(chainid == 3) return true;
	string_t payload_decoded = UTL_ARRTOSTR((int8_t *) b64url_decode_with_alloc((const uint8_t *) jwtchain->raw_payload.value, jwtchain->raw_payload.length, &decoded_len), decoded_len);
	mjson_doc* payload_doc = mjson_read(payload_decoded.value, payload_decoded.length);
	mjson_val* payload_entry = mjson_get_root(payload_doc);
	mjson_val* exp_date = mjson_property_get_value(mjson_obj_get(payload_entry, chainid == 0 ? 1 : chainid + 2));
	mjson_val* identity_public_key = mjson_property_get_value(mjson_obj_get(payload_entry, chainid == 0 ? 2 : 6));
	mjson_val* nbf_date = mjson_property_get_value(mjson_obj_get(payload_entry, chainid == 0 ? 3 : 0));
	if (identity_public_key->type != MJSON_STRING || exp_date->type != MJSON_INTEGER || nbf_date->type != MJSON_INTEGER) {
		mjson_free(payload_doc);
		return false;
	}
	if(mjson_get_int(nbf_date) > timern + 60 || mjson_get_int(exp_date) < timern - 60){
		mjson_free(payload_doc);
		return false;
	}
	*current_public_key = b64_decode_with_alloc((const uint8_t *)identity_public_key->value.String.value, identity_public_key->value.String.length, &decoded_len);
	jwtchain->signature.length = decoded_len;
	mjson_free(payload_doc);
	return true;
}

bool phd_handle_encryption_response(ltg_client_t* client, pck_packet_t* packet) {
	log_info("player encyption done");
	return true;
}

bool phd_handle_resource_pack_response(ltg_client_t* client, pck_packet_t* packet) {

	return true;
}

void phd_send_disconnect_login(ltg_client_t* client, const char* message, size_t message_len) {

	PCK_INLINE(packet, 1 + message_len, io_little_endian);

	pck_write_var_int(packet, ID_DISCONNECT);

	pck_write_string(packet, message, message_len);

	ltg_send(client, packet);

}

bool phd_send_encryption_request(ltg_client_t* client) {//weird idk is it working or not
    BIO *bio = BIO_new(BIO_s_mem());
    if (!i2d_PUBKEY_bio(bio, ltg_get_keys(sky_get_listener()))) {
        BIO_free(bio);
        return false;
    }
    size_t der_length = (size_t)BIO_pending(bio);
    unsigned char* der_string = (unsigned char *)malloc(der_length);
    if (!der_string) {
        BIO_free(bio);
        return false;
    }
    if (BIO_read(bio, der_string, (int)der_length) != der_length) {
        free(der_string);
        BIO_free(bio);
        return false;
    }
    BIO_free(bio);
	size_t out_length;
	char *new_salt = b64_encode_with_alloc(client->encryption.salt, strlen((char *)client->encryption.salt), &out_length);
	size_t json_salt_len = strlen("{\"salt\":\"\"}") + out_length + 1;
    char json_salt[json_salt_len];
    snprintf(json_salt, json_salt_len, "{\"salt\":\"%s\"}", new_salt);
	free(new_salt);
	size_t actual_salt_len;
	char *actual_salt = b64url_encode_with_alloc((unsigned char *)json_salt, json_salt_len -1, &actual_salt_len);
	char *x5u = b64_encode_with_alloc(der_string, der_length, &out_length);
	free(der_string);
	size_t raw_body_len = strlen("{\"x5u\":\"\",\"alg\":\"ES384\"}") + out_length + 1;
    char raw_body[raw_body_len];
    snprintf(raw_body, raw_body_len, "{\"x5u\":\"%s\",\"alg\":\"ES384\"}", x5u);
	free(x5u);
	size_t body_hack_len;
	unsigned char *body_hack = (unsigned char *)b64url_encode_with_alloc((unsigned char *)raw_body, raw_body_len -1, &body_hack_len);
	size_t hack_body_len = body_hack_len + actual_salt_len + 2;
    char hack_body[hack_body_len];
    snprintf(hack_body, hack_body_len, "%s.%s", (char *)body_hack, (char *)actual_salt);
	free(body_hack);
	free(actual_salt);
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		return false;
	}
	if (EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, ltg_get_keys(sky_get_listener())) != 1) {
		return false;
	}
	if (EVP_DigestSignUpdate(mdctx, hack_body, hack_body_len - 1) != 1) {
		return false;
	}
	size_t sigLength;
	if (EVP_DigestSignFinal(mdctx, NULL, &sigLength) != 1) {
		return false;
	}
	unsigned char *signature = (unsigned char *)malloc(sigLength);
	if (!signature) {
		return false;
	}
	if (EVP_DigestSignFinal(mdctx, signature, &sigLength) != 1) {
		return false;
	}
	ECDSA_SIG *parsedSignature = d2i_ECDSA_SIG(NULL, &signature, sigLength);
	if (!parsedSignature) {
		return false;
	}
	EVP_MD_CTX_free(mdctx);
	const BIGNUM *pr = ECDSA_SIG_get0_r(parsedSignature);
	const BIGNUM *ps = ECDSA_SIG_get0_s(parsedSignature);
	free(parsedSignature);
	int rlen = BN_num_bytes(pr);
    int slen = BN_num_bytes(ps);
	unsigned char sig[96];
    BN_bn2bin(pr, sig + 48 - rlen);
    BN_bn2bin(ps, sig + 96 - slen);
	BN_free((BIGNUM *)pr);
	BN_free((BIGNUM *)ps);
	size_t signature_encoded_len;
	char *signature_encoded = b64url_encode_with_alloc((unsigned char *)sig, 96, &signature_encoded_len);
	size_t final_jwt_len = hack_body_len + signature_encoded_len + 2;
    char final_jwt[final_jwt_len];
    snprintf(final_jwt, final_jwt_len, "%s.%s", (char *)hack_body, signature_encoded);
	free(signature_encoded);
	final_jwt_len -= 1;
	log_error("jwt: %s", final_jwt);
	PCK_INLINE(respond, 1 + final_jwt_len + io_var_int_length(final_jwt_len), io_little_endian);
	pck_write_var_int(respond, ID_SERVER_TO_CLIENT_HANDSHAKE);
	pck_write_string(respond, final_jwt, final_jwt_len);
	ltg_send(client, respond);
	log_warn("send handshake");
	return true;
}

void phd_send_login_success(ltg_client_t* client) {
	PCK_INLINE(respond, 5, io_little_endian);
	pck_write_var_int(respond, ID_PLAY_STATUS);
	pck_write_inte32(respond, LOGIN_SUCCESS, io_big_endian);
	ltg_send(client, respond);
}

void phd_set_up_encyption(ltg_client_t* client, unsigned char** player_key, size_t key_size) {//weird randomly working sometime
	size_t keylen = 48;//set key size
	unsigned char *derived_key = (unsigned char *) malloc(keylen);
	EVP_PKEY *player_public_key = d2i_PUBKEY(NULL, player_key, key_size);//load player key
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ltg_get_keys(sky_get_listener()), NULL);//create ctx
	if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, player_public_key) <= 0 || EVP_PKEY_derive(ctx, derived_key, &keylen) <= 0) {//combine key
        EVP_PKEY_free(player_public_key);
        EVP_PKEY_CTX_free(ctx);
		free(derived_key);
        return;
    }
    EVP_PKEY_free(player_public_key);//clear
    EVP_PKEY_CTX_free(ctx);
    // Perform SHA-256 hash (working)
	unsigned int secretKeyLen = 32;
    byte_t secretKeyBytes[secretKeyLen];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, client->encryption.salt, 16); //saltsize = 16
    EVP_DigestUpdate(mdctx, derived_key, keylen);
	EVP_MD_CTX_destroy(mdctx);
	free(derived_key);
	byte_t iv[16];//keysize
	memcpy(iv, secretKeyBytes, 12);//use 0-12
	memset(iv + 12, 0, 4);//set 13-14 to 0
	iv[15] = (unsigned char)2;//set 15 to 2
	ctr256_init(secretKeyBytes, iv, &client->encryption.encrypt, &client->encryption.decrypt);
}

void phd_send_login_plugin_request(ltg_client_t* client, const char* identifier, size_t identifier_length, const byte_t* data, size_t data_length) {

	PCK_INLINE(packet, identifier_length + data_length + 20, io_big_endian);

	pck_write_var_int(packet, 0x04);
	pck_write_var_int(packet, ltg_client_get_id(client));
	pck_write_string(packet, identifier, identifier_length);

	pck_write_bytes(packet, data, data_length);

	ltg_send(client, packet);

}

void phd_update_login_success(ltg_client_t* client) {
	// send login success packet
	phd_send_login_success(client);

	// switch to play state and join game
	ltg_client_set_state(client, ltg_play);
	// phd_send_join_game(client);

}