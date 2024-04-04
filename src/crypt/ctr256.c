#include "ctr256.h"

int ctr256_init(byte_t* key, byte_t* iv, EVP_CIPHER_CTX** e, EVP_CIPHER_CTX** d) {
	
	if ((*e = EVP_CIPHER_CTX_new()) == NULL) {
		return 0;
	}

	if (EVP_EncryptInit_ex(*e, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
		return 0;
	}

	if ((*d = EVP_CIPHER_CTX_new()) == NULL) {
		return 0;
	}

	if (EVP_DecryptInit_ex(*d, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
		return 0;
	}

	return 1;
}

int ctr256_encrypt(EVP_CIPHER_CTX* e, byte_t* restrict data, size_t len, byte_t* restrict out, int* out_len) {

	return EVP_EncryptUpdate(e, out, out_len, data, len);

}

int ctr256_decrypt(EVP_CIPHER_CTX* d, byte_t* restrict data, size_t len, byte_t* restrict out, int* out_len) {

	return EVP_DecryptUpdate(d, out, out_len, data, len);

}

int ctr256_done(EVP_CIPHER_CTX* e, EVP_CIPHER_CTX* d) {

	EVP_CIPHER_CTX_free(e);
	EVP_CIPHER_CTX_free(d);

	return 0;

}