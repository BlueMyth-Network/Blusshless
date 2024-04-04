#include <openssl/evp.h>
#include "../main.h"

int ctr256_init(byte_t* key, byte_t* iv, EVP_CIPHER_CTX** e, EVP_CIPHER_CTX** d);
int ctr256_encrypt(EVP_CIPHER_CTX* e, byte_t* restrict data, size_t len, byte_t* restrict out, int* out_len);
int ctr256_decrypt(EVP_CIPHER_CTX* d, byte_t* restrict data, size_t len, byte_t* restrict out, int* out_len);
int ctr256_done(EVP_CIPHER_CTX* e, EVP_CIPHER_CTX* d);