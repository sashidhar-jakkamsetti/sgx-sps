

#ifndef APP_CRYPTO_H_
#define APP_CRYPTO_H_

#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <iostream>
#include <string>
#include <cstring>
#include "parameters.h"

using namespace std;

RSA* generate_rsa_keypair();
RSA* extract_rsa_pubkey(RSA* keypair);
RSA* extract_rsa_privkey(RSA* keypair);
RSA* convert_buffer_2_rsa_pubkey(unsigned char* buffer, int len);
unsigned char* convert_rsa_pubkey_2_buffer(RSA* key, int* len);

EC_KEY* generate_ec_keypair();
EC_KEY* extract_ec_pubkey(EC_KEY* keypair);
EC_KEY* extract_ec_privkey(EC_KEY* keypair);
EC_KEY* convert_buffer_2_ec_pubkey(unsigned char* buffer, int len);
unsigned char* convert_ec_pubkey_2_buffer(EC_KEY* key, int* len);

unsigned char* generate_aes_key(int* aeskey_len);

unsigned char* rsa_encrypt(unsigned char* plaintext, int plaintext_len, int* ciphertext_len, RSA* pubkey);
unsigned char* rsa_decrypt(unsigned char* ciphertext, int ciphertext_len, int* plaintext_len, RSA* privkey);

unsigned char* rsa_sign(unsigned char* message, int message_len, int* signature_len, RSA* privkey);
int rsa_verify(unsigned char* message, int message_len, unsigned char* signature, int signature_len, RSA* pubkey);

unsigned char* ec_encrypt(unsigned char* plaintext, int plaintext_len, int* ciphertext_len, EC_KEY* mykey, EC_KEY* other_pubkey);
unsigned char* ec_decrypt(unsigned char* ciphertext, int ciphertext_len, int* plaintext_len, EC_KEY* mykey, EC_KEY* other_pubkey);
int get_enc_blob_ec_pubkey_extra_size();

unsigned char* ecdsa_sign(unsigned char* message, int message_len, int* signature_len, EC_KEY* privkey);
int ecdsa_verify(unsigned char* message, int message_len, unsigned char* signature, int signature_len, EC_KEY* pubkey);

unsigned char* aes_gcm_encrypt(unsigned char* aeskey, unsigned char* plaintext, int plaintext_len, int* ciphertext_len);
unsigned char* aes_gcm_decrypt(unsigned char* aeskey, unsigned char* ciphertext, int ciphertext_len, int* plaintext_len);
int get_aes_gcm_extra_size();

unsigned char* encrypt_blob_rsa_pubkey(unsigned char* plaintext, int plaintext_len, int* ciphertext_len, RSA* pubkey);
unsigned char* decrypt_blob_rsa_pubkey(unsigned char* ciphertext, int ciphertext_len, int* plaintext_len, RSA* privkey);
int get_enc_blob_rsa_pubkey_extra_size(RSA* key);

#endif