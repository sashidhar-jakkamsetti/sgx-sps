
#ifndef DATATYPES_H_
#define DATATYPES_H_

#include <stdlib.h>
#include "parameters.h"
#include <openssl/ec.h>
#include <openssl/rsa.h>

using namespace std;

typedef struct keys_output_t {
    unsigned char pk[EC_PK_SIZE_BYTES];
    unsigned char vk[EC_PK_SIZE_BYTES];
    unsigned char service_pk[RSA_PK_SIZE_BYTES];
} keys_output_t;

typedef struct setup_input_t {
    int rid;
    int counter;
    unsigned char pk[EC_PK_SIZE_BYTES];
    unsigned char vk[EC_PK_SIZE_BYTES];
} setup_input_t;

typedef struct setup_output_t {
    int nxt_recip_idx;
    unsigned char pk[EC_PK_SIZE_BYTES];
} setup_output_t;

typedef struct send_input_t {
    int rid;
    int loc;
} send_input_t;

typedef struct send_output_t {
    int nxt_msg_idx;
} send_output_t;

typedef struct receive_input_t {
    int rid;
    int counter;
    int retrieve_len;
    unsigned char sig[ECDSA_SIG_SIZE_BYTES];
} receive_input_t;

typedef struct keychain_t {
	EC_KEY* enck;
	EC_KEY* deck;
	EC_KEY* sigk;
	EC_KEY* verk;
    RSA* enck_send;
	RSA* deck_send;
} keychain_t;



#endif
