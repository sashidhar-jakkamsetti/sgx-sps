
#ifndef PARAMETERS_H_
#define PARAMETERS_H_


/* Cryptographic parameters */
#define RSA_KEY_BITS 2048
#define AES_GCM_KEY_BITS 128
#define AES_GCM_IV_BYTES 12
#define AES_GCM_TAG_BYTES 16
#define EC_PK_SIZE_BYTES 65
#define ECDSA_SIG_SIZE_BYTES 80
#define RSA_PK_SIZE_BYTES 270


/* Recipient parameters */
#define RECIPIENT_DATA_BITS 16


/* Service parameters (fully configurable)*/
#define SERVICE_MAX_RECIPIENTS 500  // For comparison with related work
// #define SERVICE_MAX_RECIPIENTS 1048572
// #define SERVICE_MAX_RECIPIENTS 16380
// #define SERVICE_MAX_RECIPIENTS 1020
// #define SERVICE_MAX_RECIPIENTS 124
// #define SERVICE_MAX_RECIPIENTS 12

#define SERVICE_MAX_MESSAGES 500000 // For comparison with related work
// #define SERVICE_MAX_MESSAGES 134271724
// #define SERVICE_MAX_MESSAGES 16777212
// #define SERVICE_MAX_MESSAGES 1048572
// #define SERVICE_MAX_MESSAGES 16380
// #define SERVICE_MAX_MESSAGES 1020
// #define SERVICE_MAX_MESSAGES 124

#define SERVICE_BATCH_RECEIVE 1     // For comparison with related work


/* ORAM parameters */
#define ORAM_BLOCK_SIZE (3*sizeof(int) + 2*EC_PK_SIZE_BYTES)
#define ORAM_BUCKET_SIZE 4
#define ORAM_ACCESS_BATCH_SIZE 32


#endif