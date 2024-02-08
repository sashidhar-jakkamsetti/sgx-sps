#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ec.h>

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "enclave_t.h"
#include "parameters.h"
#include "enclave.h"
#include "crypto.h"

using namespace std;


RSA* generate_rsa_keypair() {
    RSA* rsaKeyPair = RSA_new();
    BIGNUM* exponent = BN_new();
    
    BN_set_word(exponent, RSA_F4);
    RSA_generate_key_ex(rsaKeyPair, RSA_KEY_BITS, exponent, nullptr);

    BN_free(exponent);
    return rsaKeyPair;
}

RSA* extract_rsa_pubkey(RSA* keypair) {
    if (keypair != nullptr) {
        RSA* pubkey = RSAPublicKey_dup(keypair);
        return pubkey;
    }
    return nullptr;
}

RSA* extract_rsa_privkey(RSA* keypair) {
    if (keypair != nullptr) {
        RSA* privkey = RSAPrivateKey_dup(keypair);
        return privkey;
    }
    return nullptr;
}

RSA* convert_buffer_2_rsa_pubkey(unsigned char* buffer, int len) {
    RSA* pubkey = d2i_RSAPublicKey(NULL, (const unsigned char**)&buffer, len);
    if (pubkey == NULL) {
        ocall_debug_print("Error converting buffer to rsa key");
        return nullptr;
    }
    return pubkey;
}

unsigned char* convert_rsa_pubkey_2_buffer(RSA* key, int* len) {
    unsigned char* buffer = NULL;
    *len = i2d_RSAPublicKey(key, &buffer);
    if (*len < RSA_PK_SIZE_BYTES) {
        ocall_debug_print("Error converting rsa key to buffer");
        return nullptr;
    }
    return buffer;
}


EC_KEY* generate_ec_keypair() {
    EC_KEY* keypair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(EC_KEY_generate_key(keypair) == 0) {
        EC_KEY_free(keypair);
        return nullptr;
    }
    return keypair;
}

EC_KEY* extract_ec_pubkey(EC_KEY* keypair) {
    const EC_POINT* po_privkey = EC_KEY_get0_public_key(keypair);
    EC_KEY* pubkey = EC_KEY_new();
    const EC_GROUP* group = EC_KEY_get0_group(keypair);
    EC_KEY_set_group(pubkey, group);
    EC_KEY_set_public_key(pubkey, po_privkey);
    return pubkey;
}

EC_KEY* convert_buffer_2_ec_pubkey(unsigned char* buffer, int len) {
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    key = o2i_ECPublicKey(&key, (const unsigned char**)&buffer, len);
    if (!key) {
        ocall_debug_print("Error converting unsigned char to ec public key");
        EC_KEY_free(key);
        return nullptr;
    }
    return key;
}

unsigned char* convert_ec_pubkey_2_buffer(EC_KEY* key, int* len) {
    unsigned char *buffer = NULL;
	*len = i2o_ECPublicKey(key, &buffer);
	if (*len < EC_PK_SIZE_BYTES) {
        ocall_debug_print("Error converting ec public key to unsigned char");
        return nullptr;
    }
    return buffer;
}

EC_KEY* extract_ec_privkey(EC_KEY* keypair) {
    const BIGNUM* bn_privkey = EC_KEY_get0_private_key(keypair);
    EC_KEY* privkey = EC_KEY_new();
    const EC_GROUP* group = EC_KEY_get0_group(keypair);
    EC_KEY_set_group(privkey, group);
    EC_KEY_set_private_key(privkey, bn_privkey);
    return privkey;
}


unsigned char* generate_aes_key(int* aeskey_len) {
    *aeskey_len = AES_GCM_KEY_BITS/8;
    unsigned char* aeskey = new unsigned char[*aeskey_len];
    RAND_bytes((unsigned char*)aeskey, *aeskey_len);
    return aeskey;
}


unsigned char* rsa_encrypt(unsigned char* plaintext, int plaintext_len, int* ciphertext_len, RSA* pubkey) {
    int rsa_size = RSA_size(pubkey);
    unsigned char* ciphertext = new unsigned char[rsa_size];
    
    EVP_PKEY *evp_pubkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp_pubkey, pubkey);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_pubkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    int ret = EVP_PKEY_encrypt(ctx, ciphertext, (size_t*)ciphertext_len, plaintext, plaintext_len);
    if (ret != 1) {
        ocall_debug_print("Error encrypting data using rsa public key");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_pubkey);
    return ciphertext;
}

unsigned char* rsa_decrypt(unsigned char* ciphertext, int ciphertext_len, int* plaintext_len, RSA* privkey) {
    int rsa_size = RSA_size(privkey);
    unsigned char* plaintext = new unsigned char[rsa_size];

    EVP_PKEY *evp_privkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp_privkey, privkey);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_privkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    int ret = EVP_PKEY_decrypt(ctx, plaintext, (size_t*)plaintext_len, ciphertext, ciphertext_len);
    if (ret != 1) {
        ocall_debug_print("Error decrypting data using rsa private key");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_privkey);
    return plaintext;
}


unsigned char* rsa_sign(unsigned char* message, int message_len,  int* signature_len, RSA* privkey) {
    int rsa_size = RSA_size(privkey);
    unsigned char *signature = new unsigned char[rsa_size];

    EVP_PKEY *evp_privkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp_privkey, privkey);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, message, message_len);
    int ret = EVP_SignFinal(ctx, signature, (unsigned int*)signature_len, evp_privkey);
    if (ret != 1) {
        ocall_debug_print("Error signing data using rsa private key");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(evp_privkey);
    return signature;
}

int rsa_verify(unsigned char* message, int message_len, unsigned char* signature, int signature_len, RSA* pubkey) {
    EVP_PKEY *evp_pubkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp_pubkey, pubkey);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, message, message_len);
    int ret = EVP_VerifyFinal(ctx, signature, signature_len, evp_pubkey);
    if (ret != 1) {
        ocall_debug_print("Error verifying data using rsa public key");
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(evp_pubkey);
    return ret;
}


unsigned char* ec_encrypt(unsigned char* plaintext, int plaintext_len, int* ciphertext_len, 
    EC_KEY* mykey, EC_KEY* other_pubkey) {
    
    int ret = 0;
    int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(mykey));
    int shared_key_len = (field_size + 7)/8;
    unsigned char* shared_key = new unsigned char[shared_key_len];
    shared_key_len = ECDH_compute_key(shared_key, shared_key_len, EC_KEY_get0_public_key(other_pubkey), mykey, NULL);
    
    unsigned char aeskey[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, shared_key, shared_key_len);
    ret = SHA256_Final(aeskey, &sha256);
    if (ret != 1) {
        ocall_debug_print("Error hashing shared secret using EC_key");
    }

    unsigned char aeskey_short[AES_GCM_KEY_BITS/8];
    memcpy(aeskey_short, aeskey, AES_GCM_KEY_BITS/8);
    unsigned char* ciphertext = aes_gcm_encrypt(aeskey_short, plaintext, plaintext_len, ciphertext_len);

    delete[] shared_key;
    return ciphertext;
}

unsigned char* ec_decrypt(unsigned char* ciphertext, int ciphertext_len, int* plaintext_len, 
    EC_KEY* mykey, EC_KEY* other_pubkey) {
    
    int ret = 0;
    int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(mykey));
    int shared_key_len = (field_size + 7)/8;
    unsigned char* shared_key = new unsigned char[shared_key_len];
    shared_key_len = ECDH_compute_key(shared_key, shared_key_len, EC_KEY_get0_public_key(other_pubkey), mykey, NULL);
    
    unsigned char aeskey[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, shared_key, shared_key_len);
    ret = SHA256_Final(aeskey, &sha256);
    if (ret != 1) {
        ocall_debug_print("Error hashing shared secret using EC_key: ");
    }

    unsigned char aeskey_short[AES_GCM_KEY_BITS/8];
    memcpy(aeskey_short, aeskey, AES_GCM_KEY_BITS/8);
    unsigned char* plaintext = aes_gcm_decrypt(aeskey_short, ciphertext, ciphertext_len, plaintext_len);

    delete[] shared_key;
    return plaintext;
}

int get_enc_blob_ec_pubkey_extra_size() {
    return get_aes_gcm_extra_size();
}


unsigned char* ecdsa_sign(unsigned char* message, int message_len, int* signature_len, EC_KEY* privkey) {
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, message_len);
    SHA256_Final(hash, &sha256);
    
    ECDSA_SIG* signature = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, privkey);
    if (signature == NULL) {
        ocall_debug_print("Error signing message using EC_key: ");
    }
    unsigned char *signature_der = nullptr;
    *signature_len = i2d_ECDSA_SIG(signature, &signature_der);
    return signature_der;
}

int ecdsa_verify(unsigned char* message, int message_len, unsigned char* signature, int signature_len, EC_KEY* pubkey) {
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, message_len);
    SHA256_Final(hash, &sha256);
    
    ECDSA_SIG *signature_ver = NULL;
    d2i_ECDSA_SIG(&signature_ver, (const unsigned char**)&signature, signature_len);
    int res = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, signature_ver, pubkey);
    return res;
}


unsigned char* aes_gcm_encrypt(unsigned char* aeskey, unsigned char* plaintext, int plaintext_len, int* ciphertext_len) {
    EVP_CIPHER_CTX* ctx;
    int len = 0, offset = 0, ret = 0;
    unsigned char* ciphertext = new unsigned char[AES_GCM_IV_BYTES + plaintext_len + AES_GCM_TAG_BYTES];

    ctx = EVP_CIPHER_CTX_new();
    
    if (AES_GCM_KEY_BITS == 256) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    }
    else {
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    }
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_BYTES, NULL);

    unsigned char* iv = new unsigned char[AES_GCM_IV_BYTES];
    RAND_bytes((unsigned char*)iv, AES_GCM_IV_BYTES);
    memcpy(ciphertext, iv, AES_GCM_IV_BYTES);
    offset += AES_GCM_IV_BYTES;

    EVP_EncryptInit_ex(ctx, NULL, NULL, aeskey, iv);
    EVP_EncryptUpdate(ctx, ciphertext + offset, &len, plaintext, plaintext_len);
    offset += len;

    ret = EVP_EncryptFinal_ex(ctx, ciphertext + offset, &len);
    if (ret != 1) {
        ocall_debug_print("Error encrypting plaintext using aes gcm key");
    }
    offset += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_BYTES, ciphertext + offset);
    offset += AES_GCM_TAG_BYTES;
    *ciphertext_len = offset;

    delete[] iv;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

unsigned char* aes_gcm_decrypt(unsigned char* aeskey, unsigned char* ciphertext, int ciphertext_len, int* plaintext_len) {
    EVP_CIPHER_CTX* ctx;
    int len = 0, offset = 0, ret = 0;
    ciphertext_len = ciphertext_len - AES_GCM_IV_BYTES - AES_GCM_TAG_BYTES;
    unsigned char* plaintext = new unsigned char[ciphertext_len];

    ctx = EVP_CIPHER_CTX_new();
    
    if (AES_GCM_KEY_BITS == 256) {
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    }
    else {
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    }
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_BYTES, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, aeskey, ciphertext);
    offset += AES_GCM_IV_BYTES;

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + offset, ciphertext_len);
    *plaintext_len = len;
    offset += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_BYTES, ciphertext + offset);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (ret != 1) {
        ocall_debug_print("Error decrypting ciphertext using aes gcm key");
    }
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

int get_aes_gcm_extra_size() {
    return AES_GCM_TAG_BYTES + AES_GCM_IV_BYTES;
}


unsigned char* encrypt_blob_rsa_pubkey(unsigned char* plaintext, int plaintext_len, int* ciphertext_len, RSA* pubkey) {
    int aeskey_len = 0;
    unsigned char* aeskey = generate_aes_key(&aeskey_len);

    int aes_ciphertext_len = 0;
    unsigned char* aes_ciphertext = aes_gcm_encrypt(aeskey, plaintext, plaintext_len, &aes_ciphertext_len);

    int pk_ciphertext_aeskey_len = 0;
    unsigned char* pk_ciphertext_aeskey = rsa_encrypt(aeskey, aeskey_len, &pk_ciphertext_aeskey_len, pubkey);

    unsigned char* encrypted_blob = new unsigned char[pk_ciphertext_aeskey_len + aes_ciphertext_len + (2*sizeof(int))];
    int offset = 0;
    memcpy(encrypted_blob + offset, &pk_ciphertext_aeskey_len, sizeof(int));
    offset += sizeof(int);
    memcpy(encrypted_blob + offset, pk_ciphertext_aeskey, pk_ciphertext_aeskey_len);
    offset += pk_ciphertext_aeskey_len;
    memcpy(encrypted_blob + offset, &aes_ciphertext_len, sizeof(int));
    offset += sizeof(int);
    memcpy(encrypted_blob + offset, aes_ciphertext, aes_ciphertext_len);
    offset += aes_ciphertext_len;
    *ciphertext_len = offset;
    
    delete[] aeskey;
    delete[] aes_ciphertext;
    delete[] pk_ciphertext_aeskey;
    return encrypted_blob;
}


unsigned char* decrypt_blob_rsa_pubkey(unsigned char* ciphertext, int ciphertext_len, int* plaintext_len, RSA* privkey) {
    int offset = 0;
    int pk_ciphertext_aeskey_len = 0;
    memcpy(&pk_ciphertext_aeskey_len, ciphertext, sizeof(int));
    offset += sizeof(int);

    int aeskey_len = 0;
    unsigned char* aeskey = rsa_decrypt(ciphertext + offset, pk_ciphertext_aeskey_len, &aeskey_len, privkey);
    offset += pk_ciphertext_aeskey_len;
    
    int aes_ciphertext_len = 0;
    memcpy(&aes_ciphertext_len, ciphertext + offset, sizeof(int));
    offset += sizeof(int);
    
    unsigned char* plaintext = aes_gcm_decrypt(aeskey, ciphertext + offset, aes_ciphertext_len, plaintext_len);

    delete[] aeskey;
    return plaintext;
}


int get_enc_blob_rsa_pubkey_extra_size(RSA* key) {
    return get_aes_gcm_extra_size() + (2*sizeof(int)) + RSA_size(key);
}
