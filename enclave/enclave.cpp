
#include "enclave_t.h"
#include <string>
#include <cstring>

#include "crypto/crypto.h"
#include "enclave.h"
#include "parameters.h"
#include "datatypes.h"
#include "oram/oram.h"

using namespace std;


typedef struct enclave_orams_t {
	ORAM *messages;
	ORAM *recipients;
} enclave_orams_t;


static enclave_orams_t orams;
static keychain_t keys;
static bool is_init = false;
static int bucketSize = ORAM_BUCKET_SIZE;
static int nMessages = SERVICE_MAX_MESSAGES;
static int nRecip = SERVICE_MAX_RECIPIENTS;

static int ctr_recip = 0;
static int ctr_msg = 0;


inline void clearData(unsigned char* data, int start, int len) {
	memset(data + start, -1, len - start);
}


int ecall_init_service(int n_messages, int n_recip, int bucket_size) {

	int oram_ret = 0;
	if (!is_init) {
		nMessages = n_messages;
		nRecip = n_recip;
		bucketSize = bucket_size;
		// ocall_debug_print("Service: initiating service and creating ORAMs for messages, keys, and recipient DBs\n");

		orams.messages = new ORAM(NAME_MESSAGES_ORAM, bucketSize, nMessages);
		oram_ret = orams.messages->initialize();
		if (oram_ret != RET_SUCCESS) {
			return oram_ret;
		}
		// ocall_debug_print("Service: initialized messages DB");

		orams.recipients = new ORAM(NAME_RECIPIENTS_ORAM, bucketSize, nRecip);
		oram_ret = orams.recipients->initialize();
		if (oram_ret != RET_SUCCESS) {
			return oram_ret;
		}
		// ocall_debug_print("Service: initialized recipients DB");

		EC_KEY* keypair1 = generate_ec_keypair();
		keys.enck = extract_ec_pubkey(keypair1);
		keys.deck = extract_ec_privkey(keypair1);
		EC_KEY_free(keypair1);

		EC_KEY* keypair2 = generate_ec_keypair();
		keys.verk = extract_ec_pubkey(keypair2);
		keys.sigk = extract_ec_privkey(keypair2);
		EC_KEY_free(keypair2);

		RSA* keypair3 = generate_rsa_keypair();
		keys.enck_send = extract_rsa_pubkey(keypair3);
		keys.deck_send = extract_rsa_privkey(keypair3);
		RSA_free(keypair3);
		// ocall_debug_print("Service: enclaves keys generated");

		is_init = true;
		ctr_recip = 0;
		ctr_msg = 0;
		// ocall_debug_print("Service: service is up\n");
	}
	else {
		ocall_debug_print("Service: already initialized\n");
		return ERROR_SERVICE_RUNNING;
	}

	return RET_SUCCESS;
}


int ecall_get_keys(void* out_data, size_t out_size) {
	// string print_str = "";

	if (out_size != sizeof(keys_output_t)) {
		return ERROR_INVALID_ARGUMENTS;	
	}
	// ocall_debug_print("Service: sending enclave keys\n");

	keys_output_t out_get_keys_data;
	int buffer_len1 = 0;
	unsigned char *buffer1 = convert_ec_pubkey_2_buffer(keys.enck, &buffer_len1);
	
	if (!buffer1 || buffer_len1 != EC_PK_SIZE_BYTES) {
        ocall_debug_print("Service: Public key len is not equal to RECIPIENT_PK_SIZE_BYTES");
		return ERROR_VARIABLE_SIZE_INCONSISTENT;
    }
	memcpy(out_get_keys_data.pk, buffer1, buffer_len1);

	int buffer_len2 = 0;
	unsigned char *buffer2 = convert_ec_pubkey_2_buffer(keys.verk, &buffer_len2);
	if (!buffer2 || buffer_len2 != EC_PK_SIZE_BYTES) {
        ocall_debug_print("Service: Verification key len is not equal to RECIPIENT_VK_SIZE_BYTES");
		return ERROR_VARIABLE_SIZE_INCONSISTENT;
    }
	memcpy(out_get_keys_data.vk, buffer2, buffer_len2);

	int buffer_len3 = 0;
	unsigned char *buffer3 = convert_rsa_pubkey_2_buffer(keys.enck_send, &buffer_len3);
	if (!buffer3 || buffer_len3 != RSA_PK_SIZE_BYTES) {
        ocall_debug_print("Service: Encryption key (send) len is not equal to SERVICE_PK_SIZE_BYTES");
		return ERROR_VARIABLE_SIZE_INCONSISTENT;
    }
	memcpy(out_get_keys_data.service_pk, buffer3, buffer_len3);

	memcpy(out_data, &out_get_keys_data, sizeof(keys_output_t));
	// ocall_debug_print("Service: written enclave keys\n");
	return RET_SUCCESS;
}


int ecall_setup(void* in_data, size_t in_size, void* out_data, size_t out_size, 
		void* sig_data, size_t sig_size) {
	
	string print_str = "";
	int oram_ret = 0;
	if (in_size <= sizeof(setup_input_t) || out_size != sizeof(setup_output_t) 
			|| sig_size != ECDSA_SIG_SIZE_BYTES) {
		return ERROR_INVALID_ARGUMENTS;	
	}

	int plaintext_len = 0;
	unsigned char* plaintext = decrypt_blob_rsa_pubkey((unsigned char*)in_data, in_size, 
			&plaintext_len, keys.deck_send);

	if (plaintext_len != sizeof(setup_input_t)) {
		return ERROR_SERVICE_DECRYPTION_FAILED;
	}
	setup_input_t* setup_in_data = static_cast<setup_input_t*>((void*)plaintext);

	// ocall_debug_print("Service: setup phase for user\n");

	unsigned char data[ORAM_BLOCK_SIZE];
	clearData(data, 0, ORAM_BLOCK_SIZE);
	int offset = 0, recip_idx = -1, recip_loc = -1;
	memcpy(data + offset, &recip_idx, sizeof(int)); // recip current idx
	offset += sizeof(int);
	memcpy(data + offset, &recip_loc, sizeof(int)); // recip current loc
	offset += sizeof(int);
	memcpy(data + offset, &setup_in_data->counter, sizeof(int)); // recip current counter
	offset += sizeof(int);
	memcpy(data + offset, setup_in_data->pk, EC_PK_SIZE_BYTES); // recip pk
	offset += EC_PK_SIZE_BYTES;
	memcpy(data + offset, setup_in_data->vk, EC_PK_SIZE_BYTES); // recip vk
	offset += EC_PK_SIZE_BYTES;
	oram_ret = orams.recipients->access(1, setup_in_data->rid, data, ORAM_BLOCK_SIZE);
	if (oram_ret != RET_SUCCESS) {
		return ERROR_ORAM_RETURN_ERROR;
	}
	ctr_recip += 1;

	// ocall_debug_print("Service: wrote keys and counter for user to keys ORAM\n");
	
	setup_output_t setup_out_data;
	setup_out_data.nxt_recip_idx = ctr_recip;
	memcpy(setup_out_data.pk, setup_in_data->pk, EC_PK_SIZE_BYTES);
	memcpy(out_data, &setup_out_data, out_size);

	int signature_len = 0;
	unsigned char* signature = ecdsa_sign((unsigned char*)out_data, 
		out_size, &signature_len, keys.sigk);

	if (signature_len + sizeof(int) > ECDSA_SIG_SIZE_BYTES) {
        ocall_debug_print("Service: Signature len is not less than ECDSA_SIG_SIZE_BYTES");
		return ERROR_VARIABLE_SIZE_INCONSISTENT;
    }
	memcpy(sig_data, &signature_len, sizeof(int));
    memcpy(sig_data + sizeof(int), signature, signature_len);
	delete[] signature;

	// ocall_debug_print("Service: output written\n");
	delete[] plaintext;
	return RET_SUCCESS;
}


int ecall_send(void* in_data, size_t in_size, void* out_data, size_t out_size,
				void* sig_data, size_t sig_size) {
	
	int oram_ret = 0;
	if (in_size <= sizeof(send_input_t) || out_size != sizeof(send_output_t) 
		|| sig_size != ECDSA_SIG_SIZE_BYTES) {
		return ERROR_INVALID_ARGUMENTS;	
	}

	int plaintext_len = 0;
	unsigned char* plaintext = decrypt_blob_rsa_pubkey((unsigned char*)in_data, in_size, 
			&plaintext_len, keys.deck_send);

	if (plaintext_len != sizeof(send_input_t)) {
		return ERROR_SERVICE_DECRYPTION_FAILED;
	}
	send_input_t* send_in_data = static_cast<send_input_t*>((void*)plaintext);

	// ocall_debug_print("Service: send phase for user\n");

	unsigned char recip_data[ORAM_BLOCK_SIZE];
	clearData(recip_data, 0, ORAM_BLOCK_SIZE);
	oram_ret = orams.recipients->access(0, send_in_data->rid, recip_data, ORAM_BLOCK_SIZE);
	if (oram_ret != RET_SUCCESS){
		return ERROR_ORAM_RETURN_ERROR;
	}
	int prev_idx = 0, prev_loc = 0;
	memcpy(&prev_idx, recip_data, sizeof(int));
	memcpy(&prev_loc, recip_data + sizeof(int), sizeof(int));

	// ocall_debug_print("Service: read previous data for user from recipient DB\n");

	unsigned char message_data[ORAM_BLOCK_SIZE];
	clearData(message_data, 0, ORAM_BLOCK_SIZE);
	memcpy(message_data, &prev_idx, sizeof(int));  // Previous idx
	memcpy(message_data + sizeof(int), &prev_loc, sizeof(int));  // Previous loc
	oram_ret = orams.messages->access(1, ctr_msg, message_data, ORAM_BLOCK_SIZE);
	if (oram_ret != RET_SUCCESS){
		return ERROR_ORAM_RETURN_ERROR;
	}

	// ocall_debug_print("Service: wrote prev data for user to message DB\n");

	memcpy(recip_data, &ctr_msg, sizeof(int));
	memcpy(recip_data + sizeof(int), &send_in_data->loc, sizeof(int));
	oram_ret = orams.recipients->access(1, send_in_data->rid, recip_data, ORAM_BLOCK_SIZE);
	if (oram_ret != RET_SUCCESS){
		return ERROR_ORAM_RETURN_ERROR;
	}
	ctr_msg += 1;
	
	// ocall_debug_print("Service: wrote new data for user to recipient DB\n");

	send_output_t send_out_data;
	send_out_data.nxt_msg_idx = ctr_msg;
	memcpy(out_data, &send_out_data, out_size);

	int signature_len = 0;
	unsigned char* signature = ecdsa_sign((unsigned char*)out_data, 
		out_size, &signature_len, keys.sigk);
	if (signature_len + sizeof(int) > ECDSA_SIG_SIZE_BYTES) {
        ocall_debug_print("Service: Signature len is not less than ECDSA_SIG_SIZE_BYTES");
		return ERROR_VARIABLE_SIZE_INCONSISTENT;
    }
	memcpy(sig_data, &signature_len, sizeof(int));
    memcpy(sig_data + sizeof(int), signature, signature_len);
	delete[] signature;
	
	delete[] plaintext;
	return RET_SUCCESS;
}


int ecall_receive(void* in_data, size_t in_size, void* out_data, size_t out_size,
				void* sig_data, size_t sig_size) {
	
	string print_str = "";
	int oram_ret = 0;
	if (in_size <= sizeof(receive_input_t) || sig_size != ECDSA_SIG_SIZE_BYTES) {
		return ERROR_INVALID_ARGUMENTS;	
	}

	int plaintext_len = 0;
	unsigned char* plaintext = decrypt_blob_rsa_pubkey((unsigned char*)in_data, in_size, 
			&plaintext_len, keys.deck_send);

	if (plaintext_len != sizeof(receive_input_t)) {
		return ERROR_SERVICE_DECRYPTION_FAILED;
	}
	receive_input_t* receive_in_data = static_cast<receive_input_t*>((void*)plaintext);

	if (out_size <= (sizeof(int) * (receive_in_data->retrieve_len + 1))) {
		return ERROR_INVALID_ARGUMENTS;	
	}

	// ocall_debug_print("Service: receive phase for user\n");

	unsigned char data[ORAM_BLOCK_SIZE];
	unsigned char recip_data[ORAM_BLOCK_SIZE];
	clearData(data, 0, ORAM_BLOCK_SIZE);
	oram_ret = orams.recipients->access(0, receive_in_data->rid, data, ORAM_BLOCK_SIZE);
	if (oram_ret != RET_SUCCESS){
		return ERROR_ORAM_RETURN_ERROR;
	}
	memcpy(recip_data, data, ORAM_BLOCK_SIZE);

	// ocall_debug_print("Service: read keys and counter for user from recipient DB\n");
	int cur_ctr = 0;
	int cur_idx = 0, cur_loc = 0;
	unsigned char recip_pk_buffer[EC_PK_SIZE_BYTES];
	unsigned char recip_vk_buffer[EC_PK_SIZE_BYTES];
	int offset = 0;
	memcpy(&cur_idx, data + offset, sizeof(int));
	offset += sizeof(int);
	memcpy(&cur_loc, data + offset, sizeof(int));
	offset += sizeof(int);
	memcpy(&cur_ctr, data + offset, sizeof(int));
	offset += sizeof(int);
	memcpy(recip_pk_buffer, data + offset, EC_PK_SIZE_BYTES);
	offset += EC_PK_SIZE_BYTES;
	memcpy(recip_vk_buffer, data + offset, EC_PK_SIZE_BYTES);
	offset += EC_PK_SIZE_BYTES;

	EC_KEY* recip_pk = convert_buffer_2_ec_pubkey(recip_pk_buffer, EC_PK_SIZE_BYTES);
    EC_KEY* recip_vk = convert_buffer_2_ec_pubkey(recip_vk_buffer, EC_PK_SIZE_BYTES);

	// ocall_debug_print("Service: extracted recipient keys\n");

	int signature_len = 0;
	memcpy(&signature_len, receive_in_data->sig, sizeof(int));
	int verify_res = ecdsa_verify((unsigned char*)&receive_in_data->counter, sizeof(int), 
		receive_in_data->sig + sizeof(int), signature_len, recip_vk);
	
	if (cur_ctr != receive_in_data->counter || verify_res != 1) {
		ocall_debug_print("Service: user authentication failed: either counter or signature is wrong\n");
		return ERROR_USER_AUTH_FAILED;
	}

	int max_count = receive_in_data->retrieve_len;
	int *receive_out_data = new int[max_count + 1];
	for(int i = 0; i < max_count + 1; i++) {
		receive_out_data[i] = -1;
	}
	int count = 0;

	while (count < max_count) {
		int read_idx = 0;
		if (cur_idx >= 0) {
			read_idx = cur_idx;
			receive_out_data[count++] = cur_loc;
		}
		clearData(data, 0, ORAM_BLOCK_SIZE);
		oram_ret = orams.messages->access(0, read_idx, data, ORAM_BLOCK_SIZE);
		if (oram_ret != RET_SUCCESS){
			return ERROR_ORAM_RETURN_ERROR;
		}
		// ocall_debug_print("Service: read data for user from message DB\n");
		if (cur_idx >= 0) {
			memcpy(&cur_idx, data, sizeof(int));
			memcpy(&cur_loc, data + sizeof(int), sizeof(int));
		}
	}

	if (cur_idx >= 0) {
		receive_out_data[max_count] = -2;
	}

	offset = 0;
	memcpy(recip_data + offset, &cur_idx, sizeof(int));
	offset += sizeof(int);
	memcpy(recip_data + offset, &cur_loc, sizeof(int));
	offset += sizeof(int);
	cur_ctr += 1;
	memcpy(recip_data + offset, &cur_ctr, sizeof(int));
	oram_ret = orams.recipients->access(1, receive_in_data->rid, recip_data, ORAM_BLOCK_SIZE);
	if (oram_ret != RET_SUCCESS){
		return ERROR_ORAM_RETURN_ERROR;
	}
	// ocall_debug_print("Service: wrote index and counter for user to recipient DB\n");
	
	int plaintext_len_out = sizeof(int) * (max_count + 1);
	unsigned char* plaintext_out = (unsigned char*) receive_out_data;

	int ciphertext_len = 0;
	unsigned char* ciphertext = ec_encrypt(plaintext_out, plaintext_len_out, &ciphertext_len, 
		keys.deck, recip_pk);

	if (ciphertext_len > out_size) {
        ocall_debug_print("Service: receive out_size is less than ciphertext_len");
		return ERROR_VARIABLE_SIZE_INCONSISTENT;
    }
	memcpy(out_data, ciphertext, ciphertext_len);
	delete[] ciphertext;

	signature_len = 0;
	unsigned char* signature = ecdsa_sign((unsigned char*)out_data, 
		out_size, &signature_len, keys.sigk);
	if (signature_len + sizeof(int) > ECDSA_SIG_SIZE_BYTES) {
        ocall_debug_print("Service: Signature len is not less than ECDSA_SIG_SIZE_BYTES");
		return ERROR_VARIABLE_SIZE_INCONSISTENT;
    }
	memcpy(sig_data, &signature_len, sizeof(int));
    memcpy(sig_data + sizeof(int), signature, signature_len);
	delete[] signature;

	// ocall_debug_print("Service: output written\n");
	delete[] plaintext;
	return RET_SUCCESS;
}


int ecall_kill_service() {

	if (is_init) {
		// ocall_debug_print("Service: exiting service and destroying ORAMs\n");
		delete orams.messages;
		delete orams.recipients;
		EC_KEY_free(keys.enck);
		EC_KEY_free(keys.deck);
		EC_KEY_free(keys.verk);
		EC_KEY_free(keys.sigk);
		RSA_free(keys.enck_send);
		RSA_free(keys.deck_send);
		is_init = false;
	}
	else {
		ocall_debug_print("Service: not yet initialized\n");
		return ERROR_SERVICE_NOT_RUNNING;
	}
	
	return RET_SUCCESS;
}
