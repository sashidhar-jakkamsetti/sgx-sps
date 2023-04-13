
#include "recipient.h"
#include "enclave.h"
#include "parameters.h"
#include "utils.h"
#include <cstdlib>
#include <cmath>
#include <iostream>

using namespace std;

Recipient::Recipient(int id, int counter, int loc_domain) {
    srand(0);
    this->id = id;
    this->counter = counter;
    this->loc_domain = loc_domain;

    // info_print("Recipient: generating keys");

    EC_KEY* keypair1 = generate_ec_keypair();
    this->mykeys.enck = extract_ec_pubkey(keypair1);
    this->mykeys.deck = extract_ec_privkey(keypair1);
    EC_KEY_free(keypair1);

    EC_KEY* keypair2 = generate_ec_keypair();
    this->mykeys.verk = extract_ec_pubkey(keypair2);
    this->mykeys.sigk = extract_ec_privkey(keypair2);
    EC_KEY_free(keypair2);

    // info_print("Recipient: keys generated successfully");
}

void Recipient::set_enclavekeys(keys_output_t* keys_blob) {
    // info_print("Recipient: enclave keys marshalling");
    this->enclavekeys.enck = convert_buffer_2_ec_pubkey(keys_blob->pk, EC_PK_SIZE_BYTES);
    this->enclavekeys.verk = convert_buffer_2_ec_pubkey(keys_blob->vk, EC_PK_SIZE_BYTES);
    this->enclavekeys.enck_send = convert_buffer_2_rsa_pubkey(keys_blob->service_pk, RSA_PK_SIZE_BYTES);
    // info_print("Recipient: marshalled enclave keys successfully");
}

unsigned char* Recipient::prepare_setup_input(int* out_len) {
    setup_input_t* setup_in_data = (setup_input_t*)malloc(sizeof(setup_input_t));
    setup_in_data->rid = this->id;
    setup_in_data->counter = this->counter;

    // info_print("Recipient: setup preparing input buffer");

	int buffer_len1 = 0;
	unsigned char *buffer1 = convert_ec_pubkey_2_buffer(this->mykeys.enck, &buffer_len1);
	if (!buffer1 || buffer_len1 != EC_PK_SIZE_BYTES) {
        error_print("Recipient: Public key len is not equal to RECIPIENT_PK_SIZE_BYTES");
    }
	memcpy(setup_in_data->pk, buffer1, buffer_len1);

	int buffer_len2 = 0;
	unsigned char *buffer2 = convert_ec_pubkey_2_buffer(this->mykeys.verk, &buffer_len2);
	if (!buffer2 || buffer_len2 != EC_PK_SIZE_BYTES) {
        error_print("Recipient: Verification key len is not equal to RECIPIENT_VK_SIZE_BYTES");
    }
	memcpy(setup_in_data->vk, buffer2, buffer_len2);

    // info_print("Recipient: setup input buffer prepared");
    
    unsigned char* ciphertext = encrypt_blob_rsa_pubkey((unsigned char*) setup_in_data, 
            sizeof(setup_input_t), out_len, this->enclavekeys.enck_send);

    // info_print("Recipient: setup input buffer encrypted");

    free(setup_in_data);
    return ciphertext;
}

int Recipient::check_setup_output(unsigned char* input, int in_len) {
    // TODO: check signature from enclave
    return RET_SUCCESS;
}

unsigned char* Recipient::prepare_send_input(int* out_len) {
    send_input_t* send_in_data = (send_input_t*)malloc(sizeof(send_input_t));
    send_in_data->rid = this->id;
    send_in_data->loc = rand() % int(pow(2, this->loc_domain));
    this->sent_loc.push_back(send_in_data->loc);
    cout << "Recipient: Sending loc: " << to_string(send_in_data->loc) << endl;

    // info_print("Recipient: send input buffer prepared");

    unsigned char* ciphertext = encrypt_blob_rsa_pubkey((unsigned char*) send_in_data, 
            sizeof(send_input_t), out_len, this->enclavekeys.enck_send);

    // info_print("Recipient: send input buffer encrypted");
    free(send_in_data);
    return ciphertext;
}

int Recipient::check_send_output(unsigned char* input, int in_len) {
    // TODO: check signature from enclave
    return RET_SUCCESS;
}

unsigned char* Recipient::prepare_recieve_input(int* out_len, int receive_tot) {
    receive_input_t* receive_in_data = (receive_input_t*)malloc(sizeof(receive_input_t));
    receive_in_data->rid = this->id;
    receive_in_data->counter = this->counter++;
    receive_in_data->retrieve_len = receive_tot;

    // info_print("Recipient: receive preparing input buffer");

    int signature_len = 0;
    unsigned char* signature = ecdsa_sign((unsigned char*)&receive_in_data->counter, sizeof(int),
        &signature_len, this->mykeys.sigk);
    if (signature_len + sizeof(int) > ECDSA_SIG_SIZE_BYTES) {
        error_print("Recipient: Signature len is not less than to ECDSA_SIG_SIZE_BYTES");
    }
    memcpy(receive_in_data->sig, &signature_len, sizeof(int));
    memcpy(receive_in_data->sig + sizeof(int), signature, signature_len);
    delete[] signature;

    // info_print("Recipient: receive input buffer prepared");

    unsigned char* ciphertext = encrypt_blob_rsa_pubkey((unsigned char*) receive_in_data, 
        sizeof(receive_input_t), out_len, this->enclavekeys.enck_send);

    // info_print("Recipient: receive input buffer encrypted");
    
    free(receive_in_data);
    return ciphertext;
}

int Recipient::check_recieve_output(unsigned char* in_data, int in_size, int receive_tot) {
    if (in_size <= sizeof(int)*(receive_tot + 1)) {
		error_print("Recipient: invalid receive parameters");
        return ERROR_VARIABLE_SIZE_INCONSISTENT;
	}

    // info_print("Recipient: checking receive output buffer");

	int plaintext_len = 0;
	unsigned char* plaintext = ec_decrypt((unsigned char*)in_data, in_size, 
			&plaintext_len, this->mykeys.deck, this->enclavekeys.enck);

	if (plaintext_len != sizeof(int)*(receive_tot + 1)) {
		error_print("Recipient: Decryption output invalid size");
        return ERROR_VARIABLE_SIZE_INCONSISTENT;
	}
	int* receive_out_data = static_cast<int*>((void*)plaintext);

    // info_print("Recipient: decrypted receive output buffer");

    int i = 0;
    auto it = this->sent_loc.rbegin();
    for (; it != this->sent_loc.rend() && i < receive_tot; it++) {
        cout << "Recipient: Excepted: " << to_string(*it) << ", Received : " 
                << to_string(receive_out_data[i]) << endl;
        if (receive_out_data[i] != *it) {
            error_print("Recipient: send loc did not match received loc");
            return -1;
        }
        i++;
    }
    printf("Recipient: Received all %d loc correctly\n", i);
    
    if (this->sent_loc.size() > receive_tot) {
        this->sent_loc.erase(this->sent_loc.end() - receive_tot, this->sent_loc.end());
    }
    else if(this->sent_loc.size() == receive_tot) {
        this->sent_loc.clear();
    }
    
    if(this->sent_loc.size() > 0 && receive_out_data[receive_tot] != -2) {
        error_print("Recipient: More to retrieve, however service didn't ack it");
        return -1;
    }

    delete[] plaintext;
    return RET_SUCCESS;
}

int Recipient::get_max_recieve_output_len(int receive_tot) {
    return get_enc_blob_ec_pubkey_extra_size() + (sizeof(int) * (receive_tot + 1));
}

Recipient::~Recipient() {
    // info_print("Recipient: deleting recipient");
    EC_KEY_free(this->enclavekeys.enck);
    EC_KEY_free(this->enclavekeys.verk);
    RSA_free(this->enclavekeys.enck_send);
    EC_KEY_free(this->mykeys.enck);
    EC_KEY_free(this->mykeys.deck);
    EC_KEY_free(this->mykeys.sigk);
    EC_KEY_free(this->mykeys.verk);
    sent_loc.clear();
}