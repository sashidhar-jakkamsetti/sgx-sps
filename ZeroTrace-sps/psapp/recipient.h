

#ifndef RECIPIENT_H_
#define RECIPIENT_H_

#include <string>
#include <vector>
#include "crypto.h"
#include "Globals.hpp"
#include "datatypes.h"


using namespace std;

class Recipient {
public:
    int id;
    int counter;
    int loc_domain;
    sps_keychain_t mykeys;
    sps_keychain_t enclavekeys;
    vector<int> sent_loc;

    Recipient(int id, int counter, int loc_domain);
    ~Recipient();
    void set_enclavekeys(keys_output_t* keys_blob);
    unsigned char* prepare_setup_input(int* out_len);
    int check_setup_output(unsigned char* input, int in_len);
    unsigned char* prepare_send_input(int* out_len);
    int check_send_output(unsigned char* input, int in_len);
    unsigned char* prepare_recieve_input(int* out_len, int receive_tot);
    int check_recieve_output(unsigned char* input, int in_len, int receive_tot);
    int get_max_recieve_output_len(int receive_tot);
};

#endif