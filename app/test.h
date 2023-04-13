

#ifndef TEST_H_
#define TEST_H_

#include "enclave_u.h"
#include "sgx_urts.h"

#include "app.h"
#include "utils.h"
#include "datatypes.h"
#include "parameters.h"
#include "recipient.h"
#include "test.h"
#include "enclave.h"

int test(sgx_enclave_id_t eid);
int test(sgx_enclave_id_t eid, int n_messages, int n_recip, int bucket_size, 
                int recip_loc_domain, int send_tot, int* receive_tot_array, 
                int receive_tot_array_len, ofstream& outfile);

int experiment(sgx_enclave_id_t eid, const char* filename);

#endif