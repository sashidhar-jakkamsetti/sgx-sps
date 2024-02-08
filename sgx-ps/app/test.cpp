#include <string>
#include <cstring>
#include <map>
#include <vector>
#include <ctime>
#include <cstdlib>
#include <chrono>
#include <iostream>
#include <cmath>
#include <unistd.h>
#include <fstream>

#include "test.h"

using namespace std;


int test(sgx_enclave_id_t eid) {

    // Initialize commonly used variables
	sgx_status_t ecall_status;
	int retval, check_ret;
    string str_builder;
    chrono::high_resolution_clock::time_point start_time, end_time, start_time1, end_time1;
    int64_t elapsed_times[8];
    memset(elapsed_times, 0, sizeof(elapsed_times));

    // Load the parameters
    int n_messages = SERVICE_MAX_MESSAGES;
    int n_recip = SERVICE_MAX_RECIPIENTS;
    int bucket_size = ORAM_BUCKET_SIZE;
    int recip_loc_domain = RECIPIENT_DATA_BITS;
    int send_tot = SERVICE_BATCH_RECEIVE;
    int receive_tot = send_tot;

    // Initiate the recipient and server data
    Recipient *recip = new Recipient(1, 1, recip_loc_domain);

    // Initiate the enclave
    start_time = chrono::high_resolution_clock::now();
    ecall_status = ecall_init_service(eid, &retval, n_messages, n_recip, bucket_size);
    if (ecall_status != SGX_SUCCESS || is_error(retval)) {
        error_print("[TEST] Failed to initiate signal service");
        return -1;
    }
    end_time = chrono::high_resolution_clock::now();
    auto elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    elapsed_times[0] = elapsed_time.count();
    cout << "[TEST] Elapsed time for init: " << elapsed_time.count() << " us" << endl;
    test_print("Signal service successfully initiated\n");

    // Get public keys from enclave
    start_time = chrono::high_resolution_clock::now();
    keys_output_t* get_keys_out_data = (keys_output_t*)malloc(sizeof(keys_output_t));
    ecall_status = ecall_get_keys(eid, &retval, (void*)get_keys_out_data, sizeof(keys_output_t));
    if (ecall_status != SGX_SUCCESS || is_error(retval)) {
        error_print("[TEST] Failed to get keys signal service");
        return -1;
    }
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    elapsed_times[1] = elapsed_time.count();
    cout << "[TEST] Elapsed time for get_keys: " << elapsed_time.count() << " us" << endl;
    recip->set_enclavekeys(get_keys_out_data);
    test_print("Retrieved public keys from signal service\n");

    // Invoke the enclave to setup the recip
    int setup_in_size = 0;
    unsigned char* setup_in_data = recip->prepare_setup_input(&setup_in_size);
    void* setup_out_data = malloc(sizeof(setup_output_t));
    void* setup_sig_data = malloc(ECDSA_SIG_SIZE_BYTES);
    start_time = chrono::high_resolution_clock::now();
    ecall_status = ecall_setup(eid, &retval, (void*)setup_in_data, setup_in_size, 
        setup_out_data, sizeof(setup_output_t), setup_sig_data, ECDSA_SIG_SIZE_BYTES);
    if (ecall_status != SGX_SUCCESS || is_error(retval)) {
        error_print("[TEST] Failed to setup recipient");
        return -1;
    }
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    elapsed_times[2] = elapsed_time.count();
    cout << "[TEST] Elapsed time for setup: " << elapsed_time.count() << " us" << endl;

    check_ret = recip->check_setup_output((unsigned char*)setup_out_data, sizeof(setup_output_t));
    test_print("Setup for recipient successful\n");
    delete[] setup_in_data;
    free(setup_out_data);
    free(setup_sig_data);

    // Invoke the enclave to send multiple loc
    for (int send_i = 0; send_i < send_tot; send_i++) {
        int send_in_size = 0;
        start_time1 = chrono::high_resolution_clock::now();
        unsigned char* send_in_data = recip->prepare_send_input(&send_in_size);
        void* send_out_data = malloc(sizeof(send_output_t));
        void* send_sig_data = malloc(ECDSA_SIG_SIZE_BYTES);
        end_time1 = chrono::high_resolution_clock::now();
        elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time1 - start_time1);
        elapsed_times[3] += elapsed_time.count();

        start_time = chrono::high_resolution_clock::now();
        ecall_status = ecall_send(eid, &retval, (void*)send_in_data, send_in_size, 
            send_out_data, sizeof(send_output_t), send_sig_data, ECDSA_SIG_SIZE_BYTES);
        if (ecall_status != SGX_SUCCESS || is_error(retval)) {
            error_print("[TEST] Failed to send loc for recipient");
            return -1;
        }
        end_time = chrono::high_resolution_clock::now();
        elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
        elapsed_times[4] += elapsed_time.count();
        cout << "[TEST] Elapsed time for send: " << elapsed_time.count() << " us" << endl;
        
        check_ret = recip->check_send_output((unsigned char*)send_out_data, sizeof(send_output_t));
        test_print("Send for recipient successful\n");
        delete send_in_data;
        free(send_out_data);
        free(send_sig_data);
    }
    elapsed_times[3] /= send_tot;
    elapsed_times[4] /= send_tot;

    // Invoke the enclave to recieve loc
    int receive_in_size = 0;
    start_time1 = chrono::high_resolution_clock::now();
    unsigned char* receive_in_data = recip->prepare_recieve_input(&receive_in_size, receive_tot);
    int receive_out_size = recip->get_max_recieve_output_len(receive_tot);
    void* receive_out_data = malloc(receive_out_size);
    void* receive_sig_data = malloc(ECDSA_SIG_SIZE_BYTES);
    end_time1 = chrono::high_resolution_clock::now();
    elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time1 - start_time1);
    elapsed_times[5] = elapsed_time.count();

    start_time = chrono::high_resolution_clock::now();
    ecall_status = ecall_receive(eid, &retval, (void*)receive_in_data, receive_in_size, 
        receive_out_data, receive_out_size, receive_sig_data, ECDSA_SIG_SIZE_BYTES);
    if (ecall_status != SGX_SUCCESS || is_error(retval)) {
        error_print("[TEST] Failed to receive loc for recipient 1");
        return -1;
    }
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    elapsed_times[6] = elapsed_time.count();
    cout << "[TEST] Elapsed time for receive: " << elapsed_time.count() << " us" << endl;

    start_time1 = chrono::high_resolution_clock::now();
    check_ret = recip->check_recieve_output((unsigned char*)receive_out_data, receive_out_size, receive_tot);
    end_time1 = chrono::high_resolution_clock::now();
    elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time1 - start_time1);
    elapsed_times[5] += elapsed_time.count();
    if (check_ret == RET_SUCCESS) {
        test_print("Receive for recipient 1 successful\n");
    }
    else {
        error_print("[TEST] Receive for recipient 1 FAILED\n");
        return -1;
    }
    delete receive_in_data;
    free(receive_out_data);
    free(receive_sig_data);

    // Terminate the enclave
    start_time = chrono::high_resolution_clock::now();
    ecall_status = ecall_kill_service(eid, &retval);
    if (ecall_status != SGX_SUCCESS || is_error(retval)) {
        error_print("[TEST] Failed to destroy signal service");
        return -1;
    }
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    elapsed_times[7] = elapsed_time.count();
    cout << "[TEST] Elapsed time for destroying: " << elapsed_time.count() << " us" << endl;

    test_print("Signal service successfully destroyed\n");
    cout << "[TEST] Elapsed time (microseconds) for:" 
         << "\n\tInit: " << elapsed_times[0]
         << "\n\tGet keys: " << elapsed_times[1]
         << "\n\tSetup: " << elapsed_times[2]
         << "\n\tSend (recipient): " << elapsed_times[3]
         << "\n\tSend (server): " << elapsed_times[4]
         << "\n\tReceive (recipient): " << elapsed_times[5]
         << "\n\tReceive (server): " << elapsed_times[6] 
         << "\n\tKill: " << elapsed_times[7] 
         << endl << endl;
    
    delete recip;
    return 0;
}


int test(sgx_enclave_id_t eid, int n_messages, int n_recip, int bucket_size, int recip_loc_domain, 
            int send_tot, int* receive_tot_array, int receive_tot_array_len, ofstream& outfile) {

    // Initialize commonly used variables
	sgx_status_t ecall_status;
	int retval, check_ret;
    string str_builder;
    chrono::high_resolution_clock::time_point start_time, end_time;
    int64_t* elapsed_times = new int64_t[5 + receive_tot_array_len];
    int time_idx = 0;
    memset(elapsed_times, 0, sizeof(int64_t)*(5 + receive_tot_array_len));

    outfile << endl;

    // Initiate the recipient and server data
    Recipient *recip = new Recipient(1, 1, recip_loc_domain);

    // Initiate the service 
    start_time = chrono::high_resolution_clock::now();
    ecall_status = ecall_init_service(eid, &retval, n_messages, n_recip, bucket_size);
    if (ecall_status != SGX_SUCCESS || is_error(retval)) {
        error_print("[TEST] Failed to initiate signal service");
        return -1;
    }
    end_time = chrono::high_resolution_clock::now();
    auto elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    elapsed_times[time_idx++] = elapsed_time.count();
    cout << "[TEST] Elapsed time for init: " << elapsed_time.count() << " us" << endl;
    test_print("Signal service successfully initiated\n");

    // Get public keys from enclave
    start_time = chrono::high_resolution_clock::now();
    keys_output_t* get_keys_out_data = (keys_output_t*)malloc(sizeof(keys_output_t));
    ecall_status = ecall_get_keys(eid, &retval, (void*)get_keys_out_data, sizeof(keys_output_t));
    if (ecall_status != SGX_SUCCESS || is_error(retval)) {
        error_print("[TEST] Failed to get keys signal service");
        return -1;
    }
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    elapsed_times[time_idx++] = elapsed_time.count();
    cout << "[TEST] Elapsed time for get_keys: " << elapsed_time.count() << " us" << endl;
    recip->set_enclavekeys(get_keys_out_data);
    test_print("Retrieved public keys from signal service\n");

    // Invoke the enclave to setup the recip
    int setup_in_size = 0;
    unsigned char* setup_in_data = recip->prepare_setup_input(&setup_in_size);
    void* setup_out_data = malloc(sizeof(setup_output_t));
    void* setup_sig_data = malloc(ECDSA_SIG_SIZE_BYTES);
    start_time = chrono::high_resolution_clock::now();
    ecall_status = ecall_setup(eid, &retval, (void*)setup_in_data, setup_in_size, 
        setup_out_data, sizeof(setup_output_t), setup_sig_data, ECDSA_SIG_SIZE_BYTES);
    if (ecall_status != SGX_SUCCESS || is_error(retval)) {
        error_print("[TEST] Failed to setup recipient");
        return -1;
    }
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    elapsed_times[time_idx++] = elapsed_time.count();
    cout << "[TEST] Elapsed time for setup: " << elapsed_time.count() << " us" << endl;

    check_ret = recip->check_setup_output((unsigned char*)setup_out_data, sizeof(setup_output_t));
    test_print("Setup for recipient successful\n");
    delete[] setup_in_data;
    free(setup_out_data);
    free(setup_sig_data);

    // Invoke the enclave to send multiple loc
    for (int send_i = 0; send_i < send_tot; send_i++) {
        int send_in_size = 0;
        unsigned char* send_in_data = recip->prepare_send_input(&send_in_size);
        void* send_out_data = malloc(sizeof(send_output_t));
        void* send_sig_data = malloc(ECDSA_SIG_SIZE_BYTES);
        start_time = chrono::high_resolution_clock::now();
        ecall_status = ecall_send(eid, &retval, (void*)send_in_data, send_in_size, 
            send_out_data, sizeof(send_output_t), send_sig_data, ECDSA_SIG_SIZE_BYTES);
        if (ecall_status != SGX_SUCCESS || is_error(retval)) {
            error_print("[TEST] Failed to send loc for recipient");
            return -1;
        }
        end_time = chrono::high_resolution_clock::now();
        elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
        elapsed_times[time_idx] += elapsed_time.count();
        cout << "[TEST] Elapsed time for send: " << elapsed_time.count() << " us" << endl;
        
        check_ret = recip->check_send_output((unsigned char*)send_out_data, sizeof(send_output_t));
        test_print("Send for recipient successful\n");
        delete send_in_data;
        free(send_out_data);
        free(send_sig_data);
    }
    elapsed_times[time_idx] /= send_tot;
    time_idx++;

    // Invoke the enclave to recieve loc
    for (int receive_i = 0; receive_i < receive_tot_array_len; receive_i++) {
        int receive_in_size = 0;
        int receive_tot = receive_tot_array[receive_i];
        unsigned char* receive_in_data = recip->prepare_recieve_input(&receive_in_size, receive_tot);
        int receive_out_size = recip->get_max_recieve_output_len(receive_tot);
        void* receive_out_data = malloc(receive_out_size);
        void* receive_sig_data = malloc(ECDSA_SIG_SIZE_BYTES);
        start_time = chrono::high_resolution_clock::now();
        ecall_status = ecall_receive(eid, &retval, (void*)receive_in_data, receive_in_size, 
            receive_out_data, receive_out_size, receive_sig_data, ECDSA_SIG_SIZE_BYTES);
        if (ecall_status != SGX_SUCCESS || is_error(retval)) {
            error_print("[TEST] Failed to receive loc for recipient 1");
            return -1;
        }
        end_time = chrono::high_resolution_clock::now();
        elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
        elapsed_times[time_idx++] = elapsed_time.count();
        cout << "[TEST] Elapsed time for receive(" << receive_tot <<"): " << elapsed_time.count() << " us" << endl;

        check_ret = recip->check_recieve_output((unsigned char*)receive_out_data, receive_out_size, receive_tot);
        if (check_ret == RET_SUCCESS) {
            test_print("Receive for recipient 1 successful\n");
        }
        else {
            error_print("[TEST] Receive for recipient 1 FAILED\n");
            return -1;
        }
        delete receive_in_data;
        free(receive_out_data);
        free(receive_sig_data);
    }

    // Terminate the enclave
    start_time = chrono::high_resolution_clock::now();
    ecall_status = ecall_kill_service(eid, &retval);
    if (ecall_status != SGX_SUCCESS || is_error(retval)) {
        error_print("[TEST] Failed to destroy signal service");
        return -1;
    }
    end_time = chrono::high_resolution_clock::now();
    elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time);
    elapsed_times[time_idx++] = elapsed_time.count();
    cout << "[TEST] Elapsed time for destroying: " << elapsed_time.count() << " us" << endl;

    test_print("Signal service successfully destroyed\n");

    // Print to output file
    outfile << "[EXP] Elapsed time (microseconds) for server for:" 
            << "\n\tInit: " << elapsed_times[0] 
            << "\n\tGet keys: " << elapsed_times[1] 
            << "\n\tSetup: " << elapsed_times[2] 
            << "\n\tSend: " << elapsed_times[3];
    
    for (int j = 0; j < receive_tot_array_len; j++) {
        outfile << "\n\tReceive (L=" << receive_tot_array[j] << "): " << elapsed_times[4 + j];
    }
    outfile << "\n\tKill: " << elapsed_times[4 + receive_tot_array_len];
    
    outfile << endl << endl;

    // Clean up and leave
    delete[] elapsed_times;
    delete recip;
    return 0;
}


int experiment(sgx_enclave_id_t eid, const char* filename) {

    remove(filename);
    ofstream outfile(filename);

    /* 
        Change the below values to add test iterations.
        Currently, for every n_messages and n_recip, the code will start a new test run.
    */
    int n_messages[] = {100000, 300000, 1000000, 10000000};
    int n_recip[] = {1000, 3300, 10000, 33000, 100000};
    int bucket_size = ORAM_BUCKET_SIZE;
    int recip_loc_domain = RECIPIENT_DATA_BITS;
    int send_tot = 300;
    int receive_tot_array[] = {1, 5, 10, 25, 50, 75, 100};
    int receive_tot_array_len = sizeof(receive_tot_array)/sizeof(int);

    int ret = 0;
    int nRecip = 100;
    int nMesg = 10*nRecip;
    outfile << "*****************************************************************" << endl << endl;
    outfile << "warm up (dummy test)" << endl;
    ret = test(eid, nMesg, nRecip, bucket_size, recip_loc_domain,
                send_tot, receive_tot_array, receive_tot_array_len, outfile);
    
    outfile << "*****************************************************************" << endl << endl;
    outfile << "for each number of recipients and messages multiplier" << endl;
    for (int i = 0 ; i < sizeof(n_messages)/sizeof(int); i++) {
        for (int j = 0; j < sizeof(n_recip)/sizeof(int); j++) {
            nMesg = n_messages[i];
            nRecip = n_recip[j];
            info_print("Test initiated\n");
            outfile << "--------------------------------------------------------" << endl;
            outfile << "Test parameters: N=" << nMesg << ", M=" << nRecip << endl;
            ret = test(eid, nMesg, nRecip, bucket_size, recip_loc_domain,
                    send_tot, receive_tot_array, receive_tot_array_len, outfile);
            if (ret != RET_SUCCESS) {
                error_print("Test FAILED!!\n"); 
            }
            else{
                info_print("Test successful!!\n");
            }
        }
    }

    /* 
        Uncomment this part to also test with varying bucket size. 
    */
    // outfile << "*****************************************************************" << endl << endl;
    // outfile << "for a particular number of recipients and messages, measure varying ORAM bucket size" << endl;
    // nRecip = 10000;
    // nMesg = 10*nRecip;
    // int bucket_size_array[] = {2, 4, 8, 16, 32, 64};
    // for (int i = 0; i < sizeof(bucket_size_array)/sizeof(int); i++) {
    //     info_print("Test initiated\n");
    //     outfile << "--------------------------------------------------------" << endl;
    //     outfile << "Test parameters: N=" << nMesg << ", M=" << nRecip 
    //             << ", BucketSize=" << bucket_size_array[i] << endl;
    //     ret = test(eid, nMesg, nRecip, bucket_size_array[i], recip_loc_domain,
    //             send_tot, receive_tot_array, receive_tot_array_len, outfile);
    //     if (ret != RET_SUCCESS) {
    //         error_print("Test FAILED!!\n"); 
    //     }
    //     else{
    //         info_print("Test successful!!\n");
    //     }
    // }

    outfile.close();
    return 0;
}