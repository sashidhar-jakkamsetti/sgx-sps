
#include "enclave_u.h"
#include "sgx_urts.h"

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

#include "app.h"
#include "utils.h"
#include "datatypes.h"
#include "parameters.h"
#include "enclave.h"
#include "storage/storage.h"
#include "recipient.h"
#include "test.h"

using namespace std;


map<string, Storage*> map_storages;


void ocall_debug_print(const char* str) {
    printf("[DEBUG] %s\n", str);
}

int ocall_oram_storage_init(const char* oram_name, int n_buckets, int bucket_size) {

    string name = oram_name;
    map_storages[name] = new Storage(n_buckets, bucket_size);
    // info_print("ocall: Storage init");
    return RET_SUCCESS;
}

int ocall_oram_read_buckets(const char* oram_name, void* idx, size_t idx_size,
    void* read_bucket, size_t read_bucket_size) {
    
    if (idx_size > ORAM_ACCESS_BATCH_SIZE*sizeof(int) || idx_size < sizeof(int) || 
        map_storages.find(oram_name) == map_storages.end()) {
        return ERROR_INVALID_ARGUMENTS;
    }

    // info_print("ocall: Storage read access");
    Storage *cur_storage = map_storages[oram_name];
    int read_count = idx_size/sizeof(int);
    int bucket_size = cur_storage->getBucketSize();

    if (read_count != read_bucket_size/bucket_size) {
        error_print("ocall: Storage read_bucket_size not consistent");
        return ERROR_INVALID_ARGUMENTS;
    }

    int cur_idx;
    unsigned char *cur_bucket = new unsigned char[bucket_size];
    
    int storage_ret = 0;
    for (int i = 0; i < read_count; i++) {
        
        memcpy(&cur_idx, idx + (i*sizeof(int)), sizeof(int));
        storage_ret = cur_storage->readBucket(cur_idx, cur_bucket);
        if (storage_ret == -1) {
            error_print("ocall: Storage read arguments are invalid");
            return ERROR_INVALID_ARGUMENTS;
        }

        memcpy(read_bucket + (i*bucket_size), cur_bucket, bucket_size);
    }

    delete[] cur_bucket;
    return RET_SUCCESS;
}

int ocall_oram_write_buckets(const char* oram_name, void* idx, size_t idx_size,
    void* write_bucket, size_t write_bucket_size) {
    
    if (idx_size > ORAM_ACCESS_BATCH_SIZE*sizeof(int) || idx_size < sizeof(int) || 
        map_storages.find(oram_name) == map_storages.end()) {
        return ERROR_INVALID_ARGUMENTS;
    }

    // info_print("ocall: Storage write access");
    Storage *cur_storage = map_storages[oram_name];
    int write_count = idx_size/sizeof(int);
    int bucket_size = cur_storage->getBucketSize();

    if (write_count != write_bucket_size/bucket_size) {
        error_print("ocall: Storage write_bucket_size not consistent");
        return ERROR_INVALID_ARGUMENTS;
    }

    int cur_idx;
    unsigned char *cur_bucket = new unsigned char[bucket_size];
    
    int storage_ret = 0;
    for (int i = 0; i < write_count; i++) {
        
        memcpy(&cur_idx, idx + (i*sizeof(int)), sizeof(int));
        memcpy(cur_bucket, write_bucket + (i*bucket_size), bucket_size);

        storage_ret = cur_storage->writeBucket(cur_idx, cur_bucket);
        if (storage_ret == -1) {
            error_print("ocall: Storage write arguments are invalid");
            return ERROR_INVALID_ARGUMENTS;
        }
    }

    delete[] cur_bucket;
    return RET_SUCCESS;
}

int ocall_oram_exists(const char* oram_name) {
    // info_print("ocall: Storage test");
    return map_storages.find(oram_name) != map_storages.end();
}

int ocall_oram_kill(const char* oram_name) {
    
    if (map_storages.find(oram_name) != map_storages.end()) {
        // info_print("ocall: Killing storage"); 
        delete map_storages[oram_name];
    }
    else {
        return ERROR_INVALID_ARGUMENTS;
    }
    return RET_SUCCESS;
}


int main(int argc, char** argv) {

    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = {0};
    int updated, ret, flag = 0;
    string filename = "experiment-results.txt";
    sgx_status_t enclave_status;

    if (argc > 1) {
        string arg = argv[1];
        if (arg == "-e") {
            flag = 1;
        }
    }

    if (argc > 2) {
        string arg = argv[2];
        filename = arg;
    }

    show_version();
    srand(time(nullptr));

    enclave_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if(enclave_status != SGX_SUCCESS) {
        error_print("Fail to initialize enclave"); 
        return -1;
    }
    info_print("Enclave successfully initialized");

    if (flag == 0) {
        info_print("Test initiated\n");
        ret = test(eid);
        if (ret != RET_SUCCESS) {
            error_print("Test FAILED!!\n"); 
        }
        else{
            info_print("Test successful!!\n");
        }
    }
    else {
        info_print("Experiment initiated\n");
        ret = experiment(eid, filename.c_str());
        if (ret != RET_SUCCESS) {
            error_print("Experiment FAILED!!\n"); 
        }
        else{
            info_print("Experiment successful!!\n");
        }   
    }

    enclave_status = sgx_destroy_enclave(eid);
    if(enclave_status != SGX_SUCCESS) {
        error_print("Fail to destroy enclave"); 
        return -1;
    }
    info_print("Enclave successfully destroyed");

    info_print("Program exit success");
    return 0;
}
