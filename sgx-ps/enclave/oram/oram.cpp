
#include "sgx_trts.h"
#include "enclave_t.h"
#include "sgx_tcrypto.h"
#include "oram.h"
#include "parameters.h"
#include "enclave.h"
#include "crypto.h"

#include <cstdio>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <string>

using namespace std;

ORAM::ORAM(char* name, int bucket_size, int nblocks) {

    // ocall_debug_print("ORAM: initializing internal variables");
    // string str_builder = "";

    this->name = name;
    this->bucket_size = bucket_size;
    this->enc_bucket_size = bucket_size;
    // str_builder += "nblocks: " + to_string(nblocks) + ", ";
    int nbuckets_required = ceil(nblocks / bucket_size);
    // str_builder += "nbuckets_req: " + to_string(nbuckets_required) + ", ";
    this->nlevels = ceil(log2(nbuckets_required));
    // str_builder += "nlevels: " + to_string(this->nlevels) + ", ";
    this->nbuckets = int(pow(2, this->nlevels)) - 1;
    // str_builder += "nbuckets: " + to_string(this->nbuckets) + ", ";
    this->nleaves = int(pow(2, this->nlevels - 1));
    // str_builder += "nleaves: " + to_string(this->nleaves) + ", ";
    this->nblocks = this->bucket_size * this->nbuckets;
    // str_builder += "nblocks: " + to_string(this->nblocks) + ", ";

    sgx_read_rand((unsigned char*)this->oram_key, sizeof(sgx_aes_gcm_128bit_key_t));
    
    this->stash = unordered_map<int, Block>();
    this->posMap = new int[this->nblocks];

    for (int i = 0; i < this->nblocks; i++) {
        this->posMap[i] = getRandLeaf();
    }
    
    Bucket *bucket = new Bucket(this->bucket_size);
    for (int j = 0 ; j < this->bucket_size; j++) {
        bucket->addBlock(Block());
    }

    unsigned char* bucket_blob = bucket->getEncBlob(&this->enc_bucket_size, (unsigned char*)this->oram_key);
    delete bucket;
    delete[] bucket_blob;

    // str_builder += "enc_bucket_size: " + to_string(this->enc_bucket_size);
    // ocall_debug_print((char*)str_builder.c_str());
}

int ORAM::initialize(){
    int ocall_ret = 0;
    sgx_status_t ocall_status;
    ocall_status = ocall_oram_storage_init(&ocall_ret, (char*)this->name.c_str(), 
        this->nbuckets, this->enc_bucket_size);

    if (ocall_ret != RET_SUCCESS || ocall_status != SGX_SUCCESS) {
        return ERROR_OCALL_FAILED;
    }

    // ocall_debug_print("ORAM: initialized external storage");
    vector<int> write_idxs;
    vector<Bucket*> write_buckets;
    int write_ret = 0;
    int i = 0;

    while (i < this->nbuckets) {
        write_idxs.clear();
        write_buckets.clear();

        for (int j = 0; j < ORAM_ACCESS_BATCH_SIZE && i < this->nbuckets; j++) {
            Bucket *bucket = new Bucket(this->bucket_size);
            for (int k = 0 ; k < this->bucket_size; k++) {
                bucket->addBlock(Block());
            }
            write_idxs.push_back(i++);
            write_buckets.push_back(bucket);
        }

        writeBuckets(&write_ret, write_idxs, write_buckets);
        for (Bucket* bucket: write_buckets) {
            delete bucket;
        }
        if (write_ret != RET_SUCCESS) {
            return write_ret;
        }
    }

    // ocall_debug_print("ORAM: wrote dummy buckets to the storage");
    return RET_SUCCESS;
}

int ORAM::getRandLeaf() {
    unsigned int rand_val = 0;
    sgx_read_rand((unsigned char*)&rand_val, 4);
    return rand_val % this->nleaves;
}

int ORAM::getLocation(int leaf, int level) {
    return (1 << level) - 1 + (leaf >> (this->nlevels - level - 1));
}

Bucket* ORAM::readBucket(int* retval, int idx) {
    int ocall_ret = 0;
    sgx_status_t ocall_status;

    // ocall_debug_print("ORAM: reading bucket");

    unsigned char* read_bucket = new unsigned char[this->enc_bucket_size];
    ocall_status = ocall_oram_read_buckets(&ocall_ret, (char*)this->name.c_str(), &idx, sizeof(int),
        (void*)read_bucket, this->enc_bucket_size);

    if (ocall_ret != RET_SUCCESS || ocall_status != SGX_SUCCESS) {
        *retval = ERROR_OCALL_FAILED;
        return NULL;
    }
    
    // ocall_debug_print("ORAM: ocall success, read bucket");

    Bucket* bucket = new Bucket(read_bucket, this->enc_bucket_size, (unsigned char*)this->oram_key);
    // bucket->printBucket();
    delete[] read_bucket;
    return bucket;
}

vector<Bucket*> ORAM::readBuckets(int* retval, vector<int> idxs) {
    int ocall_ret = 0;
    sgx_status_t ocall_status;
    vector<Bucket*> buckets;

    // ocall_debug_print("ORAM: reading buckets");

    unsigned char* idx = new unsigned char[sizeof(int)*idxs.size()];
    unsigned char* read_buckets = new unsigned char[this->enc_bucket_size*idxs.size()];

    int offset_idx = 0;
    for (int i = 0; i < idxs.size(); i++) {
        int idx_value = idxs[i];
        memcpy(idx + offset_idx, &idx_value, sizeof(int));
        offset_idx += sizeof(int);
    }

    ocall_status = ocall_oram_read_buckets(&ocall_ret, (char*)this->name.c_str(), idx, sizeof(int)*idxs.size(),
        (void*)read_buckets, this->enc_bucket_size*idxs.size());

    if (ocall_ret != RET_SUCCESS || ocall_status != SGX_SUCCESS) {
        *retval = ERROR_OCALL_FAILED;
        return buckets;
    }
    
    // ocall_debug_print("ORAM: ocall success, read buckets");

    int offset_bucket = 0;
    for (int i = 0; i < idxs.size(); i++) {
        unsigned char* read_bucket = new unsigned char[this->enc_bucket_size];
        memcpy(read_bucket, read_buckets + offset_bucket, this->enc_bucket_size);
        offset_bucket += this->enc_bucket_size;

        Bucket* bucket = new Bucket(read_bucket, this->enc_bucket_size, (unsigned char*)this->oram_key);
        // bucket->printBucket();
        buckets.push_back(bucket);
        delete[] read_bucket;
    }

    delete[] idx;
    delete[] read_buckets;
    return buckets;
}

void ORAM::writeBucket(int* retval, int idx, Bucket* bucket) {
    int ocall_ret = 0;
    sgx_status_t ocall_status;

    // ocall_debug_print("ORAM: writing bucket");
    // bucket->printBucket();

    int wbucket_size = 0;
    unsigned char* write_bucket = bucket->getEncBlob(&wbucket_size, (unsigned char*)this->oram_key);
    if (wbucket_size != this->enc_bucket_size) {
        *retval = ERROR_BUCKET_SIZE_INCONSISTENT;
        return;
    }

    ocall_status = ocall_oram_write_buckets(&ocall_ret, (char*)this->name.c_str(), &idx, sizeof(int),
        (void*)write_bucket, this->enc_bucket_size);

    if (ocall_ret != RET_SUCCESS || ocall_status != SGX_SUCCESS) {
        *retval = ERROR_OCALL_FAILED;
        return;
    }
    
    // ocall_debug_print("ORAM: ocall success, wrote bucket");
    delete[] write_bucket;
}

void ORAM::writeBuckets(int* retval, vector<int> idxs, vector<Bucket*> buckets) {
    int ocall_ret = 0;
    sgx_status_t ocall_status;

    // ocall_debug_print("ORAM: writing buckets");

    unsigned char* idx = new unsigned char[sizeof(int)*idxs.size()];
    unsigned char* write_buckets = new unsigned char[this->enc_bucket_size*idxs.size()];

    int offset_idx = 0;
    int offset_bucket = 0;
    for (int i = 0; i < idxs.size(); i++) {
        int idx_value = idxs[i];
        memcpy(idx + offset_idx, &idx_value, sizeof(int));
        offset_idx += sizeof(int);

        Bucket* bucket = buckets[i];
        // bucket->printBucket();

        int wbucket_size = 0;
        unsigned char* write_bucket = bucket->getEncBlob(&wbucket_size, (unsigned char*)this->oram_key);
        if (wbucket_size != this->enc_bucket_size) {
            *retval = ERROR_BUCKET_SIZE_INCONSISTENT;
            return;
        }

        memcpy(write_buckets + offset_bucket, write_bucket, this->enc_bucket_size);
        offset_bucket += this->enc_bucket_size;

        delete[] write_bucket;
    }

    ocall_status = ocall_oram_write_buckets(&ocall_ret, (char*)this->name.c_str(), idx, sizeof(int)*idxs.size(),
        (void*)write_buckets, this->enc_bucket_size*idxs.size());

    if (ocall_ret != RET_SUCCESS || ocall_status != SGX_SUCCESS) {
        *retval = ERROR_OCALL_FAILED;
        return;
    }

    // ocall_debug_print("ORAM: ocall success, wrote buckets");
    delete[] idx;
    delete[] write_buckets;
}

int ORAM::access(int write, int idx, unsigned char *data, int data_len) {
    int retval = RET_SUCCESS;
    if (idx > this->nblocks) {
        return ERROR_ORAM_INDEX_OOR;
    }

    // printPosMap();
    int oldLeaf = this->posMap[idx];
    this->posMap[idx] = getRandLeaf();

    vector<int> read_idxs;
    for (int i = 0; i < this->nlevels; i++) {
        read_idxs.push_back(getLocation(oldLeaf, i));
    }

    vector<Bucket*> read_buckets = readBuckets(&retval, read_idxs);
    if (retval != RET_SUCCESS) {
        return retval;
    }

    // ocall_debug_print("ORAM: read path");

    for (Bucket* bucket: read_buckets) {
        for (Block block: bucket->getBlocks()) {
            if (block.id >= 0) {
                // ocall_debug_print("ORAM: pushed block to stash");
                this->stash[block.id] = Block(&block);
            }
        }
        delete bucket;
    }
    read_buckets.clear();

    // ocall_debug_print("ORAM: stored blocks to stash");

    if (write == 1) {
        this->stash[idx] = Block(idx, data);
        // ocall_debug_print("ORAM: wrote incoming block");
    }
    else {
        if (this->stash.find(idx) != this->stash.end()) {
            memcpy(data, this->stash[idx].data, data_len);
            // ocall_debug_print("ORAM: read outgoing block");
        }
        else {
            // ocall_debug_print("ORAM: read idx not found");
        }
    }

    // printStash();
    // ocall_debug_print("ORAM: performed access");

    vector<int> write_idxs;
    vector<Bucket*> write_buckets;
    for (int i = 0; i < this->nlevels; i++) {
        int bucket_idx = getLocation(oldLeaf, i);
        Bucket* new_bucket = new Bucket(this->bucket_size);
        int counter = 0;

        vector<int> evicted_keys;
        for (auto it = this->stash.begin(); it != this->stash.end(); it++) {
            if (counter >= this->bucket_size){
                break;
            }
            if (bucket_idx == getLocation(this->posMap[it->first], i)) {
                new_bucket->addBlock(Block(&it->second));
                evicted_keys.push_back(it->first);
                counter++;
            }
        }

        for (int j = 0; j < evicted_keys.size(); j++) {
            this->stash.erase(evicted_keys[j]);
        }
        // printStash();

        while (counter < this->bucket_size) {
            new_bucket->addBlock(Block());
            counter++;
        }
        write_idxs.push_back(bucket_idx);
        write_buckets.push_back(new_bucket);
    }

    // ocall_debug_print("ORAM: created write buckets buffer");

    writeBuckets(&retval, write_idxs, write_buckets);
    if (retval != RET_SUCCESS) {
        return retval;
    }

    // ocall_debug_print("ORAM: wrote path");
    for (Bucket* bucket: write_buckets) {
        delete bucket;
    }
    write_buckets.clear();

    return RET_SUCCESS;
}

char* ORAM::getName() {
    return (char*)this->name.c_str();
}

int ORAM::getNBlocks() {
    return this->nblocks;
}

int ORAM::getNLevels() {
    return this->nlevels;
}

int ORAM::getNLeaves() {
    return this->nleaves;
}

int ORAM::getNBuckets() {
    return this->nbuckets;
}

int ORAM::getStashSize() {
    return this->stash.size();
}

void ORAM::printStash(){
    string print_str = "Printing stash...\n";
    for (auto it = this->stash.begin(); it != this->stash.end(); it++) {
        print_str += "key: " + to_string(it->first) + ", ";
        print_str += it->second.getStringBlock();
    }
    ocall_debug_print((char*)print_str.c_str());
}

void ORAM::printPosMap(){
    string print_str = "Printing position map...\n";
    for (int i = 0 ; i < this->nblocks; i++) {
        print_str += "key: " + to_string(i) + ", ";
        print_str += "value: " + to_string(this->posMap[i]) + "\n";
    }
    ocall_debug_print((char*)print_str.c_str());
}

ORAM::~ORAM() {
    this->stash.clear();
    delete[] this->posMap;

    int ocall_ret = 0;
    sgx_status_t ocall_status;
    ocall_status = ocall_oram_kill(&ocall_ret, this->name.c_str());
    if (ocall_ret != RET_SUCCESS || ocall_status != SGX_SUCCESS) {
        ocall_debug_print("ORAM: external storage not freed");
    }
}