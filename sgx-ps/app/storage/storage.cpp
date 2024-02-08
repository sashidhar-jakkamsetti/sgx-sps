

#include "storage.h"
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <cstdlib>

using namespace std;


Storage::Storage(int capacity, int bucket_size) {
    this->_capacity = capacity;
    this->_bucket_size = bucket_size;
    this->buckets = new unsigned char*[capacity];
    for (int i = 0; i < this->_capacity; i++) {
        this->buckets[i] = new unsigned char[bucket_size];
    }
}

int Storage::readBucket(int idx, unsigned char* bucket) {
    if (idx >= this->_capacity || idx < 0) {
        return -1;
    }

    unsigned char* cur_bucket = this->buckets[idx];
    memcpy(bucket, cur_bucket, this->_bucket_size);

    // string print_str = "printing read bucket (storage):\n";
    // for (int i = 0; i < this->_bucket_size; i++) {
    //     int val = 0;
    //     memcpy(&val, cur_bucket + i, 1);
    //     print_str += to_string(val);
    // }
    // cout << (char*)print_str.c_str() << endl;

    return 0;
}


int Storage::writeBucket(int idx, unsigned char* bucket) {
    if (idx >= this->_capacity || idx < 0) {
        return -1;
    }
    
    unsigned char* cur_bucket = this->buckets[idx];
    memcpy(cur_bucket, bucket, this->_bucket_size);
    
    // string print_str = "printing write bucket (storage):\n";
    // for (int i = 0; i < this->_bucket_size; i++) {
    //     int val = 0;
    //     memcpy(&val, cur_bucket + i, 1);
    //     print_str += to_string(val);
    // }
    // cout << (char*)print_str.c_str() << endl;
    
    return 0;
}


Storage::~Storage() {
    for (int i = 0; i < this->_capacity; i++) {
        delete[] this->buckets[i];
    }
    delete[] this->buckets;
}

int Storage::getCapacity() {
    return this->_capacity;
}

int Storage::getBucketSize() {
    return this->_bucket_size;
}