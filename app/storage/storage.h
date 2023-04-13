

#ifndef STORAGE_H_
#define STORAGE_H_

#include <vector>
#include <string>

using namespace std;

class Storage {

private: 
    int _capacity;
    int _bucket_size;
    unsigned char** buckets;

public:
    Storage(int capacity, int bucket_size);
    int readBucket(int idx, unsigned char* bucket);
    int writeBucket(int idx, unsigned char* bucket);
    ~Storage();
    int getCapacity();
    int getBucketSize();
};

#endif