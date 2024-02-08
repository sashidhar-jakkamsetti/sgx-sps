
#ifndef ORAM_H_
#define ORAM_H_

#include <string>
#include <cstring>
#include "bucket.h"
#include "sgx_tcrypto.h"
#include "block.h"
#include <unordered_map>
#include <vector>

using namespace std;

class ORAM {

private:
    string name;
    int nlevels;
    int bucket_size;
    int enc_bucket_size;
    int nbuckets;
    int nleaves;
    int nblocks;
    sgx_aes_gcm_128bit_key_t oram_key;
    unordered_map<int, Block> stash;
    int* posMap;

    int getRandLeaf();
    int getLocation(int leaf, int level);
    Bucket* readBucket(int* retval, int idx);
    vector<Bucket*> readBuckets(int* retval, vector<int> idxs);
    void writeBucket(int* retval, int idx, Bucket* bucket);
    void writeBuckets(int* retval, vector<int> idxs, vector<Bucket*> buckets);
    void printStash();
    void printPosMap();

public:
    ORAM(char* name, int bucket_size, int nblocks);
    int initialize();
    int access(int write, int idx, unsigned char *data, int data_len);
    char* getName();
    int getNBlocks();
    int getNLevels();
    int getNLeaves();
    int getNBuckets();
    int getStashSize();
    ~ORAM();

};

#endif