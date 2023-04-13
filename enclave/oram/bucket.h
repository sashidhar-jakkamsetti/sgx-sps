

#ifndef BUCKET_H_
#define BUCKET_H_

#include <vector>
#include <stdexcept>

#include "block.h"
#include "parameters.h"
using namespace std;

class Bucket {

private:
    int capacity;
    vector<Block> blocks;

public:
    Bucket(int capacity);
    Bucket(Bucket *other);
    Bucket(unsigned char* enc_blob, int blob_size, unsigned char* aeskey);
    Block getBlock(int id);
    void addBlock(Block new_block);
    bool removeBlock(int id);
    vector<Block> getBlocks();
    int getBucketSize();
    unsigned char* getEncBlob(int* blob_size, unsigned char* aeskey);
    int getCapacity();
    virtual ~Bucket();
    void printBucket();
};

#endif