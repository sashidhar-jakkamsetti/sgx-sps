
#include "bucket.h"
#include "enclave_t.h"
#include "crypto.h"
#include "crypto.h"
#include <iostream>
#include <string>
#include <sstream>
#include <cstring>

using namespace std;


Bucket::Bucket(int capacity) {
    this->capacity = capacity;
    this->blocks = vector<Block>();
}

Bucket::~Bucket() {
    this->blocks.clear();
}

Bucket::Bucket(Bucket *other) {
    if(other == NULL){
        ocall_debug_print("Bucket: the other bucket is not initialized.");
    }
    this->capacity = other->getCapacity();
    this->blocks = vector<Block>();
    for(int i = 0; i < this->capacity; i++){
        this->blocks.push_back(Block(other->blocks[i]));
    }
}

Bucket::Bucket(unsigned char* enc_blob, int blob_size, unsigned char* aeskey) {
    int dec_blob_size = 0;
    unsigned char* dec_blob = aes_gcm_decrypt(aeskey, enc_blob, blob_size, &dec_blob_size);

    int offset = 0;
    memcpy(&this->capacity, dec_blob, sizeof(int));
    offset += sizeof(int);
    this->blocks = vector<Block>();

    int n_blocks = 0;
    memcpy(&n_blocks, dec_blob + offset, sizeof(int));
    offset += sizeof(int);

    int block_size = 0;
    memcpy(&block_size, dec_blob + offset, sizeof(int));
    offset += sizeof(int);

    for (int i = 0; i < n_blocks; i++) {
        this->blocks.push_back(Block(dec_blob + offset, block_size));
        offset += block_size;
    }
    delete[] dec_blob;
}

unsigned char* Bucket::getEncBlob(int* blob_size, unsigned char* aeskey) {
    int dec_blob_size = getBucketSize();
    unsigned char * dec_blob = new unsigned char[dec_blob_size];

    int offset = 0;
    memcpy(dec_blob, &this->capacity, sizeof(int));
    offset += sizeof(int);

    int n_blocks = this->blocks.size();
    memcpy(dec_blob + offset, &n_blocks, sizeof(int));
    offset += sizeof(int);
    
    bool first = true;
    int block_blob_size = 0;
    for (Block b: this->blocks) {
        unsigned char * block_blob = b.getBlob(&block_blob_size);
        if (first) {
            memcpy(dec_blob + offset, &block_blob_size, sizeof(int));
            offset += sizeof(int);
            first = false;
        }
        memcpy(dec_blob + offset, block_blob, block_blob_size);
        offset += block_blob_size;
        delete[] block_blob;
    }

    unsigned char* enc_blob = aes_gcm_encrypt(aeskey, dec_blob, dec_blob_size, blob_size);
    delete[] dec_blob;
    
    return enc_blob;
}

int Bucket::getBucketSize() {
    int size = 0;
    size += sizeof(int); // for capacity
    size += sizeof(int); // for number of blocks
    size += sizeof(int); // for size of each block
    if (this->blocks.size() > 0) {
        size += this->blocks.size() * this->blocks[0].getBlockSize();
    }
    return size;
}

Block Bucket::getBlock(int id) {
    Block *new_block = NULL;
    for(Block b: this->blocks) {
        if(b.id == id) {
            new_block = new Block(b);
            break;
        }
    }
    return *new_block;
}


void Bucket::addBlock(Block block) {
    if (this->blocks.size() < this->capacity) {
        Block new_block = Block(block);
        this->blocks.push_back(new_block);
    }
    else {
        ocall_debug_print("Bucket: no more space in the bucket.");
    }
}

bool Bucket::removeBlock(int id) {
    bool removed = false;
    for (int i = 0; i < this->blocks.size(); i++) {
        if (this->blocks[i].id == id) {
            this->blocks.erase(this->blocks.begin() + i);
            removed = true;
            break;
        }
    }

    return removed;
}

vector<Block> Bucket::getBlocks(){
    return this->blocks;
}

int Bucket::getCapacity() {
    return this->capacity;
}

void Bucket::printBucket() {
    string str_builder = "Printing bucket...\n";
    for (Block b: blocks) {
        str_builder += b.getStringBlock();
    }
    ocall_debug_print(str_builder.c_str());
}
