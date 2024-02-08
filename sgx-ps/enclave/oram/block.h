

#ifndef BLOCK_H_
#define BLOCK_H_

#include "parameters.h"
#include <string>
using namespace std;

class Block {

public:
    int id;
    unsigned char data[ORAM_BLOCK_SIZE];

    Block();
    Block(int id, unsigned char *data);
    Block(Block *other);
    Block(unsigned char* blob, int blob_size);
    int getBlockSize();
    unsigned char* getBlob(int* blob_size);
    ~Block();
    string getStringBlock();
};

#endif