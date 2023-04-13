
#include "block.h"
#include "enclave_t.h"
#include <string>
#include <iostream>
#include <cstring>

using namespace std;


Block::Block() {
    this->id = -1;
    memset(this->data, -1, sizeof(this->data));
}

Block::Block(int id, unsigned char* data) {
    this->id = id;
    memcpy(this->data, data, sizeof(this->data));
}

Block::Block(Block *other) {
    this->id = other->id;
    memcpy(this->data, other->data, sizeof(this->data));
}

Block::Block(unsigned char* blob, int blob_size) {
    int actual_size = getBlockSize();
    if (actual_size <= blob_size) {
        memcpy(&this->id, blob, sizeof(int));
        memcpy(this->data, blob + sizeof(int), sizeof(this->data));
    }
    else {
        ocall_debug_print("Block: constructor with blob size inconsistent");
    }
}

unsigned char* Block::getBlob(int* blob_size) {
    *blob_size = getBlockSize();
    unsigned char *blob = new unsigned char[*blob_size];
    memcpy(blob, &this->id, sizeof(int));
    memcpy(blob + sizeof(int), this->data, sizeof(this->data));
    return blob;
}

int Block::getBlockSize() {
    return sizeof(this->id) + sizeof(this->data);
}

Block::~Block() {
}

string Block::getStringBlock() {
    string str_builder = "Block " + to_string(this->id) + ": ";
    for (int i = 0; i < sizeof(this->data); i += sizeof(int)) {
        int val = 0;
        memcpy(&val, this->data + i, sizeof(int));
        str_builder += to_string(val);
        str_builder += " ";
    }
    return str_builder + "\n";
}
