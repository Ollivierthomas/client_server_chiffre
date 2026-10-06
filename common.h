#ifndef COMMON_H
#define COMMON_H

#include "chiffrement.h"
#include <stddef.h>
#include <arpa/inet.h>
#include <stdint.h>

#define MAX_RSA_BLOCKS 256

static uint64_t htonll(uint64_t value) {
    uint32_t high = htonl((uint32_t)(value >> 32));
    uint32_t low = htonl((uint32_t)value);

    return ((uint64_t)low << 32) | high;
}

static uint64_t ntohll(uint64_t value) {
    return htonll(value);
}

int send_message(int socket, char* message);
int receive_message(int socket, char* message, size_t max_length);
int send_all(int socket, const void *buffer, size_t size);
int receive_all(int socket, void *buffer, size_t size);
int receive_public_key(int socket, PublicKey *key);
int send_public_key(int socket, const PublicKey *key);
int send_encrypted_message(int socket, const uint64_t *encrypted_blocks, uint32_t text_length, uint32_t block_count);
int receive_encrypted_message(int socket, uint64_t *encrypted_blocks, uint32_t *text_length, uint32_t *block_count);

#endif