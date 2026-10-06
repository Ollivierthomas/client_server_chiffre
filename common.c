#include "common.h"
#include "chiffrement.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

int send_message(int socket, char* message) {
    if (send(socket, message, strlen(message), 0) < 0) {
        perror("Error sending message\n");
        return -1;
    }
    else {
        return 0;
    }
}

int receive_message(int socket, char* message, size_t max_length) {
    ssize_t receive = recv(socket, message, max_length - 1, 0);

    if (receive < 0) {
        perror("Error receiving message\n");
        return -1;
    }
    else if (receive == 0) {
        printf("Peer disconnected\n");
        return -1;
    }
    else {
        message[receive] = '\0';

        if (receive > 0 && message[receive - 1] == '\n') {
            message[receive - 1] = '\0';
        }

        return 0;
    }
}

int send_all(int socket, const void *buffer, size_t size) {
    const char *data = buffer;
    size_t total_sent = 0;

    while (total_sent < size) {
        ssize_t sent = send(socket, data + total_sent,
                             size - total_sent, 0);

        if (sent <= 0) {
            return -1;
        }

        total_sent += (size_t)sent;
    }

    return 0;
}

int receive_all(int socket, void *buffer, size_t size) {
    char *data = buffer;
    size_t total_received = 0;

    while (total_received < size) {
        ssize_t received = recv(socket, data + total_received,
                                 size - total_received, 0);

        if (received <= 0) {
            return -1;
        }

        total_received += (size_t)received;
    }

    return 0;
}

int send_public_key(int socket, const PublicKey *key) {
    uint64_t network_n = htonll(key->n);
    uint64_t network_e = htonll(key->e);

    if (send_all(socket, &network_n, sizeof(network_n)) == -1) {
        return -1;
    }

    return send_all(socket, &network_e, sizeof(network_e));
}

int receive_public_key(int socket, PublicKey *key) {
    uint64_t network_n;
    uint64_t network_e;

    if (receive_all(socket, &network_n, sizeof(network_n)) == -1) {
        return -1;
    }

    if (receive_all(socket, &network_e, sizeof(network_e)) == -1) {
        return -1;
    }

    key->n = ntohll(network_n);
    key->e = ntohll(network_e);

    return 0;
}

int send_encrypted_message(int socket, const uint64_t *encrypted_blocks, uint32_t text_length, uint32_t block_count) {
    uint32_t network_text_length = htonl(text_length);
    uint32_t network_block_count = htonl(block_count);

    if (send_all(socket, &network_text_length, sizeof(network_text_length)) == -1) {
        return -1;
    }

    if (send_all(socket, &network_block_count, sizeof(network_block_count)) == -1) {
        return -1;
    }

    for (uint32_t i = 0; i < block_count; i++) {
        uint64_t network_block = htonll(encrypted_blocks[i]);

        if (send_all(socket, &network_block, sizeof(network_block)) == -1) {
            return -1;
        }
    }

    return 0;
}

int receive_encrypted_message(int socket, uint64_t *encrypted_blocks, uint32_t *text_length, uint32_t *block_count) {
    uint32_t network_text_length;
    uint32_t network_block_count;

    if (receive_all(socket, &network_text_length, sizeof(network_text_length)) == -1) {
        return -1;
    }

    if (receive_all(socket, &network_block_count, sizeof(network_block_count)) == -1) {
        return -1;
    }

    *text_length = ntohl(network_text_length);
    *block_count = ntohl(network_block_count);

    if (*text_length > 1023 || *block_count > MAX_RSA_BLOCKS) {
        return -1;
    }

    if (*block_count != (*text_length + 3) / 4) {
        return -1;
    }

    for (uint32_t i = 0; i < *block_count; i++) {
        uint64_t network_block;

        if (receive_all(socket, &network_block, sizeof(network_block)) == -1) {
            return -1;
        }

        encrypted_blocks[i] = ntohll(network_block);
    }

    return 0;
}