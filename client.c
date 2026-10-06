#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include "common.h"
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include "chiffrement.h"

struct ClientThreadData {
    int socket;
    const PrivateKey *private_key;
};

static volatile bool should_stop = false;

void receive_messages_loop(int client_socket, const PrivateKey *client_private_key) {
    while (!should_stop) {
        uint64_t encrypted_blocks[MAX_RSA_BLOCKS];
        uint32_t decrypted_blocks[MAX_RSA_BLOCKS] = {0};
        uint32_t text_length;
        uint32_t block_count;

        if (receive_encrypted_message(client_socket, encrypted_blocks, &text_length, &block_count) == -1) {
            should_stop = true;
            return;
        }

        dechiffrement(encrypted_blocks, block_count, decrypted_blocks, client_private_key->d, client_private_key->n);

        printf("Message recu : %.*s\n",
               (int)text_length,
               (char *)decrypted_blocks);
    }
}

void *receive_messages_loop_thread(void *arg) {
    struct ClientThreadData *data = arg;

    receive_messages_loop(data->socket, data->private_key);
    return NULL;
}

void send_message_loop(int client_socket, const PublicKey *server_public_key) {
    char buffer[1024];
    while (!should_stop) {

        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            perror("Error reading from stdin");
            exit(EXIT_FAILURE);
        }

        buffer[strcspn(buffer, "\n")] = '\0';

        size_t text_length = strlen(buffer);
        size_t block_count = (text_length + 3) / 4;

        uint32_t plain_blocks[MAX_RSA_BLOCKS] = {0};
        uint64_t encrypted_blocks[MAX_RSA_BLOCKS];

        memcpy(plain_blocks, buffer, text_length);

        chiffrement(plain_blocks, block_count, encrypted_blocks, server_public_key->e, server_public_key->n);

        if (send_encrypted_message(client_socket, encrypted_blocks, (uint32_t)text_length, (uint32_t)block_count) == -1) {
            perror("Erreur d'envoi du message chiffre");
            should_stop = true;
        }
    }
}

void handle_sigint(int signal) {
    (void)signal;
    should_stop = true;
}

int main() {

    struct sigaction signal;
    signal.sa_handler = handle_sigint;
    sigemptyset(&signal.sa_mask);
    signal.sa_flags = 0;

    if (sigaction(SIGINT, &signal, NULL) < 0) {
        perror("Failed to setup sigaction");
        exit(EXIT_FAILURE);
    }

    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Failed to create socket\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    // server_address.sin_addr.s_addr = inet_addr("10.30.40.11"); 
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1"); 
    server_address.sin_port = htons(8989); 

    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        perror("Connection to server failed\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    PublicKey server_public_key;

    srand(time(NULL));
    PublicKey client_public_key;
    PrivateKey client_private_key;
    generate_keys(&client_public_key, &client_private_key);

    if (receive_public_key(client_socket, &server_public_key) == -1) {
        perror("Impossible de recevoir la cle publique");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    if (send_public_key(client_socket, &client_public_key) == -1) {
        perror("Impossible d'envoyer la cle publique du client");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    printf("Cle publique recue : n=%lu, e=%lu\n", server_public_key.n, server_public_key.e);

    printf("Client connected !\n");

    struct ClientThreadData thread_data = {
        .socket = client_socket,
        .private_key = &client_private_key,
    };

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, receive_messages_loop_thread, &thread_data) != 0) {
        perror("Failed to create thread\n");
        exit(EXIT_FAILURE);
    }

    send_message_loop(client_socket, &server_public_key);

    close(client_socket);
    printf("Disconnected\n");
}