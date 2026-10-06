#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include "common.h"
#include <pthread.h>
#include "client_array.h"
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include "chiffrement.h"

static volatile bool should_stop = false;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

struct ThreadData {
    int client_socket;
    struct ClientArray* client_array;
    const PrivateKey* server_private_key;
};

void receive_messages_loop(int client_socket, struct ClientArray *client_array, const PrivateKey *server_private_key) {
    (void)client_array;

    while (1) {
        uint64_t encrypted_blocks[MAX_RSA_BLOCKS];
        uint32_t decrypted_blocks[MAX_RSA_BLOCKS] = {0};
        uint32_t text_length;
        uint32_t block_count;

        if (receive_encrypted_message(client_socket, encrypted_blocks, &text_length, &block_count) == -1) {
                pthread_mutex_lock(&clients_mutex);
                ca_remove(client_array, client_socket);
                pthread_mutex_unlock(&clients_mutex);

                close(client_socket);
                return;
        }

        dechiffrement(encrypted_blocks, block_count, decrypted_blocks, server_private_key->d, server_private_key->n);

        printf("Message dechiffre : %.*s\n", (int)text_length, (char *)decrypted_blocks);

        pthread_mutex_lock(&clients_mutex);

        for (int i = 0; i < client_array->size; i++) {
            struct Client *recipient = &client_array->clients[i];

            uint64_t recipient_encrypted_blocks[MAX_RSA_BLOCKS];

            chiffrement(decrypted_blocks, block_count, recipient_encrypted_blocks, recipient->public_key.e, recipient->public_key.n);

            if (send_encrypted_message(recipient->socket, recipient_encrypted_blocks, text_length, block_count) == -1) {
                printf("Impossible d'envoyer le message chiffre au client\n");
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }
}

void *receive_messages_thread(void *arg) {
    struct ThreadData *data = arg;
    receive_messages_loop(data->client_socket, data->client_array, data->server_private_key);
    free(data);
    return NULL;
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


    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(8989);      

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    const int ON = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &ON, sizeof(ON)) < 0) {
        perror("Failed setting socket options");
        exit(EXIT_FAILURE);
    }

    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Failed to bind adress");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port 8989...\n");

    struct ClientArray array = ca_init();

    srand(time(NULL));

    PublicKey server_public_key;
    PrivateKey server_private_key;
    generate_keys(&server_public_key, &server_private_key);

    while (!should_stop) {
        struct sockaddr_in client_adress;
        
        unsigned int size = sizeof(client_adress);

        int client_socket = accept(server_socket, (struct sockaddr *)&client_adress, &size);
        
        if (client_socket < 0) {
            perror("\nError accepting client connection\n");
        }
        else {
            if (send_public_key(client_socket, &server_public_key) == -1) {
                close(client_socket);
                continue;
            }

            PublicKey client_public_key;

            if (receive_public_key(client_socket, &client_public_key) == -1) {
                close(client_socket);
                continue;
            }

            struct Client client = {
                .socket = client_socket,
                .public_key = client_public_key
            };

            pthread_mutex_lock(&clients_mutex);
            ca_add(&array, client);
            pthread_mutex_unlock(&clients_mutex);

            pthread_t thread_id;

            printf("A client is connected !\n");

            struct ThreadData *data = malloc(sizeof(struct ThreadData));
            if (data == NULL) {
                close(client_socket);
                continue;
            }
            data->client_socket = client_socket;
            data->client_array = &array;
            data->server_private_key = &server_private_key;

            if (pthread_create(&thread_id, NULL, receive_messages_thread, data) != 0) {
                perror("Failed to create thread\n");
                free(data);
                close(client_socket);
                exit(EXIT_FAILURE);
            }

            pthread_detach(thread_id);
        }
    }

    for (int i = 0; i < array.size; i++) {
        shutdown(array.clients[i].socket, SHUT_RDWR);
        close(array.clients[i].socket);
    }
    printf("Server off");
}