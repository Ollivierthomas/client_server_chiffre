#ifndef CHIFFREMENT_H
#define CHIFFREMENT_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

// 1. Définition de la structure générique via typedef
#define DEFINE_ARRAY(type) \
typedef struct Array_##type { \
    type* values; \
    size_t size; \
    size_t capacity; \
} Array_##type

// 2. Déclaration UNIQUE de la structure pour uint32_t
DEFINE_ARRAY(uint32_t);

// 3. La macro Array s'appuie désormais sur le type existant sans redéfinir struct
#define Array(type) Array_##type

// Macros pour manipuler le tableau
#define array_push(array, element) do {\
    if ((array).capacity == (array).size) {\
        if ((array).capacity == 0) {\
            (array).capacity = 2;\
        }\
        else {\
            (array).capacity *= 2;\
        }\
        (array).values = realloc((array).values, (array).capacity * sizeof(*(array).values));\
        if ((array).values == NULL) { \
            exit(1); \
        } \
    }\
    (array).values[(array).size] = element;\
    (array).size++; \
} while(0)

#define array_free(array) do {\
    if ((array).values != NULL) {\
        free((array).values);\
        (array).values = NULL;\
    }\
    (array).size = 0;\
    (array).capacity = 0;\
} while(0)

// Clées publiques et privées
typedef struct {
    uint64_t n; // Modulus
    uint64_t e; // Public exponent
} PublicKey;

typedef struct {
    uint64_t n; // Modulus
    uint64_t d; // Private exponent
} PrivateKey;

// Prototypes des fonctions
Array(uint32_t) prime_numbers(void);
bool is_prime(uint32_t nb);
uint64_t pgcd(uint64_t a, uint64_t b);
uint64_t find_e(uint64_t p, uint64_t q);
uint64_t find_d(uint64_t p, uint64_t q, uint64_t e);
__uint128_t modular_exponentiation(uint64_t m, uint64_t b, uint64_t n);
void chiffrement(uint32_t* msg, size_t taille_msg, uint64_t* chiffre, uint64_t e, uint64_t n);
void dechiffrement(uint64_t* chiffre, size_t taille_chiffre, uint32_t* dechiffre_msg, uint64_t d, uint64_t n);
void generate_keys(PublicKey* public_key, PrivateKey* private_key);

#endif