#include "chiffrement.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

Array(uint32_t) prime_numbers(void) {
    Array(uint32_t) array_prime = { .values = NULL, .size = 0, .capacity = 0 };

    uint32_t min = 4294900000;
    uint32_t max = 4294967295;

    for (uint64_t i = min; i <= max; i++) {
        if (is_prime((uint32_t)i)) {
            array_push(array_prime, (uint32_t)i);
        }
    }

    return array_prime;
}

bool is_prime(uint32_t nb) {
    if (nb < 2) return false;

    for (uint64_t i = 2; i <= sqrt(nb); i++) {
        if (nb % i == 0) { 
            return false;
        }
    }
    return true;
} 

uint64_t pgcd(uint64_t a, uint64_t b) {
    if (b == 0) {
        return a;
    }

    return pgcd(b, a % b);
}

uint64_t find_e(uint64_t p, uint64_t q) {
    uint64_t phi = (p - 1) * (q - 1);
    for (uint64_t e = 3; e < phi; e += 2) {
        if (pgcd(phi, e) == 1) {
            return e;
        }
    }
    return -1;
}

uint64_t find_d(uint64_t p, uint64_t q, uint64_t e) {
    uint64_t phi = (p - 1) * (q - 1);

    for (uint64_t k = 1; k < e; k++) {
        __uint128_t value = (__uint128_t)k * phi + 1;

        if (value % e == 0) {
            return (uint64_t)(value / e);
        }
    }

    return -1;
}
__uint128_t modular_exponentiation(uint64_t m, uint64_t b, uint64_t n) {
    if (b == 0) {
        return 1;
    } else if (b % 2 == 0) {
        __uint128_t r = modular_exponentiation(m, b / 2, n);
        return (r * r) % n;
    } else {
        __uint128_t r = modular_exponentiation(m, b - 1, n);
        return (m * r) % n;
    }
}

void chiffrement(uint32_t* msg, size_t taille_msg, uint64_t* chiffre, uint64_t e, uint64_t n) {
    for (size_t i = 0; i < taille_msg; i++) {
        chiffre[i] = modular_exponentiation(msg[i], e, n);
    }
}

void dechiffrement(uint64_t* chiffre, size_t taille_chiffre, uint32_t* dechiffre_msg, uint64_t d, uint64_t n) {
    for (size_t i = 0; i < taille_chiffre; i++) {
        dechiffre_msg[i] = modular_exponentiation(chiffre[i], d, n);
    }
}

void generate_keys(PublicKey* public_key, PrivateKey* private_key) {
    Array(uint32_t) array_prime = prime_numbers();

    uint64_t prime_p = array_prime.values[rand() % array_prime.size];
    uint64_t prime_q = array_prime.values[rand() % array_prime.size];

    if (prime_p == prime_q) {
        do {
            prime_q = array_prime.values[rand() % array_prime.size];
        } while (prime_q == prime_p);
    }

    uint64_t n = prime_p * prime_q;
    uint64_t e = find_e(prime_p, prime_q);
    uint64_t d = find_d(prime_p, prime_q, e);

    public_key->e = e;
    public_key->n = n;

    private_key->d = d;
    private_key->n = n;

    array_free(array_prime);
}