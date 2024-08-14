#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>



#define ROUNDS 20

typedef uint32_t salsa20_word;


//start DES


int initial_permutation[] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
};

/* Initial Permutation Inverse Table */
int initial_permutation_inv[] = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
};

/* Expansion D-box Table */
int expansion_dbox[] = {
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
};

/* Permutation Table */
int permutation[] = {
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
};

/* S-box Table */
int sbox[8][4][16] = {
        {
                /* S1 */
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        {
                /* S2 */
                {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        {
                /* S3 */
                {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        {
                /* S4 */
                {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        {
                /* S5 */
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        {
                /* S6 */
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        {
                /* S7 */
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        {
                /* S8 */
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
};


int permuted_choice_1[] = {
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
};


int permuted_choice_2[] = {
        14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32
};


int shift_bits[] = {
        1, 1, 2, 2, 2, 2, 2, 2,
        1, 2, 2, 2, 2, 2, 2, 1
};


unsigned long long left_shift(unsigned long long val, int shift) {
    return ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;
}


void des(unsigned long long plaintext, unsigned long long *ciphertext, unsigned long long *subkeys, int mode) {
    int i, round;
    unsigned long long input, output, temp;
    unsigned long left, right;


    input = 0;
    for (i = 0; i < 64; i++) {
        input |= ((plaintext >> (64 - initial_permutation[i])) & 1) << (63 - i);
    }


    left = input >> 32;
    right = input & 0xFFFFFFFF;

    // 16 rounds of DES
    for (round = 0; round < 16; round++) {
        temp = right;
        right = left ^ (right & 0xFFFFFFFF);
        left = temp;

        // Expansion D-box
        temp = 0;
        for (i = 0; i < 48; i++) {
            temp |= ((right >> (32 - expansion_dbox[i])) & 1) << (47 - i);
        }

        // XOR with subkey
        if (mode == 1) {
            temp ^= subkeys[round];
        } else {
            temp ^= subkeys[15 - round];
        }


        output = 0;
        for (i = 0; i < 8; i++) {
            int row = ((temp >> (42 - 6 * i)) & 0x20) | ((temp >> (47 - 6 * i)) & 1);
            int col = (temp >> (43 - 6 * i)) & 0xF;
            output |= (unsigned long long)sbox[i][row][col] << (32 - 4 * (i + 1));
        }


        temp = 0;
        for (i = 0; i < 32; i++) {
            temp |= ((output >> (32 - permutation[i])) & 1) << (31 - i);
        }

        left ^= temp;
    }


    output = ((unsigned long long)left << 32) | right;
    *ciphertext = 0;
    for (i = 0; i < 64; i++) {
        *ciphertext |= ((output >> (64 - initial_permutation_inv[i])) & 1) << (63 - i);
    }
}


void generate_subkeys(unsigned long long key, unsigned long long *subkeys) {
    int i, round;
    unsigned long long temp, left, right;

    // Permuted Choice 1
    temp = 0;
    for (i = 0; i < 56; i++) {
        temp |= ((key >> (64 - permuted_choice_1[i])) & 1) << (55 - i);
    }

    // Initial split into left and right halves
    left = temp >> 28;
    right = temp & 0xFFFFFFF;


    for (round = 0; round < 16; round++) {
        left = left_shift(left, shift_bits[round]);
        right = left_shift(right, shift_bits[round]);

        // Permuted Choice 2
        temp = ((unsigned long long)left << 28) | right;
        subkeys[round] = 0;
        for (i = 0; i < 48; i++) {
            subkeys[round] |= ((temp >> (56 - permuted_choice_2[i])) & 1) << (47 - i);
        }
    }
}
//end DES


//start Salsa20

void salsa20_core(salsa20_word out[16], const salsa20_word in[16]) {
    salsa20_word x[16];
    int i;

    memcpy(x, in, 64);

    for (i = 0; i < ROUNDS; i += 2) {
        // Odd round
        x[ 4] ^= ((x[ 0] + x[12]) << 7) | ((x[ 0] + x[12]) >> (32 - 7));
        x[ 8] ^= ((x[ 4] + x[ 0]) << 9) | ((x[ 4] + x[ 0]) >> (32 - 9));
        x[12] ^= ((x[ 8] + x[ 4]) << 13) | ((x[ 8] + x[ 4]) >> (32 - 13));
        x[ 0] ^= ((x[12] + x[ 8]) << 18) | ((x[12] + x[ 8]) >> (32 - 18));

        // Even round
        x[ 9] ^= ((x[ 5] + x[ 1]) << 7) | ((x[ 5] + x[ 1]) >> (32 - 7));
        x[13] ^= ((x[ 9] + x[ 5]) << 9) | ((x[ 9] + x[ 5]) >> (32 - 9));
        x[ 1] ^= ((x[13] + x[ 9]) << 13) | ((x[13] + x[ 9]) >> (32 - 13));
        x[ 5] ^= ((x[ 1] + x[13]) << 18) | ((x[ 1] + x[13]) >> (32 - 18));

        // Odd round
        x[14] ^= ((x[10] + x[ 6]) << 7) | ((x[10] + x[ 6]) >> (32 - 7));
        x[ 2] ^= ((x[14] + x[10]) << 9) | ((x[14] + x[10]) >> (32 - 9));
        x[ 6] ^= ((x[ 2] + x[14]) << 13) | ((x[ 2] + x[14]) >> (32 - 13));
        x[10] ^= ((x[ 6] + x[ 2]) << 18) | ((x[ 6] + x[ 2]) >> (32 - 18));

        // Even round
        x[ 3] ^= ((x[15] + x[11]) << 7) | ((x[15] + x[11]) >> (32 - 7));
        x[ 7] ^= ((x[ 3] + x[15]) << 9) | ((x[ 3] + x[15]) >> (32 - 9));
        x[11] ^= ((x[ 7] + x[ 3]) << 13) | ((x[ 7] + x[ 3]) >> (32 - 13));
        x[15] ^= ((x[11] + x[ 7]) << 18) | ((x[11] + x[ 7]) >> (32 - 18));
    }

    for (i = 0; i < 16; ++i) {
        out[i] = x[i] + in[i];
    }
}

void salsa20_encrypt(const uint8_t *input, uint8_t *output, size_t len, const uint8_t *key, const uint8_t *nonce) {
    salsa20_word state[16];
    salsa20_word block[16];
    int i, j;


    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (i = 4; i < 12; ++i) {
        state[i] = ((salsa20_word *)key)[i - 4];
    }
    state[12] = 0;
    state[13] = 0;
    for (i = 14; i < 16; ++i) {
        state[i] = ((salsa20_word *)nonce)[i - 14];
    }

    while (len >= 64) {
        salsa20_core(block, state);
        for (i = 0; i < 64; ++i) {
            output[i] = input[i] ^ ((uint8_t *)block)[i];
        }
        len -= 64;
        input += 64;
        output += 64;


        state[12] += 1;
        if (state[12] == 0) {
            state[13] += 1;
        }
    }

    if (len > 0) {
        salsa20_core(block, state);
        for (i = 0; i < len; ++i) {
            output[i] = input[i] ^ ((uint8_t *)block)[i];
        }
    }
}


//end Salsa20

//start RSA
int gcd(int a, int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}


void generate_keys(int *e, int *d, int *n) {
    int p, q, phi;

    p = 61;
    q = 53;

    *n = p * q;
    phi = (p - 1) * (q - 1);

    //1 < e < phi(n) and gcd(e, phi(n)) = 1
    *e = 17;

    // Compute d, the modular multiplicative inverse of e modulo phi(n)
    *d = 1;
    while ((*d * *e) % phi != 1) {
        (*d)++;
    }
}


void encrypt(char *message, int e, int n, int *cipher) {
    int i;
    for (i = 0; message[i] != '\0'; i++) {
       //ciphertext = (plaintext ^ e) % n
        cipher[i] = fmod(pow(message[i], e), n);
    }
    cipher[i] = -1; // Add sentinel value
}


void decrypt(int *cipher, int d, int n, char *decrypted) {
    int i;
    for (i = 0; cipher[i] != -1; i++) {
        // plaintext = (ciphertext ^ d) % n
        decrypted[i] = fmod(pow(cipher[i], d), n);
    }
    decrypted[i] = '\0';
}


//end RSA

int main() {

    FILE *f;


    f = fopen("Output.txt","w");

    fprintf(f,"DES\n");
    //DES
    unsigned long long plaintext = 0x0123456789ABCDEF;
    unsigned long long key = 0x133457799BBCDFF1;
    unsigned long long ciphertext;
    unsigned long long subkeys[16];


    generate_subkeys(key, subkeys);


    des(plaintext, &ciphertext, subkeys, 1);
    fprintf(f ,"Plaintext: 0x%llx\n", plaintext);
    fprintf(f ,"Key: 0x%llx\n", key);
    fprintf(f ,"Ciphertext: 0x%llx\n", ciphertext);


    des(ciphertext, &plaintext, subkeys, 0);
    fprintf(f,"Decrypted Ciphertext: 0x%llx\n", plaintext);

    //END DES

    fprintf(f,"Salsa\n");
    //SALSA20
    const uint8_t keyS[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const uint8_t nonce[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t plaintextS[64] = "Ana nu mai are mere";
    uint8_t ciphertextS[64];

    salsa20_encrypt(plaintextS, ciphertextS, sizeof(plaintext), keyS, nonce);

    fprintf(f,"Plaintext: %s\n", plaintextS);
    fprintf(f,"Ciphertext: ");
    for (int i = 0; i < sizeof(plaintext); i++) {
        fprintf(f,"%02x", ciphertextS[i]);
    }
    fprintf(f,"\n");

    //END SALSA20

    fprintf(f,"RSA\n");


    //RSA
    char message[] = "Ana Are Multe Mere";
    int e, d, n; // Public and private keys
    int cipher[100];
    char decrypted[100];

    generate_keys(&e, &d, &n);

    fprintf(f,"Public key (e, n): (%d, %d)\n", e, n);
    fprintf(f,"Private key (d, n): (%d, %d)\n", d, n);

    encrypt(message, e, n, cipher); // Encrypt message
    decrypt(cipher, d, n, decrypted); // Decrypt message

    fprintf(f,"Original message: %s\n", message);
    fprintf(f,"Encrypted message: ");
    for (int i = 0; cipher[i] != -1; i++) {
        fprintf(f,"%d ", cipher[i]);
    }
    fprintf(f,"\nDecrypted message: %s\n", decrypted);
    //END RSA

    fclose(f);
}