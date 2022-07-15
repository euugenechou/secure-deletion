/*
 * Copyright (C) 2018 Kaan Onarlioglu <http://www.onarlioglu.com>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * crypto.h, ver.2018.02.11
 *
 * Crypto functions for ERASER.
 */
#ifndef CRYPTO_H
#define CRYPTO_H

/* OpenSSL includes. */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "utils.h"

#define ERASER_PBKDF2_ITER 10000

/* Encryption & decryption utilities. */
EVP_CIPHER_CTX *start_encrypt(char *, char *);
int do_encrypt(EVP_CIPHER_CTX *, char *, char *, u64);
int finish_encrypt(EVP_CIPHER_CTX *, char *);
void encrypt(char *, char *, u64, char *, char *);

EVP_CIPHER_CTX *start_decrypt(char *, char *);
int do_decrypt(EVP_CIPHER_CTX *, char *, char *, u64);
int finish_decrypt(EVP_CIPHER_CTX *, char *);
void decrypt(char *, char *, u64, char *, char *);

/* PBKDF2 key derivation and digest. */
void generate_key(char *, int, char *, char *, int);
void digest_key(char *, int, char *, int, char *, int);

void init_crypto();
void cleanup_crypto();

#endif /* CRYPTO_H */
