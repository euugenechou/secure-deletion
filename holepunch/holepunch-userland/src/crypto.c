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
 * crypto.c, ver.2018.02.11
 *
 * Crypto functions for ERASER.
 */

#include "crypto.h"

#include <string.h>

/*
 * Encryption functions.
 */

/* Initializes a cipher context for encryption. */
EVP_CIPHER_CTX *start_encrypt(char *key, char *iv) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        die("Cannot create cipher\n");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ERR_print_errors_fp(stderr);
        die("Cannot init crypto context\n");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    return ctx;
}

/* Encrypts a buffer using a previously initialized cipher context. */
int do_encrypt(EVP_CIPHER_CTX *ctx, char *src, char *dst, u64 buf_len) {
    int len;

    if (EVP_EncryptUpdate(ctx, dst, &len, src, buf_len) != 1) {
        ERR_print_errors_fp(stderr);
        die("Encryption error\n");
    }
    return len;
}

/* Finalizes the encryption and frees the cipher context. */
int finish_encrypt(EVP_CIPHER_CTX *ctx, char *dst) {
    int len;

    if (EVP_EncryptFinal_ex(ctx, dst, &len) != 1) {
        ERR_print_errors_fp(stderr);
        die("Encryption error\n");
    }
    EVP_CIPHER_CTX_free(ctx);
    return len;
}

/* Simple encryption interface for OpenSSL. */
void encrypt(char *src, char *dst, u64 buf_len, char *key, char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = start_encrypt(key, iv);
    len = do_encrypt(ctx, src, dst, buf_len);
    finish_encrypt(ctx, dst + len);
}

/*
 * Decryption functions.
 */

/* Initializes a cipher context for decryption. */
EVP_CIPHER_CTX *start_decrypt(char *key, char *iv) {
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        die("Cannot create cipher\n");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        ERR_print_errors_fp(stderr);
        die("Cannot init crypto context\n");
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    return ctx;
}

/* Decrypts a buffer using a previously initialized cipher context. */
int do_decrypt(EVP_CIPHER_CTX *ctx, char *src, char *dst, u64 buf_len) {
    int len;

    if (EVP_DecryptUpdate(ctx, dst, &len, src, buf_len) != 1) {
        ERR_print_errors_fp(stderr);
        die("Encryption error\n");
    }
    return len;
}

/* Finalizes the decryption and frees the cipher context. */
int finish_decrypt(EVP_CIPHER_CTX *ctx, char *dst) {
    int len;

    if (EVP_DecryptFinal_ex(ctx, dst, &len) != 1) {
        ERR_print_errors_fp(stderr);
        die("Encryption error\n");
    }
    EVP_CIPHER_CTX_free(ctx);
    return len;
}

/* Simple decryption interface for OpenSSL. */
void decrypt(char *src, char *dst, u64 buf_len, char *key, char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = start_decrypt(key, iv);
    len = do_decrypt(ctx, src, dst, buf_len);
    finish_decrypt(ctx, dst + len);
}

/* Derives a key from a password with PBKDF2 - SHA256. */
void generate_key(
    char *pass,
    int key_len,
    char *key,
    char *salt,
    int salt_len
) {
    PKCS5_PBKDF2_HMAC(
        pass,
        strlen(pass),
        salt,
        salt_len,
        ERASER_PBKDF2_ITER,
        EVP_sha256(),
        key_len,
        key
    );
}

/* Reuses PBKDF2 to generate key digest. */
void digest_key(
    char *in,
    int in_len,
    char *out,
    int out_len,
    char *salt,
    int salt_len
) {
    PKCS5_PBKDF2_HMAC(
        in,
        in_len,
        salt,
        salt_len,
        ERASER_PBKDF2_ITER,
        EVP_sha256(),
        out_len,
        out
    );
}

/* Initializes OpenSSL. */
void init_crypto() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    // OPENSSL_config(NULL);
    OPENSSL_no_config();
}

/* Cleans up OpenSSL. */
void cleanup_crypto() {
    EVP_cleanup();
    ERR_free_strings();
}
