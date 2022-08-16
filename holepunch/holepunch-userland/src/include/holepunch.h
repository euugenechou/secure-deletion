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
 * eraser.h, ver.2018.02.11
 *
 * ERASER core.
 */
#ifndef ERASER_H
#define ERASER_H

#include <libdevmapper.h> /* Devmapper ioctl interface. */
#include <termios.h>      /* To disable terminal echoing for password prompt. */
#include <linux/fs.h>
#include <signal.h>

#include "utils.h"

#define ERASER_TARGET "eraser"
#define ERASER_DEV_PATH "/dev/mapper/"

#define ERASER_HEADER_LEN 1     /* In sectors. */
#define ERASER_HEADER_LEN 1     /* In sectors. */
#define ERASER_KEY_LEN 32       /* In bytes. */
#define ERASER_IV_LEN 16        /* In bytes. */

#define ERASER_SALT_LEN 32
#define ERASER_DIGEST_LEN 32

#define ERASER_NAME_LEN 16

#define HOLEPUNCH_PROC_FILE "/proc/holepunchtab"

#define PRG_INPUT_LEN 32
unsigned char HOLEPUNCH_PPRF_DEPTH;
#define HOLEPUNCH_KEY_GROWTH       (2*HOLEPUNCH_PPRF_DEPTH)
#define HOLEPUNCH_REFRESH_INTERVAL 10000

#define ERASER_CREATE 0
#define ERASER_OPEN 1

#define ERASER_SECTOR 4096   /* In bytes. */
/* These are just the default values for ext4. Good enough, for now. */
#define ERASER_BYTES_PER_INODE_RATIO 16384


#define MAX_DEPTH 64 
#define NODE_LABEL_LEN (MAX_DEPTH+7)/8
struct node_label {
    u64 label;
    unsigned char depth;
};

struct __attribute__((packed)) pprf_keynode {
    union {
        struct {
            u32 il;
            u32 ir;
        } next;
        char key[PRG_INPUT_LEN];
    } v;
    char flag;
#ifdef DEBUG
    struct node_label lbl;
#endif
};


/* Must match the kernel side definition. */
struct eraser_header {
    char enc_key[ERASER_KEY_LEN];           /* Encrypted disk sector encryption key. */
    char enc_key_digest[ERASER_DIGEST_LEN]; /* External key digest. */
    char enc_key_salt[ERASER_SALT_LEN];     /* External key salt. */
    char pass_salt[ERASER_SALT_LEN];        /* Password salt. */
    char slot_map_iv[ERASER_IV_LEN];        /* IV for slot map encryption. */

    u64 nv_index; /* TPM NVRAM index to store the master key in. */

    /* All in ERASER sectors. */
    u64 len;
    u64 slot_map_start;
    u64 slot_map_len;
    u64 inode_map_start;
    u64 inode_map_len;
    u64 data_start;
    u64 data_len;
};


/* Holepunch header; must match the definition in kernel. */
struct holepunch_header {
    u8 enc_key[ERASER_KEY_LEN];           /* Encrypted sector encryption key. */
    u8 enc_key_digest[ERASER_DIGEST_LEN]; /* Key digest. */
    u8 enc_key_salt[ERASER_SALT_LEN];     /* Key salt. */
    u8 pass_salt[ERASER_SALT_LEN];        /* Password salt. */
    u64 nv_index;                         /* Master key TPM NVRAM index. */

    /* IV generation key, encrypted by master key. */
    u8 iv_key[ERASER_KEY_LEN];

    /* All in ERASER sectors, strictly consecutive; header starts at zero. */
    u64 key_table_start;
    u64 pprf_fkt_start;
    u64 pprf_key_start;
    u64 data_start;
    u64 data_end; /* One past the last accesible data sector. */

    u32 master_key_count; // how many individual keys make up the master key
    u64 tag_counter;

    u32 pprf_fkt_top_width;
    u32 pprf_fkt_bottom_width;

    u32 master_key_limit;
    u8 pprf_depth;

    u8 initialized;
};

struct holepunch_key {
    u8 key[ERASER_KEY_LEN];
};

#define HOLEPUNCH_FILEKEYS_PER_SECTOR ((ERASER_SECTOR - 32)/ERASER_KEY_LEN)
#define HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR \
        (ERASER_SECTOR/sizeof(struct pprf_keynode))
#define HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR (ERASER_SECTOR/ERASER_KEY_LEN)

struct __attribute__((aligned(ERASER_SECTOR))) holepunch_filekey_sector {
    u64 tag;
    u64 magic1;
    u64 magic2;
    u64 magic3;
    struct holepunch_key entries[HOLEPUNCH_FILEKEYS_PER_SECTOR];
};

struct __attribute__((aligned(ERASER_SECTOR))) holepunch_pprf_keynode_sector {
    struct pprf_keynode entries[HOLEPUNCH_PPRF_KEYNODES_PER_SECTOR];
};

struct __attribute__((aligned(ERASER_SECTOR))) holepunch_pprf_fkt_sector {
    struct holepunch_key entries[HOLEPUNCH_PPRF_FKT_ENTRIES_PER_SECTOR];
};



/* size padded to 64 bytes, must be multiple of sector size */
struct eraser_map_entry {
    unsigned char key[ERASER_KEY_LEN];
    unsigned char iv[ERASER_IV_LEN];
    u64 status;
    u64 padding;
};



void handle_signal(int);

/* Key derivation and management. */
void get_keys(int, struct eraser_header *);
int verify_key(struct eraser_header *);
void hp_get_keys(int, struct holepunch_header *);
int hp_verify_key(struct holepunch_header *);
void cleanup_keys();


void do_init_filekeys(int, struct holepunch_header *, u64);

/* Actual commands. */
int close_eraser(char *);
void do_close(char *);
int open_eraser(char *, char *, u64, char*, char*, int);
void do_open(char *, char *, char *);
void do_create(char *, int);
void do_list();

int start_netlink_client(char *);

#endif /* ERASER_H */
