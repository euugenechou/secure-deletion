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
 * utils.h, ver.2018.02.11
 *
 * Helper functions for ERASER.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <error.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/*
 * We need to know how large our integers are.
 */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/*
 * Pretty print macros.
 */
#define NORMAL "\x1B[0m"
#define RED "\x1B[31m"
#define GREEN "\x1B[32m"

/* Print in color. */
#define print_color(color, fmt, ...)                \
    do {                                            \
        printf(color fmt NORMAL, ##__VA_ARGS__);    \
        fflush(stdout);                             \
    } while (0)

/* Print in red. */
#define print_red(fmt, ...)                     \
    print_color(RED, fmt, ##__VA_ARGS__)

/* Print in green. */
#define print_green(fmt, ...)                   \
    print_color(GREEN, fmt, ##__VA_ARGS__)

/* Print error message and exit. */
#define die(fmt, ...)                               \
    do {                                            \
        print_red(fmt NORMAL, ##__VA_ARGS__);       \
        exit(1);                                    \
    } while (0)

/* Div up shortcut. */
u64 div_ceil(u64, u64);

/* Get random data. */
int eraser_random;
void get_random_data(char *, unsigned);
void init_random();
void cleanup_random();

/* Memory management helper. */
void *try_realloc(void *, unsigned, unsigned *, unsigned, unsigned);

/* Text file reader. */
#define IO_CHUNK 1024
char *read_text_file(char *, unsigned *);

/* Hex encoder. */
unsigned char *hex_encode(unsigned char *, unsigned len);

/* Disk write helpers. */
#define ERASER_SECTOR_LEN 4096   /* In bytes. */
#define ERASER_IO_SIZE 1        /* In sectors. */
void write_sectors(int, char *, unsigned);
void read_sectors(int, char *, unsigned);
void write_bytes(int, char *, unsigned);

#endif /* UTILS_H */
