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
 * utils.c, ver.2018.02.11
 *
 * Helper functions for ERASER.
 */

#include "utils.h"

/* Div up */
u64 div_ceil(u64 n, u64 d) {
    return (n + d - 1) /  d;
}

/*
 * Functions to get random data.
 */

/* Fill a buffer with random bytes. */
void get_random_data(char *data, unsigned len) {

    ssize_t r;

    r = read(eraser_random, data, len);
    if (r == -1) {
        die("Error reading from random device\n");
    } else if (r != len) {
        die("Only read %d random bytes\n", r);
    }
}

/* Call this before get_random_data(). */
void init_random() {
    if ((eraser_random = open("/dev/urandom", O_RDONLY)) == -1) {
        die("Cannot open random device\n");
    }
}

void cleanup_random() {
    close(eraser_random);
}

/*
 * Checks a buffer's size, then allocates more memory (i.e. size * inc bytes),
 * if necessary.
 *
 * buf: buffer to check
 * cur: currently used size of the buffer
 * (in/out) max: maximum capacity of the buffer, updated to reflect the new size
 *          after a reallocation
 * inc: buffer size is increased to accomodate this many more elements size:
 * size of an element in the buffer, in bytes
 *
 * Return: the pointer to the new larger buffer
 */
void *try_realloc(void *buf, unsigned cur, unsigned *max,
                   unsigned inc, unsigned size) {
    void *new_buf;
    if (cur == *max) {
        new_buf = realloc(buf, (*max + inc) * size);
        if(!new_buf) die( "Realloc failed.\n");
        *max += inc;
        return new_buf;
    }
    return buf;
}

/*
 * Reads a text file, returns contents in a newly allocated buffer, and buffer
 * size in out argument buf_len. Caller frees the buffer.
 */
char *read_text_file(char *path, unsigned *buf_len) {

    int f;
    char *buf;
    unsigned count;
    unsigned cur;
    unsigned max;

    f = open(path, O_RDONLY);
    if (f == -1)
        die( "Cannot open file for reading, %s\n", path);

    cur = 0;
    max = IO_CHUNK;
    buf = malloc( max * sizeof(*buf));
    while ((count = read( f, buf + cur, IO_CHUNK))){
        if (count == -1)
            die("Cannot read from file %s\n", path);

        cur += count;
        buf = try_realloc(buf, cur, &max, IO_CHUNK, sizeof( *buf));
    }
    buf[cur] = '\0';
    close(f);

    if (buf_len)
        *buf_len = cur;
    return buf;
}

/* Encodes the given buffer of bytes as a hex string. */
unsigned char *hex_encode(unsigned char *in, unsigned len) {

    unsigned i;
    char *out;

    out = malloc((len * 2) + 1);

    for (i = 0; i < len; i++) {
        sprintf(out + (i * 2), "%02x", in[i]);
    }

    return out;
}

/*
 * Disk I/O helpers.
 */
void write_sectors(int fd, char *data, unsigned count) {
    if (write(fd, data, count * ERASER_SECTOR_LEN) == -1) {
        die("Error writing to device.\n");
    }
}

void read_sectors(int fd, char *data, unsigned count) {
    if (read(fd, data, count * ERASER_SECTOR_LEN) == -1) {
        die("Error reading from device.\n");
    }
}

void write_bytes(int fd, char *data, unsigned count) {
    if (write(fd, data, count) == -1) {
        die("Error writing to device.\n");
    }
}
