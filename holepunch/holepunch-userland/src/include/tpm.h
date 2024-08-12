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
 * tpm.h, ver.2018.02.11
 *
 * ERASER TPM interface.
 */

#ifndef TPM_H
#define TPM_H

// #include <trousers/trousers.h>
#include <tss/platform.h>
#include <tss/tspi.h>
#include <tss/tss_defines.h>
#include <tss/tss_error.h>
#include <tss/tss_structs.h>
#include <tss/tss_typedef.h>

struct eraser_tpm {
    TSS_HCONTEXT context;
    TSS_HTPM tpm;
};

struct eraser_nvram {
    TSS_HNVSTORE nv;
    unsigned index;
    int len;
};

struct eraser_tpm *setup_tpm(char *);
void cleanup_nvram(struct eraser_nvram *);
void cleanup_tpm(struct eraser_tpm *);
struct eraser_nvram *setup_nvram(unsigned, int, char *, struct eraser_tpm *);

TSS_RESULT write_nvram(struct eraser_nvram *, unsigned char *);
TSS_RESULT read_nvram(struct eraser_nvram *, unsigned char **);
TSS_RESULT release_nvram(struct eraser_nvram *);

#endif /* TPM_H */
