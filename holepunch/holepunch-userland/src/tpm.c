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
 * tpm.c, ver.2018.02.11
 *
 * ERASER TPM interface.
 */

#include "tpm.h"

/* If defined, use simple file I/O instead of a TPM chip. For testing only. */
#ifdef ERASER_NO_TPM

    #include <assert.h>

    #include "holepunch.h"

void check_tpm_success(TSS_RESULT r) {}
struct eraser_tpm *setup_tpm(char *owner_pass) {
    return NULL;
}
void cleanup_nvram(struct eraser_nvram *n) {}
void cleanup_tpm(struct eraser_tpm *t) {}

struct eraser_nvram *
setup_nvram(unsigned index, int len, char *owner_pass, struct eraser_tpm *t) {
    return NULL;
}

TSS_RESULT write_nvram(struct eraser_nvram *n, unsigned char *data) {
    int f;

    f = open("/tmp/tpm_test", O_RDWR | O_CREAT, 0600);
    assert(write(f, data, HOLEPUNCH_KEY_LEN) == HOLEPUNCH_KEY_LEN);
    close(f);
    return TSS_SUCCESS;
}

TSS_RESULT read_nvram(struct eraser_nvram *n, unsigned char **out) {
    int f;

    f = open("/tmp/tpm_test", O_RDWR);
    *out = malloc(HOLEPUNCH_KEY_LEN);
    assert(read(f, *out, HOLEPUNCH_KEY_LEN) == HOLEPUNCH_KEY_LEN);
    close(f);
    return TSS_SUCCESS;
}

TSS_RESULT release_nvram(struct eraser_nvram *n) {
    return TSS_SUCCESS;
}

#else

/* Real TPM stuff. */

void check_tpm_success(TSS_RESULT r) {
    if (r != TSS_SUCCESS) {
        print_red("TPM Error: %d %s\n", r, Trspi_Error_String(r));
        exit(-1); /* TODO: Do something about this, not just bail out. */
    }
}

struct eraser_tpm *setup_tpm(char *owner_pass) {
    TSS_HCONTEXT c;
    TSS_HTPM t;
    TSS_HPOLICY p;
    TSS_RESULT r;
    struct eraser_tpm *tpm;

    r = Tspi_Context_Create(&c);
    check_tpm_success(r);

    /* Connect to default system TPM. */
    r = Tspi_Context_Connect(c, NULL);
    check_tpm_success(r);

    r = Tspi_Context_GetTpmObject(c, &t);
    check_tpm_success(r);

    /* Set owner pass. */
    r = Tspi_GetPolicyObject(t, TSS_POLICY_USAGE, &p);
    check_tpm_success(r);

    r = Tspi_Policy_SetSecret(
        p,
        TSS_SECRET_MODE_PLAIN,
        strlen(owner_pass),
        owner_pass
    );
    check_tpm_success(r);

    /* Setup complete. */
    tpm = malloc(sizeof(*tpm));
    tpm->context = c;
    tpm->tpm = t;

    return tpm;
}

/* Cleanup. */
void cleanup_nvram(struct eraser_nvram *n) {
    Tspi_Context_Close(n->nv);
    free(n);
    n = NULL;
}

void cleanup_tpm(struct eraser_tpm *t) {
    Tspi_Context_Close(t->tpm);
    Tspi_Context_FreeMemory(t->context, NULL);
    Tspi_Context_Close(t->context);

    free(t);
    t = NULL;
}

struct eraser_nvram *
setup_nvram(unsigned index, int len, char *owner_pass, struct eraser_tpm *t) {
    TSS_HNVSTORE n;
    TSS_HPOLICY p;
    TSS_RESULT r;

    struct eraser_nvram *nv;

    /* Create space handle. */
    r = Tspi_Context_CreateObject(t->context, TSS_OBJECT_TYPE_NV, 0, &n);
    check_tpm_success(r);

    r = Tspi_SetAttribUint32(n, TSS_TSPATTRIB_NV_INDEX, 0, index);
    check_tpm_success(r);

    r = Tspi_SetAttribUint32(n, TSS_TSPATTRIB_NV_DATASIZE, 0, len);
    check_tpm_success(r);

    r = Tspi_SetAttribUint32(
        n,
        TSS_TSPATTRIB_NV_PERMISSIONS,
        0,
        TPM_NV_PER_OWNERREAD | TPM_NV_PER_OWNERWRITE
    );
    check_tpm_success(r);

    /* Try to define space, maybe it does not exist. */
    r = Tspi_NV_DefineSpace(n, 0, 0);
    if ((r & TSS_MAX_ERROR) == TSS_E_NV_AREA_EXIST) {
        print_red("NVRAM area already defined previously. Using that one.\n");
    } else {
        check_tpm_success(r);
    }

    /* Set owner pass. */
    r = Tspi_Context_CreateObject(
        t->context,
        TSS_OBJECT_TYPE_POLICY,
        TSS_POLICY_USAGE,
        &p
    );
    check_tpm_success(r);

    r = Tspi_Policy_SetSecret(
        p,
        TSS_SECRET_MODE_PLAIN,
        strlen(owner_pass),
        owner_pass
    );
    check_tpm_success(r);

    r = Tspi_Policy_AssignToObject(p, n);
    check_tpm_success(r);

    /* Setup complete. */
    nv = malloc(sizeof(*nv));
    nv->nv = n;
    nv->index = index;
    nv->len = len;

    return nv;
}

/* Write. */
TSS_RESULT write_nvram(struct eraser_nvram *n, unsigned char *data) {
    return Tspi_NV_WriteValue(n->nv, 0, n->len, data);
}

/* Read. */
TSS_RESULT read_nvram(struct eraser_nvram *n, unsigned char **out) {
    return Tspi_NV_ReadValue(n->nv, 0, &n->len, out);
}

/* We don't use this, yet. */
TSS_RESULT release_nvram(struct eraser_nvram *n) {
    return Tspi_NV_ReleaseSpace(n->nv);
}

#endif
