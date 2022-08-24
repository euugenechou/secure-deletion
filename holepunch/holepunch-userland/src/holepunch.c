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
 * eraser.c, ver.2018.02.11
 *
 * ERASER core.
 */

#include "utils.h"
#include "crypto.h"
#include "netlink.h"
#include "holepunch.h"
#include "tpm.h"


void handle_signal(int sig) {
    if (sig == SIGTERM) {
        print_red("Received end signal. Exiting.");
        cleanup_keys();
        exit(1);
    }
}


char enc_key[ERASER_KEY_LEN];
char *tpm_owner_pass = NULL;
struct eraser_tpm *tpm;
struct eraser_nvram *nvram;

/*
 * Key derivation and management.
 */

/* Prompts the user for a password and generates/derives the crypto key. */
void get_keys(int op, struct eraser_header *h) {
    char *pass;
    char *pass_v;
    char pass_key[ERASER_KEY_LEN];

    struct termios old_term;
    struct termios new_term;

    /* Turn terminal echo off. */
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    /* Prompt for TPM owner password. */
    printf("Please enter TPM owner password: ");
    if (scanf("%ms", &tpm_owner_pass) != 1) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        die("\nError reading password!\n");
    }

    /* Prompt for password. */
    printf("\nPlease enter ERASER password: ");
    if (scanf("%ms", &pass) != 1) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        die("\nError reading password!\n");
    }

    /* Check again. */
    if (op == ERASER_CREATE) {
        printf("\nPlease re-enter ERASER password: ");
        if (scanf("%ms", &pass_v) != 1) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
            memset(pass, 0, strlen(pass));
            die("\nError reading password!\n");
        }

        if (strcmp(pass, pass_v) != 0) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
            memset(pass, 0, strlen(pass));
            memset(pass_v, 0, strlen(pass_v));
            die("\nPasswords do not match!\n");
        }

        memset(pass_v, 0, strlen(pass_v));
        free(pass_v);
    }

    /* Derive the pass keys. */
    if (op == ERASER_CREATE) {
        get_random_data(h->pass_salt, ERASER_SALT_LEN);
    }
    generate_key(pass, ERASER_KEY_LEN, pass_key, h->pass_salt, ERASER_SALT_LEN);
    memset(pass, 0, strlen(pass));
    free(pass);
    printf("\n");

    /* Restore terminal settings. */
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);

    if (op == ERASER_CREATE) {
        /* Randomly generate the disk encryption key. */
        get_random_data(enc_key, ERASER_KEY_LEN);

        /* Store encrypted disk encryption key in the header. */
        encrypt(enc_key, h->enc_key, ERASER_KEY_LEN, pass_key, 0);
        get_random_data(h->enc_key_salt, ERASER_SALT_LEN);
        digest_key(enc_key, ERASER_KEY_LEN, h->enc_key_digest, ERASER_DIGEST_LEN, h->enc_key_salt, ERASER_SALT_LEN);

    } else {
        /* Decrypt the disk encryption key. */
        decrypt(h->enc_key, enc_key, ERASER_KEY_LEN, pass_key, 0);
    }

    /* Clean the pass key memory. */
    memset(pass_key, 0, ERASER_KEY_LEN);
}

/* Decrypt and verify the key. */
int verify_key(struct eraser_header *h) {

    char digest[ERASER_DIGEST_LEN];

    digest_key(enc_key, ERASER_KEY_LEN, digest, ERASER_DIGEST_LEN, h->enc_key_salt, ERASER_SALT_LEN);
    if(memcmp(digest, h->enc_key_digest, ERASER_DIGEST_LEN) != 0) {
        return 0;
    }

    return 1;
}


/* THIS ONLY WORKS IF WE KEEP THE FIRST 5 ENTRIES IDENTICAL TO ERASER */
void hp_get_keys(int op, struct holepunch_header *h) {
    get_keys(op, (struct eraser_header*) h);
}

int hp_verify_key(struct holepunch_header *h) {
    return verify_key((struct eraser_header*)h);
}

/* Clean the key memory. */
void cleanup_keys() {
    memset(enc_key, 0, ERASER_KEY_LEN);
    if (tpm_owner_pass) {
        free(tpm_owner_pass);
    }
}

/*
 * Actual commands.
 */

/* Closes a ERASER instance by device-mapper name. */
int close_eraser(char *mapped_dev) {

    struct dm_task *dmt;
    u32 cookie = 0;
    u16 udev_flags = 0;
    int is_success = 0;

    print_green("Closing: %s\n", mapped_dev);
#ifdef ERASER_NO_UDEV
    udev_flags |= DM_UDEV_DISABLE_DM_RULES_FLAG | DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG;
    dm_udev_set_sync_support(0);
#endif

    if (!(dmt = dm_task_create(DM_DEVICE_REMOVE))) {
        print_red("DEBUG: Cannot create dm_task\n");
        return 0;
    }

    if (!dm_task_set_name(dmt, mapped_dev)) {
        print_red("DEBUG: Cannot set device name\n");
        goto out;
    }

    if (!dm_task_set_cookie(dmt, &cookie, udev_flags)) {
        goto out;
    }

    dm_task_retry_remove(dmt);

    if (!dm_task_run(dmt)) {
        print_red("DEBUG: Cannot issue ioctl\n");
        goto out;
    }
    is_success = 1;

#ifdef ERASER_NO_UDEV
    dm_mknodes(mapped_dev);
#endif

out:
    dm_udev_wait(cookie);
    dm_task_destroy(dmt);

    print_green("Done!\n");
    return is_success;
}

/* Closes a ERASER instance. */
void do_close(char *eraser_name) {

    char *buf;
    char *tok_buf;
    char *tok;
    unsigned len;
    char *name;
    int done;

    sync();

    /* Read the ERASER proc file. */
    buf = read_text_file(HOLEPUNCH_PROC_FILE, &len);
    if (!len) {
        print_red("There are no ERASER devices open.\n");
        return;
    }

    buf[len - 1] = '\0';
    tok_buf = buf;

    /* Check all open ERASER instances. */
    done = 0;
    while (!done && (tok = strsep(&tok_buf, " "))) {

        if (strcmp(tok, eraser_name) != 0) {
            /* This is not what we are looking for. */
            strsep(&tok_buf, "\n"); /* Skip to the end of line. */
        }
        else {
            /* Found! */
            strsep(&tok_buf, " ");
            name = rindex(strsep(&tok_buf, " "), '/') + 1;
            if (!close_eraser(name)) {
                print_red("DEBUG: Cannot close %s\n", name);
            }

            done = 1;
        }
    }

    /* Not found. */
    if (!done) {
        print_red("No ERASER named \"%s\"\n", eraser_name);
    }

    free(buf);
}

/* Device mapper open. */
int open_eraser(char *dev_path, char *mapped_dev, u64 len, char *eraser_name, char *mapped_dev_path, int netlink_pid) {

    struct dm_task *dmt;
    u32 cookie = 0;
    u16 udev_flags = 0;
    int is_success = 0;
    char param[4096];
    char *hex_key;

#ifdef ERASER_NO_UDEV
    udev_flags |= DM_UDEV_DISABLE_DM_RULES_FLAG | DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG;
    dm_udev_set_sync_support(0);
#endif

    /* Hex encode the key bytes. */
    hex_key = hex_encode(enc_key, ERASER_KEY_LEN);

    /* These parameters will be passed to the kernel module. */
    snprintf(param, 4096, "%s %s %s %s %d\n",
             dev_path, eraser_name, hex_key, mapped_dev_path, netlink_pid);

    if (!(dmt = dm_task_create(DM_DEVICE_CREATE))) {
        print_red("DEBUG: Cannot create dm_task\n");
        return 0;
    }

    if (!dm_task_set_name(dmt, mapped_dev)) {
        print_red("DEBUG: Cannot set device name\n");
        goto out;
    }

    if (!dm_task_add_target(dmt, 0, len * (ERASER_SECTOR / 512), ERASER_TARGET, param)) {
        goto out;
    }

    if (!dm_task_set_add_node(dmt, DM_ADD_NODE_ON_CREATE)) {
        print_red("DEBUG: Cannot add node\n");
        goto out;
    }

    if (!dm_task_set_cookie(dmt, &cookie, udev_flags)) {
        print_red("DEBUG: Cannot set cookie\n");
        goto out;
    }

    if (!dm_task_run(dmt)) {
        print_red("DEBUG: Cannot issue ioctl\n");
        goto out;
    }

#ifdef ERASER_NO_UDEV
    dm_mknodes(mapped_dev);
#endif

    is_success = 1;

out:
    dm_udev_wait(cookie);
    dm_task_destroy(dmt);

    /* Clean the key. */
    memset(param, 0, 4096);
    memset(hex_key, 0, ERASER_KEY_LEN);
    free(hex_key);

    return is_success;
}

/* Open a ERASER instance. */
void do_open(char *dev_path, char *eraser_name, char *mapped_dev) {
    // print_red("NOT IMPLEMENTED\n");
    // return;

    struct holepunch_header *hp_h;
    char *mapped_dev_path;
    int fd;
    char *buf;
    int netlink_pid;

    /* Open device. */
    if ((fd = open(dev_path, O_RDWR)) == -1) {
        die("Cannot open device %s\n", dev_path);
    }

    /* Read header. */
    buf = malloc(ERASER_HEADER_LEN * ERASER_SECTOR);
    read_sectors(fd, buf, ERASER_HEADER_LEN);
    hp_h = (struct holepunch_header *) buf;

    /* Get password from user and check if correct. */
    hp_get_keys(ERASER_OPEN, hp_h);
    if(!hp_verify_key(hp_h)) {
        print_red("Incorrect password!\n");
        goto free_headers;
    }

    /* Define the NVRAM region on TPM. */
    tpm = setup_tpm(tpm_owner_pass);
    nvram = setup_nvram(hp_h->nv_index, ERASER_KEY_LEN, tpm_owner_pass, tpm);

    /* Construct mapped device path. */
    mapped_dev_path = malloc(strlen(ERASER_DEV_PATH) + strlen(mapped_dev) + 1);
    strcpy(mapped_dev_path, ERASER_DEV_PATH);
    strcat(mapped_dev_path, mapped_dev);

    /* Start the netlink client. */
    netlink_pid = start_netlink_client(eraser_name);
    if (netlink_pid != 0) {
        /* Device-mapper open. */
        if (!open_eraser(dev_path, mapped_dev, hp_h->data_end - hp_h->data_start, eraser_name, mapped_dev_path, netlink_pid)) {
            print_red("Cannot open ERASER device!\n");
            kill(netlink_pid, SIGTERM);
            goto free_name;
        }

        print_green("Success!\n");
    }

    #ifdef ERASER_DEBUG
        print_green("Journal start: %llu\n", hp_h->journal_start);
        print_green("Key table start: %llu\n", hp_h->key_table_start);
        print_green("PPRF fkt start: %llu\n", hp_h->fkt_start);
        print_green("PPRF key start: %llu\n", hp_h->pprf_start);
        print_green("PPRF key max elts: %llu\n", hp_h->pprf_capacity);
        print_green("Data start: %llu\n", hp_h->data_start);
        print_green("Data end: %llu\n", hp_h->data_end);
    #endif



free_name:
    free(mapped_dev_path);
free_headers:
    cleanup_keys();
    free(buf);
    close(fd);
    print_green("Done!\n");
}

/* Start netlink client. */
int start_netlink_client(char *eraser_name) {

    int pid;

    pid = fork();
    if (pid != 0) {
        return pid;
    }

    enter_netlink_loop(); /* There is no return until ERASER device is closed. */
    return pid;
}


/* Create a ERASER instance. */
void do_create(char *dev_path, int nv_index) {

    // struct eraser_header *h;
    unsigned char master_key[ERASER_KEY_LEN];
    u64 dev_size;
    u64 inode_count;
    int fd;

    /* Open device. */
    if ((fd = open(dev_path, O_RDWR)) == -1) {
        die("Cannot open device %s\n", dev_path);
    }

    init_random();
    init_crypto();

    /* ioctl for device size. */
    if (ioctl(fd, BLKGETSIZE64, &dev_size) == -1) {
        die("Cannot determine size of device %s\n", dev_path);
    }
    inode_count = div_ceil(dev_size, ERASER_BYTES_PER_INODE_RATIO);

#ifdef ERASER_DEBUG
    print_green("Device size is %llu bytes\n", dev_size);
    print_green("-> ERASER sectors: %llu\n", dev_size / ERASER_SECTOR);
    print_green("-> Expecting %llu inodes for an ext4 partition\n\n", inode_count);
#endif
    /* Compute sizes for holepunch metadata */
    struct holepunch_header *hp_h = malloc(ERASER_SECTOR * ERASER_HEADER_LEN);
    u64 key_table_len = div_ceil(inode_count, HP_KEY_PER_SECTOR);
    // XXX how is this calculated? it feels a little arbitrary
    hp_h->pprf_depth = 32 - __builtin_clz(key_table_len + HOLEPUNCH_REFRESH_INTERVAL);
    hp_h->pprf_capacity = HOLEPUNCH_REFRESH_INTERVAL * HOLEPUNCH_KEY_GROWTH_MULT * hp_h->pprf_depth;
    u64 pprf_len = div_ceil(hp_h->pprf_capacity, HP_PPRF_PER_SECTOR);

    hp_h->journal_start = ERASER_HEADER_LEN;
    hp_h->key_table_start = hp_h->journal_start + HP_JOURNAL_LEN;
    hp_h->fkt_start = hp_h->key_table_start + key_table_len;
    hp_h->fkt_bottom_width = div_ceil(pprf_len, HP_FKT_PER_SECTOR);
    hp_h->fkt_top_width = div_ceil(hp_h->fkt_bottom_width, HP_FKT_PER_SECTOR);
    hp_h->pprf_start = hp_h->fkt_start + hp_h->fkt_bottom_width + hp_h->fkt_top_width;
    hp_h->data_start = hp_h->pprf_start + pprf_len;
    hp_h->data_end = dev_size / ERASER_SECTOR;
    hp_h->pprf_size = 1;
    hp_h->in_use = 0;
// #ifdef ERASER_DEBUG
    print_green("-> Holepunch PPRF depth: %u\n\n", hp_h->pprf_depth);
// #endif

#ifdef ERASER_DEBUG
    print_green("Journal start: %llu\n", hp_h->journal_start);
    print_green("Key table start: %llu\n", hp_h->key_table_start);
    print_green("PPRF fkt start: %llu\n", hp_h->fkt_start);
    print_green("PPRF key start: %llu\n", hp_h->pprf_start);
    print_green("PPRF key max elts: %llu\n", hp_h->pprf_capacity);
    print_green("Data start: %llu\n", hp_h->data_start);
    print_green("Data end: %llu\n", hp_h->data_end);
#endif

    /* Prompt user for password and randomize the IV key. */
    hp_get_keys(ERASER_CREATE, hp_h);
    get_random_data(hp_h->iv_key, ERASER_KEY_LEN);

    /* Define the NVRAM region on TPM. */
    tpm = setup_tpm(tpm_owner_pass);
    nvram = setup_nvram(nv_index, ERASER_KEY_LEN, tpm_owner_pass, tpm);
    hp_h->nv_index = nv_index;

    get_random_data(master_key, ERASER_KEY_LEN);
    if (write_nvram(nvram, master_key) != TSS_SUCCESS) {
        print_red("Cannot write master key!");
        goto tpm_error;
    }
    memset(master_key, 0, ERASER_KEY_LEN);

    /* Write the header, then a journal entry for PPRF init. */
    write_sectors(fd, hp_h, ERASER_HEADER_LEN);
    u64 *journal_ctl = malloc(ERASER_SECTOR);
    journal_ctl[0] = HPJ_PPRF_INIT;
    get_random_data(journal_ctl + 1, ERASER_KEY_LEN);
    write_sectors(fd, journal_ctl, 1);
    /* Randomize the rest of the journal and all of the key table. */
    for (u64 i = 1; i < HP_JOURNAL_LEN + key_table_len; ++i) {
        /* Done one sector at a time so as not to overwhelm /dev/urandom. */
        get_random_data(journal_ctl, ERASER_SECTOR);
        write_sectors(fd, journal_ctl, 1);
    }
    free(journal_ctl);
    /* The journal entry will take care of the rest. */

    /* All done. */
    sync();
    print_green("\nDone!\n\n");

    free(hp_h);
tpm_error:
    cleanup_nvram(nvram);
    cleanup_tpm(tpm);
    cleanup_keys();
    cleanup_crypto();
    cleanup_random();
}

/* Reads the ERASER proc file and lists all open ERASER instances. */
void do_list() {
    char *buf;
    char *tok_buf;
    char *tok;
    unsigned len;

    buf = read_text_file(HOLEPUNCH_PROC_FILE, &len);
    if (!len)
        return;

    buf[len - 1] = '\0';
    tok_buf = buf;

    while ((tok = strsep(&tok_buf, " "))) {
        print_green("\nEraser Name: %s\n", tok);
        print_green("  --> Real Device: %s\n", strsep(&tok_buf, " "));
        print_green("  --> Virtual Device: %s\n", strsep(&tok_buf, " "));

        strsep(&tok_buf, "\n"); /* Skip to the end of line. */
    }

    free(buf);
}
