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
 * netlink.c, ver.2018.02.11
 *
 * ERASER netlink client.
 */

#include "utils.h"
#include "crypto.h"
#include "holepunch.h"
#include "netlink.h"
#include "tpm.h"

extern struct eraser_tpm *tpm;
extern struct eraser_nvram *nvram;

void enter_netlink_loop() {
    int s;
    struct sockaddr_nl sa;
    struct nlmsghdr *h;
    struct iovec iov;
    struct msghdr msg;

    unsigned char *key_out; /* TPM lib allocates this for us. */
    unsigned char key[ERASER_KEY_LEN];
    char eraser_name[ERASER_NAME_LEN + 1];

    int self_pid;

    s = -1;
    do {
        s = socket(PF_NETLINK, SOCK_RAW, ERASER_NETLINK);
        if (s < 0) {
            print_red("Cannot create socket. Will retry.\n");
        }
        sleep(3);
    } while (s < 0);
    print_green("Socket created.\n");

    /* Bind. */
    self_pid = getpid();
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = self_pid; /* Self pid. */
    sa.nl_groups = 0; /* Unicast. */
    bind(s, (struct sockaddr *) &sa, sizeof(sa));

    /* Set destination. */
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0; /* For Linux Kernel. */
    sa.nl_groups = 0; /* Unicast. */

    /* Payload setup. */
    h = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(h, 0, NLMSG_SPACE(MAX_PAYLOAD));
    h->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    h->nlmsg_pid = self_pid; /* Self pid. */

    msg.msg_name = (void *) &sa;
    msg.msg_namelen = sizeof(sa);
    iov.iov_base = (void *) h;
    iov.iov_len = h->nlmsg_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    while (1) {
        if (recvmsg(s, &msg, 0) == -1) {
            print_red("Receive failed.");
            sleep(5);
        } else {
            /* h contains what we need here. */
            if (h->nlmsg_type == ERASER_MSG_GET_KEY) {
                memcpy(eraser_name, NLMSG_DATA(h), ERASER_NAME_LEN);
                eraser_name[ERASER_NAME_LEN] = '\0';

                /* Retrieve key from TPM. */
                if (read_nvram(nvram, &key_out) != TSS_SUCCESS) {
                    print_red("Cannot read master key!");
                    /* TODO: Do something about it. */
                    break;
                }

                /* Send key. */
                memset(h, 0, NLMSG_SPACE(MAX_PAYLOAD));
                h->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
                h->nlmsg_pid = self_pid;
                h->nlmsg_type = ERASER_MSG_GET_KEY;
                strcpy(NLMSG_DATA(h), eraser_name);
                memcpy(NLMSG_DATA(h) + ERASER_NAME_LEN, key_out, ERASER_KEY_LEN);

                memset(key_out, 0, ERASER_KEY_LEN);
                free(key_out);

                iov.iov_base = (void *) h;
                iov.iov_len = h->nlmsg_len;
                msg.msg_name = (void *) &sa;
                msg.msg_namelen = sizeof(sa);
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;

                sendmsg(s, &msg, 0);

            } else if (h->nlmsg_type == ERASER_MSG_SET_KEY) {
                memcpy(eraser_name, NLMSG_DATA(h), ERASER_NAME_LEN);
                eraser_name[ERASER_NAME_LEN] = '\0';
                memcpy(key, NLMSG_DATA(h) + ERASER_NAME_LEN, ERASER_KEY_LEN);

                /* Write key to TPM. */
                if (write_nvram(nvram, key) != TSS_SUCCESS) {
                    print_red("Cannot write master key!");
                    /* TODO: Do something about it. */
                    break;
                }
                memset(key, 0, ERASER_KEY_LEN);

                /* Send ACK to kernel. */
                memset(h, 0, NLMSG_SPACE(MAX_PAYLOAD));
                h->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
                h->nlmsg_pid = self_pid;
                h->nlmsg_type = ERASER_MSG_SET_KEY;
                strcpy(NLMSG_DATA(h), eraser_name);

                iov.iov_base = (void *) h;
                iov.iov_len = h->nlmsg_len;
                msg.msg_name = (void *) &sa;
                msg.msg_namelen = sizeof(sa);
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;

                sendmsg(s, &msg, 0);
            } else if (h->nlmsg_type == ERASER_MSG_DIE) {
#ifdef ERASER_DEBUG
                print_red("ERASER closing down. I will also exit.\n");
#endif
                break;
            }
        }
    }
    close(s);
    cleanup_nvram(nvram);
    cleanup_tpm(tpm);
}
