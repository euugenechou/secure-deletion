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
 * netlink.h, ver.2018.02.11
 *
 * ERASER netlink client.
 */

#ifndef NETLINK_H
#define NETLINK_H

#include <sys/socket.h>
#include <linux/netlink.h>

#define ERASER_NETLINK 31

enum {
    ERASER_MSG_GET_KEY,
    ERASER_MSG_SET_KEY,
    ERASER_MSG_DIE,
};

#define MAX_PAYLOAD (ERASER_NAME_LEN + ERASER_KEY_LEN)

void enter_netlink_loop();

#endif /* NETLINK_H */
