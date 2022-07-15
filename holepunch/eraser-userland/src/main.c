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
 * main.c, ver.2018.02.11
 *
 * ERASER Userland Tool.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <argp.h>

#include "holepunch.h"

/*
 * Argument parsing stuff, using argp.
 */

/* Command arguments. */
#define COMMAND_CREATE "create"
#define COMMAND_OPEN "open"
#define COMMAND_CLOSE "close"
#define COMMAND_LIST "list"

const char *argp_program_version = "ERASER ver.2016.xx.xx";
const char *argp_program_bug_address = "<onarliog@ccs.neu.edu>";
static const char doc[] = "Create, open, close, list ERASER devices.";
static const char args_doc[] =
    COMMAND_CREATE  " <block-device> <tpm-nvram-index>\n"
    COMMAND_OPEN    " <block-device> <eraser-name>\n"
    COMMAND_CLOSE   " <eraser-name>\n"
    COMMAND_LIST    "\n";

static struct argp_option options[] = {
    {"device-name", 'd', "<mapped-device-name>", 0, "Mapped device name"},
    {0}
};

struct arguments {
    char *args[4];
    char *mapped_dev;
};

static error_t parse_arguments(int key, char *arg, struct argp_state *state) {

    struct arguments *arguments = state->input;

    switch (key) {
    case 'd':
        arguments->mapped_dev = arg;
        break;
    case ARGP_KEY_ARG:
        if ((state->arg_num > 2 && strcmp(arguments->args[0], COMMAND_OPEN) == 0) ||
            (state->arg_num > 2 && strcmp(arguments->args[0], COMMAND_CREATE) == 0) ||
            (state->arg_num > 1 && strcmp(arguments->args[0], COMMAND_CLOSE) == 0) ||
            (state->arg_num > 0 && strcmp(arguments->args[0], COMMAND_LIST) == 0)){
            /* Too many arguments. */
            argp_usage(state);
        }
        arguments->args[state->arg_num] = arg;
        break;
    case ARGP_KEY_END:
        if (state->arg_num == 0 ||
            (state->arg_num < 1 && strcmp(arguments->args[0], COMMAND_LIST) == 0) ||
            (state->arg_num < 3 && strcmp(arguments->args[0], COMMAND_CREATE) == 0) ||
            (state->arg_num < 2 && strcmp(arguments->args[0], COMMAND_CLOSE) == 0) ||
            (state->arg_num < 3 && strcmp(arguments->args[0], COMMAND_OPEN) == 0)) {
            /* Missing arguments. */
            argp_usage(state);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp arg_parser = {options, parse_arguments, args_doc, doc};
struct arguments arguments;

int main(int argc, char **argv) {

    assert(sizeof(struct eraser_header) < ERASER_SECTOR_LEN);
    assert((ERASER_SECTOR_LEN % sizeof(struct eraser_map_entry)) == 0);

    signal(SIGINT, handle_signal);

    /* Default arguments. */
    arguments.mapped_dev = "holepunch";

    /* Parse arguments. */
    argp_parse(&arg_parser, argc, argv, 0, 0, &arguments);

    /* Command dispatcher. */
    if (strcmp(arguments.args[0], COMMAND_CREATE) == 0) {

        print_green("Creating HOLEPUNCH on %s\n", arguments.args[1]);
        do_create(arguments.args[1], atoi(arguments.args[2]));
    }
    else if (strcmp(arguments.args[0], COMMAND_OPEN) == 0) {

        print_green("Opening HOLEPUNCH device %s on %s\n", arguments.args[2], arguments.args[1]);
        do_open(arguments.args[1], arguments.args[2], arguments.mapped_dev);
    }
    else if (strcmp(arguments.args[0], COMMAND_CLOSE) == 0) {

        print_green("Closing HOLEPUNCH device %s \n", arguments.args[1]);
        do_close(arguments.args[1]);
    }
    else if (strcmp(arguments.args[0], COMMAND_LIST) == 0) {
        print_green("Listing open HOLEPUNCH devices.\n");
        do_list();
    }
    else {
        die("Unknown command: %s\n", arguments.args[0]);
    }

    return 0;
}
