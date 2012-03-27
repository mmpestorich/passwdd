/*
Copyright (C) 2012 Daniel Hazelbaker  

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sasl/sasl.h>
#include "common.h"
#include "client.h"
#include "keys.h"
#include "config.h"
#include "listener.h"


int doExit = 0;

static void usage();


//
// Retrieve an SASL option.
//
static int getopt_func(void *context, const char *plugin_name, const char *option, const char **result, unsigned *len)
{
    const char *value;
    char option_name[256];


    //
    // Construct a more helpful option name.
    //
    if (plugin_name != NULL)
        snprintf(option_name, sizeof(option_name) - 1, "sasl_%s_%s", plugin_name, option);
    else
        snprintf(option_name, sizeof(option_name) - 1, "sasl_%s", option);
    option_name[sizeof(option_name) - 1] = '\0';

    //
    // Get the value for this option.
    //
    value = find_config(option_name);
    if (value != NULL) {
        *result = value;

        return SASL_OK;
    }

    return SASL_FAIL;
}


//
// Log a message from the SASL system.
//
static int log_func(void *context, int level, const char *message)
{
//    printf("%s\r\n", message);

    return SASL_OK;
}


static sasl_callback_t callbacks[] = {
    { SASL_CB_GETOPT, &getopt_func, NULL },
    { SASL_CB_LOG, &log_func, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};


static struct option longopts[] = {
	{ "config",	required_argument,	NULL,		'c' },
	{ "help",	no_argument,		NULL,		'h' },
	{ NULL,		0,			NULL,		0 }
};


int main(int argc, char *argv[])
{
    const char *config_file = "/etc/lpws.conf";
    int ch;


    while ((ch = getopt_long(argc, argv, "c:h", longopts, NULL)) != -1) {
        switch (ch) {
            case 'c':
                config_file = optarg;
                break;

            case 'h':
            default:
                usage();
        }

        argc -= optind;
        argv += optind;
    }

    if (init_config(config_file) == -1)
        exit(1);

    init_client();
    loadKeys();

    if (sasl_server_init(callbacks, "PasswordServer") != SASL_OK) {
        printf("Failed to initialize SASL.\r\n");
        exit(1);
    }

    init_auxprop();

    if (setupListeners() == -1) {
        printf("Failed to setup server sockets.\r\n");
        exit(1);
    }

    while (!doExit) {
        if (poll_sockets() == -1) {
            printf("Something very bad happened polling for activity. Aborting.\r\n");
            exit(2);
        }
    }

    //
    // Close all client sockets.
    //

    //
    // Close all server sockets.
    //
    closeListeners();
    
    return 0;
}


//
// Display some simple usage information to the user.
//
static void usage()
{
    printf("Usage: lpws [-c config]\r\n");
    exit(-1);
}


