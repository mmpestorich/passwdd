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
#include <netdb.h>
#include <arpa/inet.h>
#include "common.h"
#include "client.h"
#include "keys.h"
#include "config.h"
#include "listener.h"
#include "ldap.h"

int doExit = 0;

const char *myHostname = NULL;
const char *myAddress = NULL;

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

#ifdef DEBUG
    printf("CyrusOption: %s\r\n", option_name);
#endif

    //
    // Get the value for this option.
    //
    value = find_config(option_name);
    if (value != NULL) {
        *result = value;

        return SASL_OK;
    }

    //
    // If the value was not found and it is from the lpws_ldap plugin, then
    // to see if we have a generic version of the same.
    //
    if (plugin_name != NULL && strcasecmp(plugin_name, "lpws_ldap") == 0) {
        snprintf(option_name, sizeof(option_name) - 1, "ldap_%s", option);
        value = find_config(option_name);
        if (value != NULL) {
            *result = value;

            return SASL_OK;
        }
    }

    return SASL_FAIL;
}


//
// Log a message from the SASL system.
//
static int log_func(void *context, int level, const char *message)
{
#ifdef DEBUG
    printf("CyrusLog: %s\r\n", message);
#endif

    return SASL_OK;
}


static sasl_callback_t callbacks[] = {
    { SASL_CB_GETOPT, (int (*)())&getopt_func, NULL },
    { SASL_CB_LOG, (int (*)())&log_func, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};


static struct option longopts[] = {
	{ "config",	required_argument,	NULL,		'c' },
	{ "update",	no_argument,		NULL,		'u' },
	{ "force",	no_argument,		NULL,		'f' },
	{ "help",	no_argument,		NULL,		'h' },
	{ NULL,		0,			NULL,		0 }
};


int main(int argc, char *argv[])
{
    const char *config_file = "/etc/lpws.conf";
    int ch, updateAuth = 0, force = 0;


    while ((ch = getopt_long(argc, argv, "c:ufh", longopts, NULL)) != -1) {
        switch (ch) {
            case 'c':
                config_file = optarg;
                break;

            case 'u':
                updateAuth = 1;
                break;

            case 'f':
                force = 1;
                break;

            case 'h':
            default:
                usage();
        }
    }

    if (init_config(config_file) == -1)
        exit(1);

    //
    // Get the hostname and primary IP address.
    //
    char *name, *address;

    if (find_config("hostname") != NULL) {
        name = strdup(find_config("hostname"));
    }
    else {
        name = malloc(256);
        if (gethostname(name, 256) != 0)
            exit(1);
    }
    myHostname = name;

    if (find_config("ipaddress") != NULL) {
        address = strdup(find_config("ipaddress"));
    }
    else {
        struct hostent *ent = gethostbyname(myHostname);
        if (ent == NULL)
            exit(1);
        struct in_addr **addrs = (struct in_addr **)ent->h_addr_list;
        if (addrs[0] == NULL)
            exit(1);
        address = strdup(inet_ntoa(addrs[0][0]));
    }
    myAddress = address;

    printf("Running with local address %s:%s.\r\n", myHostname, myAddress);

    if (loadKeys() == -1)
        exit(1);

    //
    // Make sure all the user records have a authAuthority record for us.
    //
    if (updateAuth == 1) {
        ldap_updateAuthority(force);
        exit(0);
    }

    init_client();

    if (sasl_server_init(callbacks, "PasswordServer") != SASL_OK) {
        printf("Failed to initialize SASL.\r\n");
        exit(1);
    }

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
    printf("Usage:\r\n");
    printf("\tlpws [-c config]\r\n");
    printf("\tlpws [-c config] -u [-f]\r\n");
    exit(-1);
}

