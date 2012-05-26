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
#include <stdlib.h>
#include <unistd.h>
#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <sasl/saslutil.h>


typedef struct {
    const char *uri;
    const char *binddn;
    const char *bindpw;
    const char *basedn;
    const char *search;
} lpws_context;

typedef struct {
    char *ldap;
    char *sasl;
} lpws_attr;



//
// Do a lookup for the specified user's password, as well as a few extra
// attributes that might be useful to applications.
//
static void lpws_auxprop_lookup(void *glob_context,
                                sasl_server_params_t *sparams,
                                unsigned flags,
                                const char *user,
                                unsigned ulen)
{
    lpws_context *context = glob_context;
    const struct propval *values = sparams->utils->prop_get(sparams->propctx);
    int i;


    //
    // Check if we already have a password.
    //
    for (i = 0; values[i].name != NULL; i++) {
        if (strcmp(values[i].name, SASL_AUX_PASSWORD) != 0)
            continue;

        //
        // Check for no password found yet.
        //
        if (values[i].values == NULL || values[i].values[0] == NULL)
            break;

        //
        // Check if the existing password is ********.
        //
        if (strcmp(values[i].values[0], "********") == 0) {
            sparams->utils->prop_erase(sparams->propctx, SASL_AUX_PASSWORD);
            break;
        }

        //
        // We found an existing cleartext password, let it ride.
        //
        return;
    }

    //
    // If we get here then either no SASL_AUX_PASSWORD property has been
    // found yet or it was invalid, so we need to do our own lookup.
    //
//    sparams->utils->prop_erase(sparams->propctx, SASL_AUX_PASSWORD);
//    sparams->utils->prop_set(sparams->propctx, SASL_AUX_PASSWORD, "test", 4);
}


//
// Free memory used by this plugin.
//
static void lpws_auxprop_free(void *glob_context, const sasl_utils_t *utils)
{
    if (glob_context != NULL)
        utils->free(glob_context);
}


//
// The structure that defines this plugin.
//
static sasl_auxprop_plug_t lpws_auxprop_plugin = {
	0,
	0,
	NULL,
	lpws_auxprop_free,
	lpws_auxprop_lookup,
	"lpws",
	NULL
};


//
// Initialize the auxprop plugin for use.
//
static int lpws_auxprop_init(const sasl_utils_t *utils,
                             int max_version,
                             int *out_version,
                             sasl_auxprop_plug_t **plug,
                             const char *plugname)
{
    lpws_context *context;


    //
    // Allocate the context buffer.
    //
    context = utils->malloc(sizeof(lpws_context));
    if (context == NULL)
        return SASL_NOMEM;

    //
    // Register us with the plugin system.
    //
    *out_version = SASL_AUXPROP_PLUG_VERSION;
    lpws_auxprop_plugin.glob_context = context;
    *plug = &lpws_auxprop_plugin;

    return SASL_OK;
}


int sasl_auxprop_plug_init(const sasl_utils_t *utils, int maxversion, int *out_version, sasl_auxprop_plug_t **plug, const char *plugname)
{
    return lpws_auxprop_init(utils, maxversion, out_version, plug, plugname);
}

