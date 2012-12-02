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
#include "pwdb.h"
#include "common.h"


//
// Do a lookup for the specified user's password, as well as a few extra
// attributes that might be useful to applications.
//
static void lpws_internal_auxprop_lookup(void *glob_context,
                                         sasl_server_params_t *sparams,
                                         unsigned flags,
                                         const char *user,
                                         unsigned ulen)
{
    char	password[PASSWORD_MAX + 1];


    if (pwdb_getpassword(user, password, sizeof(password)) == 0) {
	sparams->utils->prop_erase(sparams->propctx,
				SASL_AUX_PASSWORD);
	sparams->utils->prop_set(sparams->propctx, SASL_AUX_PASSWORD,
				password, strlen(password));
        memset(password, 0, sizeof(password));
    }
}


//
// Free memory used by this plugin.
//
static void lpws_internal_auxprop_free(void *glob_context, const sasl_utils_t *utils)
{
}


//
// The structure that defines this plugin.
//
static sasl_auxprop_plug_t lpws_internal_auxprop_plugin = {
	0,
	0,
	NULL,
	lpws_internal_auxprop_free,
	lpws_internal_auxprop_lookup,
	"lpws_internal",
	NULL
};


//
// Initialize the auxprop plugin for use.
//
int lpws_internal_auxprop_init(const sasl_utils_t *utils,
                               int max_version,
                               int *out_version,
                               sasl_auxprop_plug_t **plug,
                               const char *plugname)
{
    //
    // Register us with the plugin system.
    //
    *out_version = SASL_AUXPROP_PLUG_VERSION;
    *plug = &lpws_internal_auxprop_plugin;

    return SASL_OK;
}
