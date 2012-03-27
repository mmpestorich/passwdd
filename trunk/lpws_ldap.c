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
#include <ldap.h>


#define BIND_RETRIES	5

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

static lpws_attr global_attrs[] = {
    { "userPassword", SASL_AUX_PASSWORD },
    { "uidNumber", SASL_AUX_UIDNUM },
    { "gidNumber", SASL_AUX_GIDNUM },
    { "cn", SASL_AUX_FULLNAME },
    { "homeDirectory", SASL_AUX_HOMEDIR },
    { "loginShell", SASL_AUX_SHELL },
    { NULL, NULL }
};


//
// Find "rep" in "orig" and replace it with "with". You must free() the
// returned string if the result is non-NULL. Since "orig" might be returned
// unmodified, you should malloc() your orig string too.
// Reference: http://stackoverflow.com/questions/779875/what-is-the-function-to-replace-string-in-c
//
char *str_replace(char *orig, const char *rep, const char *with)
{
    char *result; // the return string
    char *ins;    // the next insert point
    char *tmp;    // varies
    int len_rep;  // length of rep
    int len_with; // length of with
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements


    //
    // Make sure we got a valid original string.
    //
    if (orig == NULL)
        return NULL;

    //
    // Make sure we got a valid needle.
    //
    if (rep == NULL || (len_rep = strlen(rep)) == 0)
        return NULL;

    //
    // If the needle is not found, just return the original string.
    //
    if ((ins = strstr(orig, rep)) == 0)
        return orig;

    //
    // If the string to replace with is NULL then assume empty string.
    //
    if (with == NULL)
        with = "";

    //
    // Get the length of the replacement string.
    //
    len_with = strlen(with);

    //
    // Count up the number of times we need to replace.
    //
    for (count = 0; (tmp = strstr(ins, rep)) != NULL; ++count) {
        ins = tmp + len_rep;
    }

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    //
    // Memory allocation failure?
    //
    if (!result)
        return NULL;

    //
    // Replace each occurrence of "rep" with "with".
    //
    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);

    return result;
}


//
// Do a lookup for the specified user's password, as well as a few extra
// attributes that might be useful to applications.
//
static void lpws_ldap_auxprop_lookup(void *glob_context,
                                     sasl_server_params_t *sparams,
                                     unsigned flags,
                                     const char *user,
                                     unsigned ulen)
{
    lpws_context *context = glob_context;
    int version = 3, result, i;
    LDAP *ldap = NULL;
    char *attrlist[32], *search, *s;
    LDAPMessage *ldapresults = NULL, *ldapresult = NULL;
    char **attrvalues;


    //
    // Initialize a new LDAP connection.
    //
    result = ldap_initialize(&ldap, context->uri);
    if (result != LDAP_SUCCESS) {
        printf("Connect failure.\r\n");
        return;
    }

    //
    // Set for version 3.
    //
    result = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_SUCCESS) {
        printf("Option failure.\r\n");
        ldap_unbind_s(ldap);

        return;
    }

    //
    // Try a few times to bind.
    //
    for (i = 0; i < BIND_RETRIES; i++) {
        result = ldap_simple_bind_s(ldap, context->binddn, context->bindpw);
        if (result == LDAP_SUCCESS)
            break;

        printf("Bind failure.\r\n");
        sleep(2);
    }
    if (i == BIND_RETRIES) {
        ldap_unbind_s(ldap);

        return;
    }

    //
    // Create the list of attributes we want.
    //
    for (i = 0; global_attrs[i].ldap != NULL; i++) {
        attrlist[i] = global_attrs[i].ldap;
    }
    attrlist[i] = NULL;

    //
    // Create the search filter. Use the following replacements:
    //
    search = malloc(strlen(context->search) + 1);
    strcpy(search, context->search);

    //
    // %u -> username
    //
    s = str_replace(search, "%u", user);
    if (s != search) {
        free(search);
        search = s;
    }

    //
    // Search for this user.
    //
    result = ldap_search_ext_s(ldap, context->basedn, LDAP_SCOPE_SUBTREE,
                               search, attrlist, 0, NULL, NULL, NULL,
                               1, &ldapresults);
    free(search);
    if (result != LDAP_SUCCESS) {
        ldap_unbind_s(ldap);

        return;
    }

    //
    // Select the first returned result or error out.
    //
    ldapresult = ldap_first_entry(ldap, ldapresults);
    if (ldapresult == NULL) {
        ldap_msgfree(ldapresults);
        ldap_unbind_s(ldap);
    }

    //
    // Process the retrieved attributes.
    //
    for (i = 0; global_attrs[i].ldap != NULL; i++) {
        attrvalues = ldap_get_values(ldap, ldapresult, global_attrs[i].ldap);
        if (attrvalues != NULL && attrvalues[0] != NULL) {
            sparams->utils->prop_erase(sparams->propctx, global_attrs[i].sasl);
            sparams->utils->prop_set(sparams->propctx, global_attrs[i].sasl,
                                     attrvalues[0], strlen(attrvalues[0]));
        }
    }

    //
    // Cleanup.
    //
    ldap_msgfree(ldapresults);
    ldap_unbind_s(ldap);
}


//
// Free memory used by this plugin.
//
static void lpws_ldap_auxprop_free(void *glob_context, const sasl_utils_t *utils)
{
    if (glob_context != NULL)
        utils->free(glob_context);
}


//
// The structure that defines this plugin.
//
static sasl_auxprop_plug_t lpws_ldap_auxprop_plugin = {
	0,
	0,
	NULL,
	lpws_ldap_auxprop_free,
	lpws_ldap_auxprop_lookup,
	"lpws_ldap",
	NULL
};


//
// Initialize the auxprop plugin for use.
//
static int lpws_ldap_auxprop_init(const sasl_utils_t *utils,
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
    // Get the URI property.
    //
    utils->getopt(utils->getopt_context, "lpws_ldap", "uri", &context->uri, NULL);
    if (context->uri == NULL)
        context->uri = "ldap://127.0.0.1";

    //
    // Get the basedn property.
    //
    utils->getopt(utils->getopt_context, "lpws_ldap", "basedn", &context->basedn, NULL);
    if (context->basedn == NULL) {
        utils->free(context);

        return SASL_BADPARAM;
    }

    //
    // Get the search property.
    //
    utils->getopt(utils->getopt_context, "lpws_ldap", "search", &context->search, NULL);
    if (context->search == NULL)
        context->search = "uid=%u";

    //
    // Get the binddn property.
    //
    utils->getopt(utils->getopt_context, "lpws_ldap", "binddn", &context->binddn, NULL);
    if (context->binddn == NULL) {
        utils->free(context);

        return SASL_BADPARAM;
    }

    //
    // Get the bindpw property.
    //
    utils->getopt(utils->getopt_context, "lpws_ldap", "bindpw", &context->bindpw, NULL);
    if (context->bindpw == NULL) {
        utils->free(context);

        return SASL_BADPARAM;
    }

    //
    // Register us with the plugin system.
    //
    *out_version = SASL_AUXPROP_PLUG_VERSION;
    lpws_ldap_auxprop_plugin.glob_context = context;
    *plug = &lpws_ldap_auxprop_plugin;

    return SASL_OK;
}


//
// Temporary.
//
int init_auxprop()
{
    return sasl_auxprop_add_plugin("lpws_ldap", lpws_ldap_auxprop_init);
}


