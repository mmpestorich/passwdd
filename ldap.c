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
#include <ldap.h>
#include <lber.h>
#include "ldap.h"
#include "keys.h"
#include "config.h"
#include "utils.h"
#include "common.h"


#define BIND_RETRIES	5


//
// Create a new connection to the LDAP server, optionally bind to the
// server using the configured credentials.
//
LDAP *ldap_connect(int bind)
{
    struct berval	cred;
    const char		*uri, *binddn = NULL, *bindpw = NULL;
    LDAP		*ldap = NULL;
    int			i, version = 3, result;


    //
    // Get the config options we need to connect to the LDAP server.
    //
    uri = find_config("ldap_uri");
    if (uri == NULL)
        return NULL;

    //
    // Get the config options we need to bind to the LDAP server.
    //
    if (bind) {
        binddn = find_config("ldap_binddn");
        bindpw = find_config("ldap_bindpw");
        if (binddn == NULL || bindpw == NULL)
            return NULL;
    }

    //
    // Connect to the LDAP server.
    //
    if (ldap_initialize(&ldap, uri) != LDAP_SUCCESS)
        return NULL;

    //
    // Set protocol version 3.
    //
    if (ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
        ldap_unbind_ext_s(ldap, NULL, NULL);
        return NULL;
    }

    //
    // Try to bind if requested.
    //
    if (bind) {
        cred.bv_val = malloc(strlen(bindpw) + 1);
        strcpy(cred.bv_val, bindpw);
        cred.bv_len = strlen(bindpw);
        for (i = 0; i < BIND_RETRIES; i++) {
            result = ldap_sasl_bind_s(ldap, binddn, LDAP_SASL_SIMPLE,
                                      &cred, NULL, NULL, NULL);
            if (result == LDAP_SUCCESS)
                break;

            printf("Failed to bind to LDAP server, error = %d\r\n", result);
            sleep(2);
        }
        free(cred.bv_val);

        //
        // Check for failure to bind.
        //
        if (i == BIND_RETRIES) {
            ldap_unbind_ext_s(ldap, NULL, NULL);
            return NULL;
        }
    }

    return ldap;
}


//
// Disconnect from the LDAP server.
//
void ldap_disconnect(LDAP *ldap)
{
    if (ldap != NULL)
        ldap_unbind_ext_s(ldap, NULL, NULL);
}


//
// Retrieve a list of replica servers from the LDAP directory. The returned
// string is in XML format and should be free'd by the caller.
//
char *ldap_replicalist()
{
    struct berval	**attrvalues;
    LDAPMessage		*ldapresults = NULL, *ldapresult = NULL;
    const char		*basedn;
    char 		*xml = NULL, *attrlist[2];
    LDAP		*ldap = NULL;
    int			result;


    //
    // Get the config options we need to search the LDAP server.
    //
    basedn = find_config("ldap_basedn");
    if (basedn == NULL)
        return NULL;

    //
    // Get an LDAP connection.
    //
    if ((ldap = ldap_connect(0)) == NULL)
        return NULL;

    //
    // We want only a single attribute.
    //
    attrlist[0] = "apple-password-server-list";
    attrlist[1] = NULL;

    //
    // Search the LDAP database for the cn=passwordserver record.
    //
    result = ldap_search_ext_s(ldap, basedn, LDAP_SCOPE_SUBTREE,
                               "cn=passwordserver", attrlist, 0,
                               NULL, NULL, NULL, 1, &ldapresults);
    if (result != LDAP_SUCCESS) {
        ldap_disconnect(ldap);
        return NULL;
    }

    //
    // Get the first entry. If no results were found this will return NULL.
    //
    if ((ldapresult = ldap_first_entry(ldap, ldapresults)) == NULL) {
        ldap_msgfree(ldapresults);
        ldap_disconnect(ldap);

        return NULL;
    }

    //
    // Try to retrieve the results from the search.
    //
    attrvalues = ldap_get_values_len(ldap, ldapresult, "apple-password-server-list");
    if (attrvalues == NULL || attrvalues[0] == NULL) {
        ldap_msgfree(ldapresults);
        ldap_disconnect(ldap);

        return NULL;
    }

    //
    // Allocate enough space for the result string and store it.
    //
    xml = (char *)malloc(attrvalues[0]->bv_len + 1);
    memcpy(xml, attrvalues[0]->bv_val, attrvalues[0]->bv_len);
    xml[attrvalues[0]->bv_len] = '\0';

    //
    // Close the LDAP connection.
    //
    ldap_msgfree(ldapresults);
    ldap_disconnect(ldap);

    return xml;
}


//
// Search the LDAP directory for any records that need an authAuthority
// attribute. If the force parameter is set then all records that have
// an authAuthority attribute will be deleted and updated.
//
// Returns 0 on success or a negative number to indicate a fatal error
// that prevented us from doing anything. A positive number is returned
// to indicate how many records had errors of some kind.
//
int ldap_updateAuthority(int force)
{
    struct berval	**attrvalues;
    LDAPMessage		*ldapresults = NULL, *ldapresult = NULL;
    const char		*basedn, *query;
    LDAPMod		modOp, *modUser[2] = { &modOp, NULL };
    char 		*attrlist[4], *dn, *authAuthority, *uid,
			*userPassword, *modValues[2];
    LDAP		*ldap = NULL;
    int			result, errors = 0, len;


    //
    // Get the config options we need to search the LDAP server.
    //
    basedn = find_config("ldap_basedn");
    if (basedn == NULL) {
#ifdef DEBUG
        printf("No search base configured.\r\n");
#endif
        return -1;
    }

    //
    // Get an LDAP connection.
    //
    if ((ldap = ldap_connect(1)) == NULL) {
#ifdef DEBUG
        printf("Could not connect to LDAP server.\r\n");
#endif
        return -1;
    }

    //
    // We want only a single attribute.
    //
    attrlist[0] = "uid";
    attrlist[1] = "userPassword";
    attrlist[2] = NULL;
    attrlist[3] = NULL;

    //
    // If we are forcing an update then just search for any person record,
    // otherwise search for any person record that does not have a authAuthority.
    //
    if (force)
        query = "(&(objectClass=person)(uid=*))";
    else
        query = "(&(objectClass=person)(uid=*)(!(authAuthority=*)))";

    //
    // Search the LDAP database for the wanted records.
    // Only take the first 1,000 records. If you have more, uhh, too bad?
    //
    result = ldap_search_ext_s(ldap, basedn, LDAP_SCOPE_SUBTREE,
                               query, attrlist, 0,
                               NULL, NULL, NULL, 1000, &ldapresults);
    if (result != LDAP_SUCCESS) {
#ifdef DEBUG
        printf("LDAP search request failed: %s.\r\n", ldap_err2string(result));
#endif
        ldap_disconnect(ldap);
        return -1;
    }

    //
    // Go through each returned person record and process it accordingly.
    //
    for (ldapresult = ldap_first_entry(ldap, ldapresults);
         ldapresult != NULL;
         ldapresult = ldap_next_entry(ldap, ldapresult)) {
        //
        // Mark the fields as unknown to begin with.
        //
        uid = NULL;
        userPassword = NULL;

        dn = ldap_get_dn(ldap, ldapresult);
#ifdef DEBUG
        printf("Processing record %s\r\n", (dn ? dn : ""));
#endif

        //
        // Retrieve the first uid attribute.
        //
        attrvalues = ldap_get_values_len(ldap, ldapresult, "uid");
        if (attrvalues != NULL && attrvalues[0] != NULL) {
            uid = malloc(attrvalues[0]->bv_len + 1);
            memcpy(uid, attrvalues[0]->bv_val, attrvalues[0]->bv_len);
            uid[attrvalues[0]->bv_len] = '\0';
        }

        //
        // Retrieve the first userPassword attribute.
        //
        attrvalues = ldap_get_values_len(ldap, ldapresult, "userPassword");
        if (attrvalues != NULL && attrvalues[0] != NULL) {
            userPassword = malloc(attrvalues[0]->bv_len + 1);
            memcpy(userPassword, attrvalues[0]->bv_val, attrvalues[0]->bv_len);
            userPassword[attrvalues[0]->bv_len] = '\0';
        }

        //
        // Check for missing values.
        //
        if (uid == NULL || userPassword == NULL) {
#ifdef DEBUG
            printf("Record %s has either no uid or no userPassword attribute.\r\n", dn);
#endif
            ldap_memfree(dn);
            free(uid);
            free(userPassword);
            errors += 1;

            continue;
        }

        //
        // Perform a security check on the userPassword, make sure it hasn't
        // been tampered with by WGM.
        //
        if (strcmp(userPassword, "********") == 0) {
#ifdef DEBUG
            printf("Record %s has an invalid password.\r\n", dn);
#endif
            ldap_memfree(dn);
            free(uid);
            free(userPassword);
            errors += 1;
            printf("Security Warning: User %s's password has been set to '********' by Workgroup Manager.\r\n", uid);

            continue;
        }

        //
        // Generate a proper authAuthority and set it.
        //
        len = strlen(publicKeyThumbprint) + strlen(uid) + 64;
        authAuthority = malloc(len);
        snprintf(authAuthority, len, ";ApplePasswordServer;%s,%s:%s",
                 uid, publicKeyThumbprint, myAddress);

        //
        // Run an LDAP modification request to remove any existing
        // authAuthority attribute if we are in force mode.
        //
        result = LDAP_SUCCESS;
        if (force) {
            modOp.mod_op = LDAP_MOD_DELETE;
            modOp.mod_type = "authAuthority";
            modOp.mod_values = NULL;
            result = ldap_modify_ext_s(ldap, dn, modUser, NULL, NULL);
            if (result != LDAP_SUCCESS && result != LDAP_NO_SUCH_ATTRIBUTE) {
#ifdef DEBUG
                printf("Could not remove authAuthority attribute for record %s: %s.\r\n",
                       dn, ldap_err2string(result));
#endif
                errors += 1;
            }
        }

        //
        // Run an LDAP modifiction request to add the new attribute.
        //
        if (result == LDAP_SUCCESS || result == LDAP_NO_SUCH_ATTRIBUTE) {
            modOp.mod_op = LDAP_MOD_ADD;
            modOp.mod_type = "authAuthority";
            modOp.mod_values = modValues;
            modValues[0] = authAuthority;
            modValues[1] = NULL;
            result = ldap_modify_ext_s(ldap, dn, modUser, NULL, NULL);
            if (result != LDAP_SUCCESS) {
#ifdef DEBUG
                printf("Failed to add authAuthority attribute for record %s: %s.\r\n",
                       dn, ldap_err2string(result));
#endif
                errors += 1;
            }
        }

        //
        // Free up memory used by this iteration.
        //
        ldap_memfree(dn);
        free(authAuthority);
        free(uid);
        free(userPassword);
    }

    //
    // Close the LDAP connection.
    //
    ldap_msgfree(ldapresults);
    ldap_disconnect(ldap);

    return errors;
//";ApplePasswordServer;<uid>,<public thumbprint>:<myipaddress>"
}


