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
#include <ldap.h>
#include <lber.h>
#include "ldap.h"
#include "keys.h"
#include "config.h"


//
// Retrieve a list of replica servers from the LDAP directory. The returned
// string is in XML format and should be free'd by the caller.
//
char *ldap_replicalist()
{
    struct berval	**attrvalues;
    LDAPMessage		*ldapresults = NULL, *ldapresult = NULL;
    const char		*basedn, *uri;
    char 		*xml = NULL, *attrlist[2];
    LDAP		*ldap = NULL;
    int			result, version = 3;


    //
    // Get the config options we need to connect to the LDAP server.
    //
    basedn = find_config("ldap_basedn");
    uri = find_config("ldap_uri");
    if (basedn == NULL || uri == NULL)
	return NULL;

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
        ldap_unbind_ext_s(ldap, NULL, NULL);
        return NULL;
    }

    //
    // Get the first entry. If no results were found this will return NULL.
    //
    if ((ldapresult = ldap_first_entry(ldap, ldapresults)) == NULL) {
        ldap_msgfree(ldapresults);
        ldap_unbind_ext_s(ldap, NULL, NULL);

        return NULL;
    }

    //
    // Try to retrieve the results from the search.
    //
    attrvalues = ldap_get_values_len(ldap, ldapresult, "apple-password-server-list");
    if (attrvalues == NULL || attrvalues[0] == NULL) {
        ldap_msgfree(ldapresults);
        ldap_unbind_ext_s(ldap, NULL, NULL);

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
    ldap_unbind_ext_s(ldap, NULL, NULL);

    return xml;
}


//
// Search the LDAP directory for any records that need an authAuthority
// attribute. If the force parameter is set then all records that have
// an authAuthority attribute will be deleted and updated.
//
int ldap_updateAuthority(int force)
{
//";ApplePasswordServer;<uid>,<public thumbprint>:<myipaddress>"
}


