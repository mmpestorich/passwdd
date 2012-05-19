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
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "keys.h"
#include "config.h"
#include "utils.h"


RSA *privateKey = NULL;
const char *publicKeyThumbprint = NULL;


//
// Load all necessary keys, right now this is just the privateKey.
//
int loadKeys()
{
    const char	*keyfile;
    FILE	*fp;
    char	*e, *m;
    int		len;


    //
    // Allow the user to override the private key location, otherwise use
    // the standard of /etc/lpws.key.
    //
    keyfile = find_config("private_key");
    if (keyfile == NULL)
        keyfile = "/etc/lpws.key";

    //
    // Try to open the key file.
    //
    fp = fopen(keyfile, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to find private key file '%s'\r\n", keyfile);
        return -1;
    }

    //
    // Process the private key.
    //
    privateKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    //
    // Check if the key was valid.
    //
    if (privateKey == NULL) {
        fprintf(stderr, "Invalid private key file '%s'\r\n", keyfile);
        return -1;
    }

    //
    // Calculate the public key thumbprint.
    //
    e = BN_bn2dec(privateKey->e);
    m = BN_bn2dec(privateKey->n);
    if (BN_num_bits(privateKey->n) > 8192) {
        fprintf(stderr, "Your private key is larger than 8,192 bits. Think about it.\r\n");
        return -1;
    }

    //
    // Allocate space for the string and store it.
    //
    len = (5 + strlen(e) + 1 + strlen(m) + 1 + 5 + strlen(myHostname) + 1);
    publicKeyThumbprint = (const char *)malloc(len);
    snprintf((char *)publicKeyThumbprint, len, "%d %s %s root@%s",
             BN_num_bits(privateKey->n), e, m, myHostname);

    //
    // Free temporary memory used by the SSL library.
    //
    OPENSSL_free(m);
    OPENSSL_free(e);

    return 0;
}           
