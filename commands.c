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
#include <stdint.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <limits.h>
#include <openssl/rsa.h>
#include "commands.h"
#include "utils.h"
#include "keys.h"
#include "ldap.h"


//
// Command functions take 5 arguments:
// char *response - The response string that will be sent to the client, this
//                  string should be appended to if the function needs to
//                  send data back to the client.
// int argc - The number of arguments available in argv.
// char *argv[] - The arguments available.
// Client *client - Pointer to the Client object for this connection.
// void *context - User specific information, normally NULL.
//
// Each function returns a negative value if the connection should be
// closed. Otherwise the return value is the number of additional arguments
// that were consumed. i.e. "USER jason" handler would return 1 to note the
// extra argument that was used.
//
//
// Build the table of client commands we support.
//
ClientCommand clientCommands[] = {
    { "LIST",           command_list },
    { "RSAPUBLIC",      command_rsapublic },
    { "RSAVALIDATE",    command_rsavalidate },
    { "LISTREPLICAS",   command_listreplicas },

    { "NEWUSER",        command_newuser },
    { "DELETEUSER",     command_deleteuser },
    { "CHANGEPASS",     command_changepass },
    { "USER",           command_user },
    { "AUTH",           command_auth },
    { "AUTH2",          command_auth2 },

    { "QUIT",           command_quit },
    { NULL,             NULL }
};



//
// List the supported authentication mechanisms by this server.
//
int command_list(char *response, int argc, char *argv[], Client *client, void *context)
{
    buffercatf(response, "+OK %s\r\n", SUPPORTED_MECHS);

    return 0;
}


//
// Retrieve the RSA Public key information for this server.
//
int command_rsapublic(char *response, int argc, char *argv[], Client *client, void *context)
{
    buffercatf(response, "+OK %s\r\n", publicKeyThumbprint);

    return 0;
}


//
// Used by the client to make 100% sure it is talking to the right
// server. It sends us a value encrypted with our public key and then
// we decrypt it and send it back to the client for it to validate.
//
int command_rsavalidate(char *response, int argc, char *argv[], Client *client, void *context)
{
    char encoded[BUFFER_SIZE], data[BUFFER_SIZE];
    int encodedLen;
    unsigned long len;


    //
    // Verify we have the required number of arguments.
    //
    if (argc < 2) {
        buffercatf(response, "-ERR Must specify value\r\n");

        return 0;
    }

    //
    // Convert the Base64 encoded value to raw data so we can
    // try to descrypt it.
    //
    if (base64ToBinary(argv[1], encoded, &encodedLen) != SASL_OK) {
        buffercatf(response, "-ERR SASL Error\r\n");

        return 1;
    }

    //
    // Decrypt the data into cleartext.
    //
    len = RSA_private_decrypt(encodedLen,
                              (unsigned char *)encoded,
                              (unsigned char *)data,
                              privateKey, RSA_PKCS1_PADDING);

    //
    // Check for a decryption error.
    //
    if (len <= 0) {
        buffercatf(response, "-ERR RSA Error\r\n");

        return 1;
    }

    //
    // Convert the raw data into base64 so we can send it back to
    // the client.
    //
    if (binaryToBase64(data, len, encoded) != SASL_OK) {
        buffercatf(response, "-ERR SASL Error\r\n");

        return 1;
    }

    //
    // Add the response.
    //
    buffercatf(response, "+OK %s\r\n", encoded);

    return 1;
}


//
// Retrieve a list of replica servers. This is an exact duplicate of the data
// in the directory's "apple-password-server-list" key.
//
int command_listreplicas(char *response, int argc, char *argv[], Client *client, void *context)
{
    char *xml = ldap_replicalist();


    //
    // The ApplePasswordServer does not include an extra \r\n, which seems wrong
    // to me, but when I include an extra \r\n things go bad.  So maybe it just
    // checks if there is a "final" \r\n and adds it if there isn't, I don't know
    // just yet.
    //
    // Suddenly things are not working if I don't include the \r\n.  Will have to
    // study further.
    //
    buffercatf(response, "+OK %d %s\r\n", strlen(xml), xml);

    return 0;
}


//
// Create a new user and password, this is only used when creating
// OpenDirectory passwords, which we do not support yet.
//
int command_newuser(char *response, int argc, char *argv[], Client *client, void *context)
{
//    const char	*decoded = NULL;
//    unsigned	decodedLen = 0;
//    char	encoded[BUFFER_SIZE];
//    int		encodedLen;


    //
    // Verify we have the required number of arguments.
    //
    if (argc < 3) {
        buffercatf(response, "-ERR Must specify value\r\n");

        return (argc - 1);
    }

//    //
//    // Convert the Base64 encoded value to raw data so we can
//    // try to decrypt it.
//    //
//    if (base64ToBinary(argv[2], encoded, &encodedLen) != SASL_OK) {
//        buffercatf(response, "-ERR SASL Error\r\n");
//
//        return 2;
//    }
//
//    //
//    // Decode the password.
//    //
//    sasl_decode(client->sasl, encoded, encodedLen, &decoded, &decodedLen);
//    printf("password = %s\r\n", decoded);
//
//    //
//    // Add the response. The return argument is the "slot id", which for us
//    // right now is just the username.
//    //
//    buffercatf(response, "+OK %s\r\n", argv[1]);
    buffercatf(response, "-ERR Unsupported\r\n");

    return 2;
}


//
// Delete the user from the database. Right now this is a no-op.
//
int command_deleteuser(char *response, int argc, char *argv[], Client *client, void *context)
{
    buffercatf(response, "+OK\r\n");

    return 1;
}


//
// Change a user's password. Right now this is a no-op.
//
int command_changepass(char *response, int argc, char *argv[], Client *client, void *context)
{
    buffercatf(response, "+OK\r\n");

    return 2;
}


//
// Store the username to be used for this connection.
//
int command_user(char *response, int argc, char *argv[], Client *client, void *context)
{
    sasl_security_properties_t secprops;
    int result = 0;


    //
    // Check for the required number of arguments.
    //
    if (argc < 2) {
        buffercatf(response, "-ERR Must specify user\r\n");

        return 0;
    }

    //
    // Initialize the SASL connection.
    //
    result = sasl_server_new("rcmd", NULL, NULL, NULL, NULL, NULL, 0, &client->sasl);
    if (result != SASL_OK) {
        buffercatf(response, "-ERR SASL Error %d\r\n", result);

        return 1;
    }

    //
    // Set the SSF security properties.
    //
    memset(&secprops, 0L, sizeof(secprops));
    secprops.maxbufsize = 2048;
    secprops.max_ssf = UINT_MAX;
    result = sasl_setprop(client->sasl, SASL_SEC_PROPS, &secprops);
    if (result != SASL_OK) {
        buffercatf(response, "-ERR SASL Error %d\r\n", result);

        return 1;
    }

    //
    // Save the username for later use.
    //
    strncpy(client->username, argv[1], sizeof(client->username));
    client->username[sizeof(client->username) - 1] = '\0';

    //
    // If they also sent an AUTH command, process it special.
    //
    if (argc >= 3 && strcasecmp(argv[2], "AUTH") == 0) {
        result = command_auth(response, argc - 2, &argv[2], client, (void *)1);
        if (result < 0)
            return result;

        result += 1;
    }
    else
        buffercatf(response, "+OK %s\r\n", SUPPORTED_MECHS);

    return 1 + result;
}


//
// Begin authentication of the specified user.
//
int command_auth(char *response, int argc, char *argv[], Client *client, void *context)
{
    unsigned char data[BUFFER_SIZE];
    const char *out;
    unsigned outlen;
    int result, args = 0, dataLen = 0;


    //
    // Check for the required number of arguments.
    //
    if (argc < 2) {
        buffercatf(response, "-ERR Invalid mechanism\r\n");

        return 0;
    }
    args++;

    //
    // Verify we are doing things in the correct order.
    //
    if (strlen(client->username) == 0) {
        buffercatf(response, "-ERR Must specify user first\r\n");

        return args;
    }

    //
    // Convert hex data to binary.
    //
    if (argc >= 3) {
        if (argc >= 4 && strcmp(argv[2], "replay") == 0) {
            //
            // Special case handling for WEBDAV-DIGEST.
            //
            hexToBinary(argv[3], data, &dataLen);
            args += 2;
        }
        else {
            hexToBinary(argv[2], data, &dataLen);
            args++;
        }
    }

    //
    // Begin a the SASL authentication for the client.
    //
    result = sasl_server_start(client->sasl,
                               argv[1],
                               (char *)data, dataLen,
                               &out, &outlen);

    //
    // If SASL_CONTINUE then we need to send some data to the client
    // so that it can continue the process.
    //
    if (result == SASL_CONTINUE || result == SASL_OK) {
        if (out != NULL && outlen != 0) {
            char hex[BUFFER_SIZE];

            binaryToHex((unsigned char *)out, outlen, hex);
            if ((long)context == 1)
                buffercatf(response, "+AUTHOK %s\r\n", hex);
            else
                buffercatf(response, "+OK %s\r\n", hex);
        }
        else {
            if ((long)context == 1)
                buffercatf(response, "+AUTHOK\r\n");
            else
                buffercatf(response, "+OK\r\n");
        }

        if (result == SASL_OK)
            printf("Authenticated user %s using %s\r\n", client->username, argv[1]);

        return args;
    }

    //
    // If result is SASL_OK then we are finished.
    //
    if (result == SASL_OK) {
        return args;
    }

    //
    // Generic error.
    //
    buffercatf(response, "-ERR SASL %d\r\n", result);

    return args;
}


//
// Continue authentication of the specified user.
//
int command_auth2(char *response, int argc, char *argv[], Client *client, void *context)
{
    const char *out;
    unsigned char data[BUFFER_SIZE];
    int dataLen = 0;
    unsigned outlen;
    int result;


    //
    // Check for the required number of arguments.
    //
    if (argc < 2) {
        buffercatf(response, "-ERR Invalid argument list\r\n");

        return 0;
    }

    //
    // Verify we are doing things in the correct order.
    //
    if (strlen(client->username) == 0) {
        buffercatf(response, "-ERR Must specify user first\r\n");

        return 1;
    }

    //
    // Convert hex data to binary.
    //
    hexToBinary(argv[1], data, &dataLen);

    //
    // Continue the SASL authentication for the client.
    //
    result = sasl_server_step(client->sasl,
                               (char *)data, dataLen,
                               &out, &outlen);

    //
    // If result is SASL_OK then we are finished.
    //
    if (result == SASL_OK) {
        printf("Authenticated user %s.\r\n", client->username);
        buffercatf(response, "+OK\r\n");

        return 1;
    }

    //
    // If SASL_CONTINUE then we need to send some data to the client
    // so that it can continue the process.
    //
    if (result == SASL_CONTINUE) {
        char hex[BUFFER_SIZE];

        binaryToHex((unsigned char *)out, outlen, hex);
        if ((long)context == 1)
            buffercatf(response, "+AUTHOK %s\r\n", hex);
        else
            buffercatf(response, "+OK %s\r\n", hex);

        return 1;
    }

    //
    // Generic error.
    //
    buffercatf(response, "-ERR SASL %d\r\n", result);

    return 1;
}


//
// Client is done and wants to disconnect.
//
int command_quit(char *response, int argc, char *argv[], Client *client, void *context)
{
    buffercatf(response, "+OK password server signing off.\r\n");

    return -1;
}


