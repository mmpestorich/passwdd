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
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include "commands.h"
#include "utils.h"
#include "keys.h"


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
    char *e, *m;
                

    e = BN_bn2dec(privateKey->e);
    m = BN_bn2dec(privateKey->n);

    buffercatf(response, "+OK %d %s %s %s\r\n",
               BN_num_bits(privateKey->d),
               e, m, "root@daniel.hdcnet.org");

    OPENSSL_free(m);
    OPENSSL_free(e);

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
// Store the username to be used for this connection.
//
int command_user(char *response, int argc, char *argv[], Client *client, void *context)
{
    int result = 0;


    //
    // Check for the required number of arguments.
    //
    if (argc < 2) {
        buffercatf(response, "-ERR Must specify user\r\n");

        return 0;
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
        hexToBinary(argv[1], data, &dataLen);
        args++;
    }

    //
    // Begin a the SASL authentication for the client.
    //
    result = sasl_server_start(client->sasl,
                               argv[1],
                               (char *)data, dataLen,
                               &out, &outlen);

    //
    // If result is SASL_OK then we are finished.
    //
    if (result == SASL_OK) {
        buffercatf(response, "+OK\r\n");

        return args;
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


