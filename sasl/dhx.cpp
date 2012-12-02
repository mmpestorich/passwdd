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

#ifdef __cplusplus
 extern "C" {
#endif

#include <config.h>
#include <stdio.h>
#include <string.h> 
#include <sasl.h>
#include <saslplug.h>

#include "plugin_common.h"

#ifdef macintosh 
#include <sasl_plain_plugin_decl.h> 
#endif 

#include <openssl/cast.h>

#ifdef __cplusplus
 }
#endif

#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
using CryptoPP::Integer;

#ifdef __cplusplus
 extern "C" {
#endif

/*****************************  Server Section  *****************************/

//
// Define the information used by the server during operation.
//
typedef struct server_context {
    int		step;
    Integer	*g, *p;
    Integer	*privateKey, *nonce;
    char	username[129];
    byte	sharedKey[16], outBuffer[2048];
    byte	decryptiv[8], encryptiv[8];
} server_context_t;

//
// This is the prime key for the DHX exchange.
//
static byte primeKey[128] = {
    0xd9, 0xc8, 0xff, 0xb9, 0x1d, 0xff, 0x2f, 0x94,
    0xbf, 0xd2, 0xbe, 0x97, 0x42, 0xde, 0xea, 0xbb,
    0x8b, 0x71, 0xc0, 0x51, 0xe3, 0x1e, 0x39, 0x76,
    0xb9, 0x72, 0xb4, 0x14, 0x90, 0x5b, 0x1e, 0x76,
    0x88, 0xd3, 0x71, 0x3d, 0x5f, 0x8f, 0xb3, 0xbd,
    0x37, 0x32, 0x3f, 0xa1, 0x68, 0xa5, 0xea, 0x54,
    0xe4, 0xcd, 0xb7, 0x30, 0x8b, 0x3f, 0x2e, 0xff,
    0x43, 0x7c, 0x66, 0xcb, 0xac, 0x0a, 0xb8, 0x1c,
    0xcc, 0x49, 0xf3, 0xb2, 0x97, 0x1c, 0x2c, 0x1d,
    0x06, 0x00, 0xdb, 0x47, 0x9f, 0xb9, 0x7e, 0xcf,
    0x4e, 0x71, 0x07, 0xe2, 0x52, 0xc3, 0x43, 0xb4,
    0xef, 0x21, 0xf1, 0x5f, 0xf7, 0x13, 0x87, 0x69,
    0x29, 0x28, 0xa1, 0xec, 0x38, 0xc1, 0xe3, 0xf9,
    0x20, 0x0b, 0x9d, 0x2b, 0xea, 0xfb, 0xff, 0x07,
    0xc6, 0x23, 0x99, 0x48, 0xdb, 0xc2, 0xc4, 0x03,
    0xbf, 0x98, 0x65, 0xf9, 0x77, 0xef, 0x35, 0x87
};


//
// Initialize a new server mechanism for authenticating a user.
//
static int dhx_server_mech_new(void *glob_context __attribute__((unused)), 
                               sasl_server_params_t *sparams,
                               const char *challenge __attribute__((unused)),
                               unsigned challen __attribute__((unused)),
                               void **conn_context)
{
    server_context_t	*ctx;
    byte		randdata[128];
    int			i;


    //
    // Make sure we have somewhere to store our context data.
    //
    if (!conn_context) {
	PARAMERROR(sparams->utils);
	return SASL_BADPARAM;
    }

    //
    // Allocate memory to hold our context.
    //
    ctx = (server_context_t *)sparams->utils->malloc(sizeof(server_context_t));
    memset(ctx, 0, sizeof(server_context_t));

    //
    // Initialize the shared prime and base.
    //
    ctx->g = new Integer(7);
    ctx->p = new Integer(primeKey, sizeof(primeKey), Integer::UNSIGNED);

    //
    // Generate some random data for the nonce.
    //
    srandom(time(NULL));
    for (i = 0; i < 16; i++) {
        randdata[i] = (byte)random();
    }
    ctx->nonce = new Integer(randdata, 16, Integer::UNSIGNED);
    memset(randdata, 0, 16);

    //
    // Generate some random data for the private key.
    //
    srandom(time(NULL));
    for (i = 0; i < 128; i++) {
        randdata[i] = (byte)random();
    }
    ctx->privateKey = new Integer(randdata, 128, Integer::UNSIGNED);
    memset(randdata, 0, 128);

    //
    // Save the context for later use.
    //
    ctx->step = 1;
    *conn_context = (void *)ctx;    

    return SASL_OK;
}


//
// Free all the memory this context used.
//
static void dhx_server_dispose(void *conn_context,
                               const sasl_utils_t *utils)
{
    server_context_t *ctx = (server_context_t *)conn_context;

    if (ctx == NULL)
        return;

    if (ctx->g)
        delete ctx->g;
    if (ctx->p)
        delete ctx->p;
    if (ctx->nonce)
        delete ctx->nonce;
    if (ctx->privateKey != NULL)
        delete ctx->privateKey;
    memset(ctx->sharedKey, 0, sizeof(ctx->sharedKey));

    utils->free(ctx);
}


static int dhx_server_decode(void *conn_context,
                             const char *input,
                             unsigned int inputlen,
                             const char **output,
                             unsigned int *outputlen)
{
    server_context_t	*ctx = (server_context_t *)conn_context;


    //
    // Decrypt the buffer.
    //
    CAST_KEY	key;

    *output = (const char *)malloc(inputlen);
    CAST_set_key(&key, 16, ctx->sharedKey);
    CAST_cbc_encrypt((const unsigned char *)input, (unsigned char *)*output, inputlen, &key, ctx->decryptiv, CAST_DECRYPT);
    *outputlen = inputlen;

    return SASL_OK;
}


//
// Perform a general step.
//
static int dhx_server_mech_step(void *conn_context,
                                sasl_server_params_t *sparams,
                                const char *clientin,
                                unsigned clientinlen,
                                const char **serverout,
                                unsigned *serveroutlen,
                                sasl_out_params_t *oparams)
{
    server_context_t	*ctx = (server_context_t *)conn_context;


    if (ctx->step == 1) {
        unsigned int	i;
        CAST_KEY	key;
        Integer		publicKey, clientPubKey, sharedKey;
        byte		iv[8];

        //
        // Make sure we got the expected client data.
        //
        if (clientin == NULL)
            return SASL_BADPARAM;

        //
        // Determine the username.
        //
        for (i = 0; i < clientinlen && clientin[i] != '\0'; i++)
            ;
        if (i == clientinlen || i > 128)
            return SASL_BADPARAM;
        strncpy(ctx->username, clientin, 128);
        ctx->username[128] = '\0';

        //
        // Move past the second username.
        // TODO: Figure out what this is. Maybe authz id?
        //
        for (i++; i < clientinlen && clientin[i] != '\0'; i++)
            ;
        if (++i >= clientinlen || (clientinlen - i) != 132)
            return SASL_BADPARAM;
	i += 4; /* HDSD */

        //
        // Decode and the client's public key.
        //
        clientPubKey = Integer((const byte *)(clientin + i), 128, Integer::UNSIGNED);

        //
        // Calculate the shared secret.
        //
        sharedKey = Integer(a_exp_b_mod_c(clientPubKey, *ctx->privateKey, *ctx->p));
        sharedKey.Encode(ctx->sharedKey, 16, Integer::UNSIGNED);

        //
        // Generate our public key.
        //
        publicKey = Integer(a_exp_b_mod_c(*ctx->g, *ctx->privateKey, *ctx->p));

        //
        // Encode the public key to send back to the user.
        //
        publicKey.Encode(ctx->outBuffer, 128, Integer::UNSIGNED);

        //
        // Encrypt the nonce to send to the user.
        //
        memcpy(iv, "CJalbert", 8);
        ctx->nonce->Encode(ctx->outBuffer + 1024, 16, Integer::UNSIGNED);
        memset(ctx->outBuffer + 1024 + 16, 0, 16);
        CAST_set_key(&key, 16, ctx->sharedKey);
        CAST_cbc_encrypt(ctx->outBuffer + 1024, ctx->outBuffer + 128, 32, &key, iv, CAST_ENCRYPT);
        memset(ctx->outBuffer + 1024, 0, 32);

        //
        // Indicate a continuation.
        //
        *serverout = (char *)ctx->outBuffer;
        *serveroutlen = (128 + 16 + 16);
        ctx->step = 2;

        return SASL_CONTINUE;
    }
    else if (ctx->step == 2) {
        unsigned char	iv[8], unencrypted[256];
        CAST_KEY	key;
        Integer		cnonce;
        int             result = SASL_FAIL;

        //
        // Make sure we got the expected client data.
        //
        if (clientin == NULL || clientinlen > 256)
            return SASL_BADPARAM;

        //
        // Decrypt the buffer.
        //
        memcpy(iv, "LWallace", 8);
        CAST_set_key(&key, 16, ctx->sharedKey);
        CAST_cbc_encrypt((const unsigned char *)clientin, unencrypted, clientinlen, &key, iv, CAST_DECRYPT);

        //
        // Verify the nonce.
        //
        cnonce = Integer(unencrypted, 16, Integer::UNSIGNED);
        cnonce--;
        if (cnonce != *ctx->nonce)
            return SASL_BADMAC;

        //
        // Canonicalize the username... I really have no idea what this
        // does but its required.
        //
        result = sparams->canon_user(sparams->utils->conn,
                                     ctx->username, 0,
                                     SASL_CU_AUTHID | SASL_CU_AUTHZID,
                                     oparams);
        if (result != SASL_OK)
            return result;

        //
        // Verify the plaintext password.
        //
        result = sparams->utils->checkpass(sparams->utils->conn,
                                           oparams->authid,
                                           oparams->alen,
                                           (char *)unencrypted + 16,
                                           strlen((char *)unencrypted + 16));

        //
        // Cleanup.
        //
        memset(unencrypted, 0, sizeof(unencrypted));
	memcpy(ctx->decryptiv, "LWallace", 8);
	memcpy(ctx->encryptiv, "CJalbert", 8);

        //
        // Set oparams. Again, I don't know what all this is, copy and paste!
        //
        oparams->doneflag = 1;
        oparams->mech_ssf = 0;
        oparams->maxoutbuf = 0;
        oparams->encode_context = NULL;
        oparams->encode = NULL;
        oparams->decode_context = NULL;
        oparams->decode = NULL;
        oparams->param_version = 0;
        oparams->decode = &dhx_server_decode;

        return result;
    }
    else {
        return SASL_BADPROT;
    }
}


//
// The list of mechanisms we supply.
//
static sasl_server_plug_t dhx_server_plugins[] = 
{
    {
        "DHX",			/* mech_name */
        0,				/* max_ssf */
        SASL_SEC_NOPLAINTEXT
        | SASL_SEC_NOANONYMOUS,		/* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST,	/* features */
        NULL,				/* glob_context */
        &dhx_server_mech_new,		/* mech_new */
        &dhx_server_mech_step,		/* mech_step */
        &dhx_server_dispose,		/* mech_dispose */
        NULL,				/* mech_free */
        NULL,				/* setpass */
        NULL,				/* user_query */
        NULL,				/* idle */
        NULL,				/* mech_avail */
        NULL				/* spare */
    }
};


//
// Initialize the server plugin.
//
int dhx_server_plug_init(const sasl_utils_t *utils,
                         int maxversion,
                         int *out_version,
                         sasl_server_plug_t **pluglist,
                         int *plugcount)
{
    if (maxversion < SASL_SERVER_PLUG_VERSION) {
        SETERROR(utils, "PLAIN version mismatch");
        return SASL_BADVERS;
    }
    
    *out_version = SASL_SERVER_PLUG_VERSION;
    *pluglist = dhx_server_plugins;
    *plugcount = 1;  
    
    return SASL_OK;
}

#ifdef __cplusplus
 }
#endif
