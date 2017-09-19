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

#include "config.h"
#include <stdio.h>
#include <string.h> 
#include <stdint.h>
#include <sasl/sasl.h>
#include <sasl/saslplug.h>

#include "plugin_common.h"

#ifdef macintosh 
#include <sasl_plain_plugin_decl.h> 
#endif 

#include <openssl/sha.h>
#include <openssl/md4.h>

/*****************************  Server Section  *****************************/

//
// Define the information used by the server during operation.
//
typedef struct server_context {
    uint8_t	outBuffer[2048];
} server_context_t;


static uint8_t magic1[39] = {
        0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
        0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
        0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
        0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74 };
static uint8_t magic2[41] = {
        0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
        0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
        0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
        0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
        0x6E };


static void NtPasswordHash(const char *password, uint8_t *hash)
{
    MD4_CTX     ctx;


    MD4_Init(&ctx);
    MD4_Update(&ctx, password, strlen(password));
    MD4_Final(hash, &ctx);
}


static void HashNtPasswordHash(const uint8_t *hash, uint8_t *hashhash)
{
    MD4_CTX     ctx;


    MD4_Init(&ctx);
    MD4_Update(&ctx, hash, 16);
    MD4_Final(hashhash, &ctx);
}


void mschap_challengehash(const uint8_t *peerchallenge,
        const uint8_t *challenge, const char *username,
        uint8_t *challengehash)
{
    uint8_t     digest[20];
    SHA_CTX     ctx;


    SHA1_Init(&ctx);
    SHA1_Update(&ctx, peerchallenge, 16);
    SHA1_Update(&ctx, challenge, 16);
    SHA1_Update(&ctx, username, strlen(username));
    SHA1_Final(digest, &ctx);

    memcpy(challengehash, digest, 8);
}



const uint8_t *mschap_generateresponse(const char *password,
        const uint8_t *ntresponse, const uint8_t *peerchallenge,
        const uint8_t *challenge, const char *username)
{
    static uint8_t	digest[20];
    uint8_t     pwhash[16], pwhashhash[16], challengehash[8];
    SHA_CTX     ctx;


    NtPasswordHash(password, pwhash);
    HashNtPasswordHash(pwhash, pwhashhash);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, pwhashhash, 16);
    SHA1_Update(&ctx, ntresponse, 24);
    SHA1_Update(&ctx, magic1, 39);
    SHA1_Final(digest, &ctx);

    mschap_challengehash(peerchallenge, challenge, username, challengehash);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, digest, 20);
    SHA1_Update(&ctx, challengehash, 8);
    SHA1_Update(&ctx, magic2, 41);
    SHA1_Final(digest, &ctx);

    return digest;
}


//
// Initialize a new server mechanism for authenticating a user.
//
static int mschap_server_mech_new(void *glob_context __attribute__((unused)), 
                                  sasl_server_params_t *sparams,
                                  const char *challenge __attribute__((unused)),
                                  unsigned challen __attribute__((unused)),
                                  void **conn_context)
{
    server_context_t	*ctx;


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

    *conn_context = (void *)ctx;    

    return SASL_OK;
}


//
// Free all the memory this context used.
//
static void mschap_server_dispose(void *conn_context,
                                  const sasl_utils_t *utils)
{
    server_context_t *ctx = (server_context_t *)conn_context;

    if (ctx == NULL)
        return;

    utils->free(ctx);
}


//
// Perform a general step.
//
static int mschap_server_mech_step(void *conn_context,
                                   sasl_server_params_t *sparams,
                                   const char *clientin,
                                   unsigned clientinlen,
                                   const char **serverout,
                                   unsigned *serveroutlen,
                                   sasl_out_params_t *oparams)
{
    server_context_t	*ctx = (server_context_t *)conn_context;
    struct propval      auxprop_values[1];
    const char          *password_request[] = { SASL_AUX_PASSWORD, NULL }, *rslt;
    uint8_t             ntresponse[24], peerchallenge[16], challenge[16], *s;
    char                username[256];
    int                 result = SASL_FAIL;

    //
    // Make sure we got the expected client data.
    //
    if (clientin == NULL || clientinlen < 72)
        return SASL_BADPARAM;

    //
    // For now, take the first username...
    //
    strcpy(username, (char *)clientin);
    s = memchr(clientin, '\0', clientinlen);
    if (s != NULL)
        s = memchr(s+1, '\0', (clientinlen - (clientin - (char *)s)));
    if (s != NULL)
        s += 1;
    if (s == NULL || (clientinlen - (clientin - (char *)s)) < 64)
        return SASL_BADPARAM;

    memcpy(challenge, s, 16);
    memcpy(peerchallenge, s + 16, 16);
    memcpy(ntresponse, s + 16 + 16 + 8, 24);

    //
    // Get plaintext password.
    //
    result = sparams->utils->prop_request(sparams->propctx, password_request);
    if (result != SASL_OK)
        return result;

    //
    // Canonicalize the username... I really have no idea what this
    // does but its required.
    //
    result = sparams->canon_user(sparams->utils->conn,
                                 username, 0,
                                 SASL_CU_AUTHID | SASL_CU_AUTHZID,
                                 oparams);
    if (result != SASL_OK)
        return result;

    //
    // Get the actual values for the requested properties.
    //
    result = sparams->utils->prop_getnames(sparams->propctx, password_request,
					   auxprop_values);
    if (result < 0 || !auxprop_values[0].name || !auxprop_values[0].values)
        return SASL_NOUSER;

    rslt = (const char *)mschap_generateresponse(auxprop_values[0].values[0],
                                                 ntresponse, peerchallenge,
                                                 challenge, username);
    if (rslt == NULL) {
	*serverout = NULL;
        serveroutlen = 0;
        return SASL_FAIL;
    }
    memcpy(ctx->outBuffer, rslt, 20);
    *serverout = (char *)ctx->outBuffer;
    *serveroutlen = 20;

    /* erase the plaintext password */
    sparams->utils->prop_erase(sparams->propctx, password_request[0]);

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

    return result;
}


//
// The list of mechanisms we supply.
//
static sasl_server_plug_t mschap_server_plugins[] = 
{
    {
        "MS-CHAPv2",			/* mech_name */
        0,				/* max_ssf */
        SASL_SEC_NOPLAINTEXT
        | SASL_SEC_NOANONYMOUS,		/* security_flags */
        SASL_FEAT_WANT_CLIENT_FIRST,	/* features */
        NULL,				/* glob_context */
        &mschap_server_mech_new,	/* mech_new */
        &mschap_server_mech_step,	/* mech_step */
        &mschap_server_dispose,		/* mech_dispose */
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
int mschap_server_plug_init(const sasl_utils_t *utils,
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
    *pluglist = mschap_server_plugins;
    *plugcount = 1;  
    
    return SASL_OK;
}
