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

#include <sasl/saslutil.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "utils.h"

//
// Allows us to do sprintf style code with a buffer in a safe way.
// Appends to the buffer.
//
void buffercatf(char *buffer, const char *format, ...) {
    va_list args;

    va_start(args, format);
    vsnprintf(buffer + strlen(buffer), BUFFER_SIZE - strlen(buffer), format,
              args);
    va_end(args);
}

//
// A merged implementation of snprintf and strncat.
//
size_t snprintfcat(char *buf, size_t bufSize, char const *fmt, ...) {
    size_t result;
    va_list args;
    size_t len = strnlen(buf, bufSize);

    va_start(args, fmt);
    result = vsnprintf(buf + len, bufSize - len - 1, fmt, args);
    va_end(args);
    buf[len + result] = '\0';

    return result + len;
}

//
// Convert the given raw binary data into a hex-string format. The hex
// string buffer must have enough room for the stored data.
//
void binaryToHex(const unsigned char *data, int len, char *hexStr) {
    int i;
    char h, l;

    for (i = 0; i < len; i++) {
        h = (data[i] & 0xF0) >> 4;
        l = (data[i] & 0x0F);

        if (h >= 0x0A)
            *hexStr++ = ((h - 0x0A) + 'A');
        else
            *hexStr++ = (h + '0');

        if (l >= 0x0A)
            *hexStr++ = ((l - 0x0A) + 'A');
        else
            *hexStr++ = (l + '0');
    }

    *hexStr = '\0';
}

//
// Convert the hex-string into a raw binary data stream. The length of the
// data buffer is stored in the 'len' parameter. The output data buffer must
// have enough room to store the raw data-stream.
//
void hexToBinary(const char *hexStr, unsigned char *data, int *len) {
    unsigned char *d = data;
    unsigned char val;

    while (*hexStr != '\0' && *(hexStr + 1) != '\0') {
        if (*hexStr >= 'A')
            val = ((*hexStr - 'A' + 0x0A) << 4);
        else
            val = ((*hexStr - '0') << 4);
        hexStr++;

        if (*hexStr >= 'A')
            val += (*hexStr - 'A' + 0x0A);
        else
            val += (*hexStr - '0');
        hexStr++;

        *d++ = val;
    }

    *len = (d - data);
}

//
// Convert a binary data stream into a base-64 encoded string. Also prepend
// the original binary data length to the output string.
//
int binaryToBase64(const char *data, int len, char *str) {
    int result;
    unsigned int outLen;
    char *tempBuf;

    tempBuf = (char *)malloc(len * 2);
    if (tempBuf == NULL)
        return -1;

    result = sasl_encode64((char *)data, len, tempBuf, (len * 2), &outLen);
    tempBuf[outLen] = '\0';
    sprintf(str, "{%d}%s", len, tempBuf);

    free(tempBuf);

    return result;
}

//
// Convert a base-64 encoded string into a binary stream. Do a check if the
// string includes the original length at the beginning.
//
int base64ToBinary(const char *hexStr, char *data, int *dataLen) {
    int result;
    unsigned int sasl_outlen;
    unsigned long attached_outlen = 0;

    //
    // Get the original length if they provided it.
    //
    if (*hexStr == '{') {
        sscanf(hexStr + 1, "%lu", &attached_outlen);

        hexStr = strchr(hexStr, '}');
        if (hexStr == NULL)
            return -1;

        hexStr++;
    }

    result = sasl_decode64(hexStr, strlen(hexStr), (char *)data, BUFFER_SIZE,
                           &sasl_outlen);

    if (attached_outlen > 0 && attached_outlen != sasl_outlen)
        return -1;

    *dataLen = sasl_outlen;

    return result;
}
