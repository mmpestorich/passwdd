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

#ifndef __COMMON_H__
#define __COMMON_H__


#define USERNAME_MAX    63
#define PASSWORD_MAX	127

#define LISTENER_MAX    32
#define CLIENT_MAX      64
#define BUFFER_SIZE     1024
#define ARGS_MAX        32
#define SUPPORTED_MECHS "(SASL \"SMB-NTLMv2\" \"SMB-NT\" \"SMB-LAN-MANAGER\" \"MS-CHAPv2\" \"PPS\" \"OTP\" \"GSSAPI\" \"DIGEST-MD5\" \"CRAM-MD5\" \"WEBDAV-DIGEST\" \"DHX\" \"APOP\" )"

#define DEBUG

#endif /* __COMMON_H__ */

