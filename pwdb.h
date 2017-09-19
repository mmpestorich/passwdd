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

#ifndef __PWDB_H__
#define __PWDB_H__

#include <stdint.h>
#include <stdio.h>

typedef struct PasswordRec aPasswordRec;

extern int pwdb_open();
extern void pwdb_close();

extern int pwdb_adduser(const char *username, const char *password,
                        uint32_t flags);
extern int pwdb_updatepassword(const char *username, const char *password);
extern int pwdb_updateflags(const char *username, uint32_t flags);
extern int pwdb_deleteuser(const char *username);
extern int pwdb_getpassword(const char *username, char *password,
                            int password_size);

#endif /* __PWDB_H__ */
