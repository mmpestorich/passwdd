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

#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include <stdio.h>
#include "client.h"


//
// Format for the client handlers.
//
typedef int (* ClientHandler)(char *, int, char *[], Client *, void *);

typedef struct {
    const char *command;
    ClientHandler handler;
} ClientCommand;

extern int command_list(char *, int, char *argv[], Client *, void *);
extern int command_rsapublic(char *, int, char *[], Client *, void *);
extern int command_rsavalidate(char *, int, char *[], Client *, void *);
extern int command_listreplicas(char *, int, char *[], Client *, void *);

extern int command_newuser(char *, int, char *[], Client *, void *);
extern int command_deleteuser(char *, int, char *[], Client *, void *);
extern int command_changepass(char *, int, char *[], Client *, void *);
extern int command_user(char *, int, char *[], Client *, void *);
extern int command_auth(char *, int, char *[], Client *, void *);
extern int command_auth2(char *, int, char *[], Client *, void *);
extern int command_getpolicy(char *, int, char *[], Client *, void *);

extern int command_quit(char *, int, char *[], Client *, void *);

extern ClientCommand clientCommands[];

#endif /* __COMMANDS_H__ */

