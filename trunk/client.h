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

#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <sys/select.h>
#include <sasl/sasl.h>
#include "common.h"


typedef struct {
    int fd;
    char username[USERNAME_MAX];
    sasl_conn_t *sasl;
} Client;


extern void init_client();

extern int setup_clients_fdset(fd_set *read_fds);
extern void process_clients(fd_set *read_fds);
extern void process_client(int fd);

extern Client *add_client(int fd, sasl_conn_t *sasl);
extern void destroy_client(int fd);
extern Client *find_client(int fd);

#endif /* __CLIENT_H__ */

