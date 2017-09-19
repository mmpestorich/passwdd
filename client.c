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
#include <sys/socket.h>
#include <unistd.h>

#include "client.h"
#include "commands.h"
#include "common.h"
#include "utils.h"

Client clients[CLIENT_MAX];

//
// Initialize the client library.
//
void client_init() {
    int i;

    for (i = 0; i < CLIENT_MAX; i++)
        clients[i].fd = -1;
}

//
// Add all active clients into the fd_set.
//
int clients_setup_fdset(fd_set *read_fds) {
    int i, maxfd = -1;

    for (i = 0; i < CLIENT_MAX; i++) {
        if (clients[i].fd != -1) {
            FD_SET(clients[i].fd, read_fds);
            if (clients[i].fd > maxfd)
                maxfd = clients[i].fd;
        }
    }

    return maxfd;
}

//
// Process all clients that are marked as needed to be read.
//
void clients_process_message(fd_set *read_fds) {
    int i;

    for (i = 0; i < CLIENT_MAX; i++) {
        if (clients[i].fd != -1) {
            if (FD_ISSET(clients[i].fd, read_fds)) {
                client_process_message(clients[i].fd);
            }
        }
    }
}

//
// Process a message from the client.
//
void client_process_message(int fd) {
    Client *client = client_find(fd);
    char buffer[BUFFER_SIZE], *args[ARGS_MAX], *s;
    char response[BUFFER_SIZE];
    int i, len, argc, destroy = 0, c, result;

    len = recv(fd, buffer, sizeof(buffer) - 1, 0);
    if (len < 1) {
        client_destroy(fd);

        return;
    }
    buffer[len] = '\0';
#ifdef DEBUG
    printf("<<%s", buffer);
#endif

    //
    // Split the command into space-separated parameters.
    //
    argc = 0;
    args[argc++] = buffer;
    for (s = buffer + 1; *s != '\0'; s++) {
        if (*s == ' ') {
            *s++ = '\0';
            args[argc++] = s;
            if (argc == ARGS_MAX)
                break;
        } else if (*s == '\r' || *s == '\n')
            *s++ = '\0';
    }

    //
    // Walk each argument and process it.
    //
    response[0] = '\0';
    for (i = 0; i < argc; i++) {
        //
        // Look for the command and call the handler.
        //
        for (c = 0; clientCommands[c].command != NULL; c++) {
            if (strcasecmp(args[i], clientCommands[c].command) == 0) {
                result = clientCommands[c].handler(response, (argc - i),
                                                   &args[i], client, NULL);
                if (result < 0)
                    destroy = 1;
                else
                    i += result;

                break;
            }
        }

        //
        // No command found, throw an error back to the client.
        //
        if (clientCommands[c].command == NULL) {
            printf("Unknown command %s received.\r\n", args[i]);
            buffercatf(response, "-ERR Unknown command\r\n");
        }
    }

    //
    // Send the response(s).
    //
    if (strlen(response) > 0) {
        write(fd, response, strlen(response));
#ifdef DEBUG
        printf(">>%s", response);
#endif
    }

    //
    // Close the socket if requested.
    //
    if (destroy) {
        client_destroy(fd);
    }
}

//
// Add a new client to the first available slot and return a reference to
// that client record. If no more slots are available than NULL is returned.
//
Client *client_add(int fd, sasl_conn_t *sasl) {
    int i;

    for (i = 0; i < CLIENT_MAX; i++) {
        if (clients[i].fd == -1) {
            clients[i].fd = fd;
            clients[i].sasl = sasl;

            return &clients[i];
        }
    }

    return NULL;
}

//
// Destroy a client and free memory.
//
void client_destroy(int fd) {
    int i;

    for (i = 0; i < CLIENT_MAX; i++) {
        if (clients[i].fd == fd) {
            clients[i].fd = -1;
            close(fd);

            return;
        }
    }

    close(fd);
}

Client *client_find(int fd) {
    int i;

    for (i = 0; i < CLIENT_MAX; i++) {
        if (clients[i].fd == fd)
            return &clients[i];
    }

    return NULL;
}
