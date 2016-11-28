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
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"
#include "listener.h"
#include "client.h"
#include "conf.h"


typedef struct {
    int fd;
    int isTcp;
} Listener;


static Listener listeners[LISTENER_MAX];


//
// Create a listener socket on the specified port.
//
static int createUdpListener(int port)
{
    struct sockaddr_in addr;
    int fd;


    //
    // Create the socket.
    //
    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        fprintf(stderr, "Error: %s", strerror(errno));
        return -1;
    }

    //
    // Bind the socket to 0.0.0.0:port.
    //
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        fprintf(stderr, "Error: %s", strerror(errno));
        close(fd);
        return -1;
    }

    //
    // Mark for non-blocking I/O.
    //
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        close(fd);
        return -1;
    }

    return fd;
}

//
// Create a listener socket on the specified port.
//
static int createTcpListener(int port) {
    struct sockaddr_in addr;
    int fd;

    //
    // Create the socket.
    //
    fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        fprintf(stderr, "Error: %s", strerror(errno));
        return -1;
    }

    //
    // Mark the TCP socket so that we can re-use the address.
    //
    int optval = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    //
    // Bind the socket to 0.0.0.0:port.
    //
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        fprintf(stderr, "Error: %s", strerror(errno));
        close(fd);
        return -1;
    }

    //
    // Mark for non-blocking I/O.
    //
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        fprintf(stderr, "Error: %s", strerror(errno));
        close(fd);
        return -1;
    }

    //
    // If TCP socket, start listening for connects.
    //
    if (listen(fd, 5) == -1) {
        fprintf(stderr, "Error: %s", strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}


//
// Close all open listeners.
//
void closeListeners()
{
    int i;


    for (i = 0; i < LISTENER_MAX; i++) {
        if (listeners[i].fd != -1) {
            close(listeners[i].fd);
            listeners[i].fd = -1;
        }
    }
}


//
// Setup all the configured listener sockets.
//
int setupListeners()
{
    int i, l = 0;


    //
    // Mark empty all the listeners.
    //
    for (i = 0; i < LISTENER_MAX; i++)
        listeners[i].fd = -1;

    //
    // UDP Listener on 0.0.0.0:3659.
    //
    listeners[l].fd = createUdpListener(3659);
    if (listeners[l].fd == -1)
        return -1;
    listeners[l++].isTcp = 0;

    //
    // TCP Listener on 0.0.0.0:106.
    //
    listeners[l].fd = createTcpListener(106);
    if (listeners[l].fd == -1) {
        closeListeners();

        return -1;
    }
    listeners[l++].isTcp = 1;

    listeners[l].fd = createTcpListener(3659);
    if (listeners[l].fd == -1) {
        closeListeners();

        return -1;
    }
    listeners[l++].isTcp = 1;

    return 0;
}


//
// Process data from a UDP listener. This is usually a request from a client
// to "ping" us to see if we are available.
//
static int processUdpListener(int fd)
{
    struct sockaddr_in addr;
    socklen_t addrlen;
    char buffer[BUFFER_SIZE];
    int len;


    len = recvfrom(fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&addr, &addrlen);
    len = len; /* clear warning for now */
    printf("Ignoring UDP message.\r\n");

    return -1;
}


//
// Process activity on a TCP listener, this means accept a new client
// connection.
//
static int processTcpListener(int fd)
{
    struct sockaddr_in addr;
    socklen_t addrlen;
    int child;
    const char *msg;


    //
    // Accept the new client.
    //
    child = accept(fd, (struct sockaddr *)&addr, &addrlen);
    if (child == -1)
        return -1;

    //
    // Mark for non-blocking I/O.
    //
    if (fcntl(child, F_SETFL, fcntl(child, F_GETFL, 0) | O_NONBLOCK) == -1) {
        close(child);
        return -1;
    }

    //
    // Save the child to the next available client.
    //
    if (add_client(child, NULL) != NULL) {
        msg = "+OK passwdd 1.0 at 127.0.0.1 ready.\r\n";
        write(child, msg, strlen(msg));

        return 0;
    }

    //
    // Too many users.
    //
    msg = "-ERR Too many users.\r\n";
    write(child, msg, strlen(msg));

    return -1;
}


//
// Poll all sockets for activity and process anything that is found.
// TODO MMP Replace with kqueue
int poll_sockets()
{
    struct timeval timeout = { 1, 0 };
    fd_set read_fds;
    int i, maxfd = -1, fd;


    //
    // Zero out the select structs.
    //
    FD_ZERO(&read_fds);

    //
    // Add in the listener sockets.
    //
    for (i = 0; i < LISTENER_MAX; i++) {
        if (listeners[i].fd != -1) {
            FD_SET(listeners[i].fd, &read_fds);
            if (listeners[i].fd > maxfd)
                maxfd = listeners[i].fd;
        }
    }

    //
    // Add in the client sockets.
    //
    fd = setup_clients_fdset(&read_fds);
    if (fd > maxfd)
        maxfd = fd;

    //
    // Wait for activity.
    //
    if (select(maxfd + 1, &read_fds, NULL, NULL, &timeout) == -1) {
        if (errno == EINTR)
            return 0;

        printf("errno = %d\r\n", errno);
        return -1;
    }

    //
    // Look for activity on the listener sockets.
    //
    for (i = 0; i < LISTENER_MAX; i++) {
        if (listeners[i].fd != -1) {
            if (FD_ISSET(listeners[i].fd, &read_fds)) {
                if (listeners[i].isTcp == 0)
                    processUdpListener(listeners[i].fd);
                else
                    processTcpListener(listeners[i].fd);
            }
        }
    }

    //
    // Look for activity on the client sockets.
    //
    process_clients(&read_fds);

    return 0;
}


