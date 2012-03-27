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
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "config.h"


typedef struct {
    char *key;
    char *value;
} config_option;


#define CONFIG_MAX	100
static config_option options[CONFIG_MAX];

static int add_config(const char *key, const char *value);


//
// Initialize the config system by reading the config file.
//
int init_config(const char *config_file)
{
    FILE *fp;
    char line[BUFFER_SIZE], *s, *key, *value;
    int count;


    memset(&options, 0, sizeof(options));

    fp = fopen(config_file, "r");
    if (fp == NULL) {
        printf("Config file not found.\r\n");

        return -1;
    }

    for (count = 1; fgets(line, sizeof(line), fp) != NULL; count++) {
        //
        // Strip any leading whitespace.
        //
        s = line;
        while (*s == ' ' || *s == '\t')
            s++;

        //
        // Find the = character.
        //
        key = s;
        s = strchr(key, '=');
        if (s == NULL) {
            printf("Error reading config file at line %d, no = found.\r\n", count);
            fclose(fp);

            return -1;
        }

        //
        // Strip any whitespace and the = as well.
        //
        while (*s == '=' || *s == ' ' || *s == '\t')
            s--;
        s++;
        while (*s == '=' || *s == ' ' || *s == '\t')
            *s++ = '\0';

        //
        // Strip any trailing whitespace or \r or \n chars.
        //
        value = s;
        s = (value + strlen(value) - 1);
        while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
            *s-- = '\0';

        //
        // Save the config option.
        //
        add_config(key, value);
    }
    fclose(fp);

    return 0;
}


//
// Free all memory used by the config system.
//
void free_config()
{
    int i;


    for (i = 0; i < CONFIG_MAX; i++) {
        if (options[i].key != NULL) {
            free(options[i].key);
            options[i].key = NULL;
        }
        if (options[i].value != NULL) {
            free(options[i].value);
            options[i].value = NULL;
        }
    }
}


//
// Add a new value to the config system. Returns 0 on success or -1 on
// failue.
//
static int add_config(const char *key, const char *value)
{
    int i;


    for (i = 0; i < CONFIG_MAX; i++) {
        if (options[i].key == NULL) {
            options[i].key = strdup(key);
            options[i].value = strdup(value);

            return 0;
        }
    }

    return -1;
}


//
// Find the value of the given option. Returns NULL if no option has been
// defined.
//
const char *find_config(const char *option)
{
    int i;


    for (i = 0; i < CONFIG_MAX && options[i].key != NULL; i++) {
        if (strcmp(options[i].key, option) == 0)
            return options[i].value;
    }

    return NULL;
}



