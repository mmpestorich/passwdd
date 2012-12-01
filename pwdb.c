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
#include <stdlib.h>
#include <errno.h>
#include <db.h>
#include "pwdb.h"
#include "config.h"
#include "utils.h"
#include "common.h"



#define	RECORD_SIZE	1024

typedef struct PasswordRec {
    char username[USERNAME_MAX + 1];
    char password[PASSWORD_MAX + 1];
    uint32_t flags;
} aPasswordRec;


DB	*dbp = NULL;

static int pwdb_write(const char *recordid, const aPasswordRec *record, int overwrite);
static int pwdb_read(const char *recordid, aPasswordRec *record);


//
// Open the database. Returns 0 on success.
//
int	pwdb_open()
{
    const char	*database;
    int		ret;


    //
    // If we have already initialized, fail.
    //
    if (dbp != NULL)
        return -1;

    //
    // Expansion sanity check. If the size of a password record is
    // bigger than the pre-defined size, abort.
    //
    if (sizeof(aPasswordRec) > RECORD_SIZE) {
        fprintf(stderr, "Password record exceeds defined size.\r\n");
        return -1;
    }

    //
    // Get the name of the database from the config file.
    //
    database = find_config("database");
    if (database == NULL) {
	fprintf(stderr, "Database not defined in configuration.\r\n");
	return -1;
    }

    //
    // Initialize database structure for use.
    //
    ret = db_create(&dbp, NULL, 0);
    if (ret != 0)
        return -1;

    //
    // Open the database.
    //
    ret = dbp->open(dbp, NULL, database, NULL, DB_BTREE, DB_CREATE, 0);
    if (ret != 0) {
        dbp = NULL;
        return -1;
    }

    return 0;
}


//
// Close out the database so we can't access it anymore.
//
void pwdb_close()
{
    if (dbp != NULL) {
        dbp->close(dbp, 0);
        dbp = NULL;
    }
}


//
// Adds a new user to the database. On success 0 is returned otherwise a
// negative value is returned.
//
int pwdb_adduser(const char *username, const char *password, uint32_t flags)
{
    aPasswordRec	*record;
    int			ret;


    if (strlen(username) > USERNAME_MAX || strlen(password) > PASSWORD_MAX)
	return -1;

    //
    // Initialize the new record.
    //
    record = (aPasswordRec *)malloc(RECORD_SIZE);
    if (record == NULL)
	return -1;

    //
    // Populate initial data.
    //
    memset(record, 0, RECORD_SIZE);
    strncpy(record->username, username, USERNAME_MAX);
    record->username[USERNAME_MAX] = '\0';
    strncpy(record->password, password, PASSWORD_MAX);
    record->password[PASSWORD_MAX] = '\0';
    record->flags = flags;

    //
    // Write the record to the database.
    //
    ret = pwdb_write(username, record, 0);
    memset(record, 0, RECORD_SIZE);
    free(record);
    if (ret != 0)
	return -1;

    return 0;
}


//
// Update the password for the given user.
//
int pwdb_updatepassword(const char *username, const char *password)
{
    aPasswordRec	*record;
    int			ret;


    //
    // Check for valid arguments.
    //
    if (username == NULL || strlen(username) == 0 || password == NULL ||
        strlen(password) > PASSWORD_MAX)
	return -EINVAL;

    //
    // Allocate memory for the record.
    //
    record = (aPasswordRec *)malloc(RECORD_SIZE);
    if (record == NULL)
	return -ENOMEM;

    //
    // Read the existing record.
    //
    ret = pwdb_read(username, record);
    if (ret != 0) {
	memset(record, 0, RECORD_SIZE);
	free(record);
	return -ENOENT;
    }

    //
    // Modify the password and write back the record.
    //
    strncpy(record->password, password, PASSWORD_MAX);
    record->password[PASSWORD_MAX] = '\0';
    ret = pwdb_write(username, record, 1);
    memset(record, 0, RECORD_SIZE);
    free(record);
    if (ret != 0)
	return -EAGAIN;

    return 0;
}


//
// Update the flags for the given user.
//
int pwdb_updateflags(const char *username, uint32_t flags)
{
    aPasswordRec	*record;
    int			ret;


    //
    // Check for valid arguments.
    //
    if (username == NULL || strlen(username) == 0)
	return -EINVAL;

    //
    // Allocate memory for the record.
    //
    record = (aPasswordRec *)malloc(RECORD_SIZE);
    if (record == NULL)
	return -ENOMEM;

    //
    // Read the existing record.
    //
    ret = pwdb_read(username, record);
    if (ret != 0) {
	memset(record, 0, RECORD_SIZE);
	free(record);
	return -ENOENT;
    }

    //
    // Modify the flags and write back the record.
    //
    record->flags = flags;
    ret = pwdb_write(username, record, 1);
    memset(record, 0, RECORD_SIZE);
    free(record);
    if (ret != 0)
	return -EAGAIN;

    return 0;
}


//
// Delete the specified user from the database.
//
int pwdb_deleteuser(const char *username)
{
    aPasswordRec	*record;
    DBT	key;
    int	ret;


    //
    // Verify arguments.
    //
    if (username == NULL || strlen(username) == 0)
	return -EINVAL;

    //
    // Zero out existing record.
    //
    record = (aPasswordRec *)malloc(RECORD_SIZE);
    if (record == NULL)
	return -ENOMEM;
    memset(record, 0, RECORD_SIZE);
    pwdb_write(username, record, 1);

    //
    // Set the DB key to delete.
    //
    memset(&key, 0, sizeof(DBT));
    key.data = (char *)username;
    key.size = strlen(username) + 1;

    ret = dbp->del(dbp, NULL, &key, 0);

    return (ret == 0 ? 0 : -EAGAIN);
}


//
// Retrieve the plaintext password for the given user from the database.
//
int pwdb_getpassword(const char *username, char *password, int password_size)
{
    aPasswordRec	*record;
    int			ret;


    //
    // Check for valid arguments.
    //
    if (username == NULL || strlen(username) == 0 || password == NULL)
	return -EINVAL;

    //
    // Allocate memory for the record.
    //
    record = (aPasswordRec *)malloc(RECORD_SIZE);
    if (record == NULL)
	return -ENOMEM;

    //
    // Read the existing record.
    //
    ret = pwdb_read(username, record);
    if (ret != 0) {
	memset(record, 0, RECORD_SIZE);
	free(record);
	return -ENOENT;
    }

    //
    // Store the password in the user buffer.
    //
    if ((strlen(record->password) + 1) > password_size) {
	memset(record, 0, RECORD_SIZE);
	free(record);
	return -E2BIG;
    }
    strncpy(password, record->password, password_size - 1);
    record->password[password_size - 1] = '\0';
    memset(record, 0, RECORD_SIZE);
    free(record);

    return 0;
}


//
// Write a record to the database, optionally overwriting the existing
// record. If overwrite is not 1 and the recordid exists then an error
// will be returned.
//
static int pwdb_write(const char *recordid, const aPasswordRec *record, int overwrite)
{
    DBT	key, data;


    memset(&key, 0, sizeof(DBT));
    key.data = (char *)recordid;
    key.size = strlen(recordid) + 1;

    memset(&data, 0, sizeof(DBT));
    data.data = (void *)record;
    data.size = RECORD_SIZE;

    return dbp->put(dbp, NULL, &key, &data, (overwrite == 0 ? DB_NOOVERWRITE : 0));
}


//
// Read the specified record into the user-supplied location.
//
static int pwdb_read(const char *recordid, aPasswordRec *record)
{
    DBT	key, data;


    memset(&key, 0, sizeof(DBT));
    key.data = (char *)recordid;
    key.size = strlen(recordid) + 1;

    memset(&data, 0, sizeof(DBT));
    data.data = record;
    data.ulen = RECORD_SIZE;
    data.flags = DB_DBT_USERMEM;

    return dbp->get(dbp, NULL, &key, &data, 0);
}


