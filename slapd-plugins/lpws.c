#include <unistd.h>
#include <stdio.h>
#include <lber.h>
#include "lutil.h"


static const struct berval scheme_blacklist = { 8, "********" };
static const struct berval scheme_lpws = { 6, "{LPWS}" };


//
// This method always returns a password error since the password is
// just "********". This just makes sure we don't accidently let somebody
// login before the password is updated.
//
static int chk_blacklist(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{
    return LUTIL_PASSWD_ERR;
}


//
// This method will need to perform an authenticated check on the user's
// actual password which is stored in the password server's database.
//
static int chk_lpws(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{
    return 0;
    return LUTIL_PASSWD_ERR;
}

int init_module(int argc, char *argv[])
{
	//TODO MMP Missing implementations... where are they?
    //lutil_passwd_add((struct berval *)&scheme_blacklist, chk_blacklist, NULL);
    //lutil_passwd_add((struct berval *)&scheme_lpws, chk_lpws, NULL);

    return 0;
}
