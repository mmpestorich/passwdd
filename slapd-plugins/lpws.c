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


static int chk_lpws(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text)
{
    return LUTIL_PASSWD_ERR;
}

int init_module(int argc, char *argv[])
{
    lutil_passwd_add((struct berval *)&scheme_blacklist, chk_blacklist, NULL);
    lutil_passwd_add((struct berval *)&scheme_lpws, chk_lpws, NULL);

    return 0;
}
