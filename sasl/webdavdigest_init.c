
#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef macintosh
#include <sys/stat.h>
#endif
#include <fcntl.h>
#include <assert.h>

#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <sasl/saslutil.h>

#include "plugin_common.h"

#ifdef macintosh
#include <sasl_digestmd5_plugin_decl.h>
#endif

#ifdef WIN32
BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }
    return TRUE;
}
#endif

SASL_CLIENT_PLUG_INIT( webdavdigest )
SASL_SERVER_PLUG_INIT( webdavdigest )

