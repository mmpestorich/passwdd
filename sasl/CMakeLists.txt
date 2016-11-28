# Required Libraries

find_path(CRYPTOPP_INCLUDE_DIR cryptopp.h)
find_library(CRYPTOPP_LIBRARY cryptopp)

# Libraries

set(COMMON_SOURCE_FILES plugin_common.c)
set(COMMON_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR} ${OPENSSL_INCLUDE_DIR} ${SASL2_INCLUDE_DIR})
set(COMMON_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY} ${SASL2_LIBRARY})

function(add_shared_library TARGET SOURCES)
    if(${ARGC} GREATER 2)
        set(INCLUDES ${ARGV2})
        if(${ARGC} GREATER 3)
            set(LIBRARIES ${ARGV3})
        endif(${ARGC} GREATER 3)
    endif(${ARGC} GREATER 2)
    add_library(lib${TARGET} SHARED ${COMMON_SOURCE_FILES};${SOURCES})
    target_include_directories(lib${TARGET} PRIVATE ${COMMON_INCLUDE_DIRECTORIES};${INCLUDES})
    target_link_libraries(lib${TARGET} ${COMMON_LIBRARIES};${LIBRARIES})
endfunction(add_shared_library)

add_shared_library(dhx "dhx.cpp;dhx_init.c" ${CRYPTOPP_INCLUDE_DIR} ${CRYPTOPP_LIBRARY})
add_shared_library(lpws_sasl lpws.c)
set_target_properties(liblpws_sasl PROPERTIES OUTPUT_NAME liblpws)
add_shared_library(lpws_ldap lpws_ldap.c ${LDAP_INCLUDE_DIR} ${LDAP_LIBRARY})
add_shared_library(mschap "mschap.c;mschap_init.c")
add_shared_library(webdavdigest "webdavdigest.c;webdavdigest_init.c")
