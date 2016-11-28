# Project

cmake_minimum_required(VERSION 3.6.2)
project(PasswordService VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_FIND_FRAMEWORK LAST)
set(CMAKE_VERBOSE_MAKEFILE TRUE)

# Platform Configuration

include(CheckIncludeFile)
check_include_file(malloc.h HAVE_MALLOC_H)
configure_file(config.h.in config.h)

# Required Libraries

find_path(DB_INCLUDE_DIR db.h PATH_SUFFIXES db60)
find_library(DB_LIBRARY db PATH_SUFFIXES db60)

find_path(LDAP_INCLUDE_DIR ldap.h)
find_library(LDAP_LIBRARY ldap)

#find_package(PkgConfig REQUIRED)
#pkg_check_modules(OPENSSL REQUIRED openssl)
find_package(OpenSSL REQUIRED)

find_path(SASL2_INCLUDE_DIR sasl.h PATH_SUFFIXES sasl)
find_library(SASL2_LIBRARY sasl2)

# Libraries

add_subdirectory(sasl)
add_subdirectory(slapd-plugins)

# Executable

add_executable(passwdd main.c commands.c utils.c keys.c client.c conf.c ldap.c listener.c pwdb.c sasl_auxprop.c policy.c)
target_include_directories(passwdd PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${OPENSSL_INCLUDE_DIR} ${SASL2_INCLUDE_DIR} ${LDAP_INCLUDE_DIR} ${DB_INCLUDE_DIR})
target_link_libraries(passwdd ${OPENSSL_CRYPTO_LIBRARY} ${SASL2_LIBRARY} ${LDAP_LIBRARY} ${DB_LIBRARY})