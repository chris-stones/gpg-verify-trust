AC_PREREQ([2.69])
AC_INIT(gpg-verify-trust, 0.1, mail@chris-stones.uk)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/gpg-verify-trust.c)
AC_CONFIG_HEADERS(src/config.h)

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([subdir-objects])

#include <gpgme.h>
#include <string.h>
#include <argp.h>

AC_CHECK_HEADERS([gpgme.h],[],[AC_MSG_ERROR([Missing gpgme.h])])
AC_CHECK_HEADERS([string.h],[],[AC_MSG_ERROR([Missing string.h])])
AC_CHECK_HEADERS([argp.h],[],[AC_MSG_ERROR([Missing argp.h])])

AC_SEARCH_LIBS([gpgme_new],[gpgme],[],AC_MSG_ERROR([Unable to find libgpgme library]))

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
