# 
# Copyright 2016-2018 Internet Corporation for Assigned Names and Numbers.
# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(dns-stats-compactor, m4_esyscmd_s([./getversion.sh]), jim@sinodun.com)
AC_CONFIG_SRCDIR([src/compactor.cpp])
AC_CONFIG_HEADER([config.h])

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects parallel-tests color-tests])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX([11], [noext], [mandatory])
AC_PROG_LIBTOOL
AC_PROG_AWK

AC_SUBST(ASCIIDOC,[no])
AC_PATH_PROG([ASCIIDOC],[asciidoctor],[no],[$PATH$PATH_SEPARATOR/usr/local/bin])
AS_IF([test "x$ASCIIDOC" == xno], [AC_MSG_NOTICE("asciidoctor not found. Not building docs.")],[
  ASCIIDOC_MIN_VER="1.5.0"
  ASCIIDOC_VER=$($ASCIIDOC -V | head -n1 | awk ' { print $2 } ')
  AS_VERSION_COMPARE([${ASCIIDOC_VER}], [${ASCIIDOC_MIN_VER}], [ASCIIDOC_TOO_OLD=1])
  AS_IF([test $ASCIIDOC_TOO_OLD], [AC_MSG_NOTICE("asciidoctor too old require at least ${ASCIIDOC_MIN_VER} found ${ASCIIDOC_VER}. Not building docs.)])
])
AM_CONDITIONAL([BUILD_DOCS], [test ! $ASCIIDOC_TOO_OLD && test "x$ASCIIDOC" != "xno"])

# Optional features
AC_ARG_ENABLE([pseudo-anonymisation],
        [AS_HELP_STRING([--disable-pseudo-anonymisation],
                [do not include pseudo-anonymisation])],
        [],
        [enable_pseudo_anonymisation=yes])
AM_CONDITIONAL([ENABLE_PSEUDOANONYMISATION], [test "x$enable_pseudo_anonymisation" == "xyes"])

# Checks for libraries.
AC_LANG([C++])

AX_BOOST_BASE([1.54.0],, [AC_MSG_ERROR([Boost 1.54 or later not found])])
AX_BOOST_FILESYSTEM
AX_BOOST_IOSTREAMS
AX_BOOST_LOG
AX_BOOST_PROGRAM_OPTIONS
AX_BOOST_SYSTEM
AX_BOOST_THREAD
AX_PTHREAD

AS_IF([test "x$enable_pseudo_anonymisation" != xno],
        [AX_CHECK_OPENSSL([], [AC_MSG_ERROR([pseudo-anonymisation requires OpenSSL])])
         AC_DEFINE([ENABLE_PSEUDOANONYMISATION], [1], [Define to 1 to enable pseudo-anonymisation])
        ])

AC_CHECK_LIB([pcap],[pcap_create],
        [
            AC_SUBST([PCAP_LIB], ["-lpcap"])
            AC_DEFINE([HAVE_LIBPCAP], [1], [Define to 1 if you have the `pcap' library (-lpcap)])
        ],
        [AC_MSG_ERROR([pcap library not found])])
AC_CHECK_HEADERS([pcap/pcap.h])

AC_CHECK_LIB([lzma],[lzma_code],
        [
            AC_SUBST([LZMA_LIB], ["-llzma"])
            AC_DEFINE([HAVE_LIBLZMA], [1], [Define to 1 if you have the `lzma' library (-llzma)])
        ],
        [AC_MSG_ERROR([lzma library not found])])
AC_CHECK_HEADERS([lzma.h])

AC_ARG_WITH([tcmalloc],
        [AS_HELP_STRING([--with-tcmalloc],
                [Use tcmalloc library @<:@default=auto@:>@])],
        [],
        [with_tcmalloc=auto])

AS_IF([test "x$with_tcmalloc" != xno],
        [AC_CHECK_LIB([tcmalloc_minimal],[malloc],
            [AC_SUBST([TCMALLOC_LIB], ["-ltcmalloc_minimal"])
             AC_DEFINE([HAVE_LIBTCMALLOC], [1], [Define to 1 if you have libgtcmalloc_minimal])
            ],
            [if test "x$with_tcmalloc" != xauto; then
                AC_MSG_ERROR([-with-tcmalloc given but test for tcmalloc_minimal failed])
            fi])
        ])

PKG_CHECK_MODULES(libtins,
                  libtins >= 4.0,
                  [AC_DEFINE([HAVE_LIBTINS4], [1], [Define to 1 if using libtins version 4.0 or later])],
                  [PKG_CHECK_MODULES(libtins, libtins >= 3.4)])
AC_SUBST(libtins_LIBS)

AC_CHECK_HEADERS([ctemplate/template.h])
SAVED_LIBS=$LIBS
LIBS="$LIBS -lctemplate"
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([#include <ctemplate/template_string.h>], 
    [ctemplate::TemplateString s("example")])],
        [
            AC_SUBST([CTEMPLATE_LIB], ["-lctemplate"])
            AC_DEFINE([HAVE_LIBCTEMPLATE], [1], [Define to 1 if you have the `ctemplate' library (-lctemplate)])
        ],
        [AC_MSG_ERROR([ctemplate library not found])])
LIBS="$SAVED_LIBS"

AC_CHECK_LIB([maxminddb],[MMDB_open],
        [
            AC_SUBST([MAXMINDDB_LIB], ["-lmaxminddb"])
            AC_DEFINE([HAVE_LIBMAXMINDDB], [1], [Define to 1 if you have the `maxminddb' library (-lmaxminddb)])
        ],
        [AC_MSG_ERROR([maxminddb library not found])])
AC_CHECK_HEADERS([maxminddb.h])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

# Doxygen options
DX_PS_FEATURE(OFF)
DX_HTML_FEATURE(ON)
DX_MAN_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_INIT_DOXYGEN([dns-stats], [$(srcdir)/doc/doxygen/Doxyfile], [doxygen-doc])

AC_ARG_ENABLE(internal-doc,
  [AS_HELP_STRING([--enable-internal-doc],
    [Generate documentation for internal APIs @<:@default=no@:>@])],
  [], [enable_internal_doc=no])
AS_IF([test "x$enable_internal_doc" != xno],
    [DX_ENV_APPEND(ENABLE_INTERNAL, YES)],
    [DX_ENV_APPEND(ENABLE_INTERNAL, NO)])

AC_CONFIG_FILES(Makefile)

AC_OUTPUT
