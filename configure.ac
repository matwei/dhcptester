#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([dhcptester], [0.1.0], [dhcptester@mamawe.net])

# check if the source folder is correct
AC_CONFIG_SRCDIR([src/dhcptester.c])

AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-ltrace':
AC_CHECK_LIB([trace], [trace_create_packet])
AC_CHECK_LIB([uci], [uci_alloc_context])

# Checks for header files.
AC_CHECK_HEADERS([libtrace.h stdib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_UINT64_T

# Checks for library functions.
AC_CHECK_FUNCS([strdup])

AC_CONFIG_FILES([Makefile src/Makefile])
#AC_CONFIG_SUBDIRS([src])
AC_OUTPUT
