AC_PREREQ([2.61])
AC_INIT([prober], [0.9])
AC_CONFIG_SRCDIR([init.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall foreign])
AM_SILENT_RULES([yes]) # Not available for 2.61, the default on OSX Lion
AC_CONFIG_FILES([Makefile])

AC_PROG_CC
AM_PROG_CC_C_O

# Basic stuff we always need
AC_CHECK_HEADERS([inttypes.h stdint.h], [break;])
AC_CHECK_HEADERS([stdlib.h strings.h  sys/time.h unistd.h arpa/inet.h])

# Required dependencies
# real-time library
AC_CHECK_LIB([rt], [main])

# Pcap
AC_CHECK_LIB([pcap], [main], [], [AC_MSG_ERROR([Cannot find required library pcap])])
AC_CHECK_HEADERS([pcap.h])

# pthread
AC_CHECK_LIB([pthread], [main])

# PolarSSL (AES/RSA)
AC_CHECK_LIB([polarssl], [main])
AC_CHECK_HEADERS([polarssl/config.h])

# Optional: Capture signals (SIGTERM, etc) and handle cleanly
AC_CHECK_HEADERS([signal.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero floor gethostbyname memset pow select socket strdup strerror])

AC_OUTPUT
