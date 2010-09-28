#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(capstats, esyscmd([tr -d '\n' < VERSION]), robin@icir.org)
AM_INIT_AUTOMAKE

AC_CONFIG_SRCDIR([capstats.cc])
AM_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

AC_ARG_WITH(dag,
       [  --with-dag=PATH         path to the DAG library (for native support for Endace Tech.'s DAG monitoring cards)],
        if test "$withval" != "no" -a "$withval" != "NO"; then
                use_dag=yes
                DAGPATH="$withval"
                LDFLAGS="${LDFLAGS} -L${DAGPATH}/lib "
                V_INCLS="${V_INCLS} -I${DAGPATH}/include"
        else
                use_dag=no
        fi
        )

# Checks for libraries.
AC_CHECK_LIB([pcap], [dag_open])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([netinet/in.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([alarm gettimeofday memset strerror])

# Check for OS.
case "$target_os" in
linux*)
        AC_DEFINE(HAVE_LINUX,,[We are on a Linux system])
        ;;
esac

dnl ################################################
dnl # Endace DAG support
dnl ################################################

if test "$use_dag" != "no" -a "$use_dag" != "NO"; then
        AC_CHECK_LIB(dag, dag_open, use_dag=yes, use_dag=no)
        AC_CHECK_HEADER(pcap.h,,use_dag=no)

        if test "$use_dag" = "yes"; then
                  AC_DEFINE(USE_DAG,,[Include Endace DAG support])
                  LIBS="${LIBS} -ldag"
        fi
else
        use_dag=no
fi
dnl #################################################

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo  
echo "           Capstats Configuration Summary"
echo "=========================================================="
echo
echo Configuration Summary:
echo "  - DAG support: "$use_dag
echo

