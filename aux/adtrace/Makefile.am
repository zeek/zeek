## Process this file with automake to produce Makefile.in

AM_CFLAGS=@V_INCLS@

# Should use AM_ vars, but automake 1.5 errors out.
#AM_LDFLAGS = @LDFLAGS@
LDFLAGS = @LDFLAGS@

noinst_PROGRAMS = adtrace
adtrace_SOURCES = adtrace.c ether.h ethertype.h ip.h
