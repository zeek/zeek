## Process this file with automake to produce Makefile.in

# A list of all the files in the current directory which can be regenerated
MAINTAINERCLEANFILES = Makefile.in Makefile dummysensor

INCLUDES = -I$(top_srcdir)/src -W -Wall -Wno-unused

if BRO_PCAP_SUPPORT
PCAP_TESTS =
else
PCAP_TESTS = 
endif

noinst_PROGRAMS = broping broconn brohose broconftest broenum brotable $(PCAP_TESTS)

LDADD = $(top_builddir)/src/.libs/libbroccoli.a @BRO_LIBADD@

broping_SOURCES = broping.c
broconn_SOURCES = broconn.c
brohose_SOURCES = brohose.c
broenum_SOURCES = broenum.c
broconftest_SOURCES = broconftest.c
brotable_SOURCES = brotable.c

# don't install any of this stuff
#install-binPROGRAMS:
#uninstall-binPROGRAMS:

EXTRA_DIST = broping.bro brohose.bro broenum.bro broping-record.bro broconn.bro
