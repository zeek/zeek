## Process this file with automake to produce Makefile.in

# A list of all the files in the current directory which can be regenerated
MAINTAINERCLEANFILES = Makefile.in Makefile

# A list of everything we build locally, for distcheck.
DISTCLEANFILES = bro_parser.c bro_parser.h bro_lexer.c

# Always include the lexer and parser source and generated output in
# the distribution, regardless of whether we have lex and yacc on
# this system.
#
EXTRA_DIST = bro_parser.y bro_lexer.l bro_lexer.c bro_parser.c bro_parser.h

# On Solaris, we need to specifically include networking libraries.
# On Windows, we need to specifically include winsock. These are
# handled through the substitution of BRO_LIBADD, which gets defined
# according to the platform detection mechanism in the configure script.
#
# On Windows, we also need extra flags for the linker to build a DLL.
# The approach taken here is described in more detail in
# http://sources.redhat.com/autobook/autobook/autobook_253.html#SEC253
#
libbroccoli_la_LIBADD = @BRO_LIBADD@

if WINDOWS_HOST
libbroccoli_la_LDFLAGS = -mwindows -no-undefined -version-info 0:0:0
else
libbroccoli_la_LDFLAGS = -version-info 3:0:0
endif

# Optionally include support files for pcap packets
#
if BRO_PCAP_SUPPORT
PACKET_FILES = bro_packet.c bro_packet.h
else
PACKET_FILES =
endif

# Use the parser source files when we do have lex/yacc, and the generated
# parser code otherwise. Seeing .y/.l's triggers yacc/lex automatically.
if HAVE_LEX_AND_YACC
PARSER_FILES = bro_parser.y bro_lexer.l
else
PARSER_FILES = bro_lexer.c bro_parser.c bro_parser.h
endif

# lex/yacc flags -- those need to be defined regardless of whether
# we have those tools because of automake bogosity.
LEX_OUTPUT_ROOT = lex.bro
AM_LFLAGS  = -Pbro
AM_YFLAGS  = -d -v -p bro

DEBUGFLAGS = -W -Wall -Wno-unused
INCLUDES =  $(DEBUGFLAGS) -I$(top_srcdir)/compat

# Make sure the main header file gets installed in the appropriate
# include directory:
include_HEADERS = broccoli.h

# Most importantly, make sure we build a library out of all this.
lib_LTLIBRARIES = libbroccoli.la

# The sources. If we have lex and yacc, the .y and .l files for
# the parser are included, otherwise the generated .c/.h's.
libbroccoli_la_SOURCES = $(PARSER_FILES) \
	$(PACKET_FILES) 		 \
	broccoli.h			 \
	bro.c				 \
	bro_attr.c bro_attr.h		 \
	bro_attrs.c bro_attrs.h		 \
	bro_buf.h bro_buf.c 		 \
	bro_config.h bro_config.c	 \
	bro_debug.h bro_debug.c		 \
	bro_event.h bro_event.c 	 \
	bro_event_reg.h bro_event_reg.c  \
	bro_hashtable.h bro_hashtable.c  \
	bro_id.h bro_id.c		 \
	bro_io.h bro_io.c 		 \
	bro_list.h bro_list.c		 \
	bro_location.h bro_location.c	 \
	bro_object.h bro_object.c        \
	bro_openssl.h bro_openssl.c	 \
	bro_record.h bro_record.c	 \
	bro_sobject.h bro_sobject.c	 \
	bro_table.h bro_table.c          \
	bro_type.h bro_type.c		 \
	bro_type_decl.h bro_type_decl.c  \
	bro_types.h			 \
	bro_util.h bro_util.c 		 \
	bro_val.h bro_val.c
