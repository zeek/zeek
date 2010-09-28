## Process this file with automake to produce Makefile.in

SUBDIRS = src test docs bindings

# When running distcheck, make sure we skip building documentation.
#
DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc

MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.guess \
                       config.h.in config.sub configure install-sh \
		       ltconfig ltmain.sh missing mkinstalldirs \
		       stamp-h.in

bin_SCRIPTS = broccoli-config
dist_sysconf_DATA = broccoli.conf

EXTRA_DIST = README AUTHORS COPYING depcomp ylwrap shtool \
	compat/sys/queue.h broccoli.spec contrib \
	autogen.sh

