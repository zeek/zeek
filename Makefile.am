## Process this file with automake to produce Makefile.in

# snag the whole linux-include directory
EXTRA_DIST = CHANGES README VERSION shtool linux-include \
	autogen.sh depcomp ylwrap

# When running distcheck, make sure we skip building GtkDoc-based
# documentation. This applies to Broccoli only, and needs to be
# duplicated here because DISTCHECK_CONFIGURE_FLAGS isn't otherwise
# noticed.
#
DISTCHECK_CONFIGURE_FLAGS = --disable-gtk-doc

chown = @CHOWN@

# aux before src so we compile the libpcap
SUBDIRS = aux src scripts policy doc

test:
	( cd ../testing && $(MAKE) test )

install-broctl:
	$(MAKE) install
	( cd aux/broctl && $(MAKE) install-broctl )

# Deprecated. Don't use. 
install-brolite:
	$(MAKE) install
	$(INSTALL) -d $(prefix)/logs
	$(INSTALL) -d $(prefix)/archive
	$(INSTALL) -d $(prefix)/var
	( cd scripts && $(MAKE) install-brolite )
	( cd aux && $(MAKE) install-brolite )
	- @CHOWN@ -R `cat scripts/bro_user_id` ${prefix}/
	@echo "*********************************************************"
	@echo "Please run \"${prefix}/etc/bro.rc --start\" to start bro"
	@echo "*********************************************************"

docs:
	( cd doc && $(MAKE) doc )

doc-install:
	( cd doc && $(MAKE) doc-install )

update:
	( cd scripts && $(MAKE) update )
	( cd policy && $(MAKE) install )

update-sigs:
	(cd scripts && $(MAKE) update-sigs )

reports:
	( cd scripts && $(MAKE) reports )

# make sure we don't leak CVS/SVN or private policy files
dist-hook:
	rm -rf `find $(distdir) -name CVS`
	rm -rf `find $(distdir) -name .svn`
	rm -rf $(distdir)/policy/local 

release:
	./autogen.sh
	./configure
	$(MAKE) distcheck
