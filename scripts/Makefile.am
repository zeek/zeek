## Process this file with automake to produce Makefile.in

bro_bin		= ${prefix}/bin
bro_logs	= ${prefix}/logs
bro_etc		= ${prefix}/etc
bro_site	= ${prefix}/site
bro_scripts	= ${prefix}/scripts
bro_reports	= ${prefix}/reports
bro_perlmods	= ${prefix}/perl

# where to download signatures from.
SIGHOST=www.bro-ids.org

# whats our name ..
brohost = @BROHOST@

SUBDIRS = s2b

# these files need to be in the distribution
EXTRA_DIST = bro.cfg.example  bro_config.in  alert_scores  bro.rc.in \
	bro.rc-hooks.sh  bro_log_compress.sh  install_cron.sh \
	local.site.bro.default  localnetMAC.pl.in \
	mail_notice.sh  mail_reports.sh \
	make-ftp-safe-vocabulary.awk  IP4.pm signature_scores \
	perl local.lite.bro \
	alert_scores signature_scores \
	bro_log_compress.sh \
	frontend-mail-reports.sh frontend-site-report.sh push_logs.sh mail_notice.sh

# this cleans up some genereated files
MOSTLYCLEAN = bro.rc bro.cfg bro_config intern.bro bro_user_id bro_user_id.bak \
			  localnetMAC.pl local.site.bro

scoredir=$(prefix)/etc
scriptsdir=$(prefix)/scripts

# just update dist files, not the site file
# and ask me no questions, I'll tell you no ..
update: 
	$(MAKE) install_default_files

# install brolite
install-brolite: 
	- $(INSTALL) -d /usr/local/etc/rc.d/
	$(MAKE) create_dirs
	
	$(INSTALL) $(srcdir)/alert_scores $(scoredir)/alert_scores
	$(INSTALL) $(srcdir)/signature_scores $(scoredir)/signature_scores
	$(INSTALL) $(srcdir)/bro_log_compress.sh  $(bro_scripts)/bro_log_compress.sh
	$(INSTALL) $(srcdir)/frontend-mail-reports.sh  $(bro_scripts)/frontend-mail-reports.sh
	$(INSTALL) $(srcdir)/frontend-site-report.sh  $(bro_scripts)/frontend-site-report.sh
	$(INSTALL) $(srcdir)/push_logs.sh  $(bro_scripts)/push_logs.sh
	$(INSTALL) $(srcdir)/mail_notice.sh $(bro_scripts)/mail_notice.sh
	$(INSTALL) $(srcdir)/s2b/example_bro_files/signatures.sig $(prefix)/site
	$(INSTALL) $(srcdir)/s2b/bro-include/sig-addendum.sig $(datadir)/bro
	$(INSTALL) $(srcdir)/s2b/bro-include/sig-functions.bro $(datadir)/bro
	$(INSTALL) $(srcdir)/s2b/example_bro_files/sig-action.bro $(datadir)/bro

# install perl libraries and executables
install_perl_scripts:
	@if ! ${PERL} -e 'exit ($] >= 5.006001)' > /dev/null 2>&1; then \
		(cd perl && $(PERL) Makefile.PL INSTALLSCRIPT=$(bro_scripts) BROCONFIG=$(prefix)/etc/bro.cfg PREFIX=$(bro_perlmods); $(MAKE) ; $(MAKE) install) ; \
	else \
		echo "*************************************************" ; \
		echo "* Need newer version of perl to install reports *" ; \
		echo "*    and other supporting perl based tools.     *" ; \
		echo "*************************************************" ; \
	fi
# clean up the mess we made
uninstall-local:
	rm -f $(bro_scripts)/mail_reports.sh
	rm -f $(bro_scripts)/bro_log_compress.sh
	rm -f $(bro_scripts)/bro_config
	rm -f $(bro_etc)/bro.rc
	rm -f $(bro_etc)/bro.cfg
	rm -f $(bro_etc)/bro.cfg.example
	rm -f $(prefix)/etc/bro.rc-hooks.sh
	rm -f  $(prefix)/site/local.site.bro
	rm -f  $(prefix)/site/${brohost}.bro
	$(srcdir)/install_cron.sh uninstall
	-rm -f $(prefix)/etc/bro.rc-hooks.sh.new 
	-rm -f /usr/local/etc/rc.d/bro.sh


# install the stuff to do reports
reports:
	$(INSTALL) -d $(bro_scripts)
	$(INSTALL) -d $(bro_etc)
	(cd s2b && $(MAKE) all)
	(cd s2b && $(MAKE) install)
	@./bro_config
	$(INSTALL_DATA) bro.cfg  $(bro_etc)/bro.cfg
	$(INSTALL) $(srcdir)/mail_reports.sh $(bro_scripts)/mail_reports.sh
	$(INSTALL) $(srcdir)/bro_log_compress.sh $(bro_scripts)/bro_log_compress.sh
	$(INSTALL) $(srcdir)/frontend-mail-reports.sh $(bro_scripts)/frontend-mail-reports.sh
	$(INSTALL) $(srcdir)/frontend-site-report.sh $(bro_scripts)/frontend-site-report.sh
	$(INSTALL) $(srcdir)/push_logs.sh  $(bro_scripts)/push_logs.sh
	$(MAKE) install_perl_scripts

# update the signature file in $BROHOME/site, don't clobber it!
update-sigs:
	@echo "Getting signature file from $(SIGHOST)" 
	- wget http://$(SIGHOST)/download/signatures.sig -O signatures.sig.new  -o /dev/null 
	@if [ ! -s signatures.sig.new ] ; then \
		echo "Error in download. Try again later." ; \
	else \
		if [ ! -f $(prefix)/site/signatures.sig ] ; then  \
			echo "No previous version, installing new version." ; \
			cp signatures.sig.new $(prefix)/site/signatures.sig ; \
		else \
			cp signatures.sig.new $(prefix)/site/signatures.sig.new ; \
			echo "***********************************************************" ; \
			echo "A new signature file (signatures.sig.new) has been placed in" ; \
			echo "$(prefix)/site. Please compare it to your current signatures.sig " ; \
			echo "and copy it over if there are no significant differences." ; \
			echo "***********************************************************" ; \
		fi \
	fi
		
create_dirs:
	- $(INSTALL) -d $(bro_bin)
	$(INSTALL) -d $(bro_etc)
	$(INSTALL) -d $(bro_logs)
	$(INSTALL) -d $(bro_site)
	$(INSTALL) -d $(bro_scripts)
	$(INSTALL) -d $(bro_reports)

# these are files that SHOULD NOT be updated and are site specific
install_local_files:
	@if [ ! -f ${bro_site}/local.site.bro ] ; then                \
		echo "Installing local.site.bro ..." ;                           \
		if [ ! -f local.site.bro ]; then                      \
			$(INSTALL_DATA) local.site.bro.default $(bro_site)/local.site.bro ; \
		else \
			$(INSTALL_DATA) local.site.bro $(bro_site)/local.site.bro ; \
		fi \
	else \
		if [ -f local.site.bro ]; then                      \
			$(INSTALL_DATA) local.site.bro $(bro_site)/local.site.bro.new ; \
		fi \
	fi
	@if [ ! -f ${bro_site}/${brohost}.bro ] ; then                 \
		echo "Installing ${brohost}.bro ..." ;                             \
		$(INSTALL_DATA) $(srcdir)/local.lite.bro $(bro_site)/${brohost}.bro ;   \
	else \
		$(INSTALL_DATA) $(srcdir)/local.lite.bro $(bro_site)/${brohost}.bro.new ;   \
	fi
	@if [ ! -f $(prefix)/etc/bro.rc-hooks.sh ] ; then              \
		$(INSTALL_DATA) $(srcdir)/bro.rc-hooks.sh $(prefix)/etc/bro.rc-hooks.sh ;   \
	else \
		$(INSTALL_DATA) $(srcdir)/bro.rc-hooks.sh $(prefix)/etc/bro.rc-hooks.sh.new ; \
	fi

# Default files that can be installed/reinstalled, not site specific
install_default_files:
	$(INSTALL) $(srcdir)/mail_reports.sh $(bro_scripts)/mail_reports.sh
	$(INSTALL) bro.rc $(prefix)/etc/bro.rc
	$(INSTALL) bro_config  $(prefix)/scripts/bro_config
	-$(INSTALL_DATA) bro.cfg  $(bro_etc)/bro.cfg
	$(INSTALL_DATA) $(srcdir)/bro.cfg.example $(bro_etc)/bro.cfg.example
	- $(INSTALL) bro.rc /usr/local/etc/rc.d/bro.sh
	(cd s2b ; $(MAKE) install)

# install cron file
install_cron:
	$(srcdir)/install_cron.sh install

