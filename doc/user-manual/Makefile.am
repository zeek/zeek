
prefix = @prefix@
bro_dir         = ${prefix}/bro

EXTRA_DIST = README.txt bro.css Bro-user-manual.pdf bro-deployment.pdf \
	BroDir.pdf BroDir.png \
	bro-deployment.png Bro-analysis.texi Bro-blocking.texi \
	Bro-customizing.texi Bro-dir-files.texi Bro-hardware.texi \
	Bro-installation.texi Bro-intrusion-prevention.texi \
	Bro-Linux.texi Bro-log-files.texi Bro-offline-analysis.texi \
	Bro-output.texi Bro-overview.texi Bro-production.texi \
	Bro-requirements.texi Bro-running.texi Bro-setup.texi \
	Bro-signatures.texi Bro-software.texi Bro-tuning.texi \
	Bro-user-manual.texi Bro-user-manual

clean-local: doc-clean

doc: html pdf

pdf: 
	texi2dvi -s --clean --pdf Bro-user-manual.texi

html:
	@rm -rf Bro-user-manual
	makeinfo --css-include=bro.css  --html Bro-user-manual.texi

doc-clean:
	@echo "cleaning  User Manual"
	@rm -f *.log Bro-user-manual/*

doc-distclean:	clean
	@rm Makefile
