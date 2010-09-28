prefix = @prefix@
bro_dir         = ${prefix}/bro

EXTRA_DIST = README.txt bro.css bro-deployment.pdf \
	bro-deployment.png Bro-installation.texi \
	Bro-overview.texi Bro-quick-start.pdf \
	Bro-quick-start.texi Bro-requirements.texi \
	Bro-running.texi Bro-quick-start

clean-local: doc-clean

doc: html pdf

pdf: 
	texi2dvi -s --clean --pdf Bro-quick-start.texi

html:
	@rm -rf Bro-quick-start
	makeinfo --css-include=bro.css  --html Bro-quick-start.texi
	@cp *.png Bro-quick-start

doc-clean:
	@echo "cleaning Quick Start Guide"
	@rm -f *.log Bro-quick-start/*

doc-distclean: clean
	@rm Makefile


