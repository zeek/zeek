
prefix = @prefix@
bro_dir         = ${prefix}/bro

EXTRA_DIST = README.txt bro.css Bro-Ref-Manual.texi \
	analysis.texi debugger.texi intro.texi \
	predefined.texi references.texi signatures.texi \
	started.texi stmts.texi todo.texi values.texi \
	vars.texi Bro-reference-manual

clean-local: doc-clean

doc: html pdf
pdf: 
	texi2dvi -s --clean --pdf Bro-Ref-Manual.texi

html:
	@rm -rf $(prefix)/Bro-reference-manual
	makeinfo --css-include=bro.css --html Bro-Ref-Manual.texi

doc-clean:
	@echo "cleaning  Reference Manual"
	@rm -f *.log Bro-reference-manual/*

doc-distclean: clean
	@rm Makefile

