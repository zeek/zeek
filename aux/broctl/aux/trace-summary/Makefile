
DISTFILES = README README.html COPYING CHANGES Makefile trace-summary 

VERSION=$(shell grep ^Version trace-summary | awk 'BEGIN{IFS="[= ]}"}{print $$3}')
DISTDIR=trace-summary-$(VERSION)

doc: README.html

README.html: README
	asciidoc -a toc -b xhtml11-custom README
    
dist: doc
	rm -rf $(DISTDIR)
	mkdir $(DISTDIR)
	cp $(DISTFILES) $(DISTDIR)
	tar czvf $(DISTDIR).tgz $(DISTDIR)
	rm -rf $(DISTDIR)
	     

