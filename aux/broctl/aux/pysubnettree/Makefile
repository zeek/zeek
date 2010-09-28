# $Id: Makefile 6811 2009-07-06 20:41:10Z robin $
#
# Makefile not needed to build module. Use "python setup.py install" instead.
#
# This Makefile generates the SWIG wrappers and the documentation.

VERSION=0.12

DISTFILES=LICENSE Makefile README README.html SubnetTree.cc SubnetTree.h \
	SubnetTree.i SubnetTree.py SubnetTree_wrap.cc patricia.c patricia.h setup.py test.py

CLEAN=build SubnetTree_wrap.cc SubnetTree.py README.html *.pyc 

TGZ=pysubnettree-$(VERSION)

all: SubnetTree_wrap.cpp README.html

SubnetTree_wrap.cpp SubnetTree.py: SubnetTree.i SubnetTree.h
	swig -c++ -python -o SubnetTree_wrap.cc SubnetTree.i

doc: README.html

README.html : README
	-asciidoc -a toc -b xhtml11-custom README

clean:
	rm -rf $(CLEAN)

dist:
	@rm -rf $(TGZ)
	@mkdir $(TGZ)
	@cp -rp $(DISTFILES) $(TGZ)
	tar czvf $(TGZ).tar.gz $(TGZ)
	@rm -rf $(TGZ)    
