# $Id$
#
# Makefile not need to build module. Use "python setup.py install" instead.

CLEAN=build broccoli_intern_wrap.c broccoli_intern.py README.html *.pyc 

all : doc broccoli_intern_wrap.c
 
broccoli_intern_wrap.c :  broccoli_intern.i
	swig -python -I../../src -o broccoli_intern_wrap.c broccoli_intern.i

doc : README.html

clean:
	rm -rf $(CLEAN)

README.html : README
	-asciidoc -a toc -b xhtml11-custom README
