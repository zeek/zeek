
EXTRA_DIST = autogen.sh VERSION README.html

bin_PROGRAMS = capstats

capstats_SOURCES = capstats.cc version.cc
capstats_INCLUDES = -I/usr/local
capstats_LDFLAGS = -L/usr/local
capstats_LDADD = -lpcap 

version.cc: VERSION
	@rm -f $@
	sed -e 's/.*/char Version[] = "&";/' VERSION > $@
                        
doc: 
	-asciidoc --unsafe -a toc -b xhtml11-custom README
    
