## Process this file with automake to produce Makefile.in

LIBPCAP_VER = libpcap-0.9.8
LIBPCAP_LIB = $(LIBPCAP_VER)/libpcap.a

EXTRA_DIST = README $(LIBPCAP_VER).tar.gz

# if we don't have ssl, can't build bdcat
if USE_SSL
bdcat_dir = bdcat
else
bdcat_dir =
endif

# don't compile libpcap if they did a '--disable-localpcap' to configure
if USE_LOCALPCAP
built_srcs =  $(LIBPCAP_LIB)
LARGE_FILE =  "-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE"
else
built_srcs =  
endif

if USEV6
PCAPARGS = --enable-ipv6
else
PCAPARGS = 
endif

if USE_BROCCOLI
broccoli = broccoli
else
broccoli =
endif

if USE_BROCTL
broctl = broctl
else
broctl =
endif

BUILT_SOURCES = $(built_srcs)

SUBDIRS = adtrace binpac cf hf nftools rst scripts \
		$(bdcat_dir) $(broccoli) $(broctl)

DIST_SUBDIRS = adtrace binpac cf hf nftools rst scripts \
		$(bdcat_dir) $(broccoli) $(broctl)

clean-local:
	rm -rf $(LIBPCAP_VER)


$(LIBPCAP_LIB): $(top_srcdir)/aux/$(LIBPCAP_VER).tar.gz
	@echo "Unpacking libpcap sources"
	@gzip -d < $(top_srcdir)/aux/$(LIBPCAP_VER).tar.gz | tar xf -
	@echo "Building libpcap"
	( cd $(LIBPCAP_VER) && ./configure --prefix=$(prefix) $(PCAPARGS) CFLAGS=$(LARGE_FILE) && $(MAKE) )
	@chmod -R 755 $(LIBPCAP_VER)


# This is a hack. These are hardcoded here to mimic the previous
# brolite installation. While these should better go into the 
# subdirs' Makefile.am, it's not really worth the effort as 
# we will get rid of all this at some point anyway.
install-brolite:
	$(INSTALL) ./hf/hf ${bindir}
	$(INSTALL) ./hf/nf ${bindir}
	$(INSTALL) ./hf/pf ${bindir}
	$(INSTALL) ./cf/cf ${bindir}
	$(INSTALL) ./rst/rst ${bindir}
	- install -d $(prefix)/scripts/
	$(INSTALL) ./scripts/host-to-addrs $(prefix)/scripts
	$(INSTALL) ./scripts/bro-logchk.pl $(prefix)/scripts
	$(INSTALL) ./scripts/host-grep $(prefix)/scripts
	$(INSTALL) ./scripts/mvlog $(prefix)/scripts


