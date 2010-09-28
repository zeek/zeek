DISTCLEANFILES = hf.c nf.c pf.c

noinst_PROGRAMS = hf nf pf

#LEX = @V_LEX@

#.l.c:
#	$(LEX) $(srcdir)/$*.l ; rm -f $@ ; mv lex.yy.c $@

if USE_NBDNS
dns_srcs = nb_dns.c
endif

hf_SOURCES = hf.l setsignal.c version.c nb_dns.h setsignal.h gnuc.h $(dns_srcs) 
nf_SOURCES = nf.l setsignal.c 
pf_SOURCES = pf.l setsignal.c 
