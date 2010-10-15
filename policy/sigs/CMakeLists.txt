
########### install files ###############

install(FILES  dpd.sig ex.web-rules.sig http-bots.sig p0fsyn.osf  	snort-default.sig ssl-worm.sig worm.sig  DESTINATION ${DATADIR}/sigs)



#original Makefile.am contents follow:

### Process this file with automake to produce Makefile.in
#
#sigsdir=${datadir}/bro/sigs
#dist_sigs_DATA = dpd.sig ex.web-rules.sig http-bots.sig p0fsyn.osf \
#	snort-default.sig ssl-worm.sig worm.sig 
#
