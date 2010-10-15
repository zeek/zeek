
########### install files ###############

install(FILES  time-machine.bro tm-capture.bro tm-class.bro tm-contents.bro  	tm-ftp.bro tm-gap.bro tm-http.bro DESTINATION ${DATADIR}/time-machine)



#original Makefile.am contents follow:

### Process this file with automake to produce Makefile.in
#
#tmdir=${datadir}/bro/time-machine
#dist_tm_DATA = \
#	time-machine.bro tm-capture.bro tm-class.bro tm-contents.bro \
#	tm-ftp.bro tm-gap.bro tm-http.bro
#
