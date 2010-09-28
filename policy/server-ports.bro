# $Id: server-ports.bro,v 1.1.2.1 2006/05/31 23:19:07 sommer Exp $
#
# Automatically-loaded script which sets defaults for likely server ports.

redef likely_server_ports += {

	### TCP

	21/tcp,
	22/tcp,
	23/tcp,
	25/tcp,
	587/tcp,
	513/tcp,
	79/tcp,
	113/tcp,
	80/tcp,
	8080/tcp,
	8000/tcp,
	8888/tcp,
	3128/tcp,
	53/tcp,
	111/tcp,
	139/tcp,
	6346/tcp,
	8436/tcp,
	135/tcp,
	445/tcp,
	110/tcp,
	6666/tcp,
	6667/tcp,

	# SSL-relatd ports/tcp,
	443/tcp,
	563/tcp,
	585/tcp,
	614/tcp,
	636/tcp,
	989/tcp,
	990/tcp,
	992/tcp,
	993/tcp,
	994/tcp,
	995/tcp,
	8443/tcp,

	# Not analyzed (yet), but give a hint which side the server is.
	143/tcp,	# IMAP
	497/tcp,	# Dantz
	515/tcp,	# LPD
	524/tcp,	# Netware core protocol
	631/tcp,	# IPP
	1521/tcp,	# Oracle SQL
	2049/tcp,	# NFS
	5730/tcp,	# Calendar
	6000/tcp,	# X11
	6001/tcp, 	# X11
	16384/tcp,	# Connected Backup

	### UDP

	53/udp,
	111/udp,
	123/udp,
	137/udp,
	138/udp,
	161/udp,
	427/udp,	# srvloc
	2049/udp,	# NFS
};
