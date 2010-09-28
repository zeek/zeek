## Process this file with automake to produce Makefile.in

SUBDIRS = sigs time-machine

# These files are created and moved here by the src Makefile
BIF_BRO_FILES = \
	bro.bif.bro common-rw.bif.bro const.bif.bro \
	dns-rw.bif.bro event.bif.bro finger-rw.bif.bro \
	ftp-rw.bif.bro http-rw.bif.bro ident-rw.bif.bro \
	smb-rw.bif.bro smtp-rw.bif.bro strings.bif.bro

MOSTLYCLEANFILES = $(BIF_BRO_FILES)

# doesn't end in a sig
bropolicydir=$(datadir)/bro
bropolicysitedir=$(datadir)/bro/site

dist_bropolicy_DATA = bro.init adu.bro alarm.bro analy.bro \
	anon.bro arp.bro backdoor.bro bittorrent.bro \
	blaster.bro bt-tracker.bro brolite.bro \
	brolite-backdoor.bro brolite-sigs.bro \
	capture-events.bro capture-loss.bro capture-state-updates.bro \
	checkpoint.bro clear-passwords.bro conn-flood.bro conn-id.bro \
	conn.bro contents.bro cpu-adapt.bro dce.bro demux.bro \
	detect-protocols.bro detect-protocols-http.bro \
	dhcp.bro dns-anonymizer.bro dns-info.bro \
	dns-lookup.bro dns.bro dpd.bro drop.bro \
	drop-adapt.bro dyn-disable.bro \
	file-flush.bro finger.bro firewall.bro \
	flag-irc.bro flag-warez.bro frag.bro \
	ftp-anonymizer.bro ftp-cmd-arg.bro ftp-reply-pattern.bro \
	ftp-safe-words.bro ftp.bro gnutella.bro hand-over.bro \
	heavy-analysis.bro heavy.http.bro heavy.irc.bro \
	heavy.scan.bro heavy.software.bro heavy.trw.bro \
	hot-ids.bro hot.bro \
	http-abstract.bro http-anon-server.bro http-anon-useragent.bro \
	http-anon-utils.bro http-anonymizer.bro http-body.bro \
	http-detect-passwd.bro http-entity.bro \
	http-event.bro http-extract-items.bro http-header.bro \
	http-identified-files.bro http-reply.bro \
	http-request.bro http-rewriter.bro http.bro \
	icmp.bro ident-rewriter.bro ident.bro inactivity.bro \
	interconn.bro irc.bro irc-bot.bro large-conns.bro listen-clear.bro \
	listen-ssl.bro load-level.bro load-sample.bro log-append.bro \
	login.bro mime.bro mime-pop.bro mt.bro \
	ncp.bro netflow.bro netstats.bro nfs.bro \
	notice.bro notice-policy.bro notice-action-filters.bro ntp.bro \
	OS-fingerprint.bro pcap.bro peer-status.bro \
	pkt-profile.bro pop3.bro port-name.bro portmapper.bro print-filter.bro \
	print-globals.bro print-resources.bro print-sig-states.bro \
	profiling.bro proxy.bro passwords.bro \
	remote-pcap.bro remote-ping.bro \
	remote-print-id-reply.bro remote-print-id.bro remote-print.bro \
	remote-report-notices.bro remote-send-id.bro remote.bro \
	rotate-logs.bro rsh.bro \
	save-peer-status.bro scan.bro secondary-filter.bro sensor-sshd.bro \
	server-ports.bro service-probe.bro signatures.bro site.bro \
	smb.bro smtp-relay.bro smtp-rewriter.bro smtp.bro snort.bro \
	software.bro ssh-stepping.bro ssh.bro ssl-alerts.bro \
	ssl-ciphers.bro ssl-errors.bro ssl-worm.bro ssl.bro stats.bro \
	stepping.bro synflood.bro targeted-scan.bro tcp.bro \
	terminate-connection.bro tftp.bro trw.bro trw-impl.bro \
	udp.bro udp-common.bro vlan.bro weird.bro worm.bro \
	$(BIF_BRO_FILES)


install-data-hook:
	test -d $(DESTDIR)$(bropolicysitedir) || mkdir $(DESTDIR)$(bropolicysitedir)

uninstall-local:
	-rmdir $(DESTDIR)$(bropolicysitedir)
