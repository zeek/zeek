# $Id: brolite-backdoor.bro 2956 2006-05-14 01:08:34Z vern $

# Sample file for running backdoor detector
#
# Note, this can consume significant processing resources when running
# on live traffic.
#
# To run bro with this script using a Bro Lite setup:
#
#  rename this script to hostname.bro
#  run: $BROHOME/etc/bro.rc start
#  	or bro -i interface brolite-backdoor.bro

@load site

@load backdoor
@load alarm
@load weird

# By default, do backdoor detection on everything except standard HTTP
# and SMTP ports.
redef capture_filters += [ ["tcp"] = "tcp" ];
redef restrict_filters +=
	[ ["not-http"] = "not (port 80 or port 8000 or port 8080)" ];
redef restrict_filters += [ ["not-smtp"] = "not (port 25 or port 587)" ];

redef use_tagging = T;

# Set if you want to dump packets that trigger the detections.
redef dump_backdoor_packets = T;

# Disable (set to T) if you don't care about this traffic.
# redef gnutella_sig_disabled = T;
# redef kazaa_sig_disabled = T;

redef napster_sig_disabled = T;	# too many false positives

# Ignore outgoing, only report incoming backdoors.
redef backdoor_ignore_remote += {
	ftp_backdoor_sigs, ssh_backdoor_sigs, rlogin_backdoor_sigs,
	http_backdoor_sigs, http_proxy_backdoor_sigs, smtp_backdoor_sigs,
};

# Set these to send mail on backdoor alarms.
# redef mail_dest = "youremail@yourhost.dom";
# redef notice_action_filters += {
#	[BackdoorFound] = send_email_notice,
#};

# Tuning: use more aggressive timeouts to reduce CPU and memory, as these
#	have little effect on backdoor analysis.
redef tcp_SYN_timeout = 1 sec;
redef tcp_attempt_delay = 1 sec;
redef tcp_inactivity_timeout = 1 min;
redef udp_inactivity_timeout = 5 secs;
redef icmp_inactivity_timeout = 5 secs;
