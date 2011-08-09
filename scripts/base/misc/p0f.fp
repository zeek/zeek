#
# p0f - SYN fingerprints
# ----------------------
#
# .-------------------------------------------------------------------------.
# | The purpose of this file is to cover signatures for incoming TCP/IP     |
# | connections (SYN packets). This is the default mode of operation for    |
# | p0f. This is also the biggest and most up-to-date set of signatures     |
# | shipped with this project. The file also contains a detailed discussion |
# | of all metrics examined by p0f, and some practical notes on how to      |
# | add new signatures.                                                     |
# `-------------------------------------------------------------------------'
#
# (C) Copyright 2000-2006 by Michal Zalewski <lcamtuf@coredump.cx>
#
# Each line in this file specifies a single fingerprint. Please read the
# information below carefully before attempting to append any signatures
# reported by p0f as UNKNOWN to this file to avoid mistakes. Note that
# this file is compatible only with the default operation mode, and not
# with -R or -A options (SYN+ACK and RST+ modes).
#
# We use the following set metrics for fingerprinting:
#
# - Window size (WSS) - a highly OS dependent setting used for TCP/IP
#   performance control (max. amount of data to be sent without ACK).
#   Some systems use a fixed value for initial packets. On other
#   systems, it is a multiple of MSS or MTU (MSS+40). In some rare
#   cases, the value is just arbitrary.
#
#   NEW SIGNATURE: if p0f reported a special value of 'Snn', the number
#   appears to be a multiple of MSS (MSS*nn); a special value of 'Tnn' 
#   means it is a multiple of MTU ((MSS+40)*nn). Unless you notice the
#   value of nn is not fixed (unlikely), just copy the Snn or Tnn token
#   literally. If you know this device has a simple stack and a fixed
#   MTU, you can however multiply S value by MSS, or T value by MSS+40,
#   and put it instead of Snn or Tnn. One system may exhibit several T
#   or S values. In some situations, this might be a source of some
#   additional information about the setup if you have some time to dig
#   thru the kernel sources; in some other cases, like Windows, there seem
#   to be a multitude of variants and WSS selection algorithms, but it's
#   rather difficult to find a pattern without having the source.
#
#   If WSS looks like a regular fixed value (for example is a power of two), 
#   or if you can confirm the value is fixed by looking at several
#   fingerprints, please quote it literaly. If there's no apparent pattern
#   in WSS chosen, you should consider wildcarding this value - but this
#   should be the last option.
#
#   NOTE: Some NAT devices, such as Linux iptables with --set-mss, will
#   modify MSS, but not WSS. As a result, MSS is changed to reflect
#   the MTU of the NAT device, but WSS remains a multiple of the original
#   MSS. Fortunately for us, the source device would almost always be
#   hooked up to Ethernet. P0f handles it automatically for the original
#   MSS of 1460, by adding "NAT!" tag to the result. 
#   
#   In certain configurations, Linux erratically (?) uses MTU from another
#   interface on the default gw interface. This only happens on systems with
#   two network interfaces. Thus, some Linux systems that do not go thru NAT,
#   but have multiple interfaces instead, will be also tagged this way.
#
#   P0f recognizes and automatically wildcards WSS of 12345, as generated
#   by sendack and sendsyn utilities shipped with the program, when
#   reporting a new signature. See test/sendack.c and test/sendsyn.c for more
#   information about this.
#
# - Overall packet size - a function of all IP and TCP options and bugs.
#   While this is partly redundant in the real world, we record this value
#   to capture rare cases when there are IP options (which we do not currently
#   examine) or packet data past the headers. Both situations are rare.
#
#   Packet size MAY be wildcarded, but the meaning of the wildcard is
#   very special, and means the packet must be larger than PACKET_BIG
#   (defined in config.h as 100). This is usually not necessary, except
#   for some really broken implementations in RST+ mode. For more information,
#   see p0fr.fp. P0f automatically wildcards big packets when reporting
#   new signatures.
#
#   NEW SIGNATURE: Copy this value literally.
#
# - Initial TTL - We check the actual TTL of a received packet. It can't
#   be higher than the initial TTL, and also shouldn't be dramatically
#   lower (maximum distance is defined in config.h as 40 hops). 
#
#   NEW SIGNATURE: *Never* copy TTL from a p0f-reported signature literally.
#   You need to determine the initial TTL. The best way to do it is to
#   check the documentation for a remote system, or check its settings.
#   A fairly good method is to simply round the observed TTL up to
#   32, 64, 128, or 255, but it should be noted that some obscure devices
#   might not use round TTLs (in particular, some shoddy appliances and
#   IRIX and Tru64 are known to use "original" initial TTL settings). If not
#   sure, use traceroute or mtr to see how far you are from the host.
#
#   Note that -F option overrides this check if no signature can be found.
#
# - Don't fragment flag (DF) - some modern OSes set this to implement PMTU
#   discovery. Others do not bother.
#
#   NEW SIGNATURE: Copy this value literally. Note: this setting is
#   sometimes cleared by firewalls and/or certain connectivity clients.
#   Try to find out what's the actual state for a given OS if you see both,
#   and add the right one. P0f will automatically detect a case when a
#   firewall removed the DF flag and will append "(firewall!)" suffix to
#   the signature, so if the DF version is the right one, don't add no-DF
#   variant, unless it has a different meaning.
#
# - Maximum segment size (MSS) - this setting is usually link-dependent. P0f
#   uses it to determine link type of the remote host.
#
#   NEW SIGNATURE: Always wildcard this value, except for rare cases when
#   you have an appliance with a fixed value, know the system supports only
#   a very limited number of network interface types, or know the system
#   is using a value it pulled out of nowhere. I use specific unique MSS
#   to tell Google crawlbots from the rest of Linux population, for example.
#
#   If a specific MSS/MTU is unique to a certain link type, be sure to
#   add it to mtu.h instead of creating several variants of each signature.
#
# - Window scaling (WSCALE) - this feature is used to scale WSS.
#   It extends the size of a TCP/IP window to 32 bits, of sorts. Some modern
#   systems implement this feature. 
#
#   NEW SIGNATURE: Observe several signatures. Initial WSCALE is often set
#   to zero or other low value. There's usually no need to wildcard this
#   parameter.
#
# - Timestamp - some systems that implement timestamps set them to
#   zero in the initial SYN. This case is detected and handled appropriately.
#
#   NEW SIGNATURE: Copy T or T0 option literally.
#
# - Selective ACK permitted - a flag set by systems that implement 
#   selective ACK functionality,
#
#   NEW SIGNATURE: copy S option literally.
#
# - NOP option - its presence, count and sequence is a useful OS-dependent
#   characteristic,
#
#   NEW SIGNATURE: copy N options literally.
#
# - Other and unrecognized options (TTCP-related and such) - implemented by
#   some eccentric or very buggy TCP/IP stacks ;-),
#
#   NEW SIGNATURE: copy ? options literally.
#
# - EOL option. Contrary to the popular belief, the presence of EOL
#   option is actually quite rare, most systems just NOP-pad to the
#   packet boundary.
#
#   NEW SIGNATURE: copy E option literally.
#
# - The sequence of TCP all options mentioned above - this is very
#   specific to the implementation,
#
#   NEW SIGNATURE: Copy the sequence literally.
#
# - Quirks. Some buggy stacks set certain values that should be zeroed in a
#   TCP packet to non-zero values. This has no effect as of today, but is 
#   a valuable source of information. Some systems actually seem to leak
#   memory there. Other systems just exhibit harmful but very specific
#   behavior. This section captures all unusual yes-no properties not
#   related to the main and expected header layout. We detect the following:
#
#   - Data past the headers. Neither SYN nor SYN+ACK packets are supposed
#     to carry any payload. If they do, we should take notice. The actual
#     payload is not examined, but will be displayed if use the -X option.
#     Note that payload is not unusual in RST+ mode (see p0fr.fp), very
#     rare otherwise.
#
#   - Options past EOL. Some systems have some trailing data past EOL
#     in the options section of TCP/IP headers. P0f does not examine this
#     data as of today, simply detects its presence. If there is a
#     confirmed sizable population of systems that have data past EOL, it
#     might be a good idea to look at it. Until then, you have to recompile
#     p0f with DEBUG_EXTRAS set or use -x to display this data,
#
#   - Zero IP ID. This again is a (mostly) harmless setting to use a fixed
#     IP ID for packets with DF set. Some systems reportedly use zero ID,
#     most OSes do not. There is a very slight probability of a false
#     positive when IP ID is "naturally" chosen to be zero on a system
#     that otherwise does set proper values, but the probability is
#     neglible (if it becomes a problem, recompile p0f with IGNORE_ZEROID
#     set in the sources).
#
#   - IP options specified. Usually, packets do not have any IP options
#     set, but there can be some. Until there is a confirmed sizable
#     population of systems that do have IP options in a packet, p0f
#     does not examine those in detail, but it might change (use
#     DEBUG_EXTRAS or -x to display IP options if any found),
#
#   - URG pointer value. SYN packets do not have URG flag set, so the
#     value in URG pointer in TCP header is ignored. Most systems set it
#     to zero, but some OSes (some versions of Windows, for example) do
#     not zero this field or even simply leak memory; the actual value is
#     not examined, because most cases seem to be just random garbage
#     (you can use DEBUG_EXTRAS or -x to report this information though);
#     see doc/win-memleak.txt for more information,
#
#   - "Unused" field value. This should be always zero, but some systems
#     forget to clear it. This might result in some funny issues in the
#     future. P0f checks for non-zero value (and will display it if
#     DEBUG_EXTRAS is set, or you can use -x),
#
#   - ACK number non-zero. ACK value in SYN packets with no ACK flag
#     is disregarded and is usually set to zero (just like with URG
#     pointer), but some systems forget to do it. The exact value is
#     not examined (but will be displayed with DEBUG_EXTRAS, or you can
#     use -x). Note that this is not an anomaly in SYN+ACK and RST+ modes,
#
#   - Non-zero second timestamp. The initial SYN packet should have the
#     second timestamp always zeroed. SYN+ACK and RST+ may "legally" have
#     this quirk though,
#
#   - Unusual flags. If, in addition to SYN (or SYN+ACK), there are some
#     auxilinary flags that do not modify the very meaning of a packet,
#     p0f records this (this can be URG, PUSH, or something else).
#
#     Note: ECN flags (ECE and CWR) are ignored and denoted in a separate
#     way. ECN is never by default, because some systems can't handle it,
#     and it probably does not make much sense to include it in signatures
#     right now.
#
#   - TCP option segment parsing problems. If p0f fails to decode options
#     because of a badly broken packet, it records this fact.
#
#   There are several other quirks valid only in RST+ mode, see p0fr.fp for
#   more information. Those quirks are unheard of in SYN and SYN+ACK 
#   modes.
#
#   NEW SIGNATURE: Copy "quirks" section literally.
#
# We DO NOT use ToS for fingerprinting. While the original TCP/IP
# fingerprinting research believed this value would be useful for this 
# purpose, it is not. The setting is way too often tweaked by network
# devices.
#
# To wildcard MSS, WSS or WSCALE, replace it with '*'. You can also use a
# modulo operator to match any values that divide by nnn - '%nnn' (and,
# as stated above, WSS also supports special values Snn and Tnn).
#
# Fingerprint entry format:
#
# wwww:ttt:D:ss:OOO...:QQ:OS:Details
#
# wwww     - window size (can be * or %nnn or Sxx or Txx)
#	     "Snn" (multiple of MSS) and "Tnn" (multiple of MTU) are allowed.
# ttt      - initial TTL 
# D        - don't fragment bit (0 - not set, 1 - set)
# ss       - overall SYN packet size (* has a special meaning)
# OOO      - option value and order specification (see below)
# QQ       - quirks list (see below)
# OS       - OS genre (Linux, Solaris, Windows)
# details  - OS description (2.0.27 on x86, etc)
#
# If OS genre starts with '*', p0f will not show distance, link type
# and timestamp data. It is useful for userland TCP/IP stacks of
# network scanners and so on, where many settings are randomized or
# bogus.
#
# If OS genre starts with @, it denotes an approximate hit for a group
# of operating systems (signature reporting still enabled in this case). 
# Use this feature at the end of this file to catch cases for which
# you don't have a precise match, but can tell it's Windows or FreeBSD
# or whatnot by looking at, say, flag layout alone.
#
# If OS genre starts with - (which can prefix @ or *), the entry is
# not considered to be a real operating system (but userland stack
# instead). It is important to mark all scanners and so on with -,
# so that they are not used for masquerade detection (also add this
# prefix for signatures of application-induced behavior, such as
# increased window size with Opera browser).
#
# Option block description is a list of comma or space separated
# options in the order they appear in the packet:
#
# N	   - NOP option
# E	   - EOL option
# Wnnn	   - window scaling option, value nnn (or * or %nnn)
# Mnnn	   - maximum segment size option, value nnn (or * or %nnn)
# S	   - selective ACK OK
# T 	   - timestamp
# T0	   - timestamp with zero value
# ?n       - unrecognized option number n.
#
# P0f can sometimes report ?nn among the options. This means it couldn't
# recognize this option (option number nn). It's either a bug in p0f, or
# a faulty TCP/IP stack, or, if the number is listed here:
#
#   http://www.iana.org/assignments/tcp-parameters
#
# ...the stack might be simply quite exotic.
#
# To denote no TCP options, use a single '.'.
#
# Quirks section is usually an empty list ('.') of oddities or bugs of this
# particular stack. List items are not separated in any way. Possible values:
#
# P     - options past EOL,
# Z	- zero IP ID,
# I	- IP options specified,
# U	- urg pointer non-zero,
# X     - unused (x2) field non-zero,
# A	- ACK number non-zero,
# T     - non-zero second timestamp,
# F     - unusual flags (PUSH, URG, etc),
# D     - data payload,
# !     - broken options segment.
#
# WARNING WARNING WARNING
# -----------------------
#
# Do not add a system X as OS Y just because NMAP says so. It is often
# the case that X is a NAT firewall. While nmap is talking to the 
# device itself, p0f is fingerprinting the guy behind the firewall
# instead.
#
# When in doubt, use common sense, don't add something that looks like
# a completely different system as Linux or FreeBSD or LinkSys router.
# Check DNS name, establish a connection to the remote host and look
# at SYN+ACK (p0f -A -S should do) - does it look similar?
#
# Some users tweak their TCP/IP settings - enable or disable RFC1323,
# RFC1644 or RFC2018 support, disable PMTU discovery, change MTU, initial
# TTL and so on. Always compare a new rule to other fingerprints for
# this system, and verify the system isn't "customized". It is OK to
# add signature variants caused by commonly used software (PFs, security
# packages, etc), but it makes no sense to try to add every single
# possible /proc/sys/net/ipv4/* tweak on Linux or so.
#
# KEEP IN MIND: Some packet firewalls configured to normalize outgoing
# traffic (OpenBSD pf with "scrub" enabled, for example) will, well,
# normalize packets. Signatures will not correspond to the originating
# system (and probably not quite to the firewall either).
#
# NOTE: Try to keep this file in some reasonable order, from most to
# least likely systems. This will speed up operation. Also keep most
# generic and broad rules near ehe end.
#
# Still decided to add signature? Let us know - mail a copy of your discovery
# to lcamtuf@coredump.cx. You can help make p0f better, and I can help you
# make your signature more accurate.
#

##########################
# Standard OS signatures #
##########################

# ----------------- AIX ---------------------

# AIX is first because its signatures are close to NetBSD, MacOS X and
# Linux 2.0, but it uses a fairly rare MSSes, at least sometimes...
# This is a shoddy hack, though.

45046:64:0:44:M*:.:AIX:4.3

16384:64:0:44:M512:.:AIX:4.3.2 and earlier

16384:64:0:60:M512,N,W%2,N,N,T:.:AIX:4.3.3-5.2 (1)
32768:64:0:60:M512,N,W%2,N,N,T:.:AIX:4.3.3-5.2 (2)
65535:64:0:60:M512,N,W%2,N,N,T:.:AIX:4.3.3-5.2 (3)

65535:64:0:64:M*,N,W1,N,N,T,N,N,S:.:AIX:5.3 ML1

# ----------------- Linux -------------------

S1:64:0:44:M*:A:Linux:1.2.x
512:64:0:44:M*:.:Linux:2.0.3x (1)
16384:64:0:44:M*:.:Linux:2.0.3x (2)

# Endian snafu! Nelson says "ha-ha":
2:64:0:44:M*:.:Linux:2.0.3x (MkLinux) on Mac (1)
64:64:0:44:M*:.:Linux:2.0.3x (MkLinux) on Mac (2)

S4:64:1:60:M1360,S,T,N,W0:.:Linux:2.4 (Google crawlbot)
S4:64:1:60:M1430,S,T,N,W0:.:Linux:2.4-2.6 (Google crawlbot)

S2:64:1:60:M*,S,T,N,W0:.:Linux:2.4 (large MTU?)
S3:64:1:60:M*,S,T,N,W0:.:Linux:2.4 (newer)
S4:64:1:60:M*,S,T,N,W0:.:Linux:2.4-2.6

S3:64:1:60:M*,S,T,N,W1:.:Linux:2.6, seldom 2.4 (older, 1)
S4:64:1:60:M*,S,T,N,W1:.:Linux:2.6, seldom 2.4 (older, 2)
S3:64:1:60:M*,S,T,N,W2:.:Linux:2.6, seldom 2.4 (older, 3)
S4:64:1:60:M*,S,T,N,W2:.:Linux:2.6, seldom 2.4 (older, 4)
T4:64:1:60:M*,S,T,N,W2:.:Linux:2.6 (older, 5)

S4:64:1:60:M*,S,T,N,W5:.:Linux:2.6 (newer, 1)
S4:64:1:60:M*,S,T,N,W6:.:Linux:2.6 (newer, 2)
S4:64:1:60:M*,S,T,N,W7:.:Linux:2.6 (newer, 3)
T4:64:1:60:M*,S,T,N,W7:.:Linux:2.6 (newer, 4)


S20:64:1:60:M*,S,T,N,W0:.:Linux:2.2 (1)
S22:64:1:60:M*,S,T,N,W0:.:Linux:2.2 (2)
S11:64:1:60:M*,S,T,N,W0:.:Linux:2.2 (3)

# Popular cluster config scripts disable timestamps and
# selective ACK:

S4:64:1:48:M1460,N,W0:.:Linux:2.4 in cluster

# This happens only over loopback, but let's make folks happy:
32767:64:1:60:M16396,S,T,N,W0:.:Linux:2.4 (loopback)
32767:64:1:60:M16396,S,T,N,W2:.:Linux:2.6 (newer, loopback)
S8:64:1:60:M3884,S,T,N,W0:.:Linux:2.2 (loopback)

# Opera visitors:
16384:64:1:60:M*,S,T,N,W0:.:-Linux:2.2 (Opera?)
32767:64:1:60:M*,S,T,N,W0:.:-Linux:2.4 (Opera?)

# Some fairly common mods & oddities:
S22:64:1:52:M*,N,N,S,N,W0:.:Linux:2.2 (tstamp-)
S4:64:1:52:M*,N,N,S,N,W0:.:Linux:2.4 (tstamp-)
S4:64:1:52:M*,N,N,S,N,W2:.:Linux:2.6 (tstamp-)
S4:64:1:44:M*:.:Linux:2.6? (barebone, rare!)
T4:64:1:60:M1412,S,T,N,W0:.:Linux:2.4 (rare!)

# ----------------- FreeBSD -----------------

16384:64:1:44:M*:.:FreeBSD:2.0-4.2
16384:64:1:60:M*,N,W0,N,N,T:.:FreeBSD:4.4 (1)

1024:64:1:60:M*,N,W0,N,N,T:.:FreeBSD:4.4 (2)

57344:64:1:44:M*:.:FreeBSD:4.6-4.8 (RFC1323-)
57344:64:1:60:M*,N,W0,N,N,T:.:FreeBSD:4.6-4.9

32768:64:1:60:M*,N,W0,N,N,T:.:FreeBSD:4.8-5.1 (or MacOS X 10.2-10.3)
65535:64:1:60:M*,N,W0,N,N,T:.:FreeBSD:4.7-5.2 (or MacOS X 10.2-10.4) (1)
65535:64:1:60:M*,N,W1,N,N,T:.:FreeBSD:4.7-5.2 (or MacOS X 10.2-10.4) (2)

65535:64:1:60:M*,N,W0,N,N,T:Z:FreeBSD:5.1 (1)
65535:64:1:60:M*,N,W1,N,N,T:Z:FreeBSD:5.1 (2)
65535:64:1:60:M*,N,W2,N,N,T:Z:FreeBSD:5.1 (3)
65535:64:1:64:M*,N,N,S,N,W1,N,N,T:.:FreeBSD:5.3-5.4
65535:64:1:64:M*,N,W1,N,N,T,S,E:P:FreeBSD:6.x (1)
65535:64:1:64:M*,N,W0,N,N,T,S,E:P:FreeBSD:6.x (2)

65535:64:1:44:M*:Z:FreeBSD:5.2 (RFC1323-)

# 16384:64:1:60:M*,N,N,N,N,N,N,T:.:FreeBSD:4.4 (tstamp-)

# ----------------- NetBSD ------------------

16384:64:0:60:M*,N,W0,N,N,T:.:NetBSD:1.3
65535:64:0:60:M*,N,W0,N,N,T0:.:-NetBSD:1.6 (Opera)
16384:64:1:60:M*,N,W0,N,N,T0:.:NetBSD:1.6
65535:64:1:60:M*,N,W1,N,N,T0:.:NetBSD:1.6W-current (DF)
65535:64:1:60:M*,N,W0,N,N,T0:.:NetBSD:1.6X (DF)
32768:64:1:60:M*,N,W0,N,N,T0:.:NetBSD:1.6Z or 2.0 (DF)
32768:64:1:64:M1416,N,W0,S,N,N,N,N,T0:.:NetBSD:2.0G (DF)
32768:64:1:64:M*,N,W0,S,N,N,N,N,T0:.:NetBSD:3.0 (DF)

# ----------------- OpenBSD -----------------

16384:64:1:64:M*,N,N,S,N,W0,N,N,T:.:OpenBSD:3.0-3.9
57344:64:1:64:M*,N,N,S,N,W0,N,N,T:.:OpenBSD:3.3-3.4
16384:64:0:64:M*,N,N,S,N,W0,N,N,T:.:OpenBSD:3.0-3.4 (scrub)
65535:64:1:64:M*,N,N,S,N,W0,N,N,T:.:-OpenBSD:3.0-3.4 (Opera?)
32768:64:1:64:M*,N,N,S,N,W0,N,N,T:.:OpenBSD:3.7

# ----------------- Solaris -----------------

S17:64:1:64:N,W3,N,N,T0,N,N,S,M*:.:Solaris:8 (RFC1323 on)
S17:64:1:48:N,N,S,M*:.:Solaris:8 (1)
S17:255:1:44:M*:.:Solaris:2.5-7 (1)

# Sometimes, just sometimes, Solaris feels like coming up with
# rather arbitrary MSS values ;-)

S6:255:1:44:M*:.:Solaris:2.5-7 (2)
S23:64:1:48:N,N,S,M*:.:Solaris:8 (2)
S34:64:1:48:M*,N,N,S:.:Solaris:9
S34:64:1:48:M*,N,N,N,N:.:Solaris:9 (no sack)
S44:255:1:44:M*:.:Solaris:7

4096:64:0:44:M1460:.:SunOS:4.1.x

S34:64:1:52:M*,N,W0,N,N,S:.:Solaris:10 (beta)
32850:64:1:64:M*,N,N,T,N,W1,N,N,S:.:Solaris:10 (1203?)
32850:64:1:64:M*,N,W1,N,N,T,N,N,S:.:Solaris:9.1

# ----------------- IRIX --------------------

49152:60:0:44:M*:.:IRIX:6.2-6.4
61440:60:0:44:M*:.:IRIX:6.2-6.5
49152:60:0:52:M*,N,W2,N,N,S:.:IRIX:6.5 (RFC1323+) (1)
49152:60:0:52:M*,N,W3,N,N,S:.:IRIX:6.5 (RFC1323+) (2)

61440:60:0:48:M*,N,N,S:.:IRIX:6.5.12-6.5.21 (1)
49152:60:0:48:M*,N,N,S:.:IRIX:6.5.12-6.5.21 (2)

49152:60:0:64:M*,N,W2,N,N,T,N,N,S:.:IRIX:6.5 IP27

# ----------------- Tru64 -------------------
# Tru64 and OpenVMS share the same stack on occassions.
# Relax.

32768:60:1:48:M*,N,W0:.:Tru64:4.0 (or OS/2 Warp 4)
32768:60:0:48:M*,N,W0:.:Tru64:5.0 (or OpenVMS 7.x on Compaq 5.0 stack)
8192:60:0:44:M1460:.:Tru64:5.1 (no RFC1323) (or QNX 6)
61440:60:0:48:M*,N,W0:.:Tru64:v5.1a JP4 (or OpenVMS 7.x on Compaq 5.x stack)

# ----------------- OpenVMS -----------------

6144:64:1:60:M*,N,W0,N,N,T:.:OpenVMS:7.2 (Multinet 4.3-4.4 stack)

# ----------------- MacOS -------------------

S2:255:1:48:M*,W0,E:.:MacOS:8.6 classic

16616:255:1:48:M*,W0,E:.:MacOS:7.3-8.6 (OTTCP)
16616:255:1:48:M*,N,N,N,E:.:MacOS:8.1-8.6 (OTTCP)
32768:255:1:48:M*,W0,N:.:MacOS:9.0-9.2

32768:255:1:48:M1380,N,N,N,N:.:MacOS:9.1 (OT 2.7.4) (1)
65535:255:1:48:M*,N,N,N,N:.:MacOS:9.1 (OT 2.7.4) (2)

# ----------------- Windows -----------------

# Windows TCP/IP stack is a mess. For most recent XP, 2000 and
# even 98, the pathlevel, not the actual OS version, is more
# relevant to the signature. They share the same code, so it would
# seem. Luckily for us, almost all Windows 9x boxes have an
# awkward MSS of 536, which I use to tell one from another
# in most difficult cases.

8192:32:1:44:M*:.:Windows:3.11 (Tucows)
S44:64:1:64:M*,N,W0,N,N,T0,N,N,S:.:Windows:95
8192:128:1:64:M*,N,W0,N,N,T0,N,N,S:.:Windows:95b

# There were so many tweaking tools and so many stack versions for
# Windows 98 it is no longer possible to tell them from each other
# without some very serious research. Until then, there's an insane
# number of signatures, for your amusement:

S44:32:1:48:M*,N,N,S:.:Windows:98 (low TTL) (1)
8192:32:1:48:M*,N,N,S:.:Windows:98 (low TTL) (2)
%8192:64:1:48:M536,N,N,S:.:Windows:98 (13)
%8192:128:1:48:M536,N,N,S:.:Windows:98 (15)
S4:64:1:48:M*,N,N,S:.:Windows:98 (1)
S6:64:1:48:M*,N,N,S:.:Windows:98 (2)
S12:64:1:48:M*,N,N,S:.:Windows:98 (3
T30:64:1:64:M1460,N,W0,N,N,T0,N,N,S:.:Windows:98 (16)
32767:64:1:48:M*,N,N,S:.:Windows:98 (4)
37300:64:1:48:M*,N,N,S:.:Windows:98 (5)
46080:64:1:52:M*,N,W3,N,N,S:.:Windows:98 (RFC1323+)
65535:64:1:44:M*:.:Windows:98 (no sack)
S16:128:1:48:M*,N,N,S:.:Windows:98 (6)
S16:128:1:64:M*,N,W0,N,N,T0,N,N,S:.:Windows:98 (7)
S26:128:1:48:M*,N,N,S:.:Windows:98 (8)
T30:128:1:48:M*,N,N,S:.:Windows:98 (9)
32767:128:1:52:M*,N,W0,N,N,S:.:Windows:98 (10)
60352:128:1:48:M*,N,N,S:.:Windows:98 (11)
60352:128:1:64:M*,N,W2,N,N,T0,N,N,S:.:Windows:98 (12)

# What's with 1414 on NT?
T31:128:1:44:M1414:.:Windows:NT 4.0 SP6a (1)
64512:128:1:44:M1414:.:Windows:NT 4.0 SP6a (2)
8192:128:1:44:M*:.:Windows:NT 4.0 (older)

# Windows XP and 2000. Most of the signatures that were
# either dubious or non-specific (no service pack data)
# were deleted and replaced with generics at the end.

65535:128:1:48:M*,N,N,S:.:Windows:2000 SP4, XP SP1+
%8192:128:1:48:M*,N,N,S:.:Windows:2000 SP2+, XP SP1+ (seldom 98)
S20:128:1:48:M*,N,N,S:.:Windows:SP3
S45:128:1:48:M*,N,N,S:.:Windows:2000 SP4, XP SP1+ (2)
40320:128:1:48:M*,N,N,S:.:Windows:2000 SP4

S6:128:1:48:M*,N,N,S:.:Windows:XP, 2000 SP2+
S12:128:1:48:M*,N,N,S:.:Windows:XP SP1+ (1)
S44:128:1:48:M*,N,N,S:.:Windows:XP SP1+, 2000 SP3
64512:128:1:48:M*,N,N,S:.:Windows:XP SP1+, 2000 SP3 (2)
32767:128:1:48:M*,N,N,S:.:Windows:XP SP1+, 2000 SP4 (3)

# Windows 2003 & Vista

8192:128:1:52:M*,W8,N,N,N,S:.:Windows:Vista (beta)
32768:32:1:52:M1460,N,W0,N,N,S:.:Windows:2003 AS
65535:64:1:52:M1460,N,W2,N,N,S:.:Windows:2003 (1)
65535:64:1:48:M1460,N,N,S:.:Windows:2003 (2)

# Odds, ends, mods:

S52:128:1:48:M1260,N,N,S:.:Windows:XP/2000 via Cisco
65520:128:1:48:M*,N,N,S:.:Windows:XP bare-bone
16384:128:1:52:M536,N,W0,N,N,S:.:Windows:2000 w/ZoneAlarm?
2048:255:0:40:.:.:Windows:.NET Enterprise Server
44620:64:0:48:M*,N,N,S:.:Windows:ME no SP (?)
S6:255:1:48:M536,N,N,S:.:Windows:95 winsock 2
32000:128:0:48:M*,N,N,S:.:Windows:XP w/Winroute?
16384:64:1:48:M1452,N,N,S:.:Windows:XP w/Sygate? (1)
17256:64:1:48:M1460,N,N,S:.:Windows:XP w/Sygate? (2)

# No need to be more specific, it passes:
*:128:1:48:M*,N,N,S:U:-Windows:XP/2000 while downloading (leak!)

# ----------------- HP/UX -------------------

32768:64:1:44:M*:.:HP-UX:B.10.20 
32768:64:1:48:M*,W0,N:.:HP-UX:11.00-11.11

# Whoa. Hardcore WSS.
0:64:0:48:M*,W0,N:.:HP-UX:B.11.00 A (RFC1323+)

# ----------------- RiscOS ------------------

16384:64:1:68:M1460,N,W0,N,N,T,N,N,?12:.:RISC OS:3.70-4.36 (inet 5.04)
12288:32:0:44:M536:.:RISC OS:3.70 inet 4.10
4096:64:1:56:M1460,N,N,T:T:RISC OS:3.70 freenet 2.00

# ----------------- BSD/OS ------------------

8192:64:1:60:M1460,N,W0,N,N,T:.:BSD/OS:3.1-4.3 (or MacOS X 10.2)

# ---------------- NetwonOS -----------------

4096:64:0:44:M1420:.:NewtonOS:2.1

# ---------------- NeXTSTEP -----------------

S8:64:0:44:M512:.:NeXTSTEP:3.3 (1)
S4:64:0:44:M1024:.:NeXTSTEP:3.3 (2)

# ------------------ BeOS -------------------

1024:255:0:48:M*,N,W0:.:BeOS:5.0-5.1
12288:255:0:44:M*:.:BeOS:5.0.x

# ------------------ OS/400 -----------------

8192:64:1:60:M1440,N,W0,N,N,T:.:OS/400:V4R4/R5
8192:64:0:44:M536:.:OS/400:V4R3/M0
4096:64:1:60:M1440,N,W0,N,N,T:.:OS/400:V4R5 + CF67032

28672:64:0:44:M1460:A:OS/390:?

# ------------------ ULTRIX -----------------

16384:64:0:40:.:.:ULTRIX:4.5

# ------------------- QNX -------------------

S16:64:0:44:M512:.:QNX:demodisk
16384:64:0:60:M1460,N,W0,N,N,T0:.:QNX:6.x

# ------------------ Novell -----------------

16384:128:1:44:M1460:.:Novell:NetWare 5.0
6144:128:1:44:M1460:.:Novell:IntranetWare 4.11
6144:128:1:44:M1368:.:Novell:BorderManager ?

# According to rfp:
6144:128:1:52:M*,W0,N,S,N,N:.:Novell:Netware 6 SP3

# -------------- SCO UnixWare ---------------

S3:64:1:60:M1460,N,W0,N,N,T:.:SCO:UnixWare 7.1
S17:64:1:60:M*,N,W0,N,N,T:.:SCO:UnixWare 7.1.x
S23:64:1:44:M1380:.:SCO:OpenServer 5.0

# ------------------- DOS -------------------

2048:255:0:44:M536:.:DOS:Arachne via WATTCP/1.05
T2:255:0:44:M984:.:DOS:Arachne via WATTCP/1.05 (eepro)
16383:64:0:44:M536:.:DOS:Unknown via WATTCP (epppd)

# ------------------ OS/2 -------------------

S56:64:0:44:M512:.:OS/2:4
28672:64:0:44:M1460:.:OS/2:Warp 4.0

# ----------------- TOPS-20 -----------------

# Another hardcore MSS, one of the ACK leakers hunted down.
0:64:0:44:M1460:A:TOPS-20:version 7

# ------------------ AMIGA ------------------

S32:64:1:56:M*,N,N,S,N,N,?12:.:AMIGA:3.9 BB2 with Miami stack

# ------------------ Minix ------------------

# Not quite sure.
# 8192:210:0:44:M1460:X:@Minix:?

# ------------------ Plan9 ------------------

65535:255:0:48:M1460,W0,N:.:Plan9:edition 4

# ----------------- AMIGAOS -----------------

16384:64:1:48:M1560,N,N,S:.:AMIGAOS:3.9 BB2 MiamiDX

# ----------------- FreeMiNT ----------------

S44:255:0:44:M536:.:FreeMiNT:1 patch 16A (Atari)

###########################################
# Appliance / embedded / other signatures #
###########################################

# ---------- Firewalls / routers ------------

S12:64:1:44:M1460:.:@Checkpoint:(unknown 1)
S12:64:1:48:N,N,S,M1460:.:@Checkpoint:(unknown 2)
4096:32:0:44:M1460:.:ExtremeWare:4.x

S32:64:0:68:M512,N,W0,N,N,T,N,N,?12:.:Nokia:IPSO w/Checkpoint NG FP3
S16:64:0:68:M1024,N,W0,N,N,T,N,N,?12:.:Nokia:IPSO 3.7 build 026

S4:64:1:60:W0,N,S,T,M1460:.:FortiNet:FortiGate 50

8192:64:1:44:M1460:.:@Eagle:Secure Gateway

# ------- Switches and other stuff ----------

4128:255:0:44:M*:Z:Cisco:7200, Catalyst 3500, etc
S8:255:0:44:M*:.:Cisco:12008
S4:255:0:44:M536:Z:Cisco:IOS 11.0
60352:128:1:64:M1460,N,W2,N,N,T,N,N,S:.:Alteon:ACEswitch
64512:128:1:44:M1370:.:Nortel:Contivity Client

# ---------- Caches and whatnots ------------

8190:255:0:44:M1428:.:Google:Wireless Transcoder (1)
8190:255:0:44:M1460:.:Google:Wireless Transcoder (2)
8192:64:1:64:M1460,N,N,S,N,W0,N,N,T:.:NetCache:5.2
16384:64:1:64:M1460,N,N,S,N,W0,N:.:NetCache:5.3
65535:64:1:64:M1460,N,N,S,N,W*,N,N,T:.:NetCache:5.3-5.5 (or FreeBSD 5.4)
20480:64:1:64:M1460,N,N,S,N,W0,N,N,T:.:NetCache:4.1
S44:64:1:64:M1460,N,N,S,N,W0,N,N,T:.:NetCache:5.5

32850:64:1:64:N,W1,N,N,T,N,N,S,M*:.:NetCache:Data OnTap 5.x

65535:64:0:60:M1460,N,W0,N,N,T:.:CacheFlow:CacheOS 4.1
8192:64:0:60:M1380,N,N,N,N,N,N,T:.:CacheFlow:CacheOS 1.1

S4:64:0:48:M1460,N,N,S:.:Cisco:Content Engine

27085:128:0:40:.:.:Dell:PowerApp cache (Linux-based)

65535:255:1:48:N,W1,M1460:.:Inktomi:crawler
S1:255:1:60:M1460,S,T,N,W0:.:LookSmart:ZyBorg

16384:255:0:40:.:.:Proxyblocker:(what's this?)

65535:255:0:48:M*,N,N,S:.:Redline: T|X 2200

# ----------- Embedded systems --------------

S9:255:0:44:M536:.:PalmOS:Tungsten T3/C
S5:255:0:44:M536:.:PalmOS:3/4
S4:255:0:44:M536:.:PalmOS:3.5
2948:255:0:44:M536:.:PalmOS:3.5.3 (Handera)
S29:255:0:44:M536:.:PalmOS:5.0
16384:255:0:44:M1398:.:PalmOS:5.2 (Clie)
S14:255:0:44:M1350:.:PalmOS:5.2.1 (Treo)
16384:255:0:44:M1400:.:PalmOS:5.2 (Sony)

S23:64:1:64:N,W1,N,N,T,N,N,S,M1460:.:SymbianOS:7
8192:255:0:44:M1460:.:SymbianOS:6048 (Nokia 7650?)
8192:255:0:44:M536:.:SymbianOS:(Nokia 9210?)
S22:64:1:56:M1460,T,S:.:SymbianOS:? (SE P800?)
S36:64:1:56:M1360,T,S:.:SymbianOS:60xx (Nokia 6600?)
S36:64:1:60:M1360,T,S,W0,E:.:SymbianOS:60xx

32768:32:1:44:M1460:.:Windows:CE 3

# Perhaps S4?
5840:64:1:60:M1452,S,T,N,W1:.:Zaurus:3.10

32768:128:1:64:M1460,N,W0,N,N,T0,N,N,S:.:PocketPC:2002

S1:255:0:44:M346:.:Contiki:1.1-rc0

4096:128:0:44:M1460:.:Sega:Dreamcast Dreamkey 3.0
T5:64:0:44:M536:.:Sega:Dreamcast HKT-3020 (browser disc 51027)
S22:64:1:44:M1460:.:Sony:Playstation 2 (SOCOM?)

S12:64:0:44:M1452:.:AXIS:Printer Server 5600 v5.64

3100:32:1:44:M1460:.:Windows:CE 2.0

####################
# Fancy signatures #
####################

1024:64:0:40:.:.:-*NMAP:syn scan (1)
2048:64:0:40:.:.:-*NMAP:syn scan (2)
3072:64:0:40:.:.:-*NMAP:syn scan (3)
4096:64:0:40:.:.:-*NMAP:syn scan (4)

1024:64:0:40:.:A:-*NMAP:TCP sweep probe (1)
2048:64:0:40:.:A:-*NMAP:TCP sweep probe (2)
3072:64:0:40:.:A:-*NMAP:TCP sweep probe (3)
4096:64:0:40:.:A:-*NMAP:TCP sweep probe (4)

1024:64:0:60:W10,N,M265,T,E:P:-*NMAP:OS detection probe (1)
2048:64:0:60:W10,N,M265,T,E:P:-*NMAP:OS detection probe (2)
3072:64:0:60:W10,N,M265,T,E:P:-*NMAP:OS detection probe (3)
4096:64:0:60:W10,N,M265,T,E:P:-*NMAP:OS detection probe (4)

1024:64:0:60:W10,N,M265,T,E:PF:-*NMAP:OS detection probe w/flags (1)
2048:64:0:60:W10,N,M265,T,E:PF:-*NMAP:OS detection probe w/flags (2)
3072:64:0:60:W10,N,M265,T,E:PF:-*NMAP:OS detection probe w/flags (3)
4096:64:0:60:W10,N,M265,T,E:PF:-*NMAP:OS detection probe w/flags (4)

32767:64:0:40:.:.:-*NAST:syn scan

12345:255:0:40:.:A:-p0f:sendsyn utility

# UFO - see tmp/*:
56922:128:0:40:.:A:-@Mysterious:port scanner (?)
5792:64:1:60:M1460,S,T,N,W0:T:-@Mysterious:NAT device (2nd tstamp)
S12:128:1:48:M1460,E:P:@Mysterious:Chello proxy (?)
S23:64:1:64:N,W1,N,N,T,N,N,S,M1380:.:@Mysterious:GPRS gateway (?)

#####################################
# Generic signatures - just in case #
#####################################

*:128:1:52:M*,N,W0,N,N,S:.:@Windows:XP/2000 (RFC1323+, w, tstamp-)
*:128:1:52:M*,N,W*,N,N,S:.:@Windows:XP/2000 (RFC1323+, w+, tstamp-)
*:128:1:52:M*,N,N,T0,N,N,S:.:@Windows:XP/2000 (RFC1323+, w-, tstamp+)
*:128:1:64:M*,N,W0,N,N,T0,N,N,S:.:@Windows:XP/2000 (RFC1323+, w, tstamp+)
*:128:1:64:M*,N,W*,N,N,T0,N,N,S:.:@Windows:XP/2000 (RFC1323+, w+, tstamp+)

*:128:1:48:M536,N,N,S:.:@Windows:98
*:128:1:48:M*,N,N,S:.:@Windows:XP/2000


