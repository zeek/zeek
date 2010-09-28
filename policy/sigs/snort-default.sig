signature sid-524-a {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 0
  event "BAD-TRAFFIC tcp port 0 traffic"
  }

signature sid-524-b {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 0
  event "BAD-TRAFFIC tcp port 0 traffic"
  }

signature sid-525-a {
  ip-proto == udp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 0
  event "BAD-TRAFFIC udp port 0 traffic"
  }

signature sid-525-b {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 0
  event "BAD-TRAFFIC udp port 0 traffic"
  }

signature sid-526 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  payload-size > 6
  header tcp[13:1] & 255 == 2
  event "BAD-TRAFFIC data in TCP SYN packet"
  }

signature sid-528-a {
  src-ip == 127.0.0.0/8
  event "BAD-TRAFFIC loopback traffic"
  }

signature sid-528-b {
  dst-ip == 127.0.0.0/8
  event "BAD-TRAFFIC loopback traffic"
  }

signature sid-527 {
  same-ip
  event "BAD-TRAFFIC same SRC/DST"
  }

signature sid-523 {
  src-ip != local_nets
  dst-ip == local_nets
  event "BAD-TRAFFIC ip reserved bit set"
  header ip[6:1] & 224 == 128
  }

signature sid-1321 {
  src-ip != local_nets
  dst-ip == local_nets
  event "BAD-TRAFFIC 0 ttl"
  header ip[8:1] == 0
  }

signature sid-1322 {
  src-ip != local_nets
  dst-ip == local_nets
  event "BAD-TRAFFIC bad frag bits"
  header ip[6:1] & 224 == 96
  }

signature sid-1627 {
  src-ip != local_nets
  dst-ip == local_nets
  header ip[9:1] > 134
  event "BAD-TRAFFIC Unassigned/Reserved IP protocol"
  }

signature sid-1431 {
  ip-proto == tcp
  dst-ip == 232.0.0.0/8,233.0.0.0/8,239.0.0.0/8
  event "BAD-TRAFFIC syn to multicast address"
  header tcp[13:1] & 255 == 2
  }

signature sid-2186 {
  header ip[9:1] == 53
  event "BAD-TRAFFIC IP Proto 53 (SWIPE)"
  }

signature sid-2187 {
  header ip[9:1] == 55
  event "BAD-TRAFFIC IP Proto 55 (IP Mobility)"
  }

signature sid-2188 {
  header ip[9:1] == 77
  event "BAD-TRAFFIC IP Proto 77 (Sun ND)"
  }

signature sid-2189 {
  header ip[9:1] == 103
  event "BAD-TRAFFIC IP Proto 103 (PIM)"
  }

signature sid-1324 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 22
  event "EXPLOIT ssh CRC32 overflow /bin/sh"
  tcp-state established,originator
  payload /.*\/bin\/sh/
  }

signature sid-1326 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 22
  event "EXPLOIT ssh CRC32 overflow NOOP"
  tcp-state established,originator
  payload /.*\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90/
  }

signature sid-1327 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 22
  event "EXPLOIT ssh CRC32 overflow"
  tcp-state established,originator
  payload /\x00\x01\x57\x00\x00\x00\x18/
  payload /.{7}\xFF\xFF\xFF\xFF\x00\x00/
  }

signature sid-283 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == 80
  event "EXPLOIT Netscape 4.7 client overflow"
  tcp-state established,responder
  payload /.*\x33\xC9\xB1\x10\x3F\xE9\x06\x51\x3C\xFA\x47\x33\xC0\x50\xF7\xD0\x50/
  }

signature sid-300 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 2766
  event "EXPLOIT nlps x86 Solaris overflow"
  tcp-state established,originator
  payload /.*\xeb\x23\x5e\x33\xc0\x88\x46\xfa\x89\x46\xf5\x89\x36/
  }

signature sid-301 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 515
  event "EXPLOIT LPRng overflow"
  tcp-state established,originator
  payload /.*\x43\x07\x89\x5B\x08\x8D\x4B\x08\x89\x43\x0C\xB0\x0B\xCD\x80\x31\xC0\xFE\xC0\xCD\x80\xE8\x94\xFF\xFF\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x0A/
  }

signature sid-302 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 515
  event "EXPLOIT Redhat 7.0 lprd overflow"
  tcp-state established,originator
  payload /.*\x58\x58\x58\x58\x25\x2E\x31\x37\x32\x75\x25\x33\x30\x30\x24\x6E/
  }

signature sid-304 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 6373
  event "EXPLOIT SCO calserver overflow"
  tcp-state established,originator
  payload /.*\xeb\x7f\x5d\x55\xfe\x4d\x98\xfe\x4d\x9b/
  }

signature sid-305 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8080
  payload-size > 1000
  event "EXPLOIT delegate proxy overflow"
  tcp-state established,originator
  payload /.*[wW][hH][oO][iI][sS]\x3a\/\//
  }

signature sid-306 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 9090
  event "EXPLOIT VQServer admin"
  tcp-state established,originator
  payload /.*[gG][eE][tT] \/ [hH][tT][tT][pP]\/1\.1/
  }

signature sid-308 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == 21
  event "EXPLOIT NextFTP client overflow"
  tcp-state established,responder
  payload /.*\xb4\x20\xb4\x21\x8b\xcc\x83\xe9\x04\x8b\x19\x33\xc9\x66\xb9\x10/
  }

signature sid-309 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  payload-size > 512
  header tcp[13:1] & 255 == 16
  event "EXPLOIT sniffit overflow"
  payload /.*[fF][rR][oO][mM]\x3A\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90/
  }

signature sid-310 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "EXPLOIT x86 windows MailMax overflow"
  tcp-state established,originator
  payload /.*\xeb\x45\xeb\x20\x5b\xfc\x33\xc9\xb1\x82\x8b\xf3\x80\x2b/
  }

signature sid-311 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  dst-port == 80
  event "EXPLOIT Netscape 4.7 unsucessful overflow"
  tcp-state established,originator
  payload /.*\x33\xC9\xB1\x10\x3F\xE9\x06\x51\x3C\xFA\x47\x33\xC0\x50\xF7\xD0\x50/
  }

signature sid-312 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 123
  payload-size > 128
  event "EXPLOIT ntpdx overflow attempt"
  }

signature sid-313 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 518
  event "EXPLOIT ntalkd x86 Linux overflow"
  payload /.*\x01\x03\x00\x00\x00\x00\x00\x01\x00\x02\x02\xe8/
  }

signature sid-315 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 635
  event "EXPLOIT x86 Linux mountd overflow"
  payload /.*\x5e\xb0\x02\x89\x06\xfe\xc8\x89\x46\x04\xb0\x06\x89\x46/
  }

signature sid-316 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 635
  event "EXPLOIT x86 Linux mountd overflow"
  payload /.*\xeb\x56\x5E\x56\x56\x56\x31\xd2\x88\x56\x0b\x88\x56\x1e/
  }

signature sid-317 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 635
  event "EXPLOIT x86 Linux mountd overflow"
  payload /.*\xeb\x40\x5E\x31\xc0\x40\x89\x46\x04\x89\xc3\x40\x89\x06/
  }

signature sid-1240 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 2224
  event "EXPLOIT MDBMS overflow"
  tcp-state established,originator
  payload /.*\x01\x31\xDB\xCD\x80\xE8\x5B\xFF\xFF\xFF/
  }

signature sid-1261 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 4242
  payload-size > 1000
  event "EXPLOIT AIX pdnsd overflow"
  tcp-state established,originator
  payload /.*\x7F\xFF\xFB\x78\x7F\xFF\xFB\x78\x7F\xFF\xFB\x78\x7F\xFF\xFB\x78/
  payload /.*\x40\x8A\xFF\xC8\x40\x82\xFF\xD8\x3B\x36\xFE\x03\x3B\x76\xFE\x02/
  }

signature sid-1323 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 4321
  event "EXPLOIT rwhoisd format string attempt"
  tcp-state established,originator
  payload /.*-soa %p/
  }

signature sid-1398 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 6112
  event "EXPLOIT CDE dtspcd exploit attempt"
  tcp-state established,originator
  payload /.{9}1/
  payload /.{10}<willnevermatch>/
  }

signature sid-1751 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 32772
  dst-port <= 34000
  payload-size > 720
  event "EXPLOIT cachefsd buffer overflow attempt"
  tcp-state established,originator
  payload /.*\x00\x01\x87\x86\x00\x00\x00\x01\x00\x00\x00\x05/
  }

signature sid-1894 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 749
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\x00\xC0\x05\x08\x00\xC0\x05\x08\x00\xC0\x05\x08\x00\xC0\x05\x08/
  }

signature sid-1895 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 751
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\x00\xC0\x05\x08\x00\xC0\x05\x08\x00\xC0\x05\x08\x00\xC0\x05\x08/
  }

signature sid-1896 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 749
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\xff\xff\x4b\x41\x44\x4d\x30\x2e\x30\x41\x00\x00\xfb\x03/
  }

signature sid-1897 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 751
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\xff\xff\x4b\x41\x44\x4d\x30\x2e\x30\x41\x00\x00\xfb\x03/
  }

signature sid-1898 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 749
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\x2F\x73\x68\x68\x2F\x2F\x62\x69/
  }

signature sid-1899 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 751
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\x2F\x73\x68\x68\x2F\x2F\x62\x69/
  }

signature sid-1812 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 22
  event "EXPLOIT gobbles SSH exploit attempt"
  tcp-state established,originator
  payload /.*GOBBLES/
  }

signature sid-1821 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 515
  event "EXPLOIT LPD dvips remote command execution attempt"
  tcp-state established,originator
  payload /.*psfile=\x22\x60/
  }

signature sid-1838 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == 22
  event "EXPLOIT SSH server banner overflow"
  tcp-state established,responder
  payload /SSH-[^\x0a]{600}/
  }

signature sid-307 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 6666
  dst-port <= 7000
  event "EXPLOIT CHAT IRC topic overflow"
  tcp-state established,responder
  payload /.*\xeb\x4b\x5b\x53\x32\xe4\x83\xc3\x0b\x4b\x88\x23\xb8\x50\x77/
  }

signature sid-1382 {
  ip-proto == tcp
  dst-port >= 6666
  dst-port <= 7000
  event "EXPLOIT CHAT IRC Ettercap parse overflow attempt"
  tcp-state established,originator
  payload /.*[pP][rR][iI][vV][mM][sS][gG] [nN][iI][cC][kK][sS][eE][rR][vV] [iI][dD][eE][nN][tT][iI][fF][yY][^\x0a]{150}/
  }

signature sid-292 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "EXPLOIT x86 Linux samba overflow"
  tcp-state established,originator
  payload /.*\xeb\x2f\x5f\xeb\x4a\x5e\x89\xfb\x89\x3e\x89\xf2/
  }

signature sid-613 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == 10101
  header tcp[8:4] == 0
  header tcp[13:1] & 255 == 2
  header ip[8:1] > 220
  event "SCAN myscan"
  }

signature sid-616 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 113
  event "SCAN ident version request"
  tcp-state established,originator
  payload /.{0,8}VERSION\x0A/
  }

signature sid-619 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 80
  payload-size == 0
  header tcp[13:1] & 255 == 195
  event "SCAN cybercop os probe"
  }

signature sid-618 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 3128
  event "SCAN Squid Proxy attempt"
  header tcp[13:1] & 255 == 2
  }

signature sid-615 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1080
  header tcp[13:1] & 255 == 2
  event "SCAN SOCKS Proxy attempt"
  }

signature sid-620 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8080
  event "SCAN Proxy (8080) attempt"
  header tcp[13:1] & 255 == 2
  }

signature sid-621 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 1
  event "SCAN FIN"
  }

signature sid-622 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 2
  header tcp[4:4] == 1958810375
  event "SCAN ipEye SYN scan"
  }

signature sid-623 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[8:4] == 0
  header tcp[13:1] & 255 == 0
  header tcp[4:4] == 0
  event "SCAN NULL"
  }

signature sid-624 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 3
  event "SCAN SYN FIN"
  }

signature sid-625 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 63
  event "SCAN XMAS"
  }

signature sid-1228 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 41
  event "SCAN nmap XMAS"
  }

signature sid-628 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[8:4] == 0
  header tcp[13:1] & 255 == 16
  event "SCAN nmap TCP"
  }

signature sid-629 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 43
  event "SCAN nmap fingerprint attempt"
  }

signature sid-630 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 3
  event "SCAN synscan portscan"
  header ip[4:2] == 39426
  }

signature sid-626 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 216
  event "SCAN cybercop os PA12 attempt"
  payload /AAAAAAAAAAAAAAAA/
  }

signature sid-627 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[8:4] == 0
  header tcp[13:1] & 255 == 227
  event "SCAN cybercop os SFU12 probe"
  payload /AAAAAAAAAAAAAAAA/
  }

signature sid-634 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 10080
  dst-port <= 10081
  event "SCAN Amanda client version request"
  payload /.*[aA][mM][aA][nN][dD][aA]/
  }

signature sid-635 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 49
  event "SCAN XTACACS logout"
  payload /.*\x80\x07\x00\x00\x07\x00\x00\x04\x00\x00\x00\x00\x00/
  }

signature sid-636 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 7
  event "SCAN cybercop udp bomb"
  payload /.*cybercop/
  }

signature sid-637 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "SCAN Webtrends Scanner UDP Probe"
  payload /.*\x0Ahelp\x0Aquite\x0A/
  }

signature sid-1638 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 22
  event "SCAN SSH Version map attempt"
  tcp-state established,originator
  payload /.*[vV][eE][rR][sS][iI][oO][nN]_[mM][aA][pP][pP][eE][rR]/
  }

signature sid-1917 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1900
  event "SCAN UPnP service discover attempt"
  payload /M-SEARCH /
  payload /.*ssdp:discover/
  }

signature sid-1918 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[1:1] == 0
  header icmp[0:1] == 8
  event "SCAN SolarWinds IP scan attempt"
  payload /.*SolarWinds\.Net/
  }

signature sid-1133 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  header tcp[8:4] == 0
  header tcp[13:1] & 255 == 11
  event "SCAN cybercop os probe"
  payload /AAAAAAAAAAAAAAAA/
  }

signature sid-320 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER cmd_rootsh backdoor attempt"
  tcp-state established,originator
  payload /.*cmd_rootsh/
  }

signature sid-321 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER account enumeration attempt"
  tcp-state established,originator
  payload /.*[aA] [bB] [cC] [dD] [eE] [fF]/
  }

signature sid-322 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER search query"
  tcp-state established,originator
  payload /.*search/
  }

signature sid-323 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER root query"
  tcp-state established,originator
  payload /.*root/
  }

signature sid-324 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER null request"
  tcp-state established,originator
  payload /.*\x00/
  }

signature sid-326 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER remote command ; execution attempt"
  tcp-state established,originator
  payload /.*\x3b/
  }

signature sid-327 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER remote command pipe execution attempt"
  tcp-state established,originator
  payload /.*\x7c/
  }

signature sid-328 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER bomb attempt"
  tcp-state established,originator
  payload /.*@@/
  }

signature sid-330 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER redirection attempt"
  tcp-state established,originator
  payload /.*@/
  }

signature sid-331 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER cybercop query"
  tcp-state established,originator
  payload /.{0,4}\x0A     /
  }

signature sid-332 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER 0 query"
  tcp-state established,originator
  payload /.*0/
  }

signature sid-333 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER . query"
  tcp-state established,originator
  payload /.*\./
  }

signature sid-1541 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 79
  event "FINGER version query"
  tcp-state established,originator
  payload /.*version/
  }

signature sid-337 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP CEL overflow attempt"
  tcp-state established,originator
  payload /.*[cC][eE][lL] [^\x0a]{100}/
  }

signature sid-1919 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP CWD overflow attempt"
  tcp-state established,originator
  payload /.*[cC][wW][dD] [^\x0a]{100}/
  }

signature sid-1621 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP CMD overflow attempt"
  tcp-state established,originator
  payload /.*[cC][mM][dD] [^\x0a]{100}/
  }

signature sid-1379 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP STAT overflow attempt"
  tcp-state established,originator
  payload /.*[sS][tT][aA][tT] [^\x0a]{100}/
  }

signature sid-1562 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP SITE CHOWN overflow attempt"
  tcp-state established,originator
  payload /.*[sS][iI][tT][eE] /
  payload /.* [cC][hH][oO][wW][nN] [^\x0a]{100}/
  }

signature sid-1920 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP SITE NEWER overflow attempt"
  tcp-state established,originator
  payload /.*[sS][iI][tT][eE] /
  payload /.* [nN][eE][wW][eE][rR] [^\x0a]{100}/
  }

signature sid-1888 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP SITE CPWD overflow attempt"
  tcp-state established,originator
  payload /.*[sS][iI][tT][eE] /
  payload /.* [cC][pP][wW][dD] [^\x0a]{100}/
  }

signature sid-1971 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP SITE EXEC format string attempt"
  tcp-state established,originator
  payload /.*[sS][iI][tT][eE].*.{0}.*[eE][xX][eE][cC] .{1}.*%.{1}.*%/
  }

signature sid-1529 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP SITE overflow attempt"
  tcp-state established,originator
  payload /.*[sS][iI][tT][eE] [^\x0a]{100}/
  }

signature sid-1734 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP USER overflow attempt"
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR] [^\x0a]{100}/
  }

signature sid-1972 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP PASS overflow attempt"
  tcp-state established,originator
  payload /.*[pP][aA][sS][sS] [^\x0a]{100}/
  }

signature sid-1942 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP RMDIR overflow attempt"
  tcp-state established,originator
  payload /.*[rR][mM][dD][iI][rR] [^\x0a]{100}/
  }

signature sid-1973 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP MKD overflow attempt"
  tcp-state established,originator
  payload /.*[mM][kK][dD] [^\x0a]{100}/
  }

signature sid-1974 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP REST overflow attempt"
  tcp-state established,originator
  payload /.*[rR][eE][sS][tT] [^\x0a]{100}/
  }

signature sid-1975 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP DELE overflow attempt"
  tcp-state established,originator
  payload /.*[dD][eE][lL][eE] [^\x0a]{100}/
  }

signature sid-1976 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP RMD overflow attempt"
  tcp-state established,originator
  payload /.*[rR][mM][dD] [^\x0a]{100}/
  }

signature sid-1623 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP invalid MODE"
  tcp-state established,originator
  payload /.*[mM][oO][dD][eE] /
  payload /.*<willnevermatch>/
  payload /.*<willnevermatch>/
  payload /.*<willnevermatch>/
  payload /.*<willnevermatch>/
  }

signature sid-1624 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  payload-size == 10
  event "FTP large PWD command"
  tcp-state established,originator
  payload /.*[pP][wW][dD]/
  }

signature sid-1625 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  payload-size == 10
  event "FTP large SYST command"
  tcp-state established,originator
  payload /.*[sS][yY][sS][tT]/
  }

signature sid-2125 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP CWD C:\"
  tcp-state established,originator
  payload /.*[cC][wW][dD].{1}.*C:\\/
  }

signature sid-1921 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP SITE ZIPCHK attempt"
  tcp-state established,originator
  payload /.*[sS][iI][tT][eE] /
  payload /.* [zZ][iI][pP][cC][hH][kK] [^\x0a]{100}/
  }

signature sid-1864 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP SITE NEWER attempt"
  tcp-state established,originator
  payload /.*[sS][iI][tT][eE] /
  payload /.* [nN][eE][wW][eE][rR] /
  }

signature sid-361 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP site exec"
  tcp-state established,originator
  payload /.*[sS][iI][tT][eE] .*.{0}.*[eE][xX][eE][cC] /
  }

signature sid-1777 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP EXPLOIT STAT * dos attempt"
  tcp-state established,originator
  payload /.*[sS][tT][aA][tT].{1}.*\*/
  }

signature sid-1778 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP EXPLOIT STAT ? dos attempt"
  tcp-state established,originator
  payload /.*[sS][tT][aA][tT].{1}.*\?/
  }

signature sid-362 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP tar parameters"
  tcp-state established,originator
  payload /.*\" --[uU][sS][eE]-[cC][oO][mM][pP][rR][eE][sS][sS]-[pP][rR][oO][gG][rR][aA][mM]\" /
  }

signature sid-336 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP CWD ~root attempt"
  tcp-state established,originator
  payload /.*CWD /
  payload /.* ~[rR][oO][oO][tT]/
  }

signature sid-1229 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP CWD ..."
  tcp-state established,originator
  payload /.*CWD /
  payload /.* \.\.\./
  }

signature sid-1672 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP CWD ~<NEWLINE> attempt"
  tcp-state established,originator
  payload /.*CWD /
  payload /.* ~\x0A/
  }

signature sid-1728 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP CWD ~<CR><NEWLINE> attempt"
  tcp-state established,originator
  payload /.*CWD /
  payload /.* ~\x0D\x0A/
  }

signature sid-1779 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP CWD .... attempt"
  tcp-state established,originator
  payload /.*CWD /
  payload /.* \.\.\.\./
  }

signature sid-360 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP serv-u directory transversal"
  tcp-state established,originator
  payload /.*\.%20\./
  }

signature sid-1377 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP wu-ftp bad file completion attempt ["
  tcp-state established,originator
  payload /.*~.{1}.*\[/
  }

signature sid-1378 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP wu-ftp bad file completion attempt {"
  tcp-state established,originator
  payload /.*~.{1}.*\{/
  }

signature sid-1530 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP format string attempt"
  tcp-state established,originator
  payload /.*%[pP]/
  }

signature sid-1622 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP RNFR ././ attempt"
  tcp-state established,originator
  payload /.*[rR][nN][fF][rR] /
  payload /.* \.\/\.\//
  }

signature sid-1748 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  payload-size > 100
  event "FTP command overflow attempt"
  tcp-state established,originator
  }

signature sid-1992 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP LIST directory traversal attempt"
  payload /.*LIST.{1}.*\.\..{1}.*\.\./
  }

signature sid-334 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP .forward"
  tcp-state established,originator
  payload /.*\.forward/
  }

signature sid-335 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP .rhosts"
  tcp-state established,originator
  payload /.*\.rhosts/
  }

signature sid-1927 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP authorized_keys"
  tcp-state established,originator
  payload /.*authorized_keys/
  }

signature sid-356 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP passwd retrieval attempt"
  tcp-state established,originator
  payload /.*[rR][eE][tT][rR]/
  payload /.*passwd/
  }

signature sid-1928 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP shadow retrieval attempt"
  tcp-state established,originator
  payload /.*[rR][eE][tT][rR]/
  payload /.*shadow/
  }

signature sid-144 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP ADMw0rm ftp login attempt"
  tcp-state established,originator
  payload /.*USER w0rm\x0D\x0A/
  }

signature sid-353 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP adm scan"
  tcp-state established,originator
  payload /.*PASS ddd@\x0a/
  }

signature sid-354 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP iss scan"
  tcp-state established,originator
  payload /.*pass -iss@iss/
  }

signature sid-355 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP pass wh00t"
  tcp-state established,originator
  payload /.*[pP][aA][sS][sS] [wW][hH]00[tT]/
  }

signature sid-357 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP piss scan"
  tcp-state established,originator
  payload /.*pass -cklaus/
  }

signature sid-358 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP saint scan"
  tcp-state established,originator
  payload /.*pass -saint/
  }

signature sid-359 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 21
  event "FTP satan scan"
  tcp-state established,originator
  payload /.*pass -satan/
  }

signature sid-1430 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == telnet_servers
  dst-port == 23
  event "TELNET Solaris memory mismanagement exploit attempt"
  tcp-state established,originator
  payload /.*\xA0\x23\xA0\x10\xAE\x23\x80\x10\xEE\x23\xBF\xEC\x82\x05\xE0\xD6\x90\x25\xE0/
  }

signature sid-711 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == telnet_servers
  dst-port == 23
  event "TELNET SGI telnetd format bug"
  tcp-state established,originator
  payload /.*_RLD/
  payload /.*bin\/sh/
  }

signature sid-712 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == telnet_servers
  dst-port == 23
  event "TELNET ld_library_path"
  tcp-state established,originator
  payload /.*ld_library_path/
  }

signature sid-713 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == telnet_servers
  dst-port == 23
  event "TELNET livingston DOS"
  tcp-state established,originator
  payload /.*\xff\xf3\xff\xf3\xff\xf3\xff\xf3\xff\xf3/
  }

signature sid-714 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == telnet_servers
  dst-port == 23
  event "TELNET resolv_host_conf"
  tcp-state established,originator
  payload /.*resolv_host_conf/
  }

signature sid-715 {
  ip-proto == tcp
  src-ip == telnet_servers
  dst-ip != local_nets
  src-port == 23
  event "TELNET Attempted SU from wrong group"
  tcp-state established,responder
  payload /.*[tT][oO] [sS][uU] [rR][oO][oO][tT]/
  }

signature sid-717 {
  ip-proto == tcp
  src-ip == telnet_servers
  dst-ip != local_nets
  src-port == 23
  event "TELNET not on console"
  tcp-state established,responder
  payload /.*[nN][oO][tT] [oO][nN] [sS][yY][sS][tT][eE][mM] [cC][oO][nN][sS][oO][lL][eE]/
  }

signature sid-718 {
  ip-proto == tcp
  src-ip == telnet_servers
  dst-ip != local_nets
  src-port == 23
  event "TELNET login incorrect"
  tcp-state established,responder
  payload /.*Login incorrect/
  }

signature sid-719 {
  ip-proto == tcp
  src-ip == telnet_servers
  dst-ip != local_nets
  src-port == 23
  event "TELNET root login"
  tcp-state established,responder
  payload /.*login: root/
  }

signature sid-1252 {
  ip-proto == tcp
  src-ip == telnet_servers
  dst-ip != local_nets
  src-port == 23
  event "TELNET bsd telnet exploit response"
  tcp-state established,responder
  payload /.*\x0D\x0A\[Yes\]\x0D\x0A\xFF\xFE\x08\xFF\xFD\x26/
  }

signature sid-1253 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == telnet_servers
  dst-port == 23
  payload-size > 200
  event "TELNET bsd exploit client finishing"
  tcp-state established,responder
  payload /.{199}\xFF\xF6\xFF\xF6\xFF\xFB\x08\xFF\xF6/
  }

signature sid-709 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == telnet_servers
  dst-port == 23
  event "TELNET 4Dgifts SGI account attempt"
  tcp-state established,originator
  payload /.*4Dgifts/
  }

signature sid-710 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == telnet_servers
  dst-port == 23
  event "TELNET EZsetup account attempt"
  tcp-state established,originator
  payload /.*OutOfBox/
  }

signature sid-716 {
  ip-proto == tcp
  src-ip == telnet_servers
  dst-ip != local_nets
  src-port == 23
  event "TELNET access"
  tcp-state established,responder
  payload /.*\xFF\xFD\x18\xFF\xFD\x1F\xFF\xFD\x23\xFF\xFD\x27\xFF\xFD\x24/
  }

signature sid-2093 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_test: 4,>,2048,12,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap proxy integer overflow attempt TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0\x00.{3}\x00\x00\x00\x05/
  }

signature sid-2092 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap proxy integer overflow attempt UDP"
  # Not supported: byte_test: 4,>,2048,12,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0\x00.{3}\x00\x00\x00\x05/
  }

signature sid-1922 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  event "RPC portmap proxy attempt TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x05/
  }

signature sid-1923 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  event "RPC portmap proxy attempt UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x05/
  }

signature sid-1280 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  event "RPC portmap listing UDP 111"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x04/
  }

signature sid-598 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  event "RPC portmap listing TCP 111"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x04/
  }

signature sid-1949 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  event "RPC portmap SET attempt TCP 111"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x01/
  }

signature sid-1950 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  event "RPC portmap SET attempt UDP 111"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x01/
  }

signature sid-2014 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  event "RPC portmap UNSET attempt TCP 111"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x02/
  }

signature sid-2015 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  event "RPC portmap UNSET attempt UDP 111"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x02/
  }

signature sid-599 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 32771
  event "RPC portmap listing TCP 32771"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x04/
  }

signature sid-1281 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 32771
  event "RPC portmap listing UDP 32771"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x04/
  }

signature sid-1746 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap cachefsd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x8B/
  }

signature sid-1747 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap cachefsd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x8B/
  }

signature sid-1732 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rwalld request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA8/
  }

signature sid-1733 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rwalld request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA8/
  }

signature sid-575 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap admind request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xF7/
  }

signature sid-1262 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap admind request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xF7/
  }

signature sid-576 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap amountd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x03/
  }

signature sid-1263 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap amountd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x03/
  }

signature sid-577 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap bootparam request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xBA/
  }

signature sid-1264 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap bootparam request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xBA/
  }

signature sid-580 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap nisd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\xcc/
  }

signature sid-1267 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap nisd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\xcc/
  }

signature sid-581 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap pcnfsd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x02\x49\xf1/
  }

signature sid-1268 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap pcnfsd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x02\x49\xf1/
  }

signature sid-582 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rexd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB1/
  }

signature sid-1269 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rexd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB1/
  }

signature sid-584 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rusers request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA2/
  }

signature sid-1271 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rusers request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA2/
  }

signature sid-612 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC rusers query UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA2.{4}\x00\x00\x00\x02/
  }

signature sid-586 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap selection_svc request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xAF/
  }

signature sid-1273 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap selection_svc request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xAF/
  }

signature sid-587 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap status request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB8/
  }

signature sid-2016 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap status request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB8/
  }

signature sid-593 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap snmpXdmi request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x99/
  }

signature sid-1279 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap snmpXdmi request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x99/
  }

signature sid-569 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,1024,20,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC snmpXdmi overflow attempt TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x87\x99.{4}\x00\x00\x01\x01/
  }

signature sid-2045 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC snmpXdmi overflow attempt UDP"
  # Not supported: byte_test: 4,>,1024,20,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x87\x99.{4}\x00\x00\x01\x01/
  }

signature sid-2017 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap espd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x05\xF7\x75/
  }

signature sid-595 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap espd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x05\xF7\x75/
  }

signature sid-1890 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 1024
  dst-port <= 65535
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC status GHBN format string attack"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xB8.{4}\x00\x00\x00\x02.{0,251}%x %x/
  }

signature sid-1891 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 1024
  dst-port <= 65535
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC status GHBN format string attack"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xB8.{4}\x00\x00\x00\x02.{0,251}%x %x/
  }

signature sid-579 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap mountd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA5/
  }

signature sid-1266 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap mountd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA5/
  }

signature sid-574 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd TCP export request"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x05/
  }

signature sid-1924 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd UDP export request"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x05/
  }

signature sid-1925 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd TCP exportall request"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x06/
  }

signature sid-1926 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd UDP exportall request"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x06/
  }

signature sid-1951 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd TCP mount request"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x01/
  }

signature sid-1952 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd UDP mount request"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x01/
  }

signature sid-2018 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd TCP dump request"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x02/
  }

signature sid-2019 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd UDP dump request"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x02/
  }

signature sid-2020 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd TCP unmount request"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x03/
  }

signature sid-2021 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd UDP unmount request"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x03/
  }

signature sid-2022 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd TCP unmountall request"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x04/
  }

signature sid-2023 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC mountd UDP unmountall request"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x04/
  }

signature sid-1905 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 500
  dst-port <= 65535
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC AMD UDP amqproc_mount plog overflow attempt"
  # Not supported: byte_test: 4,>,512,0,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x04\x93\xF3.{4}\x00\x00\x00\x07/
  }

signature sid-1906 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 500
  dst-port <= 65535
  # Not supported: byte_test: 4,>,512,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC AMD TCP amqproc_mount plog overflow attempt"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x04\x93\xF3.{4}\x00\x00\x00\x07/
  }

signature sid-1953 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 500
  dst-port <= 65535
  event "RPC AMD TCP pid request"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x04\x93\xF3.{4}\x00\x00\x00\x09/
  }

signature sid-1954 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 500
  dst-port <= 65535
  event "RPC AMD UDP pid request"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x04\x93\xF3.{4}\x00\x00\x00\x09/
  }

signature sid-1955 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 500
  dst-port <= 65535
  event "RPC AMD TCP version request"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x04\x93\xF3.{4}\x00\x00\x00\x08/
  }

signature sid-1956 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 500
  dst-port <= 65535
  event "RPC AMD UDP version request"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x04\x93\xF3.{4}\x00\x00\x00\x08/
  }

signature sid-578 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap cmsd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xE4/
  }

signature sid-1265 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap cmsd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xE4/
  }

signature sid-1907 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC CMSD UDP CMSD_CREATE buffer overflow attempt"
  # Not supported: byte_test: 4,>,1024,0,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xE4.{4}\x00\x00\x00\x15/
  }

signature sid-1908 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,1024,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC CMSD TCP CMSD_CREATE buffer overflow attempt"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xE4.{4}\x00\x00\x00\x15/
  }

signature sid-2094 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC CMSD UDP CMSD_CREATE array buffer overflow attempt"
  # Not supported: byte_test: 4,>,1024,20,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xE4.{4}\x00\x00\x00\x15/
  }

signature sid-2095 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,1024,20,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC CMSD TCP CMSD_CREATE array buffer overflow attempt"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xE4.{4}\x00\x00\x00\x15/
  }

signature sid-1909 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,1000,28,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align
  event "RPC CMSD TCP CMSD_INSERT buffer overflow attempt"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xE4.{4}\x00\x00\x00\x06/
  }

signature sid-1910 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align
  event "RPC CMSD udp CMSD_INSERT buffer overflow attempt"
  # Not supported: byte_test: 4,>,1000,28,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xE4.{4}\x00\x00\x00\x06/
  }

signature sid-1272 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap sadmind request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x88/
  }

signature sid-585 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap sadmind request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x88/
  }

signature sid-1911 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,124,relative,align,4,20,relative,align
  event "RPC sadmind UDP NETMGT_PROC_SERVICE CLIENT_DOMAIN overflow attempt"
  # Not supported: byte_test: 4,>,512,4,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x87\x88.{4}\x00\x00\x00\x01/
  }

signature sid-1912 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,512,4,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,124,relative,align,4,20,relative,align
  event "RPC sadmind TCP NETMGT_PROC_SERVICE CLIENT_DOMAIN overflow attempt"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x87\x88.{4}\x00\x00\x00\x01/
  }

signature sid-1957 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC sadmind UDP PING"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x87\x88.{4}\x00\x00\x00\x00/
  }

signature sid-1958 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC sadmind TCP PING"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x87\x88.{4}\x00\x00\x00\x00/
  }

signature sid-583 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rstatd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA1/
  }

signature sid-1270 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rstatd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA1/
  }

signature sid-1913 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC STATD UDP stat mon_name format string exploit attempt"
  # Not supported: byte_test: 4,>,100,0,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xB8.{4}\x00\x00\x00\x01/
  }

signature sid-1914 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,100,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC STATD TCP stat mon_name format string exploit attempt"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xB8.{4}\x00\x00\x00\x01/
  }

signature sid-1915 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC STATD UDP monitor mon_name format string exploit attempt"
  # Not supported: byte_test: 4,>,100,0,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xB8.{4}\x00\x00\x00\x02/
  }

signature sid-1916 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,100,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC STATD TCP monitor mon_name format string exploit attempt"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xB8.{4}\x00\x00\x00\x02/
  }

signature sid-1277 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ypupdated request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xBC/
  }

signature sid-591 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ypupdated request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xBC/
  }

signature sid-2088 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC ypupdated arbitrary command attempt UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xBC.{4}\x00\x00\x00\x01.{4}.*\|/
  }

signature sid-2089 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC ypupdated arbitrary command attempt TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xBC.{4}\x00\x00\x00\x01.{4}.*\|/
  }

signature sid-1959 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap NFS request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA3/
  }

signature sid-1960 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap NFS request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA3/
  }

signature sid-1961 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap RQUOTA request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xAB/
  }

signature sid-1962 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap RQUOTA request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xAB/
  }

signature sid-1963 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC RQUOTA getquota overflow attempt UDP"
  # Not supported: byte_test: 4,>,128,0,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xAB.{4}\x00\x00\x00\x01/
  }

signature sid-2024 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC RQUOTA getquota overflow attempt TCP"
  # Not supported: byte_test: 4,>,128,0,relative
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xAB.{4}\x00\x00\x00\x01/
  }

signature sid-588 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ttdbserv request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xF3/
  }

signature sid-1274 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ttdbserv request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xF3/
  }

signature sid-1964 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC tooltalk UDP overflow attempt"
  # Not supported: byte_test: 4,>,128,0,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xF3.{4}\x00\x00\x00\x07/
  }

signature sid-1965 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,128,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC tooltalk TCP overflow attempt"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xF3.{4}\x00\x00\x00\x07/
  }

signature sid-589 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap yppasswd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA9/
  }

signature sid-1275 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap yppasswd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA9/
  }

signature sid-2027 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  # Not supported: byte_test: 4,>,64,0,relative
  event "RPC yppasswd old password overflow attempt UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  }

signature sid-2028 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,64,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC yppasswd old password overflow attempt TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  }

signature sid-2025 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align
  event "RPC yppasswd username overflow attempt UDP"
  # Not supported: byte_test: 4,>,64,0,relative
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  }

signature sid-2026 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,64,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align
  event "RPC yppasswd username overflow attempt TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  }

signature sid-2029 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align,4,0,relative,align
  # Not supported: byte_test: 4,>,64,0,relative
  event "RPC yppasswd new password overflow attempt UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  }

signature sid-2030 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  # Not supported: byte_test: 4,>,64,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align,4,0,relative,align
  event "RPC yppasswd new password overflow attempt TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  }

signature sid-2031 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC yppasswd user update UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  }

signature sid-2032 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC yppasswd user update TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  }

signature sid-590 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ypserv request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA4/
  }

signature sid-1276 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ypserv request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA4/
  }

signature sid-2033 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC ypserv maplist request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA4.{4}\x00\x00\x00\x0B/
  }

signature sid-2034 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC ypserv maplist request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA4.{4}\x00\x00\x00\x0B/
  }

signature sid-2035 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap network-status-monitor request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x03\x0D\x70/
  }

signature sid-2036 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap network-status-monitor request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x03\x0D\x70/
  }

signature sid-2037 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC network-status-monitor mon-callback request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x03\x0D\x70.{4}\x00\x00\x00\x01/
  }

signature sid-2038 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC network-status-monitor mon-callback request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x03\x0D\x70.{4}\x00\x00\x00\x01/
  }

signature sid-2079 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap nlockmgr request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB5/
  }

signature sid-2080 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap nlockmgr request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB5/
  }

signature sid-2081 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rpc.xfsmd request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x05\xF7\x68/
  }

signature sid-2082 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rpc.xfsmd request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x05\xF7\x68/
  }

signature sid-2083 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC rpc.xfsmd xfs_export attempt UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x05\xF7\x68.{4}\x00\x00\x00\x0D/
  }

signature sid-2084 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "RPC rpc.xfsmd xfs_export attempt TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x05\xF7\x68.{4}\x00\x00\x00\x0D/
  }

signature sid-2005 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap kcms_server request UDP"
  payload /.{3}\x00\x00\x00\x00/
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x7D/
  }

signature sid-2006 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap kcms_server request TCP"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x7D/
  }

signature sid-2007 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 32771
  dst-port <= 34000
  # Not supported: byte_jump: 4,20,relative,align,4,4,relative,align
  event "RPC kcms_server directory traversal attempt"
  tcp-state established,originator
  payload /.{7}\x00\x00\x00\x00/
  payload /.{15}\x00\x01\x87\x7D.*.{0}.*\/\.\.\//
  }

signature sid-601 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 513
  event "RSERVICES rlogin LinuxNIS"
  tcp-state established,originator
  payload /.*\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x00\x3a\x3a\x3a\x3a\x3a\x3a\x3a\x3a/
  }

signature sid-602 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 513
  event "RSERVICES rlogin bin"
  tcp-state established,originator
  payload /.*bin\x00bin\x00/
  }

signature sid-603 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 513
  event "RSERVICES rlogin echo++"
  tcp-state established,originator
  payload /.*echo \x22 \+ \+ \x22/
  }

signature sid-604 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 513
  event "RSERVICES rsh froot"
  tcp-state established,originator
  payload /.*-froot\x00/
  }

signature sid-611 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 513
  event "RSERVICES rlogin login failure"
  tcp-state established,responder
  payload /.*\x01rlogind\x3a Permission denied\./
  }

signature sid-605 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 513
  event "RSERVICES rlogin login failure"
  tcp-state established,responder
  payload /.*login incorrect/
  }

signature sid-606 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 513
  event "RSERVICES rlogin root"
  tcp-state established,originator
  payload /.*root\x00root\x00/
  }

signature sid-607 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 514
  event "RSERVICES rsh bin"
  tcp-state established,originator
  payload /.*bin\x00bin\x00/
  }

signature sid-608 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 514
  event "RSERVICES rsh echo + +"
  tcp-state established,originator
  payload /.*echo \x22\+ \+\x22/
  }

signature sid-609 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 514
  event "RSERVICES rsh froot"
  tcp-state established,originator
  payload /.*-froot\x00/
  }

signature sid-610 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 514
  event "RSERVICES rsh root"
  tcp-state established,originator
  payload /.*root\x00root\x00/
  }

signature sid-2113 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 512
  event "RSERVICES rexec username overflow attempt"
  payload /.{8}.*\x00.*.{0}.*\x00.*.{0}.*\x00/
  }

signature sid-2114 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 512
  event "RSERVICES rexec password overflow attempt"
  payload /.*\x00.{33}.*\x00.*.{0}.*\x00/
  }

signature sid-268 {
  src-ip != local_nets
  dst-ip == local_nets
  payload-size == 408
  event "DOS Jolt attack"
  header ip[6:1] & 224 == 32
  }

signature sid-270 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  event "DOS Teardrop attack"
  header ip[6:1] & 224 == 32
  header ip[4:2] == 242
  }

signature sid-271-a {
  ip-proto == udp
  src-port == 7
  dst-port == 19
  event "DOS UDP echo+chargen bomb"
  }

signature sid-271-b {
  ip-proto == udp
  src-port == 19
  dst-port == 7
  event "DOS UDP echo+chargen bomb"
  }

signature sid-272 {
  src-ip != local_nets
  dst-ip == local_nets
  header ip[9:1] == 2
  event "DOS IGMP dos attack"
  header ip[6:1] & 224 == 32
  payload /\x02\x00/
  }

signature sid-273 {
  src-ip != local_nets
  dst-ip == local_nets
  header ip[9:1] == 2
  event "DOS IGMP dos attack"
  header ip[6:1] & 224 == 32
  payload /\x00\x00/
  }

signature sid-274 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 8
  event "DOS ath"
  payload /.*\+\+\+[aA][tT][hH]/
  }

signature sid-275-a {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  header tcp[13:1] & 255 == 2
  header tcp[4:4] == 6060842
  event "DOS NAPTHA"
  header ip[4:2] == 413
  }

signature sid-275-b {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 2
  header tcp[4:4] == 6060842
  event "DOS NAPTHA"
  header ip[4:2] == 413
  }

signature sid-276 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 7070
  event "DOS Real Audio Server"
  tcp-state established,originator
  payload /.*\xff\xf4\xff\xfd\x06/
  }

signature sid-277 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 7070
  event "DOS Real Server template.html"
  tcp-state established,originator
  payload /.*\/[vV][iI][eE][wW][sS][oO][uU][rR][cC][eE]\/[tT][eE][mM][pP][lL][aA][tT][eE]\.[hH][tT][mM][lL]\?/
  }

signature sid-278 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8080
  event "DOS Real Server template.html"
  tcp-state established,originator
  payload /.*\/[vV][iI][eE][wW][sS][oO][uU][rR][cC][eE]\/[tT][eE][mM][pP][lL][aA][tT][eE]\.[hH][tT][mM][lL]\?/
  }

signature sid-279 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  payload-size == 0
  event "DOS Bay/Nortel Nautica Marlin"
  }

signature sid-281 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 9
  event "DOS Ascend Route"
  payload /.{24}.{0,17}\x4e\x41\x4d\x45\x4e\x41\x4d\x45/
  }

signature sid-282 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 617
  payload-size > 1445
  event "DOS arkiea backup"
  tcp-state established,originator
  }

signature sid-1257 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 135
  dst-port <= 139
  header tcp[13:1] & 255 == 32
  event "DOS Winnuke attack"
  }

signature sid-1408 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 3372
  payload-size > 1023
  event "DOS MSDTC attempt"
  tcp-state established,originator
  }

signature sid-1605 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 6004
  event "DOS iParty DOS attempt"
  tcp-state established,originator
  payload /.*\xFF\xFF\xFF\xFF\xFF\xFF/
  }

signature sid-1641 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 6789
  dst-port <= 6790
  payload-size == 1
  event "DOS DB2 dos attempt"
  tcp-state established,originator
  }

signature sid-1545 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == 80
  payload-size == 1
  event "DOS Cisco attempt"
  tcp-state established,originator
  payload /\x13/
  }

signature sid-221 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 8
  event "DDOS TFN Probe"
  header ip[4:2] == 678
  payload /.*1234/
  }

signature sid-222 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  event "DDOS tfn2k icmp possible communication"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 0
  payload /.*AAAAAAAAAA/
  }

signature sid-223 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 31335
  event "DDOS Trin00:DaemontoMaster(PONGdetected)"
  payload /.*PONG/
  }

signature sid-228 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "DDOS TFN client command BE"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 456
  }

signature sid-230 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 20432
  event "DDOS shaft client to handler"
  tcp-state established
  }

signature sid-231 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 31335
  event "DDOS Trin00:DaemontoMaster(messagedetected)"
  payload /.*l44/
  }

signature sid-232 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 31335
  event "DDOS Trin00:DaemontoMaster(*HELLO*detected)"
  payload /.*\*HELLO\*/
  }

signature sid-233 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 27665
  event "DDOS Trin00:Attacker to Master default startup password"
  tcp-state established,originator
  payload /.*betaalmostdone/
  }

signature sid-234 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 27665
  event "DDOS Trin00 Attacker to Master default password"
  tcp-state established,originator
  payload /.*gOrave/
  }

signature sid-235 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 27665
  event "DDOS Trin00 Attacker to Master default mdie password"
  tcp-state established,originator
  payload /.*killme/
  }

signature sid-237 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 27444
  event "DDOS Trin00:MastertoDaemon(defaultpassdetected!)"
  payload /.*l44adsl/
  }

signature sid-238 {
  ip-proto == icmp
  src-ip == local_nets
  dst-ip != local_nets
  header icmp[0:1] == 0
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "DDOS TFN server response"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 123
  payload /.*shell bound to port/
  }

signature sid-239 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 18753
  event "DDOS shaft handler to agent"
  payload /.*alive tijgu/
  }

signature sid-240 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 20433
  event "DDOS shaft agent to handler"
  payload /.*alive/
  }

signature sid-241-a {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  header tcp[13:1] & 255 == 2
  header tcp[4:4] == 674711609
  event "DDOS shaft synflood"
  }

signature sid-241-b {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  header tcp[13:1] & 255 == 2
  header tcp[4:4] == 674711609
  event "DDOS shaft synflood"
  }

signature sid-243 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 6838
  event "DDOS mstream agent to handler"
  payload /.*newserver/
  }

signature sid-244 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 10498
  event "DDOS mstream handler to agent"
  payload /.*stream\//
  }

signature sid-245 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 10498
  event "\"DDOS mstream handler ping to agent\" "
  payload /.*ping/
  }

signature sid-246 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 10498
  event "\"DDOS mstream agent pong to handler\" "
  payload /.*pong/
  }

signature sid-247 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 12754
  event "DDOS mstream client to handler"
  tcp-state established,originator
  payload /.*>/
  }

signature sid-248 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 12754
  event "DDOS mstream handler to client"
  tcp-state established,responder
  payload /.*>/
  }

signature sid-249 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 15104
  header tcp[13:1] & 255 == 2
  event "DDOS mstream client to handler"
  }

signature sid-250 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 15104
  event "DDOS mstream handler to client"
  tcp-state established,responder
  payload /.*>/
  }

signature sid-251 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "DDOS - TFN client command LE"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 51201
  }

signature sid-224 {
  ip-proto == icmp
  src-ip == 3.3.3.3/32
  dst-ip != local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht server spoof"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 666
  }

signature sid-225 {
  ip-proto == icmp
  src-ip == local_nets
  dst-ip != local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht gag server response"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 669
  payload /.*sicken/
  }

signature sid-226 {
  ip-proto == icmp
  src-ip == local_nets
  dst-ip != local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht server response"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 667
  payload /.*ficken/
  }

signature sid-227 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht client spoofworks"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 1000
  payload /.*spoofworks/
  }

signature sid-236 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht client check gag"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 668
  payload /.*gesundheit!/
  }

signature sid-229 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht client check skillz"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 666
  payload /.*skillz/
  }

signature sid-1854-a {
  ip-proto == icmp
  src-ip == local_nets
  dst-ip != local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht handler->agent (niggahbitch)"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 9015
  payload /.*niggahbitch/
  }

signature sid-1854-b {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht handler->agent (niggahbitch)"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 9015
  payload /.*niggahbitch/
  }

signature sid-1855-a {
  ip-proto == icmp
  src-ip == local_nets
  dst-ip != local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht agent->handler (skillz)"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 6666
  payload /.*skillz/
  }

signature sid-1855-b {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht agent->handler (skillz)"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 6666
  payload /.*skillz/
  }

signature sid-1856-a {
  ip-proto == icmp
  src-ip == local_nets
  dst-ip != local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht handler->agent (ficken)"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 6667
  payload /.*ficken/
  }

signature sid-1856-b {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  event "DDOS Stacheldraht handler->agent (ficken)"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 6667
  payload /.*ficken/
  }

signature sid-255 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS zone transfer TCP"
  tcp-state established,originator
  payload /.{14}.*\x00\x00\xFC/
  }

signature sid-1948 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS zone transfer UDP"
  payload /.{13}.*\x00\x00\xFC/
  }

signature sid-1435 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS named authors attempt"
  tcp-state established,originator
  payload /.{11}.*\x07[aA][uU][tT][hH][oO][rR][sS]/
  payload /.{11}.*\x04[bB][iI][nN][dD]/
  }

signature sid-256 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS named authors attempt"
  payload /.{11}.*\x07[aA][uU][tT][hH][oO][rR][sS]/
  payload /.{11}.*\x04[bB][iI][nN][dD]/
  }

signature sid-257 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS named version attempt"
  tcp-state established,originator
  payload /.{11}.*\x07[vV][eE][rR][sS][iI][oO][nN]/
  payload /.{11}.*\x04[bB][iI][nN][dD]/
  }

signature sid-1616 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS named version attempt"
  payload /.{11}.*\x07[vV][eE][rR][sS][iI][oO][nN]/
  payload /.{11}.*\x04[bB][iI][nN][dD]/
  }

signature sid-253 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == 53
  event "DNS SPOOF query response PTR with TTL: 1 min. and no authority"
  payload /.*\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00/
  payload /.*\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3c\x00\x0f/
  }

signature sid-254 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == 53
  event "DNS SPOOF query response with ttl: 1 min. and no authority"
  payload /.*\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00/
  payload /.*\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04/
  }

signature sid-258 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT named 8.2->8.2.1"
  tcp-state established,originator
  payload /.*\.\.\/\.\.\/\.\.\//
  }

signature sid-303 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT named tsig overflow attempt"
  tcp-state established,originator
  payload /.*\xAB\xCD\x09\x80\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x01\x20\x20\x20\x20\x02\x61/
  }

signature sid-314 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT named tsig overflow attempt"
  payload /.*\x80\x00\x07\x00\x00\x00\x00\x00\x01\x3F\x00\x01\x02/
  }

signature sid-259 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT named overflow (ADM)"
  tcp-state established,originator
  payload /.*thisissometempspaceforthesockinaddrinyeahyeahiknowthisislamebutanywaywhocareshorizongotitworkingsoalliscool/
  }

signature sid-260 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT named overflow (ADMROCKS)"
  tcp-state established,originator
  payload /.*ADMROCKS/
  }

signature sid-261 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT named overflow attempt"
  tcp-state established,originator
  payload /.*\xCD\x80\xE8\xD7\xFF\xFF\xFF\/bin\/sh/
  }

signature sid-262 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT x86 Linux overflow attempt"
  tcp-state established,originator
  payload /.*\x31\xc0\xb0\x3f\x31\xdb\xb3\xff\x31\xc9\xcd\x80\x31\xc0/
  }

signature sid-264 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT x86 Linux overflow attempt"
  tcp-state established,originator
  payload /.*\x31\xc0\xb0\x02\xcd\x80\x85\xc0\x75\x4c\xeb\x4c\x5e\xb0/
  }

signature sid-265 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT x86 Linux overflow attempt (ADMv2)"
  tcp-state established,originator
  payload /.*\x89\xf7\x29\xc7\x89\xf3\x89\xf9\x89\xf2\xac\x3c\xfe/
  }

signature sid-266 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT x86 FreeBSD overflow attempt"
  tcp-state established,originator
  payload /.*\xeb\x6e\x5e\xc6\x06\x9a\x31\xc9\x89\x4e\x01\xc6\x46\x05/
  }

signature sid-267 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 53
  event "DNS EXPLOIT sparc overflow attempt"
  tcp-state established,originator
  payload /.*\x90\x1a\xc0\x0f\x90\x02\x20\x08\x92\x02\x20\x0f\xd0\x23\xbf\xf8/
  }

signature sid-1941 {
  ip-proto == udp
  dst-port == 69
  event "TFTP filename overflow attempt"
  payload /\x00\x01[^\x00]{100}/
  }

signature sid-1289 {
  ip-proto == udp
  dst-port == 69
  event "TFTP GET Admin.dll"
  payload /\x00\x01/
  payload /.{1}.*[aA][dD][mM][iI][nN]\.[dD][lL][lL]/
  }

signature sid-1441 {
  ip-proto == udp
  dst-port == 69
  event "TFTP GET nc.exe"
  payload /\x00\x01/
  payload /.{1}.*[nN][cC]\.[eE][xX][eE]/
  }

signature sid-1442 {
  ip-proto == udp
  dst-port == 69
  event "TFTP GET shadow"
  payload /\x00\x01/
  payload /.{1}.*[sS][hH][aA][dD][oO][wW]/
  }

signature sid-1443 {
  ip-proto == udp
  dst-port == 69
  event "TFTP GET passwd"
  payload /\x00\x01/
  payload /.{1}.*[pP][aA][sS][sS][wW][dD]/
  }

signature sid-519 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 69
  event "TFTP parent directory"
  payload /.{1}.*\.\./
  }

signature sid-520 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 69
  event "TFTP root directory"
  payload /\x00\x01\//
  }

signature sid-518 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 69
  event "TFTP Put"
  payload /\x00\x02/
  }

signature sid-1444 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 69
  event "TFTP Get"
  payload /\x00\x01/
  }

signature sid-803 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI HyperSeek hsx.cgi directory traversal attempt"
  http /.*[\/\\]hsx\.cgi/
  tcp-state established,originator
  payload /.*\.\.\/\.\.\/.{1}.*%00/
  }

signature sid-1607 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI HyperSeek hsx.cgi access"
  http /.*[\/\\]hsx\.cgi/
  tcp-state established,originator
  }

signature sid-804 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI SWSoft ASPSeek Overflow attempt"
  http /.*[\/\\]s\.cgi/
  tcp-state established,originator
  payload /.*[tT][mM][pP][lL]=/
  }

signature sid-805 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI webspeed access"
  http /.*[\/\\]wsisa\.dll[\/\\]WService=/
  tcp-state established,originator
  payload /.*[wW][sS][mM][aA][dD][mM][iI][nN]/
  }

signature sid-806 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI yabb.cgi directory traversal attempt"
  http /.*[\/\\]YaBB\.pl/
  tcp-state established,originator
  payload /.*\.\.\//
  }

signature sid-1637 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI yabb.cgi access"
  http /.*[\/\\]YaBB\.pl/
  tcp-state established,originator
  }

signature sid-807 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI /wwwboard/passwd.txt access"
  http /.*[\/\\]wwwboard[\/\\]passwd\.txt/
  tcp-state established,originator
  }

signature sid-808 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI webdriver access"
  http /.*[\/\\]webdriver/
  tcp-state established,originator
  }

signature sid-809 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI whois_raw.cgi arbitrary command execution attempt"
  http /.*[\/\\]whois_raw\.cgi\?/
  tcp-state established,originator
  payload /.*\x0a/
  }

signature sid-810 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI whois_raw.cgi access"
  http /.*[\/\\]whois_raw\.cgi/
  tcp-state established,originator
  }

signature sid-811 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI websitepro path access"
  tcp-state established,originator
  payload /.* \/[hH][tT][tT][pP]\/1\./
  }

signature sid-812 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI webplus version access"
  http /.*[\/\\]webplus\?about/
  tcp-state established,originator
  }

signature sid-813 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI webplus directory traversal"
  http /.*[\/\\]webplus\?script/
  tcp-state established,originator
  payload /.*\.\.\//
  }

signature sid-815 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI websendmail access"
  http /.*[\/\\]websendmail/
  tcp-state established,originator
  }

signature sid-1571 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI dcforum.cgi directory traversal attempt"
  http /.*[\/\\]dcforum\.cgi/
  tcp-state established,originator
  payload /.*forum=\.\.\/\.\./
  }

signature sid-818 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI dcforum.cgi access"
  http /.*[\/\\]dcforum\.cgi/
  tcp-state established,originator
  }

signature sid-817 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI dcboard.cgi invalid user addition attempt"
  http /.*[\/\\]dcboard\.cgi/
  tcp-state established,originator
  payload /.*command=register/
  payload /.*%7cadmin/
  }

signature sid-1410 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI dcboard.cgi access"
  http /.*[\/\\]dcboard\.cgi/
  tcp-state established,originator
  }

signature sid-819 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI mmstdod.cgi access"
  http /.*[\/\\]mmstdod\.cgi/
  tcp-state established,originator
  }

signature sid-820 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI anaconda directory transversal attempt"
  http /.*[\/\\]apexec\.pl/
  tcp-state established,originator
  payload /.*[tT][eE][mM][pP][lL][aA][tT][eE]=\.\.\//
  }

signature sid-821 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI imagemap.exe overflow attempt"
  http /.*[\/\\]imagemap\.exe\?/
  tcp-state established,originator
  }

signature sid-1700 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI imagemap.exe access"
  http /.*[\/\\]imagemap\.exe/
  tcp-state established,originator
  }

signature sid-823 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cvsweb.cgi access"
  http /.*[\/\\]cvsweb\.cgi/
  tcp-state established,originator
  }

signature sid-824 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI php.cgi access"
  http /.*[\/\\]php\.cgi/
  tcp-state established,originator
  }

signature sid-825 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI glimpse access"
  http /.*[\/\\]glimpse/
  tcp-state established,originator
  }

signature sid-1608 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI htmlscript attempt"
  http /.*[\/\\]htmlscript\?\.\.[\/\\]\.\./
  tcp-state established,originator
  }

signature sid-826 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI htmlscript access"
  http /.*[\/\\]htmlscript/
  tcp-state established,originator
  }

signature sid-827 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI info2www access"
  http /.*[\/\\]info2www/
  tcp-state established,originator
  }

signature sid-828 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI maillist.pl access"
  http /.*[\/\\]maillist\.pl/
  tcp-state established,originator
  }

signature sid-829 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI nph-test-cgi access"
  http /.*[\/\\]nph-test-cgi/
  tcp-state established,originator
  }

signature sid-1451 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI NPH-publish access"
  http /.*[\/\\]nph-maillist\.pl/
  tcp-state established,originator
  }

signature sid-830 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI NPH-publish access"
  http /.*[\/\\]nph-publish/
  tcp-state established,originator
  }

signature sid-833 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI rguest.exe access"
  http /.*[\/\\]rguest\.exe/
  tcp-state established,originator
  }

signature sid-834 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI rwwwshell.pl access"
  http /.*[\/\\]rwwwshell\.pl/
  tcp-state established,originator
  }

signature sid-1644 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI test-cgi attempt"
  http /.*[\/\\]test-cgi[\/\\]\*\?\*/
  tcp-state established,originator
  }

signature sid-835 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI test-cgi access"
  http /.*[\/\\]test-cgi/
  tcp-state established,originator
  }

signature sid-1645 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI testcgi access"
  http /.*[\/\\]testcgi/
  tcp-state established,originator
  }

signature sid-1646 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI test.cgi access"
  http /.*[\/\\]test\.cgi/
  tcp-state established,originator
  }

signature sid-836 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI textcounter.pl access"
  http /.*[\/\\]textcounter\.pl/
  tcp-state established,originator
  }

signature sid-837 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI uploader.exe access"
  http /.*[\/\\]uploader\.exe/
  tcp-state established,originator
  }

signature sid-838 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI webgais access"
  http /.*[\/\\]webgais/
  tcp-state established,originator
  }

signature sid-839 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI finger access"
  http /.*[\/\\]finger/
  tcp-state established,originator
  }

signature sid-840 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI perlshop.cgi access"
  http /.*[\/\\]perlshop\.cgi/
  tcp-state established,originator
  }

signature sid-841 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI pfdisplay.cgi access"
  http /.*[\/\\]pfdisplay\.cgi/
  tcp-state established,originator
  }

signature sid-842 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI aglimpse access"
  http /.*[\/\\]aglimpse/
  tcp-state established,originator
  }

signature sid-843 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI anform2 access"
  http /.*[\/\\]AnForm2/
  tcp-state established,originator
  }

signature sid-844 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI args.bat access"
  http /.*[\/\\]args\.bat/
  tcp-state established,originator
  }

signature sid-1452 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI args.cmd access"
  http /.*[\/\\]args\.cmd/
  tcp-state established,originator
  }

signature sid-845 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI AT-admin.cgi access"
  http /.*[\/\\]AT-admin\.cgi/
  tcp-state established,originator
  }

signature sid-1453 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI AT-generated.cgi access"
  http /.*[\/\\]AT-generated\.cgi/
  tcp-state established,originator
  }

signature sid-846 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bnbform.cgi access"
  http /.*[\/\\]bnbform\.cgi/
  tcp-state established,originator
  }

signature sid-847 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI campas access"
  http /.*[\/\\]campas/
  tcp-state established,originator
  }

signature sid-848 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI view-source directory traversal"
  http /.*[\/\\]view-source/
  tcp-state established,originator
  payload /.*\.\.\//
  }

signature sid-849 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI view-source access"
  http /.*[\/\\]view-source/
  tcp-state established,originator
  }

signature sid-850 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI wais.pl access"
  http /.*[\/\\]wais\.pl/
  tcp-state established,originator
  }

signature sid-1454 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI wwwwais access"
  http /.*[\/\\]wwwwais/
  tcp-state established,originator
  }

signature sid-851 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI files.pl access"
  http /.*[\/\\]files\.pl/
  tcp-state established,originator
  }

signature sid-852 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI wguest.exe access"
  http /.*[\/\\]wguest\.exe/
  tcp-state established,originator
  }

signature sid-853 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI wrap access"
  http /.*[\/\\]wrap/
  tcp-state established,originator
  }

signature sid-854 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI classifieds.cgi access"
  http /.*[\/\\]classifieds\.cgi/
  tcp-state established,originator
  }

signature sid-856 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI environ.cgi access"
  http /.*[\/\\]environ\.cgi/
  tcp-state established,originator
  }

signature sid-1647 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI faxsurvey attempt (full path)"
  http /.*[\/\\]faxsurvey\?[\/\\]/
  tcp-state established,originator
  }

signature sid-1609 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI faxsurvey arbitrary file read attempt"
  http /.*[\/\\]faxsurvey\?cat%20/
  tcp-state established,originator
  }

signature sid-857 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI faxsurvey access"
  http /.*[\/\\]faxsurvey/
  tcp-state established,originator
  }

signature sid-858 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI filemail access"
  http /.*[\/\\]filemail\.pl/
  tcp-state established,originator
  }

signature sid-859 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI man.sh access"
  http /.*[\/\\]man\.sh/
  tcp-state established,originator
  }

signature sid-860 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI snork.bat access"
  http /.*[\/\\]snork\.bat/
  tcp-state established,originator
  }

signature sid-861 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI w3-msql access"
  http /.*[\/\\]w3-msql[\/\\]/
  tcp-state established,originator
  }

signature sid-863 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI day5datacopier.cgi access"
  http /.*[\/\\]day5datacopier\.cgi/
  tcp-state established,originator
  }

signature sid-864 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI day5datanotifier.cgi access"
  http /.*[\/\\]day5datanotifier\.cgi/
  tcp-state established,originator
  }

signature sid-866 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI post-query access"
  http /.*[\/\\]post-query/
  tcp-state established,originator
  }

signature sid-867 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI visadmin.exe access"
  http /.*[\/\\]visadmin\.exe/
  tcp-state established,originator
  }

signature sid-869 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI dumpenv.pl access"
  http /.*[\/\\]dumpenv\.pl/
  tcp-state established,originator
  }

signature sid-1536 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI calendar_admin.pl arbitrary command execution attempt"
  http /.*[\/\\]calendar_admin\.pl\?config=\|/
  tcp-state established,originator
  }

signature sid-1537 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI calendar_admin.pl access"
  http /.*[\/\\]calendar_admin\.pl/
  tcp-state established,originator
  }

signature sid-1701 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI calendar-admin.pl access"
  http /.*[\/\\]calendar-admin\.pl/
  tcp-state established,originator
  }

signature sid-1455 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI calender.pl access"
  http /.*[\/\\]calender\.pl/
  tcp-state established,originator
  }

signature sid-882 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI calendar access"
  http /.*[\/\\]calendar/
  tcp-state established,originator
  }

signature sid-1457 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI user_update_admin.pl access"
  http /.*[\/\\]user_update_admin\.pl/
  tcp-state established,originator
  }

signature sid-1458 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI user_update_passwd.pl access"
  http /.*[\/\\]user_update_passwd\.pl/
  tcp-state established,originator
  }

signature sid-870 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI snorkerz.cmd access"
  http /.*[\/\\]snorkerz\.cmd/
  tcp-state established,originator
  }

signature sid-871 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI survey.cgi access"
  http /.*[\/\\]survey\.cgi/
  tcp-state established,originator
  }

signature sid-873 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI scriptalias access"
  http /.*[\/\\][\/\\][\/\\]/
  tcp-state established,originator
  }

signature sid-875 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI win-c-sample.exe access"
  http /.*[\/\\]win-c-sample\.exe/
  tcp-state established,originator
  }

signature sid-878 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI w3tvars.pm access"
  http /.*[\/\\]w3tvars\.pm/
  tcp-state established,originator
  }

signature sid-879 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI admin.pl access"
  http /.*[\/\\]admin\.pl/
  tcp-state established,originator
  }

signature sid-880 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI LWGate access"
  http /.*[\/\\]LWGate/
  tcp-state established,originator
  }

signature sid-881 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI archie access"
  http /.*[\/\\]archie/
  tcp-state established,originator
  }

signature sid-883 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI flexform access"
  http /.*[\/\\]flexform/
  tcp-state established,originator
  }

signature sid-1610 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI formmail arbitrary command execution attempt"
  http /.*[\/\\]formmail/
  tcp-state established,originator
  payload /.*%0[aA]/
  }

signature sid-884 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI formmail access"
  http /.*[\/\\]formmail/
  tcp-state established,originator
  }

signature sid-1762 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI phf arbitrary command execution attempt"
  http /.*[\/\\]phf/
  tcp-state established,originator
  payload /.*[qQ][aA][lL][iI][aA][sS]/
  payload /.*%0a\//
  }

signature sid-886 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI phf access"
  http /.*[\/\\]phf/
  tcp-state established,originator
  }

signature sid-887 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI www-sql access"
  http /.*[\/\\]www-sql/
  tcp-state established,originator
  }

signature sid-888 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI wwwadmin.pl access"
  http /.*[\/\\]wwwadmin\.pl/
  tcp-state established,originator
  }

signature sid-889 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ppdscgi.exe access"
  http /.*[\/\\]ppdscgi\.exe/
  tcp-state established,originator
  }

signature sid-890 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI sendform.cgi access"
  http /.*[\/\\]sendform\.cgi/
  tcp-state established,originator
  }

signature sid-891 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI upload.pl access"
  http /.*[\/\\]upload\.pl/
  tcp-state established,originator
  }

signature sid-892 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI AnyForm2 access"
  http /.*[\/\\]AnyForm2/
  tcp-state established,originator
  }

signature sid-893 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI MachineInfo access"
  http /.*[\/\\]MachineInfo/
  tcp-state established,originator
  }

signature sid-1531 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bb-hist.sh attempt"
  http /.*[\/\\]bb-hist\.sh\?HISTFILE=\.\.[\/\\]\.\./
  tcp-state established,originator
  }

signature sid-894 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bb-hist.sh access"
  http /.*[\/\\]bb-hist\.sh/
  tcp-state established,originator
  }

signature sid-1459 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bb-histlog.sh access"
  http /.*[\/\\]bb-histlog\.sh/
  tcp-state established,originator
  }

signature sid-1460 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bb-histsvc.sh access"
  http /.*[\/\\]bb-histsvc\.sh/
  tcp-state established,originator
  }

signature sid-1532 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bb-hostscv.sh attempt"
  http /.*[\/\\]bb-hostsvc\.sh\?HOSTSVC\?\.\.[\/\\]\.\./
  tcp-state established,originator
  }

signature sid-1533 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bb-hostscv.sh access"
  http /.*[\/\\]bb-hostsvc\.sh/
  tcp-state established,originator
  }

signature sid-1461 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bb-rep.sh access"
  http /.*[\/\\]bb-rep\.sh/
  tcp-state established,originator
  }

signature sid-1462 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bb-replog.sh access"
  http /.*[\/\\]bb-replog\.sh/
  tcp-state established,originator
  }

signature sid-895 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI redirect access"
  http /.*[\/\\]redirect/
  tcp-state established,originator
  }

signature sid-1397 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI wayboard attempt"
  http /.*[\/\\]way-board[\/\\]way-board\.cgi/
  tcp-state established,originator
  payload /.*db=/
  payload /.*\.\.\/\.\./
  }

signature sid-896 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI way-board access"
  http /.*[\/\\]way-board/
  tcp-state established,originator
  }

signature sid-1222 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI pals-cgi arbitrary file access attempt"
  http /.*[\/\\]pals-cgi/
  tcp-state established,originator
  payload /.*[dD][oO][cC][uU][mM][eE][nN][tT][nN][aA][mM][eE]=/
  }

signature sid-897 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI pals-cgi access"
  http /.*[\/\\]pals-cgi/
  tcp-state established,originator
  }

signature sid-1572 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI commerce.cgi arbitrary file access attempt"
  http /.*[\/\\]commerce\.cgi/
  tcp-state established,originator
  payload /.*page=/
  payload /.*\/\.\.\//
  }

signature sid-898 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI commerce.cgi access"
  http /.*[\/\\]commerce\.cgi/
  tcp-state established,originator
  }

signature sid-899 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Amaya templates sendtemp.pl directory traversal attempt"
  http /.*[\/\\]sendtemp\.pl/
  tcp-state established,originator
  payload /.*[tT][eE][mM][pP][lL]=/
  }

signature sid-1702 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Amaya templates sendtemp.pl access"
  http /.*[\/\\]sendtemp\.pl/
  tcp-state established,originator
  }

signature sid-900 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI webspirs.cgi directory traversal attempt"
  http /.*[\/\\]webspirs\.cgi/
  tcp-state established,originator
  payload /.*\.\.\/\.\.\//
  }

signature sid-901 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI webspirs.cgi access"
  http /.*[\/\\]webspirs\.cgi/
  tcp-state established,originator
  }

signature sid-902 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI tstisapi.dll access"
  http /.*tstisapi\.dll/
  tcp-state established,originator
  }

signature sid-1308 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI sendmessage.cgi access"
  http /.*[\/\\]sendmessage\.cgi/
  tcp-state established,originator
  }

signature sid-1392 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI lastlines.cgi access"
  http /.*[\/\\]lastlines\.cgi/
  tcp-state established,originator
  }

signature sid-1395 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI zml.cgi attempt"
  http /.*[\/\\]zml\.cgi/
  tcp-state established,originator
  payload /.*file=\.\.\//
  }

signature sid-1396 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI zml.cgi access"
  http /.*[\/\\]zml\.cgi/
  tcp-state established,originator
  }

signature sid-1405 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI AHG search.cgi access"
  http /.*[\/\\]publisher[\/\\]search\.cgi/
  tcp-state established,originator
  payload /.*[tT][eE][mM][pP][lL][aA][tT][eE]=/
  }

signature sid-1534 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI agora.cgi attempt"
  http /.*[\/\\]store[\/\\]agora\.cgi\?cart_id=<SCRIPT>/
  tcp-state established,originator
  }

signature sid-1406 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI agora.cgi access"
  http /.*[\/\\]store[\/\\]agora\.cgi/
  tcp-state established,originator
  }

signature sid-877 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI rksh access"
  http /.*[\/\\]rksh/
  tcp-state established,originator
  }

signature sid-885 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bash access"
  http /.*[\/\\]bash/
  tcp-state established,originator
  }

signature sid-1648 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI perl.exe command attempt"
  http /.*[\/\\]perl\.exe\?/
  tcp-state established,originator
  }

signature sid-832 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI perl.exe access"
  http /.*[\/\\]perl\.exe/
  tcp-state established,originator
  }

signature sid-1649 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI perl command attempt"
  http /.*[\/\\]perl\?/
  tcp-state established,originator
  }

signature sid-1309 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI zsh access"
  http /.*[\/\\]zsh/
  tcp-state established,originator
  }

signature sid-862 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI csh access"
  http /.*[\/\\]csh/
  tcp-state established,originator
  }

signature sid-872 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI tcsh access"
  http /.*[\/\\]tcsh/
  tcp-state established,originator
  }

signature sid-868 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI rsh access"
  http /.*[\/\\]rsh/
  tcp-state established,originator
  }

signature sid-865 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ksh access"
  http /.*[\/\\]ksh/
  tcp-state established,originator
  }

signature sid-1703 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI auktion.cgi directory traversal attempt"
  http /.*[\/\\]auktion\.cgi/
  tcp-state established,originator
  payload /.*[mM][eE][nN][uU][eE]=\.\.\/\.\.\//
  }

signature sid-1465 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI auktion.cgi access"
  http /.*[\/\\]auktion\.cgi/
  tcp-state established,originator
  }

signature sid-1573 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cgiforum.pl attempt"
  http /.*[\/\\]cgiforum\.pl\?thesection=\.\.[\/\\]\.\./
  tcp-state established,originator
  }

signature sid-1466 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cgiforum.pl access"
  http /.*[\/\\]cgiforum\.pl/
  tcp-state established,originator
  }

signature sid-1574 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI directorypro.cgi attempt"
  http /.*[\/\\]directorypro\.cgi/
  tcp-state established,originator
  payload /.*show=.{1}.*\.\.\/\.\./
  }

signature sid-1467 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI directorypro.cgi access"
  http /.*[\/\\]directorypro\.cgi/
  tcp-state established,originator
  }

signature sid-1468 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Web Shopper shopper.cgi attempt"
  http /.*[\/\\]shopper\.cgi/
  tcp-state established,originator
  payload /.*[nN][eE][wW][pP][aA][gG][eE]=\.\.\//
  }

signature sid-1469 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Web Shopper shopper.cgi access"
  http /.*[\/\\]shopper\.cgi/
  tcp-state established,originator
  }

signature sid-1470 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI listrec.pl access"
  http /.*[\/\\]listrec\.pl/
  tcp-state established,originator
  }

signature sid-1471 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI mailnews.cgi access"
  http /.*[\/\\]mailnews\.cgi/
  tcp-state established,originator
  }

signature sid-1879 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI book.cgi arbitrary command execution attempt"
  http /.*[\/\\]book\.cgi/
  tcp-state established,originator
  payload /.*[cC][uU][rR][rR][eE][nN][tT]=\|/
  }

signature sid-1472 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI book.cgi access"
  http /.*[\/\\]book\.cgi/
  tcp-state established,originator
  }

signature sid-1473 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI newsdesk.cgi access"
  http /.*[\/\\]newsdesk\.cgi/
  tcp-state established,originator
  }

signature sid-1704 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cal_make.pl directory traversal attempt"
  http /.*[\/\\]cal_make\.pl/
  tcp-state established,originator
  payload /.*[pP]0=\.\.\/\.\.\//
  }

signature sid-1474 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cal_make.pl access"
  http /.*[\/\\]cal_make\.pl/
  tcp-state established,originator
  }

signature sid-1475 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI mailit.pl access"
  http /.*[\/\\]mailit\.pl/
  tcp-state established,originator
  }

signature sid-1476 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI sdbsearch.cgi access"
  http /.*[\/\\]sdbsearch\.cgi/
  tcp-state established,originator
  }

signature sid-1478 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI swc access"
  http /.*[\/\\]swc/
  tcp-state established,originator
  }

signature sid-1479 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ttawebtop.cgi arbitrary file attempt"
  http /.*[\/\\]ttawebtop\.cgi/
  tcp-state established,originator
  payload /.*[pP][gG]=\.\.\//
  }

signature sid-1480 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ttawebtop.cgi access"
  http /.*[\/\\]ttawebtop\.cgi/
  tcp-state established,originator
  }

signature sid-1481 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI upload.cgi access"
  http /.*[\/\\]upload\.cgi/
  tcp-state established,originator
  }

signature sid-1482 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI view_source access"
  http /.*[\/\\]view_source/
  tcp-state established,originator
  }

signature sid-1730 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ustorekeeper.pl directory traversal attempt"
  http /.*[\/\\]ustorekeeper\.pl/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE]=\.\.\/\.\.\//
  }

signature sid-1483 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ustorekeeper.pl access"
  http /.*[\/\\]ustorekeeper\.pl/
  tcp-state established,originator
  }

signature sid-1606 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI icat access"
  http /.*[\/\\]icat/
  tcp-state established,originator
  }

signature sid-1617 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Bugzilla doeditvotes.cgi access"
  http /.*[\/\\]doeditvotes\.cgi/
  tcp-state established,originator
  }

signature sid-1600 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI htsearch arbitrary configuration file attempt"
  http /.*[\/\\]htsearch\?-c/
  tcp-state established,originator
  }

signature sid-1601 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI htsearch arbitrary file read attempt"
  http /.*[\/\\]htsearch\?exclude=`/
  tcp-state established,originator
  }

signature sid-1602 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI htsearch access"
  http /.*[\/\\]htsearch/
  tcp-state established,originator
  }

signature sid-1501 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI a1stats a1disp3.cgi directory traversal attempt"
  http /.*[\/\\]a1disp3\.cgi\?[\/\\]\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  }

signature sid-1502 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI a1stats a1disp3.cgi access"
  http /.*[\/\\]a1disp3\.cgi/
  tcp-state established,originator
  }

signature sid-1731 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI a1stats access"
  http /.*[\/\\]a1stats[\/\\]/
  tcp-state established,originator
  }

signature sid-1503 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI admentor admin.asp access"
  http /.*[\/\\]admentor[\/\\]admin[\/\\]admin\.asp/
  tcp-state established,originator
  }

signature sid-1505 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI alchemy http server PRN arbitrary command execution attempt"
  http /.*[\/\\]PRN[\/\\]\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  }

signature sid-1506 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI alchemy http server NUL arbitrary command execution attempt"
  http /.*[\/\\]NUL[\/\\]\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  }

signature sid-1507 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI alibaba.pl arbitrary command execution attempt"
  http /.*[\/\\]alibaba\.pl\|/
  tcp-state established,originator
  }

signature sid-1508 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI alibaba.pl access"
  http /.*[\/\\]alibaba\.pl/
  tcp-state established,originator
  }

signature sid-1509 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI AltaVista Intranet Search directory traversal attempt"
  http /.*[\/\\]query\?mss=\.\./
  tcp-state established,originator
  }

signature sid-1510 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI test.bat arbitrary command execution attempt"
  http /.*[\/\\]test\.bat\|/
  tcp-state established,originator
  }

signature sid-1511 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI test.bat access"
  http /.*[\/\\]test\.bat/
  tcp-state established,originator
  }

signature sid-1512 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI input.bat arbitrary command execution attempt"
  http /.*[\/\\]input\.bat\|/
  tcp-state established,originator
  }

signature sid-1513 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI input.bat access"
  http /.*[\/\\]input\.bat/
  tcp-state established,originator
  }

signature sid-1514 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI input2.bat arbitrary command execution attempt"
  http /.*[\/\\]input2\.bat\|/
  tcp-state established,originator
  }

signature sid-1515 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI input2.bat access"
  http /.*[\/\\]input2\.bat/
  tcp-state established,originator
  }

signature sid-1516 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI envout.bat arbitrary command execution attempt"
  http /.*[\/\\]envout\.bat\|/
  tcp-state established,originator
  }

signature sid-1517 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI envout.bat access"
  http /.*[\/\\]envout\.bat/
  tcp-state established,originator
  }

signature sid-1705 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI echo.bat arbitrary command execution attempt"
  http /.*[\/\\]echo\.bat/
  tcp-state established,originator
  payload /.*&/
  }

signature sid-1706 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI echo.bat access"
  http /.*[\/\\]echo\.bat/
  tcp-state established,originator
  }

signature sid-1707 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI hello.bat arbitrary command execution attempt"
  http /.*[\/\\]hello\.bat/
  tcp-state established,originator
  payload /.*&/
  }

signature sid-1708 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI hello.bat access"
  http /.*[\/\\]hello\.bat/
  tcp-state established,originator
  }

signature sid-1650 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI tst.bat access"
  http /.*[\/\\]tst\.bat/
  tcp-state established,originator
  }

signature sid-1539 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI /cgi-bin/ls access"
  http /.*[\/\\]cgi-bin[\/\\]ls/
  tcp-state established,originator
  }

signature sid-1542 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cgimail access"
  http /.*[\/\\]cgimail/
  tcp-state established,originator
  }

signature sid-1543 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cgiwrap access"
  http /.*[\/\\]cgiwrap/
  tcp-state established,originator
  }

signature sid-1547 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI csSearch.cgi arbitrary command execution attempt"
  http /.*[\/\\]csSearch\.cgi/
  tcp-state established,originator
  payload /.*setup=/
  payload /.*`.{1}.*`/
  }

signature sid-1548 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI csSearch.cgi access"
  http /.*[\/\\]csSearch\.cgi/
  tcp-state established,originator
  }

signature sid-1553 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI /cart/cart.cgi access"
  http /.*[\/\\]cart[\/\\]cart\.cgi/
  tcp-state established,originator
  }

signature sid-1554 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI dbman db.cgi access"
  http /.*[\/\\]dbman[\/\\]db\.cgi/
  tcp-state established,originator
  }

signature sid-1555 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI DCShop access"
  http /.*[\/\\]dcshop/
  tcp-state established,originator
  }

signature sid-1556 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI DCShop orders.txt access"
  http /.*[\/\\]orders[\/\\]orders\.txt/
  tcp-state established,originator
  }

signature sid-1557 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI DCShop auth_user_file.txt access"
  http /.*[\/\\]auth_data[\/\\]auth_user_file\.txt/
  tcp-state established,originator
  }

signature sid-1565 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI eshop.pl arbitrary commane execution attempt"
  http /.*[\/\\]eshop\.pl\?seite=;/
  tcp-state established,originator
  }

signature sid-1566 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI eshop.pl access"
  http /.*[\/\\]eshop\.pl/
  tcp-state established,originator
  }

signature sid-1569 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI loadpage.cgi directory traversal attempt"
  http /.*[\/\\]loadpage\.cgi/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE]=\.\.\//
  }

signature sid-1570 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI loadpage.cgi access"
  http /.*[\/\\]loadpage\.cgi/
  tcp-state established,originator
  }

signature sid-1590 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI faqmanager.cgi arbitrary file access attempt"
  http /.*[\/\\]faqmanager\.cgi\?toc=/
  http /.*%00/
  tcp-state established,originator
  }

signature sid-1591 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI faqmanager.cgi access"
  http /.*[\/\\]faqmanager\.cgi/
  tcp-state established,originator
  }

signature sid-1592 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI /fcgi-bin/echo.exe access"
  http /.*[\/\\]fcgi-bin[\/\\]echo\.exe/
  tcp-state established,originator
  }

signature sid-1628 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI FormHandler.cgi directory traversal attempt attempt"
  http /.*[\/\\]FormHandler\.cgi/
  tcp-state established,originator
  payload /.*[rR][eE][pP][lL][yY]_[mM][eE][sS][sS][aA][gG][eE]_[aA][tT][tT][aA][cC][hH]=/
  payload /.*\/\.\.\//
  }

signature sid-1593 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI FormHandler.cgi external site redirection attempt"
  http /.*[\/\\]FormHandler\.cgi/
  tcp-state established,originator
  payload /.*[rR][eE][dD][iI][rR][eE][cC][tT]=[hH][tT][tT][pP]/
  }

signature sid-1594 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI FormHandler.cgi access"
  http /.*[\/\\]FormHandler\.cgi/
  tcp-state established,originator
  }

signature sid-1597 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI guestbook.cgi access"
  http /.*[\/\\]guestbook\.cgi/
  tcp-state established,originator
  }

signature sid-1598 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Home Free search.cgi directory traversal attempt"
  http /.*[\/\\]search\.cgi/
  tcp-state established,originator
  payload /.*[lL][eE][tT][tT][eE][rR]=\.\.\/\.\./
  }

signature sid-1599 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI search.cgi access"
  http /.*[\/\\]search\.cgi/
  tcp-state established,originator
  }

signature sid-1651 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI enivorn.pl access"
  http /.*[\/\\]enivron\.pl/
  tcp-state established,originator
  }

signature sid-1652 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI campus attempt"
  http /.*[\/\\]campus\?%0a/
  tcp-state established,originator
  }

signature sid-1653 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI campus access"
  http /.*[\/\\]campus/
  tcp-state established,originator
  }

signature sid-1654 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cart32.exe access"
  http /.*[\/\\]cart32\.exe/
  tcp-state established,originator
  }

signature sid-1655 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI pfdispaly.cgi arbitrary command execution attempt"
  http /.*[\/\\]pfdispaly\.cgi\?'/
  tcp-state established,originator
  }

signature sid-1656 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI pfdispaly.cgi access"
  http /.*[\/\\]pfdispaly\.cgi/
  tcp-state established,originator
  }

signature sid-1657 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI pagelog.cgi directory traversal attempt"
  http /.*[\/\\]pagelog\.cgi/
  tcp-state established,originator
  payload /.*[nN][aA][mM][eE]=\.\.\//
  }

signature sid-1658 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI pagelog.cgi access"
  http /.*[\/\\]pagelog\.cgi/
  tcp-state established,originator
  }

signature sid-1709 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ad.cgi access"
  http /.*[\/\\]ad\.cgi/
  tcp-state established,originator
  }

signature sid-1710 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bbs_forum.cgi access"
  http /.*[\/\\]bbs_forum\.cgi/
  tcp-state established,originator
  }

signature sid-1711 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bsguest.cgi access"
  http /.*[\/\\]bsguest\.cgi/
  tcp-state established,originator
  }

signature sid-1712 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bslist.cgi access"
  http /.*[\/\\]bslist\.cgi/
  tcp-state established,originator
  }

signature sid-1713 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cgforum.cgi access"
  http /.*[\/\\]cgforum\.cgi/
  tcp-state established,originator
  }

signature sid-1714 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI newdesk access"
  http /.*[\/\\]newdesk/
  tcp-state established,originator
  }

signature sid-1715 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI register.cgi access"
  http /.*[\/\\]register\.cgi/
  tcp-state established,originator
  }

signature sid-1716 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI gbook.cgi access"
  http /.*[\/\\]gbook\.cgi/
  tcp-state established,originator
  }

signature sid-1717 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI simplestguest.cgi access"
  http /.*[\/\\]simplestguest\.cgi/
  tcp-state established,originator
  }

signature sid-1718 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI statusconfig.pl access"
  http /.*[\/\\]statusconfig\.pl/
  tcp-state established,originator
  }

signature sid-1719 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI talkback.cgi directory traversal attempt"
  http /.*[\/\\]talkbalk\.cgi/
  tcp-state established,originator
  payload /.*[aA][rR][tT][iI][cC][lL][eE]=\.\.\/\.\.\//
  }

signature sid-1720 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI talkback.cgi access"
  http /.*[\/\\]talkbalk\.cgi/
  tcp-state established,originator
  }

signature sid-1721 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI adcycle access"
  http /.*[\/\\]adcycle/
  tcp-state established,originator
  }

signature sid-1722 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI MachineInfo access"
  http /.*[\/\\]MachineInfo/
  tcp-state established,originator
  }

signature sid-1723 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI emumail.cgi NULL attempt"
  http /.*[\/\\]emumail\.cgi/
  tcp-state established,originator
  payload /.*[tT][yY][pP][eE]=/
  payload /.*%00/
  }

signature sid-1724 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI emumail.cgi access"
  http /.*[\/\\]emumail\.cgi/
  tcp-state established,originator
  }

signature sid-1642 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI document.d2w access"
  http /.*[\/\\]document\.d2w/
  tcp-state established,originator
  }

signature sid-1643 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI db2www access"
  http /.*[\/\\]db2www/
  tcp-state established,originator
  }

signature sid-1668 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI /cgi-bin/ access"
  http /.*[\/\\]cgi-bin[\/\\]/
  tcp-state established,originator
  payload /.*\/[cC][gG][iI]-[bB][iI][nN]\/ [hH][tT][tT][pP]/
  }

signature sid-1669 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI /cgi-dos/ access"
  http /.*[\/\\]cgi-dos[\/\\]/
  tcp-state established,originator
  payload /.*\/[cC][gG][iI]-[dD][oO][sS]\/ [hH][tT][tT][pP]/
  }

signature sid-1051 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI technote main.cgi file directory traversal attempt"
  http /.*[\/\\]technote[\/\\]main\.cgi/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE][nN][aA][mM][eE]=/
  payload /.*\.\.\/\.\.\//
  }

signature sid-1052 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI technote print.cgi directory traversal attempt"
  http /.*[\/\\]technote[\/\\]print\.cgi/
  tcp-state established,originator
  payload /.*[bB][oO][aA][rR][dD]=/
  payload /.*\.\.\/\.\.\//
  payload /.*%00/
  }

signature sid-1053 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ads.cgi command execution attempt"
  http /.*[\/\\]ads\.cgi/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE]=/
  payload /.*\.\.\/\.\.\//
  payload /.*\|/
  }

signature sid-1088 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI eXtropia webstore directory traversal"
  http /.*[\/\\]web_store\.cgi/
  tcp-state established,originator
  payload /.*page=\.\.\//
  }

signature sid-1611 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI eXtropia webstore access"
  http /.*[\/\\]web_store\.cgi/
  tcp-state established,originator
  }

signature sid-1089 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI shopping cart directory traversal"
  http /.*[\/\\]shop\.cgi/
  tcp-state established,originator
  payload /.*page=\.\.\//
  }

signature sid-1090 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Allaire Pro Web Shell attempt"
  http /.*[\/\\]authenticate\.cgi\?PASSWORD/
  tcp-state established,originator
  payload /.*config\.ini/
  }

signature sid-1092 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Armada Style Master Index directory traversal"
  http /.*[\/\\]search\.cgi\?keys/
  tcp-state established,originator
  payload /.*catigory=\.\.\//
  }

signature sid-1093 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cached_feed.cgi moreover shopping cart directory traversal"
  http /.*[\/\\]cached_feed\.cgi/
  tcp-state established,originator
  payload /.*\.\.\//
  }

signature sid-2051 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cached_feed.cgi moreover shopping cart access"
  http /.*[\/\\]cached_feed\.cgi/
  tcp-state established,originator
  }

signature sid-1097 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Talentsoft Web+ exploit attempt"
  http /.*[\/\\]webplus\.cgi\?Script=[\/\\]webplus[\/\\]webping[\/\\]webping\.wml/
  tcp-state established,originator
  }

signature sid-1106 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Poll-it access"
  http /.*[\/\\]pollit[\/\\]Poll_It_SSI_v2\.0\.cgi/
  tcp-state established,originator
  }

signature sid-1149 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI count.cgi access"
  http /.*[\/\\]count\.cgi/
  tcp-state established,originator
  }

signature sid-1865 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI webdist.cgi arbitrary command attempt"
  http /.*[\/\\]webdist\.cgi/
  tcp-state established,originator
  payload /.*[dD][iI][sS][tT][lL][oO][cC]=;/
  }

signature sid-1163 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI webdist.cgi access"
  http /.*[\/\\]webdist\.cgi/
  tcp-state established,originator
  }

signature sid-1172 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bigconf.cgi access"
  http /.*[\/\\]bigconf\.cgi/
  tcp-state established,originator
  }

signature sid-1174 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI /cgi-bin/jj access"
  http /.*[\/\\]cgi-bin[\/\\]jj/
  tcp-state established,originator
  }

signature sid-1185 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bizdbsearch attempt"
  http /.*[\/\\]bizdb1-search\.cgi/
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL]/
  }

signature sid-1535 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI bizdbsearch access"
  http /.*[\/\\]bizdb1-search\.cgi/
  tcp-state established,originator
  }

signature sid-1194 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI sojourn.cgi File attempt"
  http /.*[\/\\]sojourn\.cgi\?cat=/
  tcp-state established,originator
  payload /.*%00/
  }

signature sid-1195 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI sojourn.cgi access"
  http /.*[\/\\]sojourn\.cgi/
  tcp-state established,originator
  }

signature sid-1196 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI SGI InfoSearch fname attempt"
  http /.*[\/\\]infosrch\.cgi\?/
  tcp-state established,originator
  payload /.*[fF][nN][aA][mM][eE]=/
  }

signature sid-1727 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI SGI InfoSearch fname access"
  http /.*[\/\\]infosrch\.cgi/
  tcp-state established,originator
  }

signature sid-1204 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ax-admin.cgi access"
  http /.*[\/\\]ax-admin\.cgi/
  tcp-state established,originator
  }

signature sid-1205 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI axs.cgi access"
  http /.*[\/\\]axs\.cgi/
  tcp-state established,originator
  }

signature sid-1206 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cachemgr.cgi access"
  http /.*[\/\\]cachemgr\.cgi/
  tcp-state established,originator
  }

signature sid-1208 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI responder.cgi access"
  http /.*[\/\\]responder\.cgi/
  tcp-state established,originator
  }

signature sid-1211 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI web-map.cgi access"
  http /.*[\/\\]web-map\.cgi/
  tcp-state established,originator
  }

signature sid-1215 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ministats admin access"
  http /.*[\/\\]ministats[\/\\]admin\.cgi/
  tcp-state established,originator
  }

signature sid-1219 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI dfire.cgi access"
  http /.*[\/\\]dfire\.cgi/
  tcp-state established,originator
  }

signature sid-1305 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI txt2html.cgi directory traversal attempt"
  http /.*[\/\\]txt2html\.cgi/
  tcp-state established,originator
  payload /.*\/\.\.\/\.\.\/\.\.\/\.\.\//
  }

signature sid-1304 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI txt2html.cgi access"
  http /.*[\/\\]txt2html\.cgi/
  tcp-state established,originator
  }

signature sid-1488 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI store.cgi directory traversal attempt"
  http /.*[\/\\]store\.cgi/
  tcp-state established,originator
  payload /.*\.\.\//
  }

signature sid-1307 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI store.cgi access"
  http /.*[\/\\]store\.cgi/
  tcp-state established,originator
  }

signature sid-1494 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI SIX webboard generate.cgi attempt"
  http /.*[\/\\]generate\.cgi/
  tcp-state established,originator
  payload /.*content=\.\.\//
  }

signature sid-1495 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI SIX webboard generate.cgi access"
  http /.*[\/\\]generate\.cgi/
  tcp-state established,originator
  }

signature sid-1496 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI spin_client.cgi access"
  http /.*[\/\\]spin_client\.cgi/
  tcp-state established,originator
  }

signature sid-1787 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI csPassword.cgi access"
  http /.*[\/\\]csPassword\.cgi/
  tcp-state established,originator
  }

signature sid-1788 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI csPassword password.cgi.tmp access"
  http /.*[\/\\]password\.cgi\.tmp/
  tcp-state established,originator
  }

signature sid-1763 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Nortel Contivity cgiproc DOS attempt"
  http /.*[\/\\]cgiproc\?Nocfile=/
  tcp-state established,originator
  }

signature sid-1764 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Nortel Contivity cgiproc DOS attempt"
  http /.*[\/\\]cgiproc\?\$/
  tcp-state established,originator
  }

signature sid-1765 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Nortel Contivity cgiproc access"
  http /.*[\/\\]cgiproc/
  tcp-state established,originator
  }

signature sid-1805 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI Oracle reports CGI access"
  http /.*[\/\\]rwcgi60/
  tcp-state established,originator
  payload /.*setauth=/
  }

signature sid-1822 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI alienform.cgi directory traversal attempt"
  http /.*[\/\\]alienform\.cgi/
  tcp-state established,originator
  payload /.*\.\|\.\/\.\|\./
  }

signature sid-1823 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI AlienForm af.cgi directory traversal attempt"
  http /.*[\/\\]af\.cgi/
  tcp-state established,originator
  payload /.*\.\|\.\/\.\|\./
  }

signature sid-1824 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI alienform.cgi access"
  http /.*[\/\\]alienform\.cgi/
  tcp-state established,originator
  }

signature sid-1825 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI AlienForm af.cgi access"
  http /.*[\/\\]af\.cgi/
  tcp-state established,originator
  }

signature sid-1868 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8080
  event "WEB-CGI story.pl arbitrary file read attempt"
  http /.*[\/\\]story\.pl/
  tcp-state established,originator
  payload /.*next=\.\.\//
  }

signature sid-1869 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8080
  event "WEB-CGI story.pl access"
  http /.*[\/\\]story\.pl/
  tcp-state established,originator
  }

signature sid-1870 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI siteUserMod.cgi access"
  http /.*[\/\\]\.cobalt[\/\\]siteUserMod[\/\\]siteUserMod\.cgi/
  tcp-state established,originator
  }

signature sid-1875 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cgicso access"
  http /.*[\/\\]cgicso/
  tcp-state established,originator
  }

signature sid-1876 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI nph-publish.cgi access"
  http /.*[\/\\]nph-publish\.cgi/
  tcp-state established,originator
  }

signature sid-1877 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI printenv access"
  http /.*[\/\\]printenv/
  tcp-state established,originator
  }

signature sid-1878 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI sdbsearch.cgi access"
  http /.*[\/\\]sdbsearch\.cgi/
  tcp-state established,originator
  }

signature sid-1931 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI rpc-nlog.pl access"
  http /.*[\/\\]rpc-nlog\.pl/
  tcp-state established,originator
  }

signature sid-1932 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI rpc-smb.pl access"
  http /.*[\/\\]rpc-smb\.pl/
  tcp-state established,originator
  }

signature sid-1933 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI cart.cgi access"
  http /.*[\/\\]cart\.cgi/
  tcp-state established,originator
  }

signature sid-1994 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI vpasswd.cgi access"
  http /.*[\/\\]vpasswd\.cgi/
  tcp-state established,originator
  }

signature sid-1995 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI alya.cgi access"
  http /.*[\/\\]alya\.cgi/
  tcp-state established,originator
  }

signature sid-1996 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI viralator.cgi access"
  http /.*[\/\\]viralator\.cgi/
  tcp-state established,originator
  }

signature sid-2001 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI smartsearch.cgi access"
  http /.*[\/\\]smartsearch\.cgi/
  tcp-state established,originator
  }

signature sid-1862 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI mrtg.cgi directory traversal attempt"
  http /.*[\/\\]mrtg\.cgi/
  tcp-state established,originator
  payload /.*cfg=\/\.\.\//
  }

signature sid-2052 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI overflow.cgi access"
  http /.*[\/\\]overflow\.cgi/
  tcp-state established,originator
  }

signature sid-1850 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI way-board.cgi access"
  http /.*[\/\\]way-board\.cgi/
  tcp-state established,originator
  }

signature sid-2053 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI process_bug.cgi access"
  http /.*[\/\\]process_bug\.cgi/
  tcp-state established,originator
  }

signature sid-2054 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI enter_bug.cgi arbitrary command attempt"
  http /.*[\/\\]enter_bug\.cgi/
  tcp-state established,originator
  payload /.*[wW][hH][oO]=.*.{0}.*;/
  }

signature sid-2055 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI enter_bug.cgi access"
  http /.*[\/\\]enter_bug\.cgi/
  tcp-state established,originator
  }

signature sid-2085 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI parse_xml.cgi access"
  http /.*[\/\\]parse_xml\.cgi/
  tcp-state established,originator
  }

signature sid-2086 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == 1220
  event "WEB-CGI streaming server parse_xml.cgi access"
  tcp-state established,originator
  payload /.*\/[pP][aA][rR][sS][eE]_[xX][mM][lL]\.[cC][gG][iI]/
  }

signature sid-2115 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI album.pl access"
  tcp-state established,originator
  payload /.*\/[aA][lL][bB][uU][mM]\.[pP][lL]/
  }

signature sid-2116 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI chipcfg.cgi access"
  http /.*[\/\\]chipcfg\.cgi/
  tcp-state established,originator
  }

signature sid-2127 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI ikonboard.cgi access"
  http /.*[\/\\]ikonboard\.cgi/
  tcp-state established,originator
  }

signature sid-2128 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-CGI swsrv.cgi access"
  http /.*[\/\\]srsrv\.cgi/
  tcp-state established,originator
  }

signature sid-903 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION cfcache.map access"
  http /.*[\/\\]cfcache\.map/
  tcp-state established,originator
  }

signature sid-904 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION exampleapp application.cfm"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]email[\/\\]application\.cfm/
  tcp-state established,originator
  }

signature sid-905 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION application.cfm access"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]publish[\/\\]admin[\/\\]application\.cfm/
  tcp-state established,originator
  }

signature sid-906 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION getfile.cfm access"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]email[\/\\]getfile\.cfm/
  tcp-state established,originator
  }

signature sid-907 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION addcontent.cfm access"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]publish[\/\\]admin[\/\\]addcontent\.cfm/
  tcp-state established,originator
  }

signature sid-908 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION administrator access"
  http /.*[\/\\]cfide[\/\\]administrator[\/\\]index\.cfm/
  tcp-state established,originator
  }

signature sid-909 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION datasource username attempt"
  tcp-state established,originator
  payload /.*[cC][fF]_[sS][eE][tT][dD][aA][tT][aA][sS][oO][uU][rR][cC][eE][uU][sS][eE][rR][nN][aA][mM][eE]\(\)/
  }

signature sid-910 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION fileexists.cfm access"
  http /.*[\/\\]cfdocs[\/\\]snippets[\/\\]fileexists\.cfm/
  tcp-state established,originator
  }

signature sid-911 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION exprcalc access"
  http /.*[\/\\]cfdocs[\/\\]expeval[\/\\]exprcalc\.cfm/
  tcp-state established,originator
  }

signature sid-912 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION parks access"
  http /.*[\/\\]cfdocs[\/\\]examples[\/\\]parks[\/\\]detail\.cfm/
  tcp-state established,originator
  }

signature sid-913 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION cfappman access"
  http /.*[\/\\]cfappman[\/\\]index\.cfm/
  tcp-state established,originator
  }

signature sid-914 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION beaninfo access"
  http /.*[\/\\]cfdocs[\/\\]examples[\/\\]cvbeans[\/\\]beaninfo\.cfm/
  tcp-state established,originator
  }

signature sid-915 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION evaluate.cfm access"
  http /.*[\/\\]cfdocs[\/\\]snippets[\/\\]evaluate\.cfm/
  tcp-state established,originator
  }

signature sid-916 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION getodbcdsn access"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[gG][eE][tT][oO][dD][bB][cC][dD][sS][nN]\(\)/
  }

signature sid-917 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION db connections flush attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[dD][bB][cC][oO][nN][nN][eE][cC][tT][iI][oO][nN][sS]_[fF][lL][uU][sS][hH]\(\)/
  }

signature sid-918 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION expeval access"
  http /.*[\/\\]cfdocs[\/\\]expeval[\/\\]/
  tcp-state established,originator
  }

signature sid-919 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION datasource passwordattempt"
  tcp-state established,originator
  payload /.*[cC][fF]_[sS][eE][tT][dD][aA][tT][aA][sS][oO][uU][rR][cC][eE][pP][aA][sS][sS][wW][oO][rR][dD]\(\)/
  }

signature sid-920 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION datasource attempt"
  tcp-state established,originator
  payload /.*[cC][fF]_[iI][sS][cC][oO][lL][dD][fF][uU][sS][iI][oO][nN][dD][aA][tT][aA][sS][oO][uU][rR][cC][eE]\(\)/
  }

signature sid-921 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION admin encrypt attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[eE][nN][cC][rR][yY][pP][tT]\(\)/
  }

signature sid-922 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION displayfile access"
  http /.*[\/\\]cfdocs[\/\\]expeval[\/\\]displayopenedfile\.cfm/
  tcp-state established,originator
  }

signature sid-923 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION getodbcin attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[gG][eE][tT][oO][dD][bB][cC][iI][nN][iI]\(\)/
  }

signature sid-924 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION admin decrypt attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[dD][eE][cC][rR][yY][pP][tT]\(\)/
  }

signature sid-925 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION mainframeset access"
  http /.*[\/\\]cfdocs[\/\\]examples[\/\\]mainframeset\.cfm/
  tcp-state established,originator
  }

signature sid-926 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION set odbc ini attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[sS][eE][tT][oO][dD][bB][cC][iI][nN][iI]\(\)/
  }

signature sid-927 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION settings refresh attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[sS][eE][tT][tT][iI][nN][gG][sS]_[rR][eE][fF][rR][eE][sS][hH]\(\)/
  }

signature sid-928 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION exampleapp access"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]/
  tcp-state established,originator
  }

signature sid-929 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION CFUSION_VERIFYMAIL access"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[vV][eE][rR][iI][fF][yY][mM][aA][iI][lL]\(\)/
  }

signature sid-930 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION snippets attempt"
  http /.*[\/\\]cfdocs[\/\\]snippets[\/\\]/
  tcp-state established,originator
  }

signature sid-931 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION cfmlsyntaxcheck.cfm access"
  http /.*[\/\\]cfdocs[\/\\]cfmlsyntaxcheck\.cfm/
  tcp-state established,originator
  }

signature sid-932 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION application.cfm access"
  http /.*[\/\\]application\.cfm/
  tcp-state established,originator
  }

signature sid-933 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION onrequestend.cfm access"
  http /.*[\/\\]onrequestend\.cfm/
  tcp-state established,originator
  }

signature sid-935 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION startstop DOS access"
  http /.*[\/\\]cfide[\/\\]administrator[\/\\]startstop\.html/
  tcp-state established,originator
  }

signature sid-936 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION gettempdirectory.cfm access "
  http /.*[\/\\]cfdocs[\/\\]snippets[\/\\]gettempdirectory\.cfm/
  tcp-state established,originator
  }

signature sid-1659 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION sendmail.cfm access"
  http /.*[\/\\]sendmail\.cfm/
  tcp-state established,originator
  }

signature sid-1540 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-COLDFUSION ?Mode=debug attempt"
  http /.*Mode=debug/
  tcp-state established,originator
  }

signature sid-1970 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-IIS MDAC Content-Type overflow attempt"
  http /.*[\/\\]msadcs\.dll/
  tcp-state established,originator
  payload /.*Content-Type:[^\x0A]{50}/
  }

signature sid-1076 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS repost.asp access"
  http /.*[\/\\]scripts[\/\\]repost\.asp/
  tcp-state established,originator
  }

signature sid-1806 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS .htr Transfer-Encoding: chunked"
  http /.*\.htr/
  tcp-state established,originator
  payload /.*[tT][rR][aA][nN][sS][fF][eE][rR]-[eE][nN][cC][oO][dD][iI][nN][gG]:/
  payload /.*[cC][hH][uU][nN][kK][eE][dD]/
  }

signature sid-1618 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS .asp Transfer-Encoding: chunked"
  http /.*\.asp/
  tcp-state established,originator
  payload /.*[tT][rR][aA][nN][sS][fF][eE][rR]-[eE][nN][cC][oO][dD][iI][nN][gG]:/
  payload /.*[cC][hH][uU][nN][kK][eE][dD]/
  }

signature sid-1626 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS /StoreCSVS/InstantOrder.asmx request"
  http /.*[\/\\]StoreCSVS[\/\\]InstantOrder\.asmx/
  tcp-state established,originator
  }

signature sid-1750 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS users.xml access"
  http /.*[\/\\]users\.xml/
  tcp-state established,originator
  }

signature sid-1753 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS as_web.exe access"
  http /.*[\/\\]as_web\.exe/
  tcp-state established,originator
  }

signature sid-1754 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS as_web4.exe access"
  http /.*[\/\\]as_web4\.exe/
  tcp-state established,originator
  }

signature sid-1756 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS NewsPro administration authentication attempt"
  tcp-state established,originator
  payload /.*logged,true/
  }

signature sid-1772 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS pbserver access"
  http /.*[\/\\]pbserver[\/\\]pbserver\.dll/
  tcp-state established,originator
  }

signature sid-1660 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS trace.axd access"
  http /.*[\/\\]trace\.axd/
  tcp-state established,originator
  }

signature sid-1484 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS /isapi/tstisapi.dll access"
  http /.*[\/\\]isapi[\/\\]tstisapi\.dll/
  tcp-state established,originator
  }

signature sid-1485 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS mkilog.exe access"
  http /.*[\/\\]mkilog\.exe/
  tcp-state established,originator
  }

signature sid-1486 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ctss.idc access"
  http /.*[\/\\]ctss\.idc/
  tcp-state established,originator
  }

signature sid-1487 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS /iisadmpwd/aexp2.htr access"
  http /.*[\/\\]iisadmpwd[\/\\]aexp2\.htr/
  tcp-state established,originator
  }

signature sid-969 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS WebDAV file lock attempt"
  tcp-state established,originator
  payload /LOCK /
  }

signature sid-971 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ISAPI .printer access"
  http /.*\.printer/
  tcp-state established,originator
  }

signature sid-1243 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ISAPI .ida attempt"
  http /.*\.ida\?/
  tcp-state established,originator
  }

signature sid-1242 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ISAPI .ida access"
  http /.*\.ida/
  tcp-state established,originator
  }

signature sid-1244 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ISAPI .idq attempt"
  http /.*\.idq\?/
  tcp-state established,originator
  }

signature sid-1245 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ISAPI .idq access"
  http /.*\.idq/
  tcp-state established,originator
  }

signature sid-972 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS %2E-asp access"
  http /.*%2e\.asp/
  tcp-state established,originator
  }

signature sid-973 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS *.idc attempt"
  http /.*[\/\\]\*\.idc/
  tcp-state established,originator
  }

signature sid-974 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS .... access"
  tcp-state established,originator
  payload /.*\x2e\x2e\x5c\x2e\x2e/
  }

signature sid-975 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS .asp::$DATA access"
  http /.*\.asp\x3a\x3a\$DATA/
  tcp-state established,originator
  }

signature sid-976 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS .bat? access"
  http /.*\.bat\?/
  tcp-state established,originator
  }

signature sid-977 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS .cnf access"
  http /.*\.cnf/
  tcp-state established,originator
  }

signature sid-978 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ASP contents view"
  tcp-state established,originator
  payload /.*%20/
  payload /.*&[cC][iI][rR][eE][sS][tT][rR][iI][cC][tT][iI][oO][nN]=[nN][oO][nN][eE]/
  payload /.*&[cC][iI][hH][iI][lL][iI][tT][eE][tT][yY][pP][eE]=[fF][uU][lL][lL]/
  }

signature sid-979 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ASP contents view"
  http /.*\.htw\?CiWebHitsFile/
  tcp-state established,originator
  }

signature sid-980 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS CGImail.exe access"
  http /.*[\/\\]scripts[\/\\]CGImail\.exe/
  tcp-state established,originator
  }

signature sid-981 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS unicode directory traversal attempt"
  tcp-state established,originator
  payload /.*\/\.\.%[cC]0%[aA][fF]\.\.\//
  }

signature sid-982 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS unicode directory traversal attempt"
  tcp-state established,originator
  payload /.*\/\.\.%[cC]1%1[cC]\.\.\//
  }

signature sid-983 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS unicode directory traversal attempt"
  tcp-state established,originator
  payload /.*\/\.\.%[cC]1%9[cC]\.\.\//
  }

signature sid-1945 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS unicode directory traversal attempt"
  tcp-state established,originator
  payload /.*\/\.\.%255[cC]\.\./
  }

signature sid-986 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS MSProxy access"
  http /.*[\/\\]scripts[\/\\]proxy[\/\\]w3proxy\.dll/
  tcp-state established,originator
  }

signature sid-1725 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS +.htr code fragment attempt"
  http /.*\+\.htr/
  tcp-state established,originator
  }

signature sid-987 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS .htr access"
  http /.*\.htr/
  tcp-state established,originator
  }

signature sid-988 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS SAM Attempt"
  tcp-state established,originator
  payload /.*[sS][aA][mM]\._/
  }

signature sid-989 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS Unicode2.pl script (File permission canonicalization)"
  http /.*[\/\\]sensepost\.exe/
  tcp-state established,originator
  }

signature sid-990 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS _vti_inf access"
  http /.*_vti_inf\.html/
  tcp-state established,originator
  }

signature sid-991 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS achg.htr access"
  http /.*[\/\\]iisadmpwd[\/\\]achg\.htr/
  tcp-state established,originator
  }

signature sid-994 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS /scripts/iisadmin/default.htm access"
  http /.*[\/\\]scripts[\/\\]iisadmin[\/\\]default\.htm/
  tcp-state established,originator
  }

signature sid-995 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ism.dll access"
  http /.*[\/\\]scripts[\/\\]iisadmin[\/\\]ism\.dll\?http[\/\\]dir/
  tcp-state established,originator
  }

signature sid-996 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS anot.htr access"
  http /.*[\/\\]iisadmpwd[\/\\]anot/
  tcp-state established,originator
  }

signature sid-997 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS asp-dot attempt"
  http /.*\.asp\./
  tcp-state established,originator
  }

signature sid-998 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS asp-srch attempt"
  http /.*#filename=\*\.asp/
  tcp-state established,originator
  }

signature sid-1000 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS bdir.htr access"
  http /.*[\/\\]bdir\.htr/
  tcp-state established,originator
  }

signature sid-1661 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS cmd32.exe access"
  tcp-state established,originator
  payload /.*[cC][mM][dD]32\.[eE][xX][eE]/
  }

signature sid-1002 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS cmd.exe access"
  tcp-state established,originator
  payload /.*[cC][mM][dD]\.[eE][xX][eE]/
  }

signature sid-1003 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS cmd? access"
  tcp-state established,originator
  payload /.*\.[cC][mM][dD]\?&/
  }

signature sid-1007 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS cross-site scripting attempt"
  http /.*[\/\\]Form_JScript\.asp/
  tcp-state established,originator
  }

signature sid-1380 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS cross-site scripting attempt"
  http /.*[\/\\]Form_VBScript\.asp/
  tcp-state established,originator
  }

signature sid-1008 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS del attempt"
  tcp-state established,originator
  payload /.*&[dD][eE][lL]\+\/[sS]\+[cC]\x3a\\\*\.\*/
  }

signature sid-1009 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS directory listing"
  http /.*[\/\\]ServerVariables_Jscript\.asp/
  tcp-state established,originator
  }

signature sid-1010 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS encoding access"
  tcp-state established,originator
  payload /.*\x25\x31\x75/
  }

signature sid-1011 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS exec-src access"
  tcp-state established,originator
  payload /.*#[fF][iI][lL][eE][nN][aA][mM][eE]=\*\.[eE][xX][eE]/
  }

signature sid-1012 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS fpcount attempt"
  http /.*[\/\\]fpcount\.exe/
  tcp-state established,originator
  payload /.*[dD][iI][gG][iI][tT][sS]=/
  }

signature sid-1013 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS fpcount access"
  http /.*[\/\\]fpcount\.exe/
  tcp-state established,originator
  }

signature sid-1015 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS getdrvs.exe access"
  http /.*[\/\\]scripts[\/\\]tools[\/\\]getdrvs\.exe/
  tcp-state established,originator
  }

signature sid-1016 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS global.asa access"
  http /.*[\/\\]global\.asa/
  tcp-state established,originator
  }

signature sid-1017 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS idc-srch attempt"
  tcp-state established,originator
  payload /.*#[fF][iI][lL][eE][nN][aA][mM][eE]=\*\.[iI][dD][cC]/
  }

signature sid-1018 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS iisadmpwd attempt"
  http /.*[\/\\]iisadmpwd[\/\\]aexp/
  tcp-state established,originator
  }

signature sid-1019 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS index server file source code attempt"
  http /.*\?CiWebHitsFile=[\/\\]/
  tcp-state established,originator
  payload /.*&CiRestriction=none&CiHiliteType=Full/
  }

signature sid-1020 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS isc$data attempt"
  http /.*\.idc\x3a\x3a\$data/
  tcp-state established,originator
  }

signature sid-1021 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS ism.dll attempt"
  http /.*%20%20%20%20%20\.htr/
  tcp-state established,originator
  }

signature sid-1022 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS jet vba access"
  http /.*[\/\\]advworks[\/\\]equipment[\/\\]catalog_type\.asp/
  tcp-state established,originator
  }

signature sid-1023 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS msadcs.dll access"
  http /.*[\/\\]msadcs\.dll/
  tcp-state established,originator
  }

signature sid-1024 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS newdsn.exe access"
  http /.*[\/\\]scripts[\/\\]tools[\/\\]newdsn\.exe/
  tcp-state established,originator
  }

signature sid-1025 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS perl access"
  http /.*[\/\\]scripts[\/\\]perl/
  tcp-state established,originator
  }

signature sid-1026 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS perl-browse0a attempt"
  http /.*%0a\.pl/
  tcp-state established,originator
  }

signature sid-1027 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS perl-browse20 attempt"
  http /.*%20\.pl/
  tcp-state established,originator
  }

signature sid-1029 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS scripts-browse access"
  http /.*[\/\\]scripts[\/\\]\x20/
  tcp-state established,originator
  }

signature sid-1030 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS search97.vts access"
  http /.*[\/\\]search97\.vts/
  tcp-state established,originator
  }

signature sid-1037 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS showcode.asp access"
  http /.*[\/\\]showcode\.asp/
  tcp-state established,originator
  }

signature sid-1038 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS site server config access"
  http /.*[\/\\]adsamples[\/\\]config[\/\\]site\.csc/
  tcp-state established,originator
  }

signature sid-1039 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS srch.htm access"
  http /.*[\/\\]samples[\/\\]isapi[\/\\]srch\.htm/
  tcp-state established,originator
  }

signature sid-1040 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS srchadm access"
  http /.*[\/\\]srchadm/
  tcp-state established,originator
  }

signature sid-1041 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS uploadn.asp access"
  http /.*[\/\\]scripts[\/\\]uploadn\.asp/
  tcp-state established,originator
  }

signature sid-1042 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS view source via translate header"
  tcp-state established,originator
  payload /.*[tT][rR][aA][nN][sS][lL][aA][tT][eE]\x3a [fF]/
  }

signature sid-1043 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS viewcode.asp access"
  http /.*[\/\\]viewcode\.asp/
  tcp-state established,originator
  }

signature sid-1044 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS webhits access"
  http /.*\.htw/
  tcp-state established,originator
  }

signature sid-1726 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS doctodep.btr access"
  http /.*doctodep\.btr/
  tcp-state established,originator
  }

signature sid-1046 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS site/iisamples access"
  http /.*[\/\\]site[\/\\]iisamples/
  tcp-state established,originator
  }

signature sid-1256 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS CodeRed v2 root.exe access"
  http /.*[\/\\]root\.exe/
  tcp-state established,originator
  }

signature sid-1283 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS outlook web dos"
  http /.*[\/\\]exchange[\/\\]LogonFrm\.asp\?/
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL][bB][oO][xX]=/
  payload /.*\x25\x25\x25/
  }

signature sid-1400 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS /scripts/samples/ access"
  http /.*[\/\\]scripts[\/\\]samples[\/\\]/
  tcp-state established,originator
  }

signature sid-1401 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS /msadc/samples/ access"
  http /.*[\/\\]msadc[\/\\]samples[\/\\]/
  tcp-state established,originator
  }

signature sid-1402 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS iissamples access"
  http /.*[\/\\]iissamples[\/\\]/
  tcp-state established,originator
  }

signature sid-970 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS multiple decode attempt"
  http /.*%5c/
  http /.*\.\./
  tcp-state established,originator
  }

signature sid-993 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS iisadmin access"
  http /.*[\/\\]iisadmin/
  tcp-state established,originator
  }

signature sid-1285 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS msdac access"
  http /.*[\/\\]msdac[\/\\]/
  tcp-state established,originator
  }

signature sid-1286 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS _mem_bin access"
  http /.*[\/\\]_mem_bin[\/\\]/
  tcp-state established,originator
  }

signature sid-1595 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS htimage.exe access"
  http /.*[\/\\]htimage\.exe/
  tcp-state established,originator
  }

signature sid-1817 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS MS Site Server default login attempt"
  http /.*[\/\\]SiteServer[\/\\]Admin[\/\\]knowledge[\/\\]persmbr[\/\\]/
  tcp-state established,originator
  payload /.*[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]: [bB][aA][sS][iI][cC] [tT][eE][rR][bB][uU][fF]9[bB][bB][mM]9[uU][eE][wW]1[vV][dD][xX][mM]6[tT][gG][rR][hH][cC][fF][bB][hH][cC]3[nN]3[bB]3[jJ][kK][xX][zZ][eE]=/
  }

signature sid-1818 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS MS Site Server admin attempt"
  http /.*[\/\\]Site Server[\/\\]Admin[\/\\]knowledge[\/\\]persmbr[\/\\]/
  tcp-state established,originator
  }

signature sid-1075 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS postinfo.asp access"
  http /.*[\/\\]scripts[\/\\]postinfo\.asp/
  tcp-state established,originator
  }

signature sid-1567 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS /exchange/root.asp attempt"
  http /.*[\/\\]exchange[\/\\]root\.asp\?acs=anon/
  tcp-state established,originator
  }

signature sid-1568 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS /exchange/root.asp access"
  http /.*[\/\\]exchange[\/\\]root\.asp/
  tcp-state established,originator
  }

signature sid-2090 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS WEBDAV exploit attempt"
  tcp-state established,originator
  payload /.*HTTP\/1\.1\x0aContent-type\x3a text\/xml\x0aHOST\x3a.{1}.*Accept\x3a \x2a\/\x2a\x0aTranslate\x3a f\x0aContent-length\x3a5276\x0a\x0a/
  }

signature sid-2091 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS WEBDAV nessus safe scan attempt"
  tcp-state established,originator
  payload /.*SEARCH \/ HTTP\/1\.1\x0d\x0aHost\x3a.{0,251}\x0d\x0a\x0d\x0a/
  }

signature sid-2117 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS Battleaxe Forum login.asp access"
  http /.*myaccount[\/\\]login\.asp/
  tcp-state established,originator
  }

signature sid-2129 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS nsiislog.dll access"
  http /.*[\/\\]nsiislog\.dll/
  tcp-state established,originator
  }

signature sid-2130 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS IISProtect siteadmin.asp access"
  http /.*[\/\\]iisprotect[\/\\]admin[\/\\]SiteAdmin\.asp/
  tcp-state established,originator
  }

signature sid-2157 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS IISProtect globaladmin.asp access"
  http /.*[\/\\]iisprotect[\/\\]admin[\/\\]GlobalAdmin\.asp/
  tcp-state established,originator
  }

signature sid-2131 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS IISProtect access"
  http /.*[\/\\]iisprotect[\/\\]admin[\/\\]/
  tcp-state established,originator
  }

signature sid-2132 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS Synchrologic Email Accelerator userid list access attempt"
  http /.*[\/\\]en[\/\\]admin[\/\\]aggregate\.asp/
  tcp-state established,originator
  }

signature sid-2133 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS MS BizTalk server access"
  http /.*[\/\\]biztalkhttpreceive\.dll/
  tcp-state established,originator
  }

signature sid-2134 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-IIS register.asp access"
  http /.*[\/\\]register\.asp/
  tcp-state established,originator
  }

signature sid-1248 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE rad fp30reg.dll access"
  http /.*[\/\\]fp30reg\.dll/
  tcp-state established,originator
  }

signature sid-1249 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE frontpage rad fp4areg.dll access"
  http /.*[\/\\]fp4areg\.dll/
  tcp-state established,originator
  }

signature sid-937 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE _vti_rpc access"
  http /.*[\/\\]_vti_rpc/
  tcp-state established,originator
  }

signature sid-939 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE posting"
  http /.*[\/\\]author\.dll/
  tcp-state established,originator
  payload /.*[pP][oO][sS][tT]/
  }

signature sid-940 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE shtml.dll access"
  http /.*[\/\\]_vti_bin[\/\\]shtml\.dll/
  tcp-state established,originator
  }

signature sid-941 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE contents.htm access"
  http /.*[\/\\]admcgi[\/\\]contents\.htm/
  tcp-state established,originator
  }

signature sid-942 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE orders.htm access"
  http /.*[\/\\]_private[\/\\]orders\.htm/
  tcp-state established,originator
  }

signature sid-943 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE fpsrvadm.exe access"
  http /.*[\/\\]fpsrvadm\.exe/
  tcp-state established,originator
  }

signature sid-944 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE fpremadm.exe access"
  http /.*[\/\\]fpremadm\.exe/
  tcp-state established,originator
  }

signature sid-945 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE fpadmin.htm access"
  http /.*[\/\\]admisapi[\/\\]fpadmin\.htm/
  tcp-state established,originator
  }

signature sid-946 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE fpadmcgi.exe access"
  http /.*[\/\\]scripts[\/\\]Fpadmcgi\.exe/
  tcp-state established,originator
  }

signature sid-947 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE orders.txt access"
  http /.*[\/\\]_private[\/\\]orders\.txt/
  tcp-state established,originator
  }

signature sid-948 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE form_results access"
  http /.*[\/\\]_private[\/\\]form_results\.txt/
  tcp-state established,originator
  }

signature sid-949 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE registrations.htm access"
  http /.*[\/\\]_private[\/\\]registrations\.htm/
  tcp-state established,originator
  }

signature sid-950 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE cfgwiz.exe access"
  http /.*[\/\\]cfgwiz\.exe/
  tcp-state established,originator
  }

signature sid-951 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE authors.pwd access"
  http /.*[\/\\]authors\.pwd/
  tcp-state established,originator
  }

signature sid-952 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE author.exe access"
  http /.*[\/\\]_vti_bin[\/\\]_vti_aut[\/\\]author\.exe/
  tcp-state established,originator
  }

signature sid-953 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE administrators.pwd access"
  http /.*[\/\\]administrators\.pwd/
  tcp-state established,originator
  }

signature sid-954 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE form_results.htm access"
  http /.*[\/\\]_private[\/\\]form_results\.htm/
  tcp-state established,originator
  }

signature sid-955 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE access.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]access\.cnf/
  tcp-state established,originator
  }

signature sid-956 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE register.txt access"
  http /.*[\/\\]_private[\/\\]register\.txt/
  tcp-state established,originator
  }

signature sid-957 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE registrations.txt access"
  http /.*[\/\\]_private[\/\\]registrations\.txt/
  tcp-state established,originator
  }

signature sid-958 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE service.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]service\.cnf/
  tcp-state established,originator
  }

signature sid-959 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE service.pwd"
  http /.*[\/\\]service\.pwd/
  tcp-state established,originator
  }

signature sid-960 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE service.stp access"
  http /.*[\/\\]_vti_pvt[\/\\]service\.stp/
  tcp-state established,originator
  }

signature sid-961 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE services.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]services\.cnf/
  tcp-state established,originator
  }

signature sid-962 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE shtml.exe access"
  http /.*[\/\\]_vti_bin[\/\\]shtml\.exe/
  tcp-state established,originator
  }

signature sid-963 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE svcacl.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]svcacl\.cnf/
  tcp-state established,originator
  }

signature sid-964 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE users.pwd access"
  http /.*[\/\\]users\.pwd/
  tcp-state established,originator
  }

signature sid-965 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE writeto.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]writeto\.cnf/
  tcp-state established,originator
  }

signature sid-966 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE fourdots request"
  tcp-state established,originator
  payload /.*\x2e\x2e\x2e\x2e\x2f/
  }

signature sid-967 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE dvwssr.dll access"
  http /.*[\/\\]dvwssr\.dll/
  tcp-state established,originator
  }

signature sid-968 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE register.htm access"
  http /.*[\/\\]_private[\/\\]register\.htm/
  tcp-state established,originator
  }

signature sid-1288 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-FRONTPAGE /_vti_bin/ access"
  http /.*[\/\\]_vti_bin[\/\\]/
  tcp-state established,originator
  }

signature sid-1497 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cross site scripting attempt"
  tcp-state established,originator
  payload /.*<[sS][cC][rR][iI][pP][tT]>/
  }

signature sid-1667 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cross site scripting (img src=javascript) attempt"
  tcp-state established,originator
  payload /.*[iI][mM][gG] [sS][rR][cC]=[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]/
  }

signature sid-1250 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Cisco IOS HTTP configuration attempt"
  http /.*[\/\\]level[\/\\]/
  http /.*[\/\\]exec[\/\\]/
  tcp-state established,originator
  }

signature sid-1047 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise DOS"
  tcp-state established,originator
  payload /REVLOG \/ /
  }

signature sid-1048 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise directory listing attempt"
  tcp-state established,originator
  payload /INDEX /
  }

signature sid-1050 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC iPlanet GETPROPERTIES attempt"
  tcp-state established,originator
  payload /GETPROPERTIES/
  }

signature sid-1054 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC weblogic view source attempt"
  http /.*\.js%70/
  tcp-state established,originator
  }

signature sid-1055 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat directory traversal attempt"
  http /.*%00\.jsp/
  tcp-state established,originator
  }

signature sid-1056 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat view source attempt"
  http /.*%252ejsp/
  tcp-state established,originator
  }

signature sid-1057 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ftp attempt"
  tcp-state established,originator
  payload /.*[fF][tT][pP]\.[eE][xX][eE]/
  }

signature sid-1058 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC xp_enumdsn attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[eE][nN][uU][mM][dD][sS][nN]/
  }

signature sid-1059 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC xp_filelist attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[fF][iI][lL][eE][lL][iI][sS][tT]/
  }

signature sid-1060 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC xp_availablemedia attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[aA][vV][aA][iI][lL][aA][bB][lL][eE][mM][eE][dD][iI][aA]/
  }

signature sid-1061 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC xp_cmdshell attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[cC][mM][dD][sS][hH][eE][lL][lL]/
  }

signature sid-1062 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC nc.exe attempt"
  tcp-state established,originator
  payload /.*[nN][cC]\.[eE][xX][eE]/
  }

signature sid-1064 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC wsh attempt"
  tcp-state established,originator
  payload /.*[wW][sS][hH]\.[eE][xX][eE]/
  }

signature sid-1065 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC rcmd attempt"
  tcp-state established,originator
  payload /.*[rR][cC][mM][dD]\.[eE][xX][eE]/
  }

signature sid-1066 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC telnet attempt"
  tcp-state established,originator
  payload /.*[tT][eE][lL][nN][eE][tT]\.[eE][xX][eE]/
  }

signature sid-1067 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC net attempt"
  tcp-state established,originator
  payload /.*[nN][eE][tT]\.[eE][xX][eE]/
  }

signature sid-1068 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC tftp attempt"
  tcp-state established,originator
  payload /.*[tT][fF][tT][pP]\.[eE][xX][eE]/
  }

signature sid-1069 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC xp_regread attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[rR][eE][gG][rR][eE][aA][dD]/
  }

signature sid-1977 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC xp_regwrite attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[rR][eE][gG][wW][rR][iI][tT][eE]/
  }

signature sid-1978 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC xp_regdeletekey attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[rR][eE][gG][dD][eE][lL][eE][tT][eE][kK][eE][yY]/
  }

signature sid-1070 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC WebDAV search access"
  tcp-state established,originator
  payload /.{0,1}[sS][eE][aA][rR][cC][hH] /
  }

signature sid-1071 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC .htpasswd access"
  tcp-state established,originator
  payload /.*\.[hH][tT][pP][aA][sS][sS][wW][dD]/
  }

signature sid-1072 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Lotus Domino directory traversal"
  http /.*\.nsf[\/\\]/
  http /.*\.\.[\/\\]/
  tcp-state established,originator
  }

signature sid-1077 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC queryhit.htm access"
  http /.*[\/\\]samples[\/\\]search[\/\\]queryhit\.htm/
  tcp-state established,originator
  }

signature sid-1078 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC counter.exe access"
  http /.*[\/\\]scripts[\/\\]counter\.exe/
  tcp-state established,originator
  }

signature sid-1079 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC WebDAV propfind access"
  tcp-state established,originator
  payload /.*<[aA]:[pP][rR][oO][pP][fF][iI][nN][dD]/
  payload /.*[xX][mM][lL][nN][sS]:[aA]=\"[dD][aA][vV]\">/
  }

signature sid-1080 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC unify eWave ServletExec upload"
  http /.*[\/\\]servlet[\/\\]com\.unify\.servletexec\.UploadServlet/
  tcp-state established,originator
  }

signature sid-1081 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Servers suite DOS"
  http /.*[\/\\]dsgw[\/\\]bin[\/\\]search\?context=/
  tcp-state established,originator
  }

signature sid-1082 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC amazon 1-click cookie theft"
  tcp-state established,originator
  payload /.*[rR][eE][fF]%3[cC][sS][cC][rR][iI][pP][tT]%20[lL][aA][nN][gG][uU][aA][gG][eE]%3[dD]%22[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]/
  }

signature sid-1083 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC unify eWave ServletExec DOS"
  http /.*[\/\\]servlet[\/\\]ServletExec/
  tcp-state established,originator
  }

signature sid-1084 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Allaire JRUN DOS attempt"
  http /.*servlet[\/\\]\.\.\.\.\.\.\./
  tcp-state established,originator
  }

signature sid-1091 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ICQ Webfront HTTP DOS"
  http /.*\?\?\?\?\?\?\?\?\?\?/
  tcp-state established,originator
  }

signature sid-1095 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Talentsoft Web+ Source Code view access"
  http /.*[\/\\]webplus\.exe\?script=test\.wml/
  tcp-state established,originator
  }

signature sid-1096 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Talentsoft Web+ internal IP Address access"
  http /.*[\/\\]webplus\.exe\?about/
  tcp-state established,originator
  }

signature sid-1098 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC SmartWin CyberOffice Shopping Cart access"
  http /.*_private[\/\\]shopping_cart\.mdb/
  tcp-state established,originator
  }

signature sid-1099 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cybercop scan"
  http /.*[\/\\]cybercop/
  tcp-state established,originator
  }

signature sid-1100 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC L3retriever HTTP Probe"
  tcp-state established,originator
  payload /.*User-Agent\x3a Java1\.2\.1\x0d\x0a/
  }

signature sid-1101 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Webtrends HTTP probe"
  tcp-state established,originator
  payload /.*User-Agent\x3a Webtrends Security Analyzer\x0d\x0a/
  }

signature sid-1102 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Nessus 404 probe"
  http /.*[\/\\]nessus_is_probing_you_/
  tcp-state established,originator
  }

signature sid-1103 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape admin passwd"
  http /.*[\/\\]admin-serv[\/\\]config[\/\\]admpw/
  tcp-state established,originator
  }

signature sid-1105 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC BigBrother access"
  http /.*[\/\\]bb-hostsvc\.sh\?HOSTSVC/
  tcp-state established,originator
  }

signature sid-1612 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ftp.pl attempt"
  http /.*[\/\\]ftp\.pl\?dir=\.\.[\/\\]\.\./
  tcp-state established,originator
  }

signature sid-1107 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ftp.pl access"
  http /.*[\/\\]ftp\.pl/
  tcp-state established,originator
  }

signature sid-1108 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat server snoop access"
  http /.*[\/\\]jsp[\/\\]snp[\/\\]/
  http /.*\.snp/
  tcp-state established,originator
  }

signature sid-1109 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ROXEN directory list attempt"
  http /.*\x2F\x25\x30\x30/
  tcp-state established,originator
  }

signature sid-1110 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC apache source.asp file access"
  http /.*[\/\\]site[\/\\]eg[\/\\]source\.asp/
  tcp-state established,originator
  }

signature sid-1111 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat server exploit access"
  http /.*[\/\\]contextAdmin[\/\\]contextAdmin\.html/
  tcp-state established,originator
  }

signature sid-1112 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC http directory traversal"
  tcp-state established,originator
  payload /.*\.\.\\/
  }

signature sid-1115 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ICQ webserver DOS"
  http /.*\.html[\/\\]\.\.\.\.\.\./
  tcp-state established,originator
  }

signature sid-1116 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Lotus DelDoc attempt"
  http /.*\?DeleteDocument/
  tcp-state established,originator
  }

signature sid-1117 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Lotus EditDoc attempt"
  http /.*\?EditDocument/
  tcp-state established,originator
  }

signature sid-1118 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ls%20-l"
  tcp-state established,originator
  payload /.*[lL][sS]%20-[lL]/
  }

signature sid-1119 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC mlog.phtml access"
  http /.*[\/\\]mlog\.phtml/
  tcp-state established,originator
  }

signature sid-1120 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC mylog.phtml access"
  http /.*[\/\\]mylog\.phtml/
  tcp-state established,originator
  }

signature sid-1122 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /etc/passwd"
  tcp-state established,originator
  payload /.*\/[eE][tT][cC]\/[pP][aA][sS][sS][wW][dD]/
  }

signature sid-1123 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ?PageServices access"
  http /.*\?PageServices/
  tcp-state established,originator
  }

signature sid-1124 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Ecommerce check.txt access"
  http /.*[\/\\]config[\/\\]check\.txt/
  tcp-state established,originator
  }

signature sid-1125 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC webcart access"
  http /.*[\/\\]webcart[\/\\]/
  tcp-state established,originator
  }

signature sid-1126 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC AuthChangeUrl access"
  http /.*_AuthChangeUrl\?/
  tcp-state established,originator
  }

signature sid-1127 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC convert.bas access"
  http /.*[\/\\]scripts[\/\\]convert\.bas/
  tcp-state established,originator
  }

signature sid-1128 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cpshost.dll access"
  http /.*[\/\\]scripts[\/\\]cpshost\.dll/
  tcp-state established,originator
  }

signature sid-1129 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC .htaccess access"
  tcp-state established,originator
  payload /.*\.[hH][tT][aA][cC][cC][eE][sS][sS]/
  }

signature sid-1130 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC .wwwacl access"
  http /.*\.wwwacl/
  tcp-state established,originator
  }

signature sid-1131 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC .wwwacl access"
  http /.*\.www_acl/
  tcp-state established,originator
  }

signature sid-1136 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cd.."
  tcp-state established,originator
  payload /.*[cC][dD]\.\./
  }

signature sid-1140 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC guestbook.pl access"
  http /.*[\/\\]guestbook\.pl/
  tcp-state established,originator
  }

signature sid-1613 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC handler attempt"
  http /.*[\/\\]handler/
  http /.*\|/
  tcp-state established,originator
  }

signature sid-1141 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC handler access"
  http /.*[\/\\]handler/
  tcp-state established,originator
  }

signature sid-1142 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /.... access"
  tcp-state established,originator
  payload /.*\/\.\.\.\./
  }

signature sid-1143 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ///cgi-bin access"
  http /.*[\/\\][\/\\][\/\\]cgi-bin/
  tcp-state established,originator
  }

signature sid-1144 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /cgi-bin/// access"
  http /.*[\/\\]cgi-bin[\/\\][\/\\][\/\\]/
  tcp-state established,originator
  }

signature sid-1145 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /~root access"
  http /.*[\/\\]~root/
  tcp-state established,originator
  }

signature sid-1662 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /~ftp access"
  http /.*[\/\\]~ftp/
  tcp-state established,originator
  }

signature sid-1146 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Ecommerce import.txt access"
  http /.*[\/\\]config[\/\\]import\.txt/
  tcp-state established,originator
  }

signature sid-1147 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cat%20 access"
  tcp-state established,originator
  payload /.*[cC][aA][tT]%20/
  }

signature sid-1148 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Ecommerce import.txt access"
  http /.*[\/\\]orders[\/\\]import\.txt/
  tcp-state established,originator
  }

signature sid-1150 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino catalog.nsf access"
  http /.*[\/\\]catalog\.nsf/
  tcp-state established,originator
  }

signature sid-1151 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino domcfg.nsf access"
  http /.*[\/\\]domcfg\.nsf/
  tcp-state established,originator
  }

signature sid-1152 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino domlog.nsf access"
  http /.*[\/\\]domlog\.nsf/
  tcp-state established,originator
  }

signature sid-1153 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino log.nsf access"
  http /.*[\/\\]log\.nsf/
  tcp-state established,originator
  }

signature sid-1154 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino names.nsf access"
  http /.*[\/\\]names\.nsf/
  tcp-state established,originator
  }

signature sid-1575 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino mab.nsf access"
  http /.*[\/\\]mab\.nsf/
  tcp-state established,originator
  }

signature sid-1576 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino cersvr.nsf access"
  http /.*[\/\\]cersvr\.nsf/
  tcp-state established,originator
  }

signature sid-1577 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino setup.nsf access"
  http /.*[\/\\]setup\.nsf/
  tcp-state established,originator
  }

signature sid-1578 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino statrep.nsf access"
  http /.*[\/\\]statrep\.nsf/
  tcp-state established,originator
  }

signature sid-1579 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino webadmin.nsf access"
  http /.*[\/\\]webadmin\.nsf/
  tcp-state established,originator
  }

signature sid-1580 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino events4.nsf access"
  http /.*[\/\\]events4\.nsf/
  tcp-state established,originator
  }

signature sid-1581 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino ntsync4.nsf access"
  http /.*[\/\\]ntsync4\.nsf/
  tcp-state established,originator
  }

signature sid-1582 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino collect4.nsf access"
  http /.*[\/\\]collect4\.nsf/
  tcp-state established,originator
  }

signature sid-1583 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino mailw46.nsf access"
  http /.*[\/\\]mailw46\.nsf/
  tcp-state established,originator
  }

signature sid-1584 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino bookmark.nsf access"
  http /.*[\/\\]bookmark\.nsf/
  tcp-state established,originator
  }

signature sid-1585 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino agentrunner.nsf access"
  http /.*[\/\\]agentrunner\.nsf/
  tcp-state established,originator
  }

signature sid-1586 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Domino mail.box access"
  http /.*[\/\\]mail\.box/
  tcp-state established,originator
  }

signature sid-1155 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Ecommerce checks.txt access"
  http /.*[\/\\]orders[\/\\]checks\.txt/
  tcp-state established,originator
  }

signature sid-1156 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC apache DOS attempt"
  tcp-state established,originator
  payload /.*\x2f\x2f\x2f\x2f\x2f\x2f\x2f\x2f/
  }

signature sid-1157 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape PublishingXpert access"
  http /.*[\/\\]PSUser[\/\\]PSCOErrPage\.htm/
  tcp-state established,originator
  }

signature sid-1158 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC windmail.exe access"
  http /.*[\/\\]windmail\.exe/
  tcp-state established,originator
  }

signature sid-1159 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC webplus access"
  http /.*[\/\\]webplus\?script/
  tcp-state established,originator
  }

signature sid-1160 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape dir index wp"
  http /.*\?wp-/
  tcp-state established,originator
  }

signature sid-1162 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cart 32 AdminPwd access"
  http /.*[\/\\]c32web\.exe[\/\\]ChangeAdminPassword/
  tcp-state established,originator
  }

signature sid-1164 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC shopping cart access"
  http /.*[\/\\]quikstore\.cfg/
  tcp-state established,originator
  }

signature sid-1614 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Novell Groupwise gwweb.exe attempt"
  http /.*[\/\\]GWWEB\.EXE\?HELP=/
  tcp-state established,originator
  }

signature sid-1165 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Novell Groupwise gwweb.exe access"
  tcp-state established,originator
  payload /.*\/[gG][wW][wW][eE][bB]\.[eE][xX][eE]/
  }

signature sid-1166 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ws_ftp.ini access"
  http /.*[\/\\]ws_ftp\.ini/
  tcp-state established,originator
  }

signature sid-1167 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC rpm_query access"
  http /.*[\/\\]rpm_query/
  tcp-state established,originator
  }

signature sid-1168 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC mall log order access"
  http /.*[\/\\]mall_log_files[\/\\]order\.log/
  tcp-state established,originator
  }

signature sid-1173 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC architext_query.pl access"
  http /.*[\/\\]ews[\/\\]architext_query\.pl/
  tcp-state established,originator
  }

signature sid-1175 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC wwwboard.pl access"
  http /.*[\/\\]wwwboard\.pl/
  tcp-state established,originator
  }

signature sid-1176 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC order.log access"
  http /.*[\/\\]admin_files[\/\\]order\.log/
  tcp-state established,originator
  }

signature sid-1177 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-verify-link/
  tcp-state established,originator
  }

signature sid-1180 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC get32.exe access"
  http /.*[\/\\]get32\.exe/
  tcp-state established,originator
  }

signature sid-1181 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Annex Terminal DOS attempt"
  http /.*[\/\\]ping\?query=/
  tcp-state established,originator
  }

signature sid-1182 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cgitest.exe attempt"
  http /.*[\/\\]cgitest\.exe\x0d\x0auser/
  tcp-state established,originator
  }

signature sid-1587 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cgitest.exe access"
  http /.*[\/\\]cgitest\.exe/
  tcp-state established,originator
  }

signature sid-1183 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-cs-dump/
  tcp-state established,originator
  }

signature sid-1184 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-ver-info/
  tcp-state established,originator
  }

signature sid-1186 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-ver-diff/
  tcp-state established,originator
  }

signature sid-1187 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC SalesLogix Eviewer web command attempt"
  http /.*[\/\\]slxweb\.dll[\/\\]admin\?command=/
  tcp-state established,originator
  }

signature sid-1588 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC SalesLogix Eviewer access"
  http /.*[\/\\]slxweb\.dll/
  tcp-state established,originator
  }

signature sid-1188 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-start-ver/
  tcp-state established,originator
  }

signature sid-1189 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-stop-ver/
  tcp-state established,originator
  }

signature sid-1190 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-uncheckout/
  tcp-state established,originator
  }

signature sid-1191 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-html-rend/
  tcp-state established,originator
  }

signature sid-1381 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Trend Micro OfficeScan attempt"
  http /.*[\/\\]officescan[\/\\]cgi[\/\\]jdkRqNotify\.exe\?/
  http /.*domain=/
  http /.*event=/
  tcp-state established,originator
  }

signature sid-1192 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Trend Micro OfficeScan access"
  http /.*[\/\\]officescan[\/\\]cgi[\/\\]jdkRqNotify\.exe/
  tcp-state established,originator
  }

signature sid-1193 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC oracle web arbitrary command execution attempt"
  http /.*[\/\\]ows-bin[\/\\]/
  http /.*\?&/
  tcp-state established,originator
  }

signature sid-1880 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC oracle web application server access"
  http /.*[\/\\]ows-bin[\/\\]/
  tcp-state established,originator
  }

signature sid-1198 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-usr-prop/
  tcp-state established,originator
  }

signature sid-1202 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC search.vts access"
  http /.*[\/\\]search\.vts/
  tcp-state established,originator
  }

signature sid-1615 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC htgrep attempt"
  http /.*[\/\\]htgrep/
  tcp-state established,originator
  payload /.*hdr=\//
  }

signature sid-1207 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC htgrep access"
  http /.*[\/\\]htgrep/
  tcp-state established,originator
  }

signature sid-1209 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC .nsconfig access"
  http /.*[\/\\]\.nsconfig/
  tcp-state established,originator
  }

signature sid-1212 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Admin_files access"
  http /.*[\/\\]admin_files/
  tcp-state established,originator
  }

signature sid-1213 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC backup access"
  http /.*[\/\\]backup/
  tcp-state established,originator
  }

signature sid-1214 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC intranet access"
  http /.*[\/\\]intranet[\/\\]/
  tcp-state established,originator
  }

signature sid-1216 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC filemail access"
  http /.*[\/\\]filemail/
  tcp-state established,originator
  }

signature sid-1217 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC plusmail access"
  http /.*[\/\\]plusmail/
  tcp-state established,originator
  }

signature sid-1218 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC adminlogin access"
  http /.*[\/\\]adminlogin/
  tcp-state established,originator
  }

signature sid-1220 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ultraboard access"
  http /.*[\/\\]ultraboard/
  tcp-state established,originator
  }

signature sid-1589 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC musicat empower attempt"
  http /.*[\/\\]empower\?DB=/
  tcp-state established,originator
  }

signature sid-1221 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC musicat empower access"
  http /.*[\/\\]empower/
  tcp-state established,originator
  }

signature sid-1224 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ROADS search.pl attempt"
  http /.*[\/\\]ROADS[\/\\]cgi-bin[\/\\]search\.pl/
  tcp-state established,originator
  payload /.*[fF][oO][rR][mM]=/
  }

signature sid-1230 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC VirusWall FtpSave access"
  http /.*[\/\\]FtpSave\.dll/
  tcp-state established,originator
  }

signature sid-1234 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC VirusWall FtpSaveCSP access"
  http /.*[\/\\]FtpSaveCSP\.dll/
  tcp-state established,originator
  }

signature sid-1235 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC VirusWall FtpSaveCVP access"
  http /.*[\/\\]FtpSaveCVP\.dll/
  tcp-state established,originator
  }

signature sid-1236 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat sourecode view"
  http /.*\.js%2570/
  tcp-state established,originator
  }

signature sid-1237 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat sourecode view"
  http /.*\.j%2573p/
  tcp-state established,originator
  }

signature sid-1238 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat sourecode view"
  http /.*\.%256Asp/
  tcp-state established,originator
  }

signature sid-1241 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC SWEditServlet directory traversal attempt"
  http /.*[\/\\]SWEditServlet/
  tcp-state established,originator
  payload /.*template=\.\.\/\.\.\/\.\.\//
  }

signature sid-1259 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC SWEditServlet access"
  http /.*[\/\\]SWEditServlet/
  tcp-state established,originator
  }

signature sid-1139 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC whisker HEAD/./"
  tcp-state established,originator
  payload /.*HEAD\/\.\//
  }

signature sid-1258 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC HP OpenView Manager DOS"
  http /.*[\/\\]OvCgi[\/\\]OpenView5\.exe\?Context=Snmp&Action=Snmp&Host=&Oid=/
  tcp-state established,originator
  }

signature sid-1260 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC long basic authorization string"
  tcp-state established,originator
  payload /.*[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]: [bB][aA][sS][iI][cC] [^\x0A]{512}/
  }

signature sid-1291 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC sml3com access"
  http /.*[\/\\]graphics[\/\\]sml3com/
  tcp-state established,originator
  }

signature sid-1001 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC carbo.dll access"
  http /.*[\/\\]carbo\.dll/
  tcp-state established,originator
  payload /.*[iI][cC][aA][tT][cC][oO][mM][mM][aA][nN][dD]=/
  }

signature sid-1302 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC console.exe access"
  http /.*[\/\\]cgi-bin[\/\\]console\.exe/
  tcp-state established,originator
  }

signature sid-1303 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cs.exe access"
  http /.*[\/\\]cgi-bin[\/\\]cs\.exe/
  tcp-state established,originator
  }

signature sid-1113 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC http directory traversal"
  tcp-state established,originator
  payload /.*\.\.\//
  }

signature sid-1375 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC sadmind worm access"
  tcp-state established,originator
  payload /.{0,1}GET x HTTP\/1\.0/
  }

signature sid-1376 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC jrun directory browse attempt"
  http /.*[\/\\]%3f\.jsp/
  tcp-state established,originator
  }

signature sid-1385 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC mod-plsql administration access"
  http /.*[\/\\]admin_[\/\\]/
  tcp-state established,originator
  }

signature sid-1391 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Phorecast remote code execution attempt"
  tcp-state established,originator
  payload /.*includedir=/
  }

signature sid-1403 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC viewcode access"
  http /.*[\/\\]viewcode/
  tcp-state established,originator
  }

signature sid-1404 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC showcode access"
  http /.*[\/\\]showcode/
  tcp-state established,originator
  }

signature sid-1433 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC .history access"
  http /.*[\/\\]\.history/
  tcp-state established,originator
  }

signature sid-1434 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC .bash_history access"
  http /.*[\/\\]\.bash_history/
  tcp-state established,originator
  }

signature sid-1489 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /~nobody access"
  http /.*[\/\\]~nobody/
  tcp-state established,originator
  }

signature sid-1492 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC RBS ISP /newuser  directory traversal attempt"
  http /.*[\/\\]newuser\?Image=\.\.[\/\\]\.\./
  tcp-state established,originator
  }

signature sid-1493 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC RBS ISP /newuser access"
  http /.*[\/\\]newuser/
  tcp-state established,originator
  }

signature sid-1663 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC *%0a.pl access"
  http /.*[\/\\]\*%0a\.pl/
  tcp-state established,originator
  }

signature sid-1664 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC mkplog.exe access"
  http /.*[\/\\]mkplog\.exe/
  tcp-state established,originator
  }

signature sid-1665 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC mkilog.exe access"
  http /.*[\/\\]mkilog\.exe/
  tcp-state established,originator
  }

signature sid-509 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC PCCS mysql database admin tool access"
  tcp-state established,originator
  payload /.{0,5}[pP][cC][cC][sS][mM][yY][sS][qQ][lL][aA][dD][mM]\/[iI][nN][cC][sS]\/[dD][bB][cC][oO][nN][nN][eE][cC][tT]\.[iI][nN][cC]/
  }

signature sid-1769 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC .DS_Store access"
  http /.*[\/\\]\.DS_Store/
  tcp-state established,originator
  }

signature sid-1770 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC .FBCIndex access"
  http /.*[\/\\]\.FBCIndex/
  tcp-state established,originator
  }

signature sid-1500 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ExAir access"
  http /.*[\/\\]exair[\/\\]search[\/\\]/
  tcp-state established,originator
  }

signature sid-1519 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC apache ?M=D directory list attempt"
  http /.*[\/\\]\?M=D/
  tcp-state established,originator
  }

signature sid-1520 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC server-info access"
  http /.*[\/\\]server-info/
  tcp-state established,originator
  }

signature sid-1521 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC server-status access"
  http /.*[\/\\]server-status/
  tcp-state established,originator
  }

signature sid-1522 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ans.pl attempt"
  http /.*[\/\\]ans\.pl\?p=\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  }

signature sid-1523 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ans.pl access"
  http /.*[\/\\]ans\.pl/
  tcp-state established,originator
  }

signature sid-1524 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC AxisStorpoint CD attempt"
  http /.*[\/\\]cd[\/\\]\.\.[\/\\]config[\/\\]html[\/\\]cnf_gi\.htm/
  tcp-state established,originator
  }

signature sid-1525 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Axis Storpoint CD access"
  http /.*[\/\\]config[\/\\]html[\/\\]cnf_gi\.htm/
  tcp-state established,originator
  }

signature sid-1526 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC basilix sendmail.inc access"
  http /.*[\/\\]inc[\/\\]sendmail\.inc/
  tcp-state established,originator
  }

signature sid-1527 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC basilix mysql.class access"
  http /.*[\/\\]class[\/\\]mysql\.class/
  tcp-state established,originator
  }

signature sid-1528 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC BBoard access"
  http /.*[\/\\]servlet[\/\\]sunexamples\.BBoardServlet/
  tcp-state established,originator
  }

signature sid-1544 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Cisco Catalyst command execution attempt"
  http /.*[\/\\]exec[\/\\]show[\/\\]config[\/\\]cr/
  tcp-state established,originator
  }

signature sid-1546 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Cisco /%% DOS attempt"
  http /.*[\/\\]%%/
  tcp-state established,originator
  }

signature sid-1551 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /CVS/Entries access"
  http /.*[\/\\]CVS[\/\\]Entries/
  tcp-state established,originator
  }

signature sid-1552 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC cvsweb version access"
  http /.*[\/\\]cvsweb[\/\\]version/
  tcp-state established,originator
  }

signature sid-1559 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /doc/packages access"
  http /.*[\/\\]doc[\/\\]packages/
  tcp-state established,originator
  }

signature sid-1560 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /doc/ access"
  http /.*[\/\\]doc[\/\\]/
  tcp-state established,originator
  }

signature sid-1561 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ?open access"
  http /.*\?open/
  tcp-state established,originator
  }

signature sid-1563 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC login.htm attempt"
  http /.*[\/\\]login\.htm\?password=/
  tcp-state established,originator
  }

signature sid-1564 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC login.htm access"
  http /.*[\/\\]login\.htm/
  tcp-state established,originator
  }

signature sid-1603 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC DELETE attempt"
  tcp-state established,originator
  payload /[dD][eE][lL][eE][tT][eE] /
  }

signature sid-1670 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /home/ftp access"
  http /.*[\/\\]home[\/\\]ftp/
  tcp-state established,originator
  }

signature sid-1671 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /home/www access"
  http /.*[\/\\]home[\/\\]www/
  tcp-state established,originator
  }

signature sid-1738 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC global.inc access"
  http /.*[\/\\]global\.inc/
  tcp-state established,originator
  }

signature sid-1744 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC SecureSite authentication bypass attempt"
  tcp-state established,originator
  payload /.*[sS][eE][cC][uU][rR][eE]_[sS][iI][tT][eE], [oO][kK]/
  }

signature sid-1757 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC b2 arbitrary command execution attempt"
  http /.*[\/\\]b2[\/\\]b2-include[\/\\]/
  tcp-state established,originator
  payload /.*b2inc/
  payload /.*http:\/\//
  }

signature sid-1758 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC b2 access"
  http /.*[\/\\]b2[\/\\]b2-include[\/\\]/
  tcp-state established,originator
  payload /.*b2inc/
  payload /.*http:\/\//
  }

signature sid-1766 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC search.dll directory listing attempt"
  http /.*[\/\\]search\.dll/
  tcp-state established,originator
  payload /.*query=%00/
  }

signature sid-1767 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC search.dll access"
  http /.*[\/\\]search\.dll/
  tcp-state established,originator
  }

signature sid-1498 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8181
  event "WEB-MISC PIX firewall manager directory traversal attempt"
  http /.*[\/\\]\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  }

signature sid-1604 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 4080
  event "WEB-MISC iChat directory traversal attempt"
  http /.*[\/\\]\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  }

signature sid-1558 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8080
  event "WEB-MISC Delegate whois overflow attempt"
  tcp-state established,originator
  payload /.*[wW][hH][oO][iI][sS]:\/\//
  }

signature sid-1518 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8000
  event "WEB-MISC nstelemetry.adp access"
  http /.*[\/\\]nstelemetry\.adp/
  tcp-state established,originator
  }

signature sid-1132 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 457
  event "WEB-MISC Netscape Unixware overflow"
  tcp-state established,originator
  payload /.*\xeb\x5f\x9a\xff\xff\xff\xff\x07\xff\xc3\x5e\x31\xc0\x89\x46\x9d/
  }

signature sid-1199 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 2301
  event "WEB-MISC Compaq Insight directory traversal"
  http /.*\.\.[\/\\]/
  tcp-state established,originator
  }

signature sid-1231 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC VirusWall catinfo access"
  http /.*[\/\\]catinfo/
  tcp-state established,originator
  }

signature sid-1232 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1812
  event "WEB-MISC VirusWall catinfo access"
  http /.*[\/\\]catinfo/
  tcp-state established,originator
  }

signature sid-1809 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Apache Chunked-Encoding worm attempt"
  tcp-state established,originator
  payload /.*[cC][cC][cC][cC][cC][cC][cC]: [aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA]/
  }

signature sid-1807 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Transfer-Encoding: chunked"
  tcp-state established,originator
  payload /.*[tT][rR][aA][nN][sS][fF][eE][rR]-[eE][nN][cC][oO][dD][iI][nN][gG]:/
  payload /.*[cC][hH][uU][nN][kK][eE][dD]/
  }

signature sid-1814 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC CISCO VoIP DOS ATTEMPT"
  http /.*[\/\\]StreamingStatistics/
  tcp-state established,originator
  }

signature sid-1820 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC IBM Net.Commerce orderdspc.d2w access"
  http /.*[\/\\]ncommerce3[\/\\]ExecMacro[\/\\]orderdspc\.d2w/
  tcp-state established,originator
  }

signature sid-1826 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC WEB-INF access"
  http /.*[\/\\]WEB-INF/
  tcp-state established,originator
  }

signature sid-1827 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat servlet mapping cross site scripting attempt"
  http /.*[\/\\]servlet[\/\\]/
  http /.*[\/\\]org\.apache\./
  tcp-state established,originator
  }

signature sid-1828 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC iPlanet Search directory traversal attempt"
  http /.*[\/\\]search/
  tcp-state established,originator
  payload /.*NS-query-pat=/
  payload /.*\.\.\/\.\.\//
  }

signature sid-1829 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat TroubleShooter servlet access"
  http /.*[\/\\]examples[\/\\]servlet[\/\\]TroubleShooter/
  tcp-state established,originator
  }

signature sid-1830 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Tomcat SnoopServlet servlet access"
  http /.*[\/\\]examples[\/\\]servlet[\/\\]SnoopServlet/
  tcp-state established,originator
  }

signature sid-1831 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC jigsaw dos attempt"
  http /.*[\/\\]servlet[\/\\]con/
  tcp-state established,originator
  }

signature sid-1835 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Macromedia SiteSpring cross site scripting attempt"
  http /.*[\/\\]error[\/\\]500error\.jsp/
  http /.*et=/
  http /.*<script/
  tcp-state established,originator
  }

signature sid-1839 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC mailman cross site scripting attempt"
  http /.*[\/\\]mailman[\/\\]/
  http /.*\?/
  http /.*info=/
  http /.*<script/
  tcp-state established,originator
  }

signature sid-1847 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC webalizer access"
  http /.*[\/\\]webalizer[\/\\]/
  tcp-state established,originator
  }

signature sid-1848 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC webcart-lite access"
  http /.*[\/\\]webcart-lite[\/\\]/
  tcp-state established,originator
  }

signature sid-1849 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC webfind.exe access"
  http /.*[\/\\]webfind\.exe/
  tcp-state established,originator
  }

signature sid-1851 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC active.log access"
  http /.*[\/\\]active\.log/
  tcp-state established,originator
  }

signature sid-1852 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC robots.txt access"
  http /.*[\/\\]robots\.txt/
  tcp-state established,originator
  }

signature sid-1857 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC robot.txt access"
  http /.*[\/\\]robot\.txt/
  tcp-state established,originator
  }

signature sid-1858 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8181
  event "WEB-MISC CISCO PIX Firewall Manager directory traversal attempt"
  http /.*[\/\\]pixfir~1[\/\\]how_to_login\.html/
  tcp-state established,originator
  }

signature sid-1859 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 9090
  event "WEB-MISC Sun JavaServer default password login attempt"
  http /.*[\/\\]servlet[\/\\]admin/
  tcp-state established,originator
  payload /.*ae9f86d6beaa3f9ecb9a5b7e072a4138/
  }

signature sid-1860 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8080
  event "WEB-MISC Linksys router default password login attempt (:admin)"
  tcp-state established,originator
  payload /.*Authorization: Basic OmFkbWlu/
  }

signature sid-1861 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8080
  event "WEB-MISC Linksys router default password login attempt (admin:admin)"
  tcp-state established,originator
  payload /.*[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]: /
  payload /.* [bB][aA][sS][iI][cC] /
  payload /.*YWRtaW46YWRtaW4/
  }

signature sid-1871 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Oracle XSQLConfig.xml access"
  http /.*[\/\\]XSQLConfig\.xml/
  tcp-state established,originator
  }

signature sid-1872 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Oracle Dynamic Monitoring Services (dms) access"
  http /.*[\/\\]dms0/
  tcp-state established,originator
  }

signature sid-1873 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC globals.jsa access"
  http /.*[\/\\]globals\.jsa/
  tcp-state established,originator
  }

signature sid-1874 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC Oracle Java Process Manager access"
  http /.*[\/\\]oprocmgr-status/
  tcp-state established,originator
  }

signature sid-1881 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC bad HTTP/1.1 request, Potentially worm attack"
  tcp-state established,originator
  payload /GET \/ HTTP\/1\.1\x0d\x0a\x0d\x0a/
  }

signature sid-1104 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  payload-size == 1
  event "WEB-MISC whisker space splice attack"
  tcp-state established,originator
  payload /\x20/
  }

signature sid-1087 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  payload-size < 5
  event "WEB-MISC whisker tab splice attack"
  tcp-state established,originator
  payload /.*\x09/
  }

signature sid-1808 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC apache chunked encoding memory corruption exploit attempt"
  tcp-state established,originator
  payload /.*\xC0\x50\x52\x89\xE1\x50\x51\x52\x50\xB8\x3B\x00\x00\x00\xCD\x80/
  }

signature sid-1943 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /Carello/add.exe access"
  http /.*[\/\\]Carello[\/\\]add\.exe/
  tcp-state established,originator
  }

signature sid-1944 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC /ecscripts/ecware.exe access"
  http /.*[\/\\]ecscripts[\/\\]ecware\.exe/
  tcp-state established,originator
  }

signature sid-1969 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-MISC ion-p access"
  http /.*[\/\\]ion-p/
  tcp-state established,originator
  }

signature sid-1499 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8888
  event "WEB-MISC SiteScope Service access"
  http /.*[\/\\]SiteScope[\/\\]cgi[\/\\]go\.exe[\/\\]SiteScope/
  tcp-state established,originator
  }

signature sid-1946 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8888
  event "WEB-MISC answerbook2 admin attempt"
  http /.*[\/\\]cgi-bin[\/\\]admin[\/\\]admin/
  tcp-state established,originator
  }

signature sid-1947 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 8888
  event "WEB-MISC answerbook2 arbitrary command execution attempt"
  http /.*[\/\\]ab2[\/\\]/
  tcp-state established,originator
  payload /.{1}.*;/
  }

signature sid-1979 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC perl post attempt"
  http /.*[\/\\]perl[\/\\]/
  tcp-state established,originator
  payload /POST/
  }

signature sid-2056 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC TRACE attempt"
  tcp-state established,originator
  payload /TRACE/
  }

signature sid-2057 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC helpout.exe access"
  http /.*[\/\\]helpout\.exe/
  tcp-state established,originator
  }

signature sid-2058 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC MsmMask.exe attempt"
  http /.*[\/\\]MsmMask\.exe/
  tcp-state established,originator
  payload /.*mask=/
  }

signature sid-2059 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC MsmMask.exe access"
  http /.*[\/\\]MsmMask\.exe/
  tcp-state established,originator
  }

signature sid-2060 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC DB4Web access"
  http /.*[\/\\]DB4Web[\/\\]/
  tcp-state established,originator
  }

signature sid-2061 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC Tomcat null byte directory listing attempt"
  http /.*\x00\.jsp/
  tcp-state established,originator
  }

signature sid-2062 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC iPlanet .perf access"
  http /.*[\/\\]\.perf/
  tcp-state established,originator
  }

signature sid-2063 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC Demarc SQL injection attempt"
  http /.*[\/\\]dm[\/\\]demarc/
  tcp-state established,originator
  payload /.*s_key=.*.{0}.*'.{1}.*'.*.{0}.*'/
  }

signature sid-2064 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC Lotus Notes .csp script source download attempt"
  http /.*\.csp/
  tcp-state established,originator
  payload /.*\.csp\./
  }

signature sid-2066 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC Lotus Notes .pl script source download attempt"
  http /.*\.pl/
  tcp-state established,originator
  payload /.*\.pl\./
  }

signature sid-2067 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC Lotus Notes .exe script source download attempt"
  http /.*\.exe/
  tcp-state established,originator
  payload /.*\.exe\./
  }

signature sid-2068 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC BitKeeper arbitrary command attempt"
  http /.*[\/\\]diffs[\/\\]/
  tcp-state established,originator
  payload /.*'.*.{0}.*\x3b.{1}.*'/
  }

signature sid-2069 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC chip.ini access"
  http /.*[\/\\]chip\.ini/
  tcp-state established,originator
  }

signature sid-2070 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC post32.exe arbitrary command attempt"
  http /.*[\/\\]post32\.exe\|/
  tcp-state established,originator
  }

signature sid-2071 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC post32.exe access"
  http /.*[\/\\]post32\.exe/
  tcp-state established,originator
  }

signature sid-2072 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC lyris.pl access"
  http /.*[\/\\]lyris\.pl/
  tcp-state established,originator
  }

signature sid-2073 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC globals.pl access"
  http /.*[\/\\]globals\.pl/
  tcp-state established,originator
  }

signature sid-2135 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC philboard.mdb access"
  http /.*[\/\\]philboard\.mdb/
  tcp-state established,originator
  }

signature sid-2136 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC philboard_admin.asp authentication bypass attempt"
  http /.*[\/\\]philboard_admin\.asp/
  tcp-state established,originator
  payload /.*[cC][oO][oO][kK][iI][eE].*.{0}.*philboard_admin=True/
  }

signature sid-2137 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC philboard_admin.asp access"
  http /.*[\/\\]philboard_admin\.asp/
  tcp-state established,originator
  }

signature sid-2138 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC logicworks.ini access"
  http /.*[\/\\]logicworks\.ini/
  tcp-state established,originator
  }

signature sid-2139 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC /*.shtml access"
  http /.*[\/\\]\*\.shtml/
  tcp-state established,originator
  }

signature sid-2156 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-MISC mod_gzip_status access"
  http /.*[\/\\]mod_gzip_status/
  tcp-state established,originator
  }

signature sid-1233 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  dst-port == http_ports
  event "WEB-CLIENT Outlook EML access"
  http /.*\.eml/
  tcp-state established,originator
  }

signature sid-1735 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == http_ports
  event "WEB-CLIENT XMLHttpRequest attempt"
  tcp-state established,responder
  payload /.*new XMLHttpRequest\(/
  payload /.*[fF][iI][lL][eE]:\/\//
  }

signature sid-1284 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  dst-port == http_ports
  event "WEB-CLIENT readme.eml download attempt"
  http /.*[\/\\]readme\.eml/
  tcp-state established,originator
  }

signature sid-1290 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == http_ports
  event "WEB-CLIENT readme.eml autoload attempt"
  tcp-state established,responder
  payload /.*[wW][iI][nN][dD][oO][wW]\.[oO][pP][eE][nN]\(\"[rR][eE][aA][dD][mM][eE]\.[eE][mM][lL]\"/
  }

signature sid-1840 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == http_ports
  event "WEB-CLIENT Javascript document.domain attempt"
  tcp-state established,responder
  payload /.*[dD][oO][cC][uU][mM][eE][nN][tT]\.[dD][oO][mM][aA][iI][nN]\(/
  }

signature sid-1841 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == http_ports
  event "WEB-CLIENT Javascript URL host spoofing attempt"
  tcp-state established,responder
  payload /.*[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]:\/\//
  }

signature sid-1774 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP bb_smilies.php access"
  http /.*[\/\\]bb_smilies\.php/
  tcp-state established,originator
  }

signature sid-1423 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP content-disposition memchr overflow"
  tcp-state established,originator
  payload /.*Content-Disposition:/
  payload /.*name=\"\xCC\xCC\xCC\xCC\xCC/
  }

signature sid-1736 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP squirrel mail spell-check arbitrary command attempt"
  http /.*[\/\\]squirrelspell[\/\\]modules[\/\\]check_me\.mod\.php/
  tcp-state established,originator
  payload /.*[sS][qQ][sS][pP][eE][lL][lL]_[aA][pP][pP]\[/
  }

signature sid-1737 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP squirrel mail theme arbitrary command attempt"
  http /.*[\/\\]left_main\.php/
  tcp-state established,originator
  payload /.*[cC][mM][dD][dD]=/
  }

signature sid-1739 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP DNSTools administrator authentication bypass attempt"
  http /.*[\/\\]dnstools\.php/
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR]_[lL][oO][gG][gG][eE][dD]_[iI][nN]=[tT][rR][uU][eE]/
  payload /.*[uU][sS][eE][rR]_[dD][nN][sS][tT][oO][oO][lL][sS]_[aA][dD][mM][iI][nN][iI][sS][tT][rR][aA][tT][oO][rR]=[tT][rR][uU][eE]/
  }

signature sid-1740 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP DNSTools authentication bypass attempt"
  http /.*[\/\\]dnstools\.php/
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR]_[lL][oO][gG][gG][eE][dD]_[iI][nN]=[tT][rR][uU][eE]/
  }

signature sid-1741 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP DNSTools access"
  http /.*[\/\\]dnstools\.php/
  tcp-state established,originator
  }

signature sid-1742 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Blahz-DNS dostuff.php modify user attempt"
  http /.*[\/\\]dostuff\.php\?action=modify_user/
  tcp-state established,originator
  }

signature sid-1743 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Blahz-DNS dostuff.php access"
  http /.*[\/\\]dostuff\.php/
  tcp-state established,originator
  }

signature sid-1745 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Messagerie supp_membre.php access"
  http /.*[\/\\]supp_membre\.php/
  tcp-state established,originator
  }

signature sid-1773 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP php.exe access"
  http /.*[\/\\]php\.exe/
  tcp-state established,originator
  }

signature sid-1815 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP directory.php arbitrary command attempt"
  http /.*[\/\\]directory\.php/
  tcp-state established,originator
  payload /.*dir=/
  payload /.*;/
  }

signature sid-1816 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP directory.php access"
  http /.*[\/\\]directory\.php/
  tcp-state established,originator
  }

signature sid-1834 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP PHP-Wiki cross site scripting attempt"
  http /.*[\/\\]modules\.php\?/
  http /.*name=Wiki/
  http /.*<script/
  tcp-state established,originator
  }

signature sid-1967 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP phpbb quick-reply.php arbitrary command attempt"
  http /.*[\/\\]quick-reply\.php/
  tcp-state established,originator
  payload /.{1}.*phpbb_root_path=/
  }

signature sid-1968 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP phpbb quick-reply.php access"
  http /.*[\/\\]quick-reply\.php/
  tcp-state established,originator
  }

signature sid-1997 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP read_body.php access attempt"
  http /.*[\/\\]read_body\.php/
  tcp-state established,originator
  }

signature sid-1998 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP calendar.php access"
  http /.*[\/\\]calendar\.php/
  tcp-state established,originator
  }

signature sid-1999 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP edit_image.php access"
  http /.*[\/\\]edit_image\.php/
  tcp-state established,originator
  }

signature sid-2000 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP readmsg.php access"
  http /.*[\/\\]readmsg\.php/
  tcp-state established,originator
  }

signature sid-2002 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP external include path"
  http /.*\.php/
  tcp-state established,originator
  payload /.*path=http:\/\//
  }

signature sid-1134 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Phorum admin access"
  http /.*[\/\\]admin\.php3/
  tcp-state established,originator
  }

signature sid-1161 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP piranha passwd.php3 access"
  http /.*[\/\\]passwd\.php3/
  tcp-state established,originator
  }

signature sid-1178 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Phorum read access"
  http /.*[\/\\]read\.php3/
  tcp-state established,originator
  }

signature sid-1179 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Phorum violation access"
  http /.*[\/\\]violation\.php3/
  tcp-state established,originator
  }

signature sid-1197 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Phorum code access"
  http /.*[\/\\]code\.php3/
  tcp-state established,originator
  }

signature sid-1300 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP admin.php file upload attempt"
  http /.*[\/\\]admin\.php/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE]_[nN][aA][mM][eE]=/
  }

signature sid-1301 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP admin.php access"
  http /.*[\/\\]admin\.php/
  tcp-state established,originator
  }

signature sid-1407 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP smssend.php access"
  http /.*[\/\\]smssend\.php/
  tcp-state established,originator
  }

signature sid-1399 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP PHP-Nuke remote file include attempt"
  http /.*index\.php/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE]=[hH][tT][tT][pP]:\/\//
  }

signature sid-1490 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Phorum /support/common.php attempt"
  http /.*[\/\\]support[\/\\]common\.php/
  tcp-state established,originator
  payload /.*ForumLang=\.\.\//
  }

signature sid-1491 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Phorum /support/common.php access"
  http /.*[\/\\]support[\/\\]common\.php/
  tcp-state established,originator
  }

signature sid-1137 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Phorum authentication access"
  tcp-state established,originator
  payload /.*[pP][hH][pP]_[aA][uU][tT][hH]_[uU][sS][eE][rR]=[bB][oO][oO][gG][iI][eE][mM][aA][nN]/
  }

signature sid-1085 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP strings overflow"
  tcp-state established,originator
  payload /.*\xba\x49\xfe\xff\xff\xf7\xd2\xb9\xbf\xff\xff\xff\xf7\xd1/
  }

signature sid-1086 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP strings overflow"
  http /.*\?STRENGUR/
  tcp-state established,originator
  }

signature sid-1254 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP PHPLIB remote command attempt"
  tcp-state established,originator
  payload /.*_PHPLIB\[libdir\]/
  }

signature sid-1255 {
  ip-proto == tcp
  src-ip == http_servers
  dst-ip != local_nets
  dst-port == http_ports
  event "WEB-PHP PHPLIB remote command attempt"
  http /.*[\/\\]db_mysql\.inc/
  tcp-state established,originator
  }

signature sid-2074 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Mambo uploadimage.php upload php file attempt"
  http /.*[\/\\]uploadimage\.php/
  tcp-state established,originator
  payload /.*userfile_name=.{1}.*\.php/
  }

signature sid-2075 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Mambo upload.php upload php file attempt"
  http /.*[\/\\]upload\.php/
  tcp-state established,originator
  payload /.*userfile_name=.{1}.*\.php/
  }

signature sid-2076 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Mambo uploadimage.php access"
  http /.*[\/\\]uploadimage\.php/
  tcp-state established,originator
  }

signature sid-2077 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Mambo upload.php access"
  http /.*[\/\\]upload\.php/
  tcp-state established,originator
  }

signature sid-2078 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP phpBB privmsg.php access"
  http /.*[\/\\]privmsg\.php/
  tcp-state established,originator
  }

signature sid-2140 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP p-news.php access"
  http /.*[\/\\]p-news\.php/
  tcp-state established,originator
  }

signature sid-2141 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP shoutbox.php directory traversal attempt"
  http /.*[\/\\]shoutbox\.php/
  tcp-state established,originator
  payload /.*conf=.*.{0}.*\.\.\//
  }

signature sid-2142 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP shoutbox.php access"
  http /.*[\/\\]shoutbox\.php/
  tcp-state established,originator
  }

signature sid-2143 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP b2 cafelog gm-2-b2.php remote command execution attempt"
  http /.*[\/\\]gm-2-b2\.php/
  tcp-state established,originator
  payload /.*b2inc=http/
  }

signature sid-2144 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP b2 cafelog gm-2-b2.php access"
  http /.*[\/\\]gm-2-b2\.php/
  tcp-state established,originator
  }

signature sid-2145 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP TextPortal admin.php default password (admin) attempt"
  http /.*[\/\\]admin\.php/
  tcp-state established,originator
  payload /.*op=admin_enter/
  payload /.*password=admin/
  }

signature sid-2146 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP TextPortal admin.php default password (12345) attempt"
  http /.*[\/\\]admin\.php/
  tcp-state established,originator
  payload /.*op=admin_enter/
  payload /.*password=12345/
  }

signature sid-2147 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP BLNews objects.inc.php4 remote command execution attempt"
  http /.*[\/\\]objects\.inc\.php4/
  tcp-state established,originator
  payload /.*Server\[path\]=http/
  }

signature sid-2148 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP BLNews objects.inc.php4 access"
  http /.*[\/\\]objects\.inc\.php4/
  tcp-state established,originator
  }

signature sid-2149 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP Turba status.php access"
  http /.*[\/\\]turba[\/\\]status\.php/
  tcp-state established,originator
  }

signature sid-2150 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP ttCMS header.php remote command execution attempt"
  http /.*[\/\\]admin[\/\\]templates[\/\\]header\.php/
  tcp-state established,originator
  payload /.*admin_root=http/
  }

signature sid-2151 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP ttCMS header.php access"
  http /.*[\/\\]admin[\/\\]templates[\/\\]header\.php/
  tcp-state established,originator
  }

signature sid-2152 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP test.php access"
  http /.*[\/\\]test\.php/
  tcp-state established,originator
  }

signature sid-2153 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP autohtml.php directory traversal attempt"
  http /.*[\/\\]autohtml\.php/
  tcp-state established,originator
  payload /.*name=.*.{0}.*\.\.\/\.\.\//
  }

signature sid-2154 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP autohtml.php access"
  http /.*[\/\\]autohtml\.php/
  tcp-state established,originator
  }

signature sid-2155 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-PHP ttforum remote command execution attempt"
  http /.*forum[\/\\]index\.php/
  tcp-state established,originator
  payload /.*template=http/
  }

signature sid-676 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB sp_start_job - program execution"
  tcp-state established,originator
  payload /.{31}[sS]\x00[pP]\x00_\x00[sS]\x00[tT]\x00[aA]\x00[rR]\x00[tT]\x00_\x00[jJ]\x00[oO]\x00[bB]\x00/
  }

signature sid-677 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB sp_password password change"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[pP]\x00[aA]\x00[sS]\x00[sS]\x00[wW]\x00[oO]\x00[rR]\x00[dD]\x00/
  }

signature sid-678 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB sp_delete_alert log file deletion"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[dD]\x00[eE]\x00[lL]\x00[eE]\x00[tT]\x00[eE]\x00_\x00[aA]\x00[lL]\x00[eE]\x00/
  }

signature sid-679 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB sp_adduser database user creation"
  tcp-state established,originator
  payload /.{31}[sS]\x00[pP]\x00_\x00[aA]\x00[dD]\x00[dD]\x00[uU]\x00[sS]\x00[eE]\x00[rR]\x00/
  }

signature sid-708 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_enumresultset possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[eE]\x00[nN]\x00[uU]\x00[mM]\x00[rR]\x00[eE]\x00[sS]\x00[uU]\x00[lL]\x00[tT]\x00[sS]\x00[eE]\x00[tT]\x00/
  }

signature sid-1386 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB raiserror possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[rR]\x00[aA]\x00[iI]\x00[sS]\x00[eE]\x00[rR]\x00[rR]\x00[oO]\x00[rR]\x00/
  }

signature sid-702 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_displayparamstmt possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[dD]\x00[iI]\x00[sS]\x00[pP]\x00[lL]\x00[aA]\x00[yY]\x00[pP]\x00[aA]\x00[rR]\x00[aA]\x00[mM]\x00[sS]\x00[tT]\x00[mM]\x00[tT]\x00/
  }

signature sid-703 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_setsqlsecurity possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[sS]\x00[eE]\x00[tT]\x00[sS]\x00[qQ]\x00[lL]\x00[sS]\x00[eE]\x00[cC]\x00[uU]\x00[rR]\x00[iI]\x00[tT]\x00[yY]\x00/
  }

signature sid-681 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_cmdshell program execution"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[cC]\x00[mM]\x00[dD]\x00[sS]\x00[hH]\x00[eE]\x00[lL]\x00[lL]\x00/
  }

signature sid-689 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_reg* registry access"
  tcp-state established,originator
  payload /.{31}[xX]\x00[pP]\x00_\x00[rR]\x00[eE]\x00[gG]\x00/
  }

signature sid-690 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_printstatements possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[pP]\x00[rR]\x00[iI]\x00[nN]\x00[tT]\x00[sS]\x00[tT]\x00[aA]\x00[tT]\x00[eE]\x00[mM]\x00[eE]\x00[nN]\x00[tT]\x00[sS]\x00/
  }

signature sid-692 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB shellcode attempt"
  tcp-state established,originator
  payload /.*\x39\x20\xd0\x00\x92\x01\xc2\x00\x52\x00\x55\x00\x39\x20\xec\x00/
  }

signature sid-694 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB shellcode attempt"
  tcp-state established,originator
  payload /.*\x48\x00\x25\x00\x78\x00\x77\x00\x90\x00\x90\x00\x90\x00\x90\x00\x90\x00\x33\x00\xc0\x00\x50\x00\x68\x00\x2e\x00/
  }

signature sid-695 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_sprintf possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[sS]\x00[pP]\x00[rR]\x00[iI]\x00[nN]\x00[tT]\x00[fF]\x00/
  }

signature sid-696 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_showcolv possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[sS]\x00[hH]\x00[oO]\x00[wW]\x00[cC]\x00[oO]\x00[lL]\x00[vV]\x00/
  }

signature sid-697 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_peekqueue possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[pP]\x00[eE]\x00[eE]\x00[kK]\x00[qQ]\x00[uU]\x00[eE]\x00[uU]\x00[eE]\x00/
  }

signature sid-698 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_proxiedmetadata possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[pP]\x00[rR]\x00[oO]\x00[xX]\x00[iI]\x00[eE]\x00[dD]\x00[mM]\x00[eE]\x00[tT]\x00[aA]\x00[dD]\x00[aA]\x00[tT]\x00[aA]\x00/
  }

signature sid-700 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 139
  event "MS-SQL/SMB xp_updatecolvbm possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[uU]\x00[pP]\x00[dD]\x00[aA]\x00[tT]\x00[eE]\x00[cC]\x00[oO]\x00[lL]\x00[vV]\x00[bB]\x00[mM]\x00/
  }

signature sid-673 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL sp_start_job - program execution"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[sS]\x00[tT]\x00[aA]\x00[rR]\x00[tT]\x00_\x00[jJ]\x00[oO]\x00[bB]\x00/
  }

signature sid-674 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_displayparamstmt possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[dD]\x00[iI]\x00[sS]\x00[pP]\x00[lL]\x00[aA]\x00[yY]\x00[pP]\x00[aA]\x00[rR]\x00[aA]\x00[mM]\x00[sS]\x00[tT]\x00[mM]\x00[tT]/
  }

signature sid-675 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_setsqlsecurity possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[sS]\x00[eE]\x00[tT]\x00[sS]\x00[qQ]\x00[lL]\x00[sS]\x00[eE]\x00[cC]\x00[uU]\x00[rR]\x00[iI]\x00[tT]\x00[yY]\x00/
  }

signature sid-682 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_enumresultset possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[eE]\x00[nN]\x00[uU]\x00[mM]\x00[rR]\x00[eE]\x00[sS]\x00[uU]\x00[lL]\x00[tT]\x00[sS]\x00[eE]\x00[tT]\x00/
  }

signature sid-683 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL sp_password - password change"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[pP]\x00[aA]\x00[sS]\x00[sS]\x00[wW]\x00[oO]\x00[rR]\x00[dD]\x00/
  }

signature sid-684 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL sp_delete_alert log file deletion"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[dD]\x00[eE]\x00[lL]\x00[eE]\x00[tT]\x00[eE]\x00_\x00[aA]\x00[lL]\x00[eE]\x00[rR]\x00[tT]\x00/
  }

signature sid-685 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL sp_adduser - database user creation"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[aA]\x00[dD]\x00[dD]\x00[uU]\x00[sS]\x00[eE]\x00[rR]\x00/
  }

signature sid-686 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_reg* - registry access"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[rR]\x00[eE]\x00[gG]\x00/
  }

signature sid-687 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_cmdshell - program execution"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[cC]\x00[mM]\x00[dD]\x00[sS]\x00[hH]\x00[eE]\x00[lL]\x00[lL]\x00/
  }

signature sid-691 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL shellcode attempt"
  tcp-state established,originator
  payload /.*\x39\x20\xd0\x00\x92\x01\xc2\x00\x52\x00\x55\x00\x39\x20\xec\x00/
  }

signature sid-693 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL shellcode attempt"
  tcp-state established,originator
  payload /.*\x48\x00\x25\x00\x78\x00\x77\x00\x90\x00\x90\x00\x90\x00\x90\x00\x90\x00\x33\x00\xc0\x00\x50\x00\x68\x00\x2e\x00/
  }

signature sid-699 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_printstatements possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[pP]\x00[rR]\x00[iI]\x00[nN]\x00[tT]\x00[sS]\x00[tT]\x00[aA]\x00[tT]\x00[eE]\x00[mM]\x00[eE]\x00[nN]\x00[tT]\x00[sS]\x00/
  }

signature sid-701 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_updatecolvbm possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[uU]\x00[pP]\x00[dD]\x00[aA]\x00[tT]\x00[eE]\x00[cC]\x00[oO]\x00[lL]\x00[vV]\x00[bB]\x00[mM]\x00/
  }

signature sid-704 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_sprintf possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[sS]\x00[pP]\x00[rR]\x00[iI]\x00[nN]\x00[tT]\x00[fF]\x00/
  }

signature sid-705 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_showcolv possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[sS]\x00[hH]\x00[oO]\x00[wW]\x00[cC]\x00[oO]\x00[lL]\x00[vV]\x00/
  }

signature sid-706 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_peekqueue possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[pP]\x00[eE]\x00[eE]\x00[kK]\x00[qQ]\x00[uU]\x00[eE]\x00[uU]\x00[eE]\x00/
  }

signature sid-707 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL xp_proxiedmetadata possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[pP]\x00[rR]\x00[oO]\x00[xX]\x00[iI]\x00[eE]\x00[dD]\x00[mM]\x00[eE]\x00[tT]\x00[aA]\x00[dD]\x00[aA]\x00[tT]\x00[aA]\x00/
  }

signature sid-1387 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 1433
  event "MS-SQL raiserror possible buffer overflow"
  tcp-state established,originator
  payload /.*[rR]\x00[aA]\x00[iI]\x00[sS]\x00[eE]\x00[rR]\x00[rR]\x00[oO]\x00[rR]\x00/
  }

signature sid-1759 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 445
  event "MS-SQL xp_cmdshell program execution (445)"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[cC]\x00[mM]\x00[dD]\x00[sS]\x00[hH]\x00[eE]\x00[lL]\x00[lL]\x00/
  }

signature sid-688 {
  ip-proto == tcp
  src-ip == sql_servers
  dst-ip != local_nets
  src-port == 1433
  event "MS-SQL sa login failed"
  tcp-state established,responder
  payload /.*Login failed for user \x27sa\x27/
  }

signature sid-680 {
  ip-proto == tcp
  src-ip == sql_servers
  dst-ip != local_nets
  src-port == 139
  event "MS-SQL/SMB sa login failed"
  tcp-state established,responder
  payload /.{82}.*Login failed for user \x27sa\x27/
  }

signature sid-2003 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1434
  event "MS-SQL Worm propagation attempt"
  payload /\x04/
  payload /.*\x81\xF1\x03\x01\x04\x9B\x81\xF1\x01/
  payload /.*sock/
  payload /.*send/
  }

signature sid-2004 {
  ip-proto == udp
  src-ip == local_nets
  dst-ip != local_nets
  dst-port == 1434
  event "MS-SQL Worm propagation attempt OUTBOUND"
  payload /\x04/
  payload /.*\x81\xF1\x03\x01\x04\x9B\x81\xF1/
  payload /.*sock/
  payload /.*send/
  }

signature sid-2049 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1434
  event "MS-SQL ping attempt"
  payload /\x02/
  }

signature sid-2050 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1434
  payload-size > 100
  event "MS-SQL version overflow attempt"
  payload /\x04/
  }

signature sid-1225 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 6000
  event "X11 MIT Magic Cookie detected"
  tcp-state established
  payload /.*MIT-MAGIC-COOKIE-1/
  }

signature sid-1226 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 6000
  event "X11 xopen"
  tcp-state established
  payload /.*\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00/
  }

signature sid-465 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 8
  event "ICMP ISS Pinger"
  payload /.{0,24}\x49\x53\x53\x50\x4e\x47\x52\x51/
  }

signature sid-466 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[1:1] == 0
  header icmp[0:1] == 8
  event "ICMP L3retriever Ping"
  payload /ABCDEFGHIJKLMNOPQRSTUVWABCDEFGHI/
  }

signature sid-467 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  payload-size == 20
  header icmp[0:1] == 8
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "ICMP Nemesis v1.1 Echo"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 0
  payload /\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/
  }

signature sid-469 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  payload-size == 0
  header icmp[0:1] == 8
  event "ICMP PING NMAP"
  }

signature sid-471 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  payload-size == 0
  header icmp[0:1] == 8
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "ICMP icmpenum v1.1.1"
  header ip[4:2] == 666
  header icmp[0:1] == 0,8
  header icmp[4:2] == 666
  }

signature sid-472 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[1:1] == 1
  header icmp[0:1] == 5
  event "ICMP redirect host"
  }

signature sid-473 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[1:1] == 0
  header icmp[0:1] == 5
  event "ICMP redirect net"
  }

signature sid-474 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  payload-size == 8
  header icmp[0:1] == 8
  event "ICMP superscan echo"
  payload /\x00\x00\x00\x00\x00\x00\x00\x00/
  }

signature sid-475 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 0
  event "ICMP traceroute ipopts"
  ip-options rr
  }

signature sid-476 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[1:1] == 0
  header icmp[0:1] == 8
  event "ICMP webtrends scanner"
  payload /.*\x00\x00\x00\x00\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45\x45/
  }

signature sid-477 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[1:1] == 0
  header icmp[0:1] == 4
  event "ICMP Source Quench"
  }

signature sid-478 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  payload-size == 4
  header icmp[0:1] == 8
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "ICMP Broadscan Smurf Scanner"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 0
  }

signature sid-480 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 8
  event "ICMP PING speedera"
  payload /.{0,92}\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f/
  }

signature sid-481 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 8
  event "ICMP TJPingPro1.1Build 2 Windows"
  payload /.{0,16}\x54\x4a\x50\x69\x6e\x67\x50\x72\x6f\x20\x62\x79\x20\x4a\x69\x6d/
  }

signature sid-482 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 8
  event "ICMP PING WhatsupGold Windows"
  payload /.{0,16}\x57\x68\x61\x74\x73\x55\x70\x20\x2d\x20\x41\x20\x4e\x65\x74\x77/
  }

signature sid-483 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 8
  event "ICMP PING CyberKit 2.2 Windows"
  payload /.{0,16}\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa/
  }

signature sid-484 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  header icmp[0:1] == 8
  event "ICMP PING Sniffer Pro/NetXRay network scan"
  payload /.{0,13}\x43\x69\x6e\x63\x6f\x20\x4e\x65\x74\x77\x6f\x72\x6b\x2c\x20\x49\x6e\x63\x2e/
  }

signature sid-485 {
  ip-proto == icmp
  header icmp[1:1] == 13
  header icmp[0:1] == 3
  event "ICMP Destination Unreachable (Communication Administratively Prohibited)"
  }

signature sid-486 {
  ip-proto == icmp
  header icmp[1:1] == 10
  header icmp[0:1] == 3
  event "ICMP Destination Unreachable (Communication with Destination Host is Administratively Prohibited)"
  }

signature sid-487 {
  ip-proto == icmp
  header icmp[1:1] == 9
  header icmp[0:1] == 3
  event "ICMP Destination Unreachable (Communication with Destination Network is Administratively Prohibited)"
  }

signature sid-1813 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  event "ICMP digital island bandwidth query"
  payload /mailto:ops@digisle\.com/
  }

signature sid-499 {
  ip-proto == icmp
  src-ip != local_nets
  dst-ip == local_nets
  payload-size > 800
  event "ICMP Large ICMP Packet"
  }

signature sid-1293 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS nimda .eml"
  tcp-state established,originator
  payload /.*\x00\.\x00E\x00M\x00L/
  }

signature sid-1294 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS nimda .nws"
  tcp-state established,originator
  payload /.*\x00\.\x00N\x00W\x00S/
  }

signature sid-1295 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS nimda RICHED20.DLL"
  tcp-state established,originator
  payload /.*R\x00I\x00C\x00H\x00E\x00D\x002\x000/
  }

signature sid-529 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS DOS RFPoison"
  tcp-state established,originator
  payload /.*\x5C\x00\x5C\x00\x2A\x00\x53\x00\x4D\x00\x42\x00\x53\x00\x45\x00\x52\x00\x56\x00\x45\x00\x52\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00/
  }

signature sid-530 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS NT NULL session"
  tcp-state established,originator
  payload /.*\x00\x00\x00\x00\x57\x00\x69\x00\x6E\x00\x64\x00\x6F\x00\x77\x00\x73\x00\x20\x00\x4E\x00\x54\x00\x20\x00\x31\x00\x33\x00\x38\x00\x31/
  }

signature sid-1239 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS RFParalyze Attempt"
  tcp-state established,originator
  payload /.*BEAVIS/
  payload /.*yep yep/
  }

signature sid-532 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB ADMIN$access"
  tcp-state established,originator
  payload /.*\\ADMIN\$\x00\x41\x3a\x00/
  }

signature sid-533 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB C$ access"
  tcp-state established,originator
  payload /.*\x5cC\$\x00\x41\x3a\x00/
  }

signature sid-534 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB CD.."
  tcp-state established,originator
  payload /.*\\\.\.\x2f\x00\x00\x00/
  }

signature sid-535 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB CD..."
  tcp-state established,originator
  payload /.*\\\.\.\.\x00\x00\x00/
  }

signature sid-536 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB D$access"
  tcp-state established,originator
  payload /.*\\D\$\x00\x41\x3a\x00/
  }

signature sid-537 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB IPC$ share access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\x75/
  payload /.*\\[iI][pP][cC]\$\x00/
  }

signature sid-538 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB IPC$ share access (unicode)"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\x75/
  payload /.*\x5c\x00[iI]\x00[pP]\x00[cC]\x00\$\x00/
  }

signature sid-2101 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB SMB_COM_TRANSACTION Max Parameter and Max Count of 0 DOS Attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\x25/
  payload /.{42}\x00\x00\x00\x00/
  }

signature sid-2103 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  # Not supported: byte_test: 2,>,1024,0,relative,little
  event "NETBIOS SMB trans2open buffer overflow attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xffSMB\x32/
  payload /.{59}\x00\x14/
  }

signature sid-2174 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB winreg access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\xa2/
  payload /.{84}.*\\[wW][iI][nN][rR][eE][gG]\x00/
  }

signature sid-2175 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB winreg access (unicode)"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\xa2/
  payload /.{84}.*\\\x00[wW]\x00[iI]\x00[nN]\x00[rR]\x00[eE]\x00[gG]\x00/
  }

signature sid-2176 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB Startup Folder access attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\x32/
  payload /.*Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\x00/
  }

signature sid-2177 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 139
  event "NETBIOS SMB Startup Folder access attempt (unicode)"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\x32/
  payload /.*\\\x00S\x00t\x00a\x00r\x00t\x00 \x00M\x00e\x00n\x00u\x00\\\x00P\x00r\x00o\x00g\x00r\x00a\x00m\x00s\x00\\\x00S\x00t\x00a\x00r\x00t\x00u\x00p/
  }

signature sid-2190 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 135
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS DCERPC invalid bind attempt"
  tcp-state established,originator
  payload /.{0}\x05.{1}\x0b.{21}\x00/
  }

signature sid-2191 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 445
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS SMB DCERPC invalid bind attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB]\x25.{56}\x26\x00.{5}\x5c\x00[pP]\x00[iI]\x00[pP]\x00[eE]\x00\x5c\x00.{2}\x05.{1}\x0b.{21}\x00/
  }

signature sid-2192 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 135
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS DCERPC ISystemActivator bind attempt"
  tcp-state established,originator
  payload /.{0}\x05.{1}\x0b.{29}\xA0\x01\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46/
  }

signature sid-2193 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 445
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS SMB DCERPC ISystemActivator bind attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB]\x25.{56}\x26\x00.{5}\x5c\x00[pP]\x00[iI]\x00[pP]\x00[eE]\x00\x5c\x00.{0}\x05.{1}\x0b.{29}\xA0\x01\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46/
  }

signature sid-2251 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 135
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS DCERPC Remote Activation bind attempt"
  payload /.{0}\x05.{1}\x0b.{29}\xB8\x4A\x9F\x4D\x1C\x7D\xCF\x11\x86\x1E\x00\x20\xAF\x6E\x7C\x57/
  }

signature sid-2252 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 445
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS SMB DCERPC Remote Activation bind attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB]\x25.{56}\x26\x00.{5}\x5c\x00[pP]\x00[iI]\x00[pP]\x00[eE]\x00\x5c\x00.{0}\x05.{1}\x0b.{29}\xB8\x4A\x9F\x4D\x1C\x7D\xCF\x11\x86\x1E\x00\x20\xAF\x6E\x7C\x57/
  }

signature sid-500 {
  src-ip != local_nets
  dst-ip == local_nets
  event "MISC source route lssr"
  ip-options lsrr
  }

signature sid-501 {
  src-ip != local_nets
  dst-ip == local_nets
  event "MISC source route lssre"
  ip-options lsrre
  }

signature sid-502 {
  src-ip != local_nets
  dst-ip == local_nets
  event "MISC source route ssrr"
  ip-options ssrr 
  }

signature sid-503 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == 20
  dst-port >= 0
  dst-port <= 1023
  header tcp[13:1] & 255 == 2
  event "MISC Source Port 20 to <1024"
  }

signature sid-504 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == 53
  dst-port >= 0
  dst-port <= 1023
  header tcp[13:1] & 255 == 2
  event "MISC source port 53 to <1024"
  }

signature sid-505 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1417
  event "MISC Insecure TIMBUKTU Password"
  tcp-state established,originator
  payload /.{0,13}\x05\x00\x3E/
  }

signature sid-507 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 5631
  event "MISC PCAnywhere Attempted Administrator Login"
  tcp-state established,originator
  payload /.*ADMINISTRATOR/
  }

signature sid-508 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 70
  event "MISC gopher proxy"
  tcp-state established,originator
  payload /.*[fF][tT][pP]\x3a/
  payload /.*@\//
  }

signature sid-512 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port >= 5631
  src-port <= 5632
  event "MISC PCAnywhere Failed Login"
  tcp-state established,responder
  payload /.{0,3}Invalid login/
  }

signature sid-513 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 7161
  header tcp[13:1] & 255 == 18
  event "MISC Cisco Catalyst Remote Access"
  }

signature sid-514 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  dst-port == 27374
  event "MISC ramen worm"
  tcp-state established,originator
  payload /.{0,4}[gG][eE][tT] /
  }

signature sid-516 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "MISC SNMP NT UserList"
  payload /.*\x2b\x06\x10\x40\x14\xd1\x02\x19/
  }

signature sid-517 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 177
  event "MISC xdmcp query"
  payload /.*\x00\x01\x00\x03\x00\x01\x00/
  }

signature sid-1867 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 177
  event "MISC xdmcp info query"
  payload /.*\x00\x01\x00\x02\x00\x01\x00/
  }

signature sid-522 {
  src-ip != local_nets
  dst-ip == local_nets
  header ip[6:1] & 224 == 32
  payload-size < 25
  event "MISC Tiny Fragments"
  }

signature sid-1384 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1900
  event "MISC UPnP malformed advertisement"
  payload /.*[nN][oO][tT][iI][fF][yY] \* /
  }

signature sid-1388 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1900
  event "MISC UPnP Location overflow"
  payload /.*\x0d[lL][oO][cC][aA][tT][iI][oO][nN]\x3a[^\x0a]{128}/
  }

signature sid-1393 {
  ip-proto == tcp
  src-ip == aim_servers
  dst-ip == local_nets
  event "MISC AIM AddGame attempt"
  tcp-state established,responder
  payload /.*[aA][iI][mM]:[aA][dD][dD][gG][aA][mM][eE]\?/
  }

signature sid-1752 {
  ip-proto == tcp
  src-ip == aim_servers
  dst-ip == local_nets
  event "MISC AIM AddExternalApp attempt"
  tcp-state established,responder
  payload /.*[aA][iI][mM]:[aA][dD][dD][eE][xX][tT][eE][rR][nN][aA][lL][aA][pP][pP]\?/
  }

signature sid-1504 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 7001
  event "MISC AFS access"
  payload /.*\x00\x00\x03\xe7\x00\x00\x00\x00\x00\x00\x00\x65\x00\x00\x00\x00\x00\x00\x00\x00\x0d\x05\x00\x00\x00\x00\x00\x00\x00/
  }

signature sid-1636 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 32000
  payload-size > 500
  event "MISC Xtramail Username overflow attempt"
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR][nN][aA][mM][eE]: /
  }

signature sid-1887 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == 443
  event "MISC OpenSSL Worm traffic"
  tcp-state established,originator
  payload /.*[tT][eE][rR][mM]=[xX][tT][eE][rR][mM]/
  }

signature sid-1889 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == http_servers
  src-port == 2002
  dst-port == 2002
  event "MISC slapper worm admin traffic"
  payload /\x00\x00\x45\x00\x00\x45\x00\x00\x40\x00/
  }

signature sid-1447 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 3389
  event "MISC MS Terminal server request (RDP)"
  tcp-state established,originator
  payload /\x03\x00\x00\x0b\x06\xE0\x00\x00\x00\x00\x00/
  }

signature sid-1448 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 3389
  event "MISC MS Terminal server request"
  tcp-state established,originator
  payload /\x03\x00\x00/
  payload /.{4}\xe0\x00\x00\x00\x00\x00/
  }

signature sid-1819 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 2533
  event "MISC Alcatel PABX 4400 connection attempt"
  tcp-state established,originator
  payload /\x00\x01\x43/
  }

signature sid-1939 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 67
  # Not supported: byte_test: 1,>,6,2
  event "MISC bootp hardware address length overflow"
  payload /\x01/
  }

signature sid-1940 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 67
  # Not supported: byte_test: 1,>,7,1
  event "MISC bootp invalid hardware type"
  payload /\x01/
  }

signature sid-2039 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 67
  event "MISC bootp hostname format string attempt"
  payload /\x01.{240}.*\x0C.*.{0}.*%.{1}.{0,7}%.{1}.{0,7}%/
  }

signature sid-1966 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 27155
  event "MISC GlobalSunTech Access Point Information Disclosure attempt"
  payload /.*gstsearch/
  }

signature sid-1987 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 7100
  payload-size > 512
  event "MISC xfs overflow attempt"
  tcp-state established,originator
  payload /\x42\x00\x02/
  }

signature sid-2041 {
  ip-proto == udp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 49
  event "MISC xtacacs failed login response"
  payload /\x80\x02.{4}.*\x02/
  }

signature sid-2043 {
  ip-proto == udp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 500
  dst-port == 500
  event "MISC isakmp login failed"
  payload /.{16}\x10\x05.{13}\x00\x00\x00\x01\x01\x00\x00\x18/
  }

signature sid-2047 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 873
  event "MISC rsyncd module list access"
  tcp-state established,originator
  payload /\x23list/
  }

signature sid-2048 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 873
  # Not supported: byte_test: 2,>,4000,0
  event "MISC rsyncd overflow attempt"
  tcp-state originator
  payload /.{1}\x00\x00/
  }

signature sid-2008 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 2401
  event "MISC CVS invalid user authentication response"
  tcp-state established,responder
  payload /.*E Fatal error, aborting\./
  payload /.*\x3a no such user/
  }

signature sid-2009 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 2401
  event "MISC CVS invalid repository response"
  tcp-state established,responder
  payload /.*error /
  payload /.*: no such repository/
  payload /.*I HATE YOU/
  }

signature sid-2010 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 2401
  event "MISC CVS double free exploit attempt response"
  tcp-state established,responder
  payload /.*free\(\): warning: chunk is already free/
  }

signature sid-2011 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 2401
  event "MISC CVS invalid directory response"
  tcp-state established,responder
  payload /.*E protocol error: invalid directory syntax in/
  }

signature sid-2012 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 2401
  event "MISC CVS missing cvsroot response"
  tcp-state established,responder
  payload /.*E protocol error: Root request missing/
  }

signature sid-2013 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 2401
  event "MISC CVS invalid module response"
  tcp-state established,responder
  payload /.*cvs server: cannot find module.{1}.*error/
  }

signature sid-2126 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 1723
  payload-size > 156
  event "MISC Microsoft PPTP Start Control Request buffer overflow attempt"
  tcp-state established,originator
  payload /.{1}\x00\x01/
  payload /.{7}\x00\x01/
  }

signature sid-2158-a {
  ip-proto == tcp
  src-port == 179
  # Not supported: byte_test: 2,<,19,0,relative
  event "MISC BGP invalid length"
  payload /.*\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff/
  }

signature sid-2158-b {
  ip-proto == tcp
  dst-port == 179
  # Not supported: byte_test: 2,<,19,0,relative
  event "MISC BGP invalid length"
  payload /.*\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff/
  }

signature sid-2159-a {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 179
  event "MISC BGP invalid type (0)"
  tcp-state established
  payload /\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff.{2}\x00/
  }

signature sid-2159-b {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 179
  event "MISC BGP invalid type (0)"
  tcp-state established
  payload /\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff.{2}\x00/
  }

signature sid-1292 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  event "ATTACK-RESPONSES directory listing"
  tcp-state established,responder
  payload /.*Volume Serial Number/
  }

signature sid-494 {
  ip-proto == tcp
  src-ip == http_servers
  dst-ip != local_nets
  src-port == http_ports
  event "ATTACK-RESPONSES command completed"
  tcp-state established,responder
  payload /.*[cC][oO][mM][mM][aA][nN][dD] [cC][oO][mM][pP][lL][eE][tT][eE][dD]/
  }

signature sid-495 {
  ip-proto == tcp
  src-ip == http_servers
  dst-ip != local_nets
  src-port == http_ports
  event "ATTACK-RESPONSES command error"
  tcp-state established,responder
  payload /.*[bB][aA][dD] [cC][oO][mM][mM][aA][nN][dD] [oO][rR] [fF][iI][lL][eE][nN][aA][mM][eE]/
  }

signature sid-497 {
  ip-proto == tcp
  src-ip == http_servers
  dst-ip != local_nets
  src-port == http_ports
  event "ATTACK-RESPONSES file copied ok"
  tcp-state established,responder
  payload /.*1 [fF][iI][lL][eE]\([sS]\) [cC][oO][pP][iI][eE][dD]/
  }

signature sid-1200 {
  ip-proto == tcp
  src-ip == http_servers
  dst-ip != local_nets
  src-port == http_ports
  event "ATTACK-RESPONSES Invalid URL"
  tcp-state established,responder
  payload /.*[iI][nN][vV][aA][lL][iI][dD] [uU][rR][lL]/
  }

signature sid-1666 {
  ip-proto == tcp
  src-ip == http_servers
  dst-ip != local_nets
  src-port == http_ports
  event "ATTACK-RESPONSES index of /cgi-bin/ response"
  tcp-state established,responder
  payload /.*[iI][nN][dD][eE][xX] [oO][fF] \/[cC][gG][iI]-[bB][iI][nN]\//
  }

signature sid-1201 {
  ip-proto == tcp
  src-ip == http_servers
  dst-ip != local_nets
  src-port == http_ports
  event "ATTACK-RESPONSES 403 Forbidden"
  tcp-state established,responder
  payload /HTTP\/1\.1 403/
  }

signature sid-498 {
  event "ATTACK-RESPONSES id check returned root"
  payload /.*uid=0\(root\)/
  }

signature sid-1882 {
  src-ip == local_nets
  dst-ip != local_nets
  # Not supported: byte_test: 5,<,65537,0,relative,string,5,<,65537,0,relative,string
  event "ATTACK-RESPONSES id check returned userid"
  payload /.*uid=.{0}.{0,10} gid=/
  }

signature sid-1464 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 8002
  event "ATTACK-RESPONSES oracle one hour install"
  tcp-state established,responder
  payload /.*Oracle Applications One-Hour Install/
  }

signature sid-1900 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 749
  event "ATTACK-RESPONSES successful kadmind buffer overflow attempt"
  tcp-state established,responder
  payload /\*GOBBLE\*/
  }

signature sid-1901 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 751
  event "ATTACK-RESPONSES successful kadmind buffer overflow attempt"
  tcp-state established,responder
  payload /\*GOBBLE\*/
  }

signature sid-1810 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 22
  event "ATTACK-RESPONSES successful gobbles ssh exploit (GOBBLE)"
  tcp-state established,responder
  payload /.*\x2aGOBBLE\x2a/
  }

signature sid-1811 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 22
  event "ATTACK-RESPONSES successful gobbles ssh exploit (uname)"
  tcp-state established,responder
  payload /.*uname/
  }

signature sid-2104 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 512
  event "ATTACK-RESPONSES rexec username too long response"
  tcp-state established,responder
  payload /username too long/
  }

signature sid-2123 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port < 21
  src-port > 23
  event "ATTACK-RESPONSES Microsoft cmd.exe banner"
  tcp-state established,responder
  payload /.*Microsoft Windows.*.{0}.*\(C\) Copyright 1985-.*.{0}.*Microsoft Corp\./
  }

signature sid-1673 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE EXECUTE_SYSTEM attempt"
  tcp-state established,originator
  payload /.*[eE][xX][eE][cC][uU][tT][eE]_[sS][yY][sS][tT][eE][mM]/
  }

signature sid-1674 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE connect_data(command=version) attempt"
  tcp-state established,originator
  payload /.*[cC][oO][nN][nN][eE][cC][tT]_[dD][aA][tT][aA]\([cC][oO][mM][mM][aA][nN][dD]=[vV][eE][rR][sS][iI][oO][nN]\)/
  }

signature sid-1675 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE misparsed login response"
  tcp-state established,responder
  payload /.*[dD][eE][sS][cC][rR][iI][pP][tT][iI][oO][nN]=\(/
  payload /.*<willnevermatch>/
  payload /.*<willnevermatch>/
  }

signature sid-1676 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE select union attempt"
  tcp-state established,originator
  payload /.*[sS][eE][lL][eE][cC][tT] /
  payload /.* [uU][nN][iI][oO][nN] /
  }

signature sid-1677 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE select like '%' attempt"
  tcp-state established,originator
  payload /.* [wW][hH][eE][rR][eE] /
  payload /.* [lL][iI][kK][eE] '%'/
  }

signature sid-1678 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE select like \"%\" attempt"
  tcp-state established,originator
  payload /.* [wW][hH][eE][rR][eE] /
  payload /.* [lL][iI][kK][eE] \"%\"/
  }

signature sid-1679 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE describe attempt"
  tcp-state established,originator
  payload /.*[dD][eE][sS][cC][rR][iI][bB][eE] /
  }

signature sid-1680 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE all_constraints access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[cC][oO][nN][sS][tT][rR][aA][iI][nN][tT][sS]/
  }

signature sid-1681 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE all_views access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[vV][iI][eE][wW][sS]/
  }

signature sid-1682 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE all_source access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[sS][oO][uU][rR][cC][eE]/
  }

signature sid-1683 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE all_tables access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[tT][aA][bB][lL][eE][sS]/
  }

signature sid-1684 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE all_tab_columns access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[tT][aA][bB]_[cC][oO][lL][uU][mM][nN][sS]/
  }

signature sid-1685 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE all_tab_privs access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[tT][aA][bB]_[cC][oO][lL][uU][mM][nN][sS]/
  }

signature sid-1686 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE dba_tablespace access"
  tcp-state established,originator
  payload /.*[dD][bB][aA]_[tT][aA][bB][lL][eE][sS][pP][aA][cC][eE]/
  }

signature sid-1687 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE dba_tables access"
  tcp-state established,originator
  payload /.*[dD][bB][aA]_[tT][aA][bB][lL][eE][sS]/
  }

signature sid-1688 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE user_tablespace access"
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR]_[tT][aA][bB][lL][eE][sS][pP][aA][cC][eE]/
  }

signature sid-1689 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE sys.all_users access"
  tcp-state established,originator
  payload /.*[sS][yY][sS]\.[aA][lL][lL]_[uU][sS][eE][rR][sS]/
  }

signature sid-1690 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE grant attempt"
  tcp-state established,originator
  payload /.*[gG][rR][aA][nN][tT] /
  payload /.* [tT][oO] /
  }

signature sid-1691 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE ALTER USER attempt"
  tcp-state established,originator
  payload /.*[aA][lL][tT][eE][rR] [uU][sS][eE][rR]/
  payload /.* [iI][dD][eE][nN][tT][iI][fF][iI][eE][dD] [bB][yY] /
  }

signature sid-1692 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE drop table attempt"
  tcp-state established,originator
  payload /.*[dD][rR][oO][pP] [tT][aA][bB][lL][eE]/
  }

signature sid-1693 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE create table attempt"
  tcp-state established,originator
  payload /.*[cC][rR][eE][aA][tT][eE] [tT][aA][bB][lL][eE]/
  }

signature sid-1694 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE alter table attempt"
  tcp-state established,originator
  payload /.*[aA][lL][tT][eE][rR] [tT][aA][bB][lL][eE]/
  }

signature sid-1695 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE truncate table attempt"
  tcp-state established,originator
  payload /.*[tT][rR][uU][nN][cC][aA][tT][eE] [tT][aA][bB][lL][eE]/
  }

signature sid-1696 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE create database attempt"
  tcp-state established,originator
  payload /.*[cC][rR][eE][aA][tT][eE] [dD][aA][tT][aA][bB][aA][sS][eE]/
  }

signature sid-1697 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == oracle_ports
  event "ORACLE alter database attempt"
  tcp-state established,originator
  payload /.*[aA][lL][tT][eE][rR] [dD][aA][tT][aA][bB][aA][sS][eE]/
  }

signature sid-1775 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 3306
  event "MYSQL root login attempt"
  tcp-state established,originator
  payload /.*\x0A\x00\x00\x01\x85\x04\x00\x00\x80\x72\x6F\x6F\x74\x00/
  }

signature sid-1776 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == sql_servers
  dst-port == 3306
  event "MYSQL show databases attempt"
  tcp-state established,originator
  payload /.*\x0f\x00\x00\x00\x03show databases/
  }

signature sid-1893 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "SNMP missing community string attempt"
  payload /.{4}.{0,8}\x04\x00/
  }

signature sid-1892 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "SNMP null community string attempt"
  payload /.{4}.{0,7}\x04\x01\x00/
  }

signature sid-1409 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 161
  dst-port <= 162
  event "SNMP community string buffer overflow attempt"
  payload /.{3}.*\x02\x01\x00\x04\x82\x01\x00/
  }

signature sid-1422 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port >= 161
  dst-port <= 162
  event "SNMP community string buffer overflow attempt (with evasion)"
  payload /.{6} \x04\x82\x01\x00/
  }

signature sid-1411 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "SNMP public access udp"
  payload /.*public/
  }

signature sid-1412 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "SNMP public access tcp"
  tcp-state established,originator
  payload /.*public/
  }

signature sid-1413 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "SNMP private access udp"
  payload /.*private/
  }

signature sid-1414 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "SNMP private access tcp"
  tcp-state established,originator
  payload /.*private/
  }

signature sid-1415 {
  ip-proto == udp
  dst-ip == 255.255.255.255
  dst-port == 161
  event "SNMP Broadcast request"
  }

signature sid-1416 {
  ip-proto == udp
  dst-ip == 255.255.255.255
  dst-port == 162
  event "SNMP broadcast trap"
  }

signature sid-1417 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "SNMP request udp"
  }

signature sid-1418 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "SNMP request tcp"
  }

signature sid-1419 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 162
  event "SNMP trap udp"
  }

signature sid-1420 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 162
  event "SNMP trap tcp"
  }

signature sid-1421 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 705
  event "SNMP AgentX/tcp request"
  }

signature sid-1426 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 161
  event "SNMP PROTOS test-suite-req-app attempt"
  payload /.*\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6C\x69\x63\xA0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0E\x30\x0C\x06\x08\x2B\x06\x01\x02\x01\x01\x05\x00\x05\x00/
  }

signature sid-1427 {
  ip-proto == udp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 162
  event "SNMP PROTOS test-suite-trap-app attempt"
  payload /.*\x30\x38\x02\x01\x00\x04\x06\x70\x75\x62\x6C\x69\x63\xA4\x2B\x06/
  }

signature sid-655 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  src-port == 113
  dst-port == 25
  event "SMTP sendmail 8.6.9 exploit"
  tcp-state established,originator
  payload /.*\x0aD\//
  }

signature sid-658 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP exchange mime DOS"
  tcp-state established,originator
  payload /.*charset = \x22\x22/
  }

signature sid-659 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP expn decode"
  tcp-state established,originator
  payload /.*[eE][xX][pP][nN] [dD][eE][cC][oO][dD][eE]/
  }

signature sid-660 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP expn root"
  tcp-state established,originator
  payload /.*[eE][xX][pP][nN] [rR][oO][oO][tT]/
  }

signature sid-1450 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP expn *@"
  tcp-state established,originator
  payload /.*[eE][xX][pP][nN] \*@/
  }

signature sid-661 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP majordomo ifs"
  tcp-state established,originator
  payload /.*eply-to\x3a a~\.`\/bin\//
  }

signature sid-662 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP sendmail 5.5.5 exploit"
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL] [fF][rR][oO][mM]\x3a\x20\x22\x7c/
  }

signature sid-663 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP rcpt to sed command attempt"
  tcp-state established,originator
  payload /.*[rR][cC][pP][tT] [tT][oO]:.*.{0}.*\|.*.{0}.*sed /
  }

signature sid-664 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP RCPT TO decode attempt"
  tcp-state established,originator
  payload /.*[rR][cC][pP][tT] [tT][oO]\x3a [dD][eE][cC][oO][dD][eE]/
  }

signature sid-665 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP sendmail 5.6.5 exploit"
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL] [fF][rR][oO][mM]\x3a\x20\x7c\/[uU][sS][rR]\/[uU][cC][bB]\/[tT][aA][iI][lL]/
  }

signature sid-667 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP sendmail 8.6.10 exploit"
  tcp-state established,originator
  payload /.*Croot\x0d\x0aMprog, P=\/bin\//
  }

signature sid-668 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP sendmail 8.6.10 exploit"
  tcp-state established,originator
  payload /.*Croot\x09\x09\x09\x09\x09\x09\x09Mprog,P=\/bin/
  }

signature sid-669 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP sendmail 8.6.9 exploit"
  tcp-state established,originator
  payload /.*\x0aCroot\x0aMprog/
  }

signature sid-670 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP sendmail 8.6.9 exploit"
  tcp-state established,originator
  payload /.*\x0aC\x3adaemon\x0aR/
  }

signature sid-671 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP sendmail 8.6.9c exploit"
  tcp-state established,originator
  payload /.*\x0aCroot\x0d\x0aMprog/
  }

signature sid-672 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP vrfy decode"
  tcp-state established,originator
  payload /.*[vV][rR][fF][yY] [dD][eE][cC][oO][dD][eE]/
  }

signature sid-1446 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP vrfy root"
  tcp-state established,originator
  payload /.*[vV][rR][fF][yY] [rR][oO][oO][tT]/
  }

signature sid-631 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP ehlo cybercop attempt"
  tcp-state established,originator
  payload /.*ehlo cybercop\x0aquit\x0a/
  }

signature sid-632 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP expn cybercop attempt"
  tcp-state established,originator
  payload /.*expn cybercop/
  }

signature sid-1549 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP HELO overflow attempt"
  tcp-state established,originator
  payload /HELO [^\x0a]{500}/
  }

signature sid-1550 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP ETRN overflow attempt"
  tcp-state established,originator
  payload /ETRN [^\x0A]{500}/
  }

signature sid-2087 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  event "SMTP From comment overflow attempt"
  tcp-state established,originator
  payload /.*From:.*.{0}.*<><><><><><><><><><><><><><><><><><><><><><>.{1}.*\(.{1}.*\)/
  }

signature sid-2183 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == smtp_servers
  dst-port == 25
  # Not supported: byte_test: 1,<,256,100,relative
  event "SMTP Content-Transfer-Encoding overflow attempt"
  tcp-state established,originator
  payload /.*Content-Transfer-Encoding:[^\x0a]{100}/
  }

signature sid-1993 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP login literal buffer overflow attempt"
  tcp-state established,originator
  payload /.* LOGIN .*.{0}.* \{/
  }

signature sid-1842 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  event "IMAP login buffer overflow attempt"
  tcp-state established,originator
  payload /.* LOGIN [^\x0a]{100}/
  }

signature sid-2105 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP authenticate literal overflow attempt"
  tcp-state established,originator
  payload /.* [aA][uU][tT][hH][eE][nN][tT][iI][cC][aA][tT][eE] .*.{0}.*\{/
  }

signature sid-1844 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  event "IMAP authenticate overflow attempt"
  tcp-state established,originator
  payload /.* [aA][uU][tT][hH][eE][nN][tT][iI][cC][aA][tT][eE] [^\x0a]{100}/
  }

signature sid-1930 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP auth overflow attempt"
  tcp-state established,originator
  payload /.* [aA][uU][tT][hH]/
  payload /.*\{/
  }

signature sid-1902 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP lsub literal overflow attempt"
  payload /.* LSUB \x22.*.{0}.*\x22 \{/
  }

signature sid-2106 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  event "IMAP lsub overflow attempt"
  payload /.* LSUB [^\x0a]{100}/
  }

signature sid-1845 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP list literal overflow attempt"
  tcp-state established,originator
  payload /.* LIST \x22.*.{0}.*\x22 \{/
  }

signature sid-2118 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  event "IMAP list overflow attempt"
  tcp-state established,originator
  payload /.* [lL][iI][sS][tT] [^\x0a]{100}/
  }

signature sid-2119 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP rename literal overflow attempt"
  tcp-state established,originator
  payload /.* RENAME \x22.*.{0}.*\x22 \{/
  }

signature sid-1903 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  event "IMAP rename overflow attempt"
  tcp-state established,originator
  payload /.* [rR][eE][nN][aA][mM][eE] [^\x0a]{1024}/
  }

signature sid-1904 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  event "IMAP find overflow attempt"
  tcp-state established,originator
  payload /.* [fF][iI][nN][dD] [^\x0a]{1024}/
  }

signature sid-1755 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  event "IMAP partial body buffer overflow attempt"
  tcp-state established,originator
  payload /.* PARTIAL /
  payload /.* BODY\[[^\]]{1024}/
  }

signature sid-2046 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  event "IMAP partial body.peek buffer overflow attempt"
  tcp-state established,originator
  payload /.* PARTIAL /
  payload /.* BODY\.PEEK\[[^\]]{1024}/
  }

signature sid-2107 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  event "IMAP create buffer overflow attempt"
  tcp-state established,originator
  payload /.* CREATE [^\x0a]{1024}/
  }

signature sid-2120 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 143
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP create literal buffer overflow attempt"
  tcp-state established,originator
  payload /.* CREATE.*.{0}.* \{/
  }

signature sid-1934 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 109
  event "POP2 FOLD overflow attempt"
  tcp-state established,originator
  payload /.*FOLD [^\x0A]{256}/
  }

signature sid-1935 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 109
  event "POP2 FOLD arbitrary file attempt"
  tcp-state established,originator
  payload /.*FOLD \//
  }

signature sid-284 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 109
  event "POP2 x86 Linux overflow"
  tcp-state established,originator
  payload /.*\xeb\x2c\x5b\x89\xd9\x80\xc1\x06\x39\xd9\x7c\x07\x80\x01/
  }

signature sid-285 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 109
  event "POP2 x86 Linux overflow"
  tcp-state established,originator
  payload /.*\xff\xff\xff\x2f\x42\x49\x4e\x2f\x53\x48\x00/
  }

signature sid-2121 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  # Not supported: byte_test: 1,>,0,0,relative,string
  event "POP3 DELE negative arguement attempt"
  payload /[dD][eE][lL][eE].{1}.*-/
  }

signature sid-2122 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  # Not supported: byte_test: 1,>,0,0,relative,string
  event "POP3 UIDL negative arguement attempt"
  payload /[uU][iI][dD][lL].{1}.*-/
  }

signature sid-1866 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 USER overflow attempt"
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR][^\x0a]{50}/
  }

signature sid-2108 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 CAPA overflow attempt"
  tcp-state established,originator
  payload /.*[cC][aA][pP][aA][^\x0a]{10}/
  }

signature sid-2109 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 TOP overflow attempt"
  tcp-state established,originator
  payload /.*[tT][oO][pP][^\x0a]{10}/
  }

signature sid-2110 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 STAT overflow attempt"
  tcp-state established,originator
  payload /.*[sS][tT][aA][tT][^\x0a]{10}/
  }

signature sid-2111 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 DELE overflow attempt"
  tcp-state established,originator
  payload /.*[dD][eE][lL][eE][^\x0a]{10}/
  }

signature sid-2112 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 RSET overflow attempt"
  tcp-state established,originator
  payload /.*[rR][sS][eE][tT][^\x0a]{10}/
  }

signature sid-1936 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 AUTH overflow attempt"
  tcp-state established,originator
  payload /.*[aA][uU][tT][hH][^\x0a]{50}/
  }

signature sid-1937 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 LIST overflow attempt"
  tcp-state established,originator
  payload /.*[lL][iI][sS][tT][^\x0a]{50}/
  }

signature sid-1938 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 XTND overflow attempt"
  tcp-state established,originator
  payload /.*[xX][tT][nN][dD][^\x0a]{50}/
  }

signature sid-1634 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 PASS overflow attempt"
  tcp-state established,originator
  payload /.*[pP][aA][sS][sS][^\x0a]{50}/
  }

signature sid-1635 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 APOP overflow attempt"
  tcp-state established,originator
  payload /.*[aA][pP][oO][pP][^\x0a]{256}/
  }

signature sid-286 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 EXPLOIT x86 BSD overflow"
  tcp-state established,originator
  payload /.*\|5e0 e31c 0b03 b8d7 e0e8 9fa 89f9\|/
  }

signature sid-287 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 EXPLOIT x86 BSD overflow"
  tcp-state established,originator
  payload /.*\x68\x5d\x5e\xff\xd5\xff\xd4\xff\xf5\x8b\xf5\x90\x66\x31/
  }

signature sid-288 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 EXPLOIT x86 Linux overflow"
  tcp-state established,originator
  payload /.*\xd8\x40\xcd\x80\xe8\xd9\xff\xff\xff\/bin\/sh/
  }

signature sid-289 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 EXPLOIT x86 SCO overflow"
  tcp-state established,originator
  payload /.*\x56\x0e\x31\xc0\xb0\x3b\x8d\x7e\x12\x89\xf9\x89\xf9/
  }

signature sid-290 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 110
  event "POP3 EXPLOIT qpopper overflow"
  tcp-state established,originator
  payload /.*\xE8\xD9\xFF\xFF\xFF\/bin\/sh/
  }

signature sid-1792 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  src-port == 119
  event "NNTP return code buffer overflow attempt"
  tcp-state established,originator
  payload /200 [^\x0a]{64}/
  }

signature sid-1538 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  dst-port == 119
  event "NNTP AUTHINFO USER overflow attempt"
  tcp-state established,originator
  payload /[aA][uU][tT][hH][iI][nN][fF][oO] [uU][sS][eE][rR] [^\x0a]{500}/
  }

signature sid-1760 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 902
  event "OTHER-IDS ISS RealSecure 6 event collector connection attempt"
  tcp-state established,responder
  payload /.{29}6[iI][sS][sS] [eE][cC][nN][rR][aA] [bB][uU][iI][lL][tT]-[iI][nN] [pP][rR][oO][vV][iI][dD][eE][rR], [sS][tT][rR][oO][nN][gG] [eE][nN][cC][rR][yY][pP][tT][iI][oO][nN]/
  }

signature sid-1761 {
  ip-proto == tcp
  src-ip == local_nets
  dst-ip != local_nets
  src-port == 2998
  event "OTHER-IDS ISS RealSecure 6 daemon connection attempt"
  tcp-state established,responder
  payload /.{29}6[iI][sS][sS] [eE][cC][nN][rR][aA] [bB][uU][iI][lL][tT]-[iI][nN] [pP][rR][oO][vV][iI][dD][eE][rR], [sS][tT][rR][oO][nN][gG] [eE][nN][cC][rR][yY][pP][tT][iI][oO][nN]/
  }

signature sid-1629 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == local_nets
  event "OTHER-IDS SecureNetPro traffic"
  tcp-state established
  payload /\x00\x67\x00\x01\x00\x03/
  }


