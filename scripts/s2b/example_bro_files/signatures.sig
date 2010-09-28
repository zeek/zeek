# This file was created by s2b.pl on Mon Sep 20 13:14:53 2004.
# This file is dynamically generated each time s2b.pl is run and therefore any 
# changes done manually will be overwritten.
# $Id: signatures.sig 840 2004-11-30 22:33:48Z jason $

signature s2b-1292-8 {
  ip-proto == tcp
  event "ATTACK-RESPONSES directory listing"
  tcp-state established,responder
  payload /.*Volume Serial Number/
}

signature s2b-495-7 {
  ip-proto == tcp
  src-port == http_ports
  event "ATTACK-RESPONSES command error"
  tcp-state established,responder
  payload /.*[bB][aA][dD] [cC][oO][mM][mM][aA][nN][dD] [oO][rR] [fF][iI][lL][eE][nN][aA][mM][eE]/
}

signature s2b-497-8 {
  ip-proto == tcp
  src-port == http_ports
  event "ATTACK-RESPONSES file copied ok"
  tcp-state established,responder
  payload /.*1 [fF][iI][lL][eE]\x28[sS]\x29 [cC][oO][pP][iI][eE][dD]/
}

signature s2b-1666-5 {
  ip-proto == tcp
  src-port == http_ports
  event "ATTACK-RESPONSES index of /cgi-bin/ response"
  tcp-state established,responder
  payload /.*[iI][nN][dD][eE][xX] [oO][fF] \/[cC][gG][iI]-[bB][iI][nN]\//
  requires-reverse-signature ! http_error
}

signature s2b-498-6 {
  event "ATTACK-RESPONSES id check returned root"
  payload /.*uid=0\x28root\x29/
}

signature s2b-1882-10 {
  # Not supported: byte_test: 5,<,65537,0,relative,string,5,<,65537,0,relative,string
  event "ATTACK-RESPONSES id check returned userid"
  payload /.*uid=.{0,10} gid=/
  requires-reverse-signature ! http_error
}

signature s2b-1464-3 {
  ip-proto == tcp
  src-port == 8002
  event "ATTACK-RESPONSES oracle one hour install"
  tcp-state established,responder
  payload /.*Oracle Applications One-Hour Install/
  requires-reverse-signature ! http_error
}

signature s2b-1900-10 {
  ip-proto == tcp
  src-port == 749
  event "ATTACK-RESPONSES successful kadmind buffer overflow attempt"
  tcp-state established,responder
  payload /\*GOBBLE\*/
  requires-reverse-signature ! http_error
}

signature s2b-1901-10 {
  ip-proto == tcp
  src-port == 751
  event "ATTACK-RESPONSES successful kadmind buffer overflow attempt"
  tcp-state established,responder
  payload /\*GOBBLE\*/
}

signature s2b-1810-9 {
  ip-proto == tcp
  src-port == 22
  event "ATTACK-RESPONSES successful gobbles ssh exploit GOBBLE"
  tcp-state established,responder
  payload /.*\*GOBBLE\*/
  requires-reverse-signature ! http_error
}

signature s2b-1811-8 {
  ip-proto == tcp
  src-port == 22
  event "ATTACK-RESPONSES successful gobbles ssh exploit uname"
  tcp-state established,responder
  payload /.*uname/
}

signature s2b-2104-3 {
  ip-proto == tcp
  src-port == 512
  event "ATTACK-RESPONSES rexec username too long response"
  tcp-state established,responder
  payload /username too long/
}

signature s2b-2123-2 {
  ip-proto == tcp
  src-port < 21
  src-port > 23
  event "ATTACK-RESPONSES Microsoft cmd.exe banner"
  tcp-state established,responder
  payload /.*Microsoft Windows.*.*\x28C\x29 Copyright 1985-.*.*Microsoft Corp\./
  requires-reverse-signature ! http_error
}

signature s2b-2412-3 {
  ip-proto == tcp
  event "ATTACK-RESPONSES successful cross site scripting forced download attempt"
  tcp-state established,originator
  payload /.*\x0AReferer\x3A res\x3A\/C\x3A/
}

signature s2b-103-7 {
  ip-proto == tcp
  src-port == 27374
  event "BACKDOOR subseven 22"
  tcp-state established,originator
  payload /.*\x0D\x0A\[RPL\]002\x0D\x0A/
}

signature s2b-107-6 {
  ip-proto == tcp
  src-port == 16959
  event "BACKDOOR subseven DEFCON8 2.1 access"
  tcp-state established,responder
  payload /.*PWD/
}

signature s2b-109-5 {
  ip-proto == tcp
  src-port >= 12345
  src-port <= 12346
  event "BACKDOOR netbus active"
  tcp-state established,responder
  payload /.*NetBus/
}

signature s2b-110-4 {
  ip-proto == tcp
  dst-port >= 12345
  dst-port <= 12346
  event "BACKDOOR netbus getinfo"
  tcp-state established,originator
  payload /.*GetInfo\x0D/
}

signature s2b-115-5 {
  ip-proto == tcp
  src-port == 20034
  event "BACKDOOR netbus active"
  tcp-state established,originator
  payload /.*NetBus/
}

signature s2b-1980-1 {
  ip-proto == udp
  dst-port == 2140
  event "BACKDOOR DeepThroat 3.1 Connection attempt"
  payload /00/
}

signature s2b-195-5 {
  ip-proto == udp
  src-port == 2140
  event "BACKDOOR DeepThroat 3.1 Server Response"
  payload /.*Ahhhh My Mouth Is Open/
}

signature s2b-1981-1 {
  ip-proto == udp
  dst-port == 3150
  event "BACKDOOR DeepThroat 3.1 Connection attempt [3150]"
  payload /00/
}

signature s2b-1982-1 {
  ip-proto == udp
  src-port == 3150
  event "BACKDOOR DeepThroat 3.1 Server Response [3150]"
  payload /.*Ahhhh My Mouth Is Open/
}

signature s2b-1983-1 {
  ip-proto == udp
  dst-port == 4120
  event "BACKDOOR DeepThroat 3.1 Connection attempt [4120]"
  payload /00/
}

signature s2b-1984-1 {
  ip-proto == udp
  src-port == 4120
  event "BACKDOOR DeepThroat 3.1 Server Response [4120]"
  payload /.*Ahhhh My Mouth Is Open/
}

signature s2b-119-5 {
  ip-proto == tcp
  src-port == 6789
  event "BACKDOOR Doly 2.0 access"
  tcp-state established,responder
  payload /.{0,23}Wtzup Use/
}

signature s2b-104-7 {
  ip-proto == tcp
  src-port >= 1024
  src-port <= 65535
  dst-port == 2589
  event "BACKDOOR - Dagger_1.4.0_client_connect"
  tcp-state established,originator
  payload /.{0,1}\x0B\x00\x00\x00\x07\x00\x00\x00Connect/
}

signature s2b-105-7 {
  ip-proto == tcp
  src-port == 2589
  dst-port >= 1024
  dst-port <= 65535
  event "BACKDOOR - Dagger_1.4.0"
  tcp-state established,responder
  payload /2\x00\x00\x00\x06\x00\x00\x00Drives\x24\x00/
}

signature s2b-106-8 {
  ip-proto == tcp
  src-port == 80
  dst-port == 1054
  header tcp[8:4] == 101058054
  header tcp[13:1] & 255 == 16
  header tcp[4:4] == 101058054
  event "BACKDOOR ACKcmdC trojan scan"
  tcp-state stateless
}

signature s2b-108-6 {
  ip-proto == tcp
  dst-port == 7597
  event "BACKDOOR QAZ Worm Client Login access"
  tcp-state established,originator
  payload /.*qazwsx\.hsq/
}

signature s2b-117-6 {
  ip-proto == tcp
  src-port == 146
  dst-port >= 1024
  dst-port <= 65535
  event "BACKDOOR Infector.1.x"
  tcp-state established,responder
  payload /.*WHATISIT/
}

signature s2b-118-5 {
  ip-proto == tcp
  src-port == 666
  dst-port >= 1024
  dst-port <= 65535
  event "BACKDOOR SatansBackdoor.2.0.Beta"
  tcp-state established,responder
  payload /.*Remote\x3A You are connected to me\./
}

signature s2b-120-5 {
  ip-proto == tcp
  src-port == 146
  dst-port >= 1000
  dst-port <= 1300
  event "BACKDOOR Infector 1.6 Server to Client"
  tcp-state established,responder
  payload /.*WHATISIT/
}

signature s2b-145-5 {
  ip-proto == tcp
  src-port != 80
  dst-port == 21554
  event "BACKDOOR GirlFriendaccess"
  tcp-state established,originator
  payload /.*Girl/
}

signature s2b-146-5 {
  ip-proto == tcp
  src-port == 30100
  event "BACKDOOR NetSphere access"
  tcp-state established,responder
  payload /.*NetSphere/
}

signature s2b-147-5 {
  ip-proto == tcp
  src-port == 6969
  event "BACKDOOR GateCrasher"
  tcp-state established,responder
  payload /.*GateCrasher/
}

signature s2b-152-6 {
  ip-proto == tcp
  src-port >= 5401
  src-port <= 5402
  event "BACKDOOR BackConstruction 2.1 Connection"
  tcp-state established,responder
  payload /.*c\x3A\x5C/
}

signature s2b-153-5 {
  ip-proto == tcp
  src-port == 23476
  event "BACKDOOR DonaldDick 1.53 Traffic"
  tcp-state established,responder
  payload /.*pINg/
}

signature s2b-155-5 {
  ip-proto == tcp
  src-port >= 30100
  src-port <= 30102
  event "BACKDOOR NetSphere 1.31.337 access"
  tcp-state established,responder
  payload /.*NetSphere/
}

signature s2b-157-5 {
  ip-proto == tcp
  dst-port == 666
  event "BACKDOOR BackConstruction 2.1 Client FTP Open Request"
  tcp-state established,originator
  payload /.*FTPON/
}

signature s2b-158-5 {
  ip-proto == tcp
  src-port == 666
  event "BACKDOOR BackConstruction 2.1 Server FTP Open Reply"
  tcp-state established,responder
  payload /.*FTP Port open/
}

signature s2b-159-6 {
  ip-proto == tcp
  dst-port == 5032
  dst-ip == local_nets
  event "BACKDOOR NetMetro File List"
  tcp-state established,originator
  payload /.*--/
}

signature s2b-161-4 {
  ip-proto == udp
  src-port == 3344
  dst-port == 3345
  event "BACKDOOR Matrix 2.0 Client connect"
  payload /.*activate/
}

signature s2b-162-4 {
  ip-proto == udp
  src-port == 3345
  dst-port == 3344
  event "BACKDOOR Matrix 2.0 Server access"
  payload /.*logged in/
}

signature s2b-163-8 {
  ip-proto == tcp
  src-port == 5714
  header tcp[13:1] & 255 == 18
  event "BACKDOOR WinCrash 1.0 Server Active"
  tcp-state stateless
  payload /.*\xB4\xB4/
}

signature s2b-185-5 {
  ip-proto == tcp
  dst-port == 79
  event "BACKDOOR CDK"
  tcp-state established,originator
  payload /.{0,9}[yY][pP][iI]0[cC][aA]/
}

signature s2b-208-5 {
  ip-proto == tcp
  src-port == 555
  event "BACKDOOR PhaseZero Server Active on Network"
  tcp-state established,responder
  payload /.*phAse/
}

signature s2b-209-4 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR w00w00 attempt"
  tcp-state established,originator
  payload /.*w00w00/
}

signature s2b-210-3 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR attempt"
  tcp-state established,originator
  payload /.*[bB][aA][cC][kK][dD][oO][oO][rR]/
}

signature s2b-211-3 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR MISC r00t attempt"
  tcp-state established,originator
  payload /.*r00t/
}

signature s2b-212-3 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR MISC rewt attempt"
  tcp-state established,originator
  payload /.*rewt/
}

signature s2b-213-4 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR MISC Linux rootkit attempt"
  tcp-state established,originator
  payload /.*wh00t!/
}

signature s2b-214-4 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR MISC Linux rootkit attempt lrkr0x"
  tcp-state established,originator
  payload /.*lrkr0x/
}

signature s2b-215-4 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR MISC Linux rootkit attempt"
  tcp-state established,originator
  payload /.*[dD]13[hH][hH]\[/
}

signature s2b-216-6 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR MISC Linux rootkit satori attempt"
  tcp-state established,originator
  payload /.*satori/
}

signature s2b-217-3 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR MISC sm4ck attempt"
  tcp-state established,originator
  payload /.*hax0r/
}

signature s2b-219-6 {
  ip-proto == tcp
  dst-port == 23
  event "BACKDOOR HidePak backdoor attempt"
  tcp-state established,originator
  payload /.*StoogR/
}

signature s2b-614-7 {
  ip-proto == tcp
  src-port == 31790
  dst-port == 31789
  header tcp[13:1] & 255 == 16
  event "BACKDOOR hack-a-tack attempt"
  tcp-state stateless
  payload /A/
}

signature s2b-1853-6 {
  ip-proto == udp
  dst-port == 35555
  event "BACKDOOR win-trin00 connection attempt"
  payload /png \[\]\.\.Ks l44/
}

signature s2b-1843-6 {
  ip-proto == tcp
  dst-port == 33270
  event "BACKDOOR trinity connection attempt"
  tcp-state established,originator
  payload /!@\x23/
}

signature s2b-2100-2 {
  ip-proto == tcp
  event "BACKDOOR SubSeven 2.1 Gold server connection response"
  tcp-state established,responder
  payload /connected\. time\/date\x3A .{1}.*version\x3A GOLD 2\.1/
}

signature s2b-2124-3 {
  ip-proto == tcp
  dst-port == 34012
  event "BACKDOOR Remote PC Access connection attempt"
  tcp-state established,originator
  payload /\x28\x00\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00/
}

signature s2b-2271-2 {
  ip-proto == tcp
  event "BACKDOOR FsSniffer connection attempt"
  tcp-state established,originator
  payload /.*RemoteNC Control Password\x3A/
}

signature s2b-2375-3 {
  ip-proto == tcp
  dst-port >= 3127
  dst-port <= 3199
  event "BACKDOOR DoomJuice file upload attempt"
  tcp-state established,originator
  payload /^\x85\x13<\x9E\xA2/
}

signature s2b-542-10 {
  ip-proto == tcp
  dst-port >= 6666
  dst-port <= 7000
  event "CHAT IRC nick change"
  tcp-state established,originator
  payload /.*NICK /
}

signature s2b-1639-6 {
  ip-proto == tcp
  dst-port >= 6666
  dst-port <= 7000
  event "CHAT IRC DCC file transfer request"
  tcp-state established,originator
  payload /.*[pP][rR][iI][vV][mM][sS][gG] /
  payload /.* \x3A\.[dD][cC][cC] [sS][eE][nN][dD]/
}

signature s2b-1640-6 {
  ip-proto == tcp
  dst-port >= 6666
  dst-port <= 7000
  event "CHAT IRC DCC chat request"
  tcp-state established,originator
  payload /.*[pP][rR][iI][vV][mM][sS][gG] /
  payload /.* \x3A\.[dD][cC][cC] [cC][hH][aA][tT] [cC][hH][aA][tT]/
}

signature s2b-1729-5 {
  ip-proto == tcp
  dst-port >= 6666
  dst-port <= 7000
  event "CHAT IRC channel join"
  tcp-state established,originator
  payload /.*[jJ][oO][iI][nN] \x3A \x23/
}

signature s2b-1463-6 {
  ip-proto == tcp
  src-port >= 6666
  src-port <= 7000
  event "CHAT IRC message"
  tcp-state established
  payload /.*[pP][rR][iI][vV][mM][sS][gG] /
}

signature s2b-1789-3 {
  ip-proto == tcp
  dst-port >= 6666
  dst-port <= 7000
  event "CHAT IRC dns request"
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR][hH][oO][sS][tT] /
}

signature s2b-1790-4 {
  ip-proto == tcp
  src-port >= 6666
  src-port <= 7000
  event "CHAT IRC dns response"
  tcp-state established,responder
  payload /.*\x3A/
  payload /.* 302 /
  payload /.*=\+/
}

signature s2b-221-3 {
  ip-proto == icmp
  header icmp[0:1] == 8
  event "DDOS TFN Probe"
  header ip[4:2] == 678
  payload /.*1234/
}

signature s2b-222-2 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "DDOS tfn2k icmp possible communication"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 0
  payload /.*AAAAAAAAAA/
}

signature s2b-223-3 {
  ip-proto == udp
  dst-port == 31335
  event "DDOS Trin00 Daemon to Master PONG message detected"
  payload /.*PONG/
}

signature s2b-228-3 {
  ip-proto == icmp
  header icmp[0:1] == 0
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "DDOS TFN client command BE"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 456
}

signature s2b-230-5 {
  ip-proto == tcp
  src-port == 20432
  event "DDOS shaft client login to handler"
  tcp-state established,responder
  payload /.*login\x3A/
}

signature s2b-239-2 {
  ip-proto == udp
  dst-port == 18753
  event "DDOS shaft handler to agent"
  payload /.*alive tijgu/
}

signature s2b-240-2 {
  ip-proto == udp
  dst-port == 20433
  event "DDOS shaft agent to handler"
  payload /.*alive/
}

signature s2b-241-7 {
  ip-proto == tcp
  header tcp[13:1] & 255 == 2
  header tcp[4:4] == 674711609
  event "DDOS shaft synflood"
  tcp-state stateless
}

signature s2b-231-3 {
  ip-proto == udp
  dst-port == 31335
  event "DDOS Trin00 Daemon to Master message detected"
  payload /.*l44/
}

signature s2b-232-5 {
  ip-proto == udp
  dst-port == 31335
  event "DDOS Trin00 Daemon to Master *HELLO* message detected"
  payload /.*\*HELLO\*/
}

signature s2b-233-3 {
  ip-proto == tcp
  dst-port == 27665
  event "DDOS Trin00 Attacker to Master default startup password"
  tcp-state established,originator
  payload /.*betaalmostdone/
}

signature s2b-234-2 {
  ip-proto == tcp
  dst-port == 27665
  event "DDOS Trin00 Attacker to Master default password"
  tcp-state established,originator
  payload /.*gOrave/
}

signature s2b-235-2 {
  ip-proto == tcp
  dst-port == 27665
  event "DDOS Trin00 Attacker to Master default mdie password"
  tcp-state established,originator
  payload /.*killme/
}

signature s2b-237-2 {
  ip-proto == udp
  dst-port == 27444
  event "DDOS Trin00 Master to Daemon default password attempt"
  payload /.*l44adsl/
}

signature s2b-243-2 {
  ip-proto == udp
  dst-port == 6838
  event "DDOS mstream agent to handler"
  payload /.*newserver/
}

signature s2b-244-3 {
  ip-proto == udp
  dst-port == 10498
  event "DDOS mstream handler to agent"
  payload /.*stream\//
}

signature s2b-245-3 {
  ip-proto == udp
  dst-port == 10498
  event "DDOS mstream handler ping to agent"
  payload /.*ping/
}

signature s2b-246-2 {
  ip-proto == udp
  dst-port == 10498
  event "DDOS mstream agent pong to handler"
  payload /.*pong/
}

signature s2b-247-4 {
  ip-proto == tcp
  dst-port == 12754
  event "DDOS mstream client to handler"
  tcp-state established,originator
  payload /.*>/
}

signature s2b-249-7 {
  ip-proto == tcp
  dst-port == 15104
  header tcp[13:1] & 255 == 2
  event "DDOS mstream client to handler"
  tcp-state stateless
}

signature s2b-250-4 {
  ip-proto == tcp
  src-port == 15104
  event "DDOS mstream handler to client"
  tcp-state established,responder
  payload /.*>/
}

signature s2b-251-3 {
  ip-proto == icmp
  header icmp[0:1] == 0
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "DDOS - TFN client command LE"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 51201
}

signature s2b-224-3 {
  ip-proto == icmp
  src-ip == 3.3.3.3/32
  header icmp[0:1] == 0
  event "DDOS Stacheldraht server spoof"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 666
}

signature s2b-225-6 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "DDOS Stacheldraht gag server response"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 669
  payload /.*sicken/
}

signature s2b-226-6 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "DDOS Stacheldraht server response"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 667
  payload /.*ficken/
}

signature s2b-227-6 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "DDOS Stacheldraht client spoofworks"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 1000
  payload /.*spoofworks/
}

signature s2b-236-6 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "DDOS Stacheldraht client check gag"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 668
  payload /.*gesundheit!/
}

signature s2b-229-5 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "DDOS Stacheldraht client check skillz"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 666
  payload /.*skillz/
}

signature s2b-1854-7 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "DDOS Stacheldraht handler->agent niggahbitch"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 9015
  payload /.*niggahbitch/
}

signature s2b-1855-7 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "DDOS Stacheldraht agent->handler skillz"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 6666
  payload /.*skillz/
}

signature s2b-1856-7 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "DDOS Stacheldraht handler->agent ficken"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 6667
  payload /.*ficken/
}

signature s2b-255-11 {
  ip-proto == tcp
  dst-port == 53
  event "DNS zone transfer TCP"
  tcp-state established,originator
  payload /.{14}.*\x00\x00\xFC/
}

signature s2b-1948-4 {
  ip-proto == udp
  dst-port == 53
  event "DNS zone transfer UDP"
  payload /.{13}.*\x00\x00\xFC/
}

signature s2b-1435-6 {
  ip-proto == tcp
  dst-port == 53
  event "DNS named authors attempt"
  tcp-state established,originator
  payload /.{11}.*\x07[aA][uU][tT][hH][oO][rR][sS]/
  payload /.{11}.*\x04[bB][iI][nN][dD]/
}

signature s2b-256-5 {
  ip-proto == udp
  dst-port == 53
  event "DNS named authors attempt"
  payload /.{11}.*\x07[aA][uU][tT][hH][oO][rR][sS]/
  payload /.{11}.*\x04[bB][iI][nN][dD]/
}

signature s2b-257-8 {
  ip-proto == tcp
  dst-port == 53
  event "DNS named version attempt"
  tcp-state established,originator
  payload /.{11}.*\x07[vV][eE][rR][sS][iI][oO][nN]/
  payload /.{11}.*\x04[bB][iI][nN][dD]/
}

signature s2b-253-4 {
  ip-proto == udp
  src-port == 53
  event "DNS SPOOF query response PTR with TTL of 1 min. and no authority"
  payload /.*\x85\x80\x00\x01\x00\x01\x00\x00\x00\x00/
  payload /.*\xC0\x0C\x00\x0C\x00\x01\x00\x00\x00<\x00\x0F/
}

signature s2b-254-4 {
  ip-proto == udp
  src-port == 53
  event "DNS SPOOF query response with TTL of 1 min. and no authority"
  payload /.*\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00/
  payload /.*\xC0\x0C\x00\x01\x00\x01\x00\x00\x00<\x00\x04/
}

signature s2b-303-11 {
  ip-proto == tcp
  dst-port == 53
  event "DNS EXPLOIT named tsig overflow attempt"
  tcp-state established,originator
  payload /.*\xAB\xCD\x09\x80\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x01    \x02a/
}

signature s2b-314-9 {
  ip-proto == udp
  dst-port == 53
  event "DNS EXPLOIT named tsig overflow attempt"
  payload /.*\x80\x00\x07\x00\x00\x00\x00\x00\x01\?\x00\x01\x02/
}

signature s2b-259-7 {
  ip-proto == tcp
  dst-port == 53
  event "DNS EXPLOIT named overflow ADM"
  tcp-state established,originator
  payload /.*thisissometempspaceforthesockinaddrinyeahyeahiknowthisislamebutanywaywhocareshorizongotitworkingsoalliscool/
}

signature s2b-260-9 {
  ip-proto == tcp
  dst-port == 53
  event "DNS EXPLOIT named overflow ADMROCKS"
  tcp-state established,originator
  payload /.*ADMROCKS/
}

signature s2b-261-6 {
  ip-proto == tcp
  dst-port == 53
  event "DNS EXPLOIT named overflow attempt"
  tcp-state established,originator
  payload /.*\xCD\x80\xE8\xD7\xFF\xFF\xFF\/bin\/sh/
}

signature s2b-262-6 {
  ip-proto == tcp
  dst-port == 53
  event "DNS EXPLOIT x86 Linux overflow attempt"
  tcp-state established,originator
  payload /.*1\xC0\xB0\?1\xDB\xB3\xFF1\xC9\xCD\x801\xC0/
}

signature s2b-264-6 {
  ip-proto == tcp
  dst-port == 53
  event "DNS EXPLOIT x86 Linux overflow attempt"
  tcp-state established,originator
  payload /.*1\xC0\xB0\x02\xCD\x80\x85\xC0uL\xEBL\^\xB0/
}

signature s2b-265-7 {
  ip-proto == tcp
  dst-port == 53
  event "DNS EXPLOIT x86 Linux overflow attempt ADMv2"
  tcp-state established,originator
  payload /.*\x89\xF7\x29\xC7\x89\xF3\x89\xF9\x89\xF2\xAC<\xFE/
}

signature s2b-266-6 {
  ip-proto == tcp
  dst-port == 53
  event "DNS EXPLOIT x86 FreeBSD overflow attempt"
  tcp-state established,originator
  payload /.*\xEBn\^\xC6\x06\x9A1\xC9\x89N\x01\xC6F\x05/
}

signature s2b-267-5 {
  ip-proto == tcp
  dst-port == 53
  event "DNS EXPLOIT sparc overflow attempt"
  tcp-state established,originator
  payload /.*\x90\x1A\xC0\x0F\x90\x02 \x08\x92\x02 \x0F\xD0\x23\xBF\xF8/
}

signature s2b-268-4 {
  payload-size == 408
  event "DOS Jolt attack"
  header ip[6:1] & 224 == 32
}

signature s2b-270-6 {
  ip-proto == udp
  event "DOS Teardrop attack"
  header ip[6:1] & 224 == 32
  header ip[4:2] == 242
}

signature s2b-271-4 {
  ip-proto == udp
  src-port == 7
  dst-port == 19
  event "DOS UDP echo+chargen bomb"
}

signature s2b-272-7 {
  header ip[9:1] == 2
  event "DOS IGMP dos attack"
  header ip[6:1] & 224 == 32
  payload /\x02\x00/
}

signature s2b-273-7 {
  header ip[9:1] == 2
  event "DOS IGMP dos attack"
  header ip[6:1] & 224 == 32
  payload /\x00\x00/
}

signature s2b-274-5 {
  ip-proto == icmp
  header icmp[0:1] == 8
  event "DOS ath"
  payload /.*\+\+\+[aA][tT][hH]/
}

signature s2b-275-10 {
  ip-proto == tcp
  header tcp[13:1] & 255 == 2
  header tcp[4:4] == 6060842
  event "DOS NAPTHA"
  tcp-state stateless
  header ip[4:2] == 413
}

signature s2b-276-5 {
  ip-proto == tcp
  dst-port == 7070
  event "DOS Real Audio Server"
  tcp-state established,originator
  payload /.*\xFF\xF4\xFF\xFD\x06/
}

signature s2b-278-5 {
  ip-proto == tcp
  dst-port == 8080
  event "DOS Real Server template.html"
  tcp-state established,originator
  payload /.*\/[vV][iI][eE][wW][sS][oO][uU][rR][cC][eE]\/[tT][eE][mM][pP][lL][aA][tT][eE]\.[hH][tT][mM][lL]\?/
}

signature s2b-279-3 {
  ip-proto == udp
  dst-port == 161
  payload-size == 0
  event "DOS Bay/Nortel Nautica Marlin"
}

signature s2b-281-5 {
  ip-proto == udp
  dst-port == 9
  event "DOS Ascend Route"
  payload /.{24}.{0,17}NAMENAME/
}

signature s2b-282-7 {
  ip-proto == tcp
  dst-port == 617
  payload-size > 1445
  event "DOS arkiea backup"
  tcp-state established,originator
}

signature s2b-1257-8 {
  ip-proto == tcp
  dst-port >= 135
  dst-port <= 139
  header tcp[13:1] & 255 == 32
  event "DOS Winnuke attack"
  tcp-state stateless
}

signature s2b-1408-8 {
  ip-proto == tcp
  dst-port == 3372
  event "DOS MSDTC attempt"
  tcp-state established,originator
  payload-size == 1024
}

signature s2b-1605-6 {
  ip-proto == tcp
  dst-port == 6004
  dst-ip == local_nets
  event "DOS iParty DOS attempt"
  tcp-state established,originator
  payload /.*\xFF\xFF\xFF\xFF\xFF\xFF/
}

signature s2b-1641-5 {
  ip-proto == tcp
  dst-port >= 6789
  dst-port <= 6790
  payload-size == 1
  event "DOS DB2 dos attempt"
  tcp-state established,originator
}

signature s2b-1545-7 {
  ip-proto == tcp
  dst-port == 80
  payload-size == 1
  event "DOS Cisco attempt"
  tcp-state established,originator
  payload /\x13/
}

signature s2b-2486-5 {
  ip-proto == udp
  dst-port == 500
  # Not supported: byte_test: 2,>,4,30,2,<,8,30
  event "DOS ISAKMP invalid identification payload attempt"
  payload /.{15}\x05/
}

signature s2b-1324-6 {
  ip-proto == tcp
  dst-port == 22
  event "EXPLOIT ssh CRC32 overflow /bin/sh"
  tcp-state established,originator
  payload /.*\/bin\/sh/
}

signature s2b-1326-6 {
  ip-proto == tcp
  dst-port == 22
  event "EXPLOIT ssh CRC32 overflow NOOP"
  tcp-state established,originator
  payload /.*\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90/
}

signature s2b-1327-7 {
  ip-proto == tcp
  dst-port == 22
  event "EXPLOIT ssh CRC32 overflow"
  tcp-state established,originator
  payload /\x00\x01W\x00\x00\x00\x18/
  payload /.{7}\xFF\xFF\xFF\xFF\x00\x00/
}

signature s2b-283-10 {
  ip-proto == tcp
  src-port == 80
  event "EXPLOIT Netscape 4.7 client overflow"
  tcp-state established,responder
  payload /.*3\xC9\xB1\x10\?\xE9\x06Q<\xFAG3\xC0P\xF7\xD0P/
}

signature s2b-300-7 {
  ip-proto == tcp
  dst-port == 2766
  event "EXPLOIT nlps x86 Solaris overflow"
  tcp-state established,originator
  payload /.*\xEB\x23\^3\xC0\x88F\xFA\x89F\xF5\x896/
}

signature s2b-301-7 {
  ip-proto == tcp
  dst-port == 515
  event "EXPLOIT LPRng overflow"
  tcp-state established,originator
  payload /.*C\x07\x89\[\x08\x8DK\x08\x89C\x0C\xB0\x0B\xCD\x801\xC0\xFE\xC0\xCD\x80\xE8\x94\xFF\xFF\xFF\/bin\/sh\x0A/
}

signature s2b-302-6 {
  ip-proto == tcp
  dst-port == 515
  event "EXPLOIT Redhat 7.0 lprd overflow"
  tcp-state established,originator
  payload /.*XXXX%\.172u%300\x24n/
}

signature s2b-305-9 {
  ip-proto == tcp
  dst-port == 8080
  payload-size > 1000
  event "EXPLOIT delegate proxy overflow"
  tcp-state established,originator
  payload /.*[wW][hH][oO][iI][sS]\x3A\/\//
}

signature s2b-308-8 {
  ip-proto == tcp
  src-port == 21
  event "EXPLOIT NextFTP client overflow"
  tcp-state established,responder
  payload /.*\xB4 \xB4!\x8B\xCC\x83\xE9\x04\x8B\x193\xC9f\xB9\x10/
}

signature s2b-309-9 {
  ip-proto == tcp
  dst-port == 25
  payload-size > 512
  header tcp[13:1] & 255 == 16
  event "EXPLOIT sniffit overflow"
  tcp-state stateless
  payload /.*[fF][rR][oO][mM]\x3A\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90/
}

signature s2b-310-8 {
  ip-proto == tcp
  dst-port == 25
  event "EXPLOIT x86 windows MailMax overflow"
  tcp-state established,originator
  payload /.*\xEBE\xEB \[\xFC3\xC9\xB1\x82\x8B\xF3\x80\+/
}

signature s2b-311-11 {
  ip-proto == tcp
  dst-port == 80
  event "EXPLOIT Netscape 4.7 unsucessful overflow"
  tcp-state established,originator
  payload /.*3\xC9\xB1\x10\?\xE9\x06Q<\xFAG3\xC0P\xF7\xD0P/
}

signature s2b-313-4 {
  ip-proto == udp
  dst-port == 518
  event "EXPLOIT ntalkd x86 Linux overflow"
  payload /.*\x01\x03\x00\x00\x00\x00\x00\x01\x00\x02\x02\xE8/
}

signature s2b-315-6 {
  ip-proto == udp
  dst-port == 635
  event "EXPLOIT x86 Linux mountd overflow"
  payload /.*\^\xB0\x02\x89\x06\xFE\xC8\x89F\x04\xB0\x06\x89F/
}

signature s2b-316-6 {
  ip-proto == udp
  dst-port == 635
  event "EXPLOIT x86 Linux mountd overflow"
  payload /.*\xEBV\^VVV1\xD2\x88V\x0B\x88V\x1E/
}

signature s2b-317-6 {
  ip-proto == udp
  dst-port == 635
  event "EXPLOIT x86 Linux mountd overflow"
  payload /.*\xEB@\^1\xC0@\x89F\x04\x89\xC3@\x89\x06/
}

signature s2b-1240-5 {
  ip-proto == tcp
  dst-port == 2224
  event "EXPLOIT MDBMS overflow"
  tcp-state established,originator
  payload /.*\x011\xDB\xCD\x80\xE8\[\xFF\xFF\xFF/
}

signature s2b-1261-10 {
  ip-proto == tcp
  dst-port == 4242
  payload-size > 1000
  event "EXPLOIT AIX pdnsd overflow"
  tcp-state established,originator
  payload /.*\x7F\xFF\xFBx\x7F\xFF\xFBx\x7F\xFF\xFBx\x7F\xFF\xFBx/
  payload /.*@\x8A\xFF\xC8@\x82\xFF\xD8\x3B6\xFE\x03\x3Bv\xFE\x02/
}

signature s2b-1398-10 {
  ip-proto == tcp
  dst-port == 6112
  event "EXPLOIT CDE dtspcd exploit attempt"
  tcp-state established,originator
  payload /.{9}1/
  payload /.{10}<willnevermatch>/
}

signature s2b-1751-5 {
  ip-proto == tcp
  dst-port >= 32772
  dst-port <= 34000
  payload-size > 720
  event "EXPLOIT cachefsd buffer overflow attempt"
  tcp-state established,originator
  payload /.*\x00\x01\x87\x86\x00\x00\x00\x01\x00\x00\x00\x05/
}

signature s2b-1894-8 {
  ip-proto == tcp
  dst-port == 749
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\x00\xC0\x05\x08\x00\xC0\x05\x08\x00\xC0\x05\x08\x00\xC0\x05\x08/
}

signature s2b-1895-8 {
  ip-proto == tcp
  dst-port == 751
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\x00\xC0\x05\x08\x00\xC0\x05\x08\x00\xC0\x05\x08\x00\xC0\x05\x08/
}

signature s2b-1896-8 {
  ip-proto == tcp
  dst-port == 749
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\xFF\xFFKADM0\.0A\x00\x00\xFB\x03/
}

signature s2b-1897-8 {
  ip-proto == tcp
  dst-port == 751
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\xFF\xFFKADM0\.0A\x00\x00\xFB\x03/
}

signature s2b-1898-8 {
  ip-proto == tcp
  dst-port == 749
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\/shh\/\/bi/
}

signature s2b-1899-8 {
  ip-proto == tcp
  dst-port == 751
  event "EXPLOIT kadmind buffer overflow attempt"
  tcp-state established,originator
  payload /.*\/shh\/\/bi/
}

signature s2b-1812-5 {
  ip-proto == tcp
  dst-port == 22
  event "EXPLOIT gobbles SSH exploit attempt"
  tcp-state established,originator
  payload /.*GOBBLES/
}

signature s2b-1821-7 {
  ip-proto == tcp
  dst-port == 515
  event "EXPLOIT LPD dvips remote command execution attempt"
  tcp-state established,originator
  payload /.*psfile=\x22`/
}

signature s2b-1838-8 {
  ip-proto == tcp
  src-port == 22
  # Not supported: pcre: /^SSH-\s[^\n]{200}/ism
  event "EXPLOIT SSH server banner overflow"
  tcp-state established,responder
  # Not supported: isdataat: 200,relative
  payload /((^)|(\n+))[sS][sS][hH]-[\x20\x09\x0b][^\n]{200}/
}

signature s2b-307-9 {
  ip-proto == tcp
  dst-port >= 6666
  dst-port <= 7000
  event "EXPLOIT CHAT IRC topic overflow"
  tcp-state established,responder
  payload /.*\xEBK\[S2\xE4\x83\xC3\x0BK\x88\x23\xB8Pw/
}

signature s2b-1382-9 {
  ip-proto == tcp
  dst-port >= 6666
  dst-port <= 7000
  # Not supported: pcre: /^PRIVMSG\s+nickserv\s+IDENTIFY\s[^\n]{100}/smi
  event "EXPLOIT CHAT IRC Ettercap parse overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  payload /((^)|(\n+))[pP][rR][iI][vV][mM][sS][gG][\x20\x09\x0b]+[nN][iI][cC][kK][sS][eE][rR][vV][\x20\x09\x0b]+[iI][dD][eE][nN][tT][iI][fF][yY][\x20\x09\x0b][^\n]{100}/
}

signature s2b-292-8 {
  ip-proto == tcp
  dst-port == 139
  event "EXPLOIT x86 Linux samba overflow"
  tcp-state established,originator
  payload /.*\xEB\/_\xEBJ\^\x89\xFB\x89>\x89\xF2/
}

signature s2b-2319-1 {
  ip-proto == tcp
  dst-port == 1655
  # Not supported: pcre: /^PASS\s[^\n]{49}/smi
  event "EXPLOIT ebola PASS overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[uU][sS][eE][rR][\x20\x09\x0b][^\n]{49}/
}

signature s2b-2320-1 {
  ip-proto == tcp
  dst-port == 1655
  # Not supported: pcre: /^USER\s[^\n]{49}/smi
  event "EXPLOIT ebola USER overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[uU][sS][eE][rR][^\x0a]{49}/
}

signature s2b-2376-3 {
  ip-proto == udp
  dst-port == 500
  # Not supported: byte_test: 4,>,2043,24,2,>,2043,30
  event "EXPLOIT ISAKMP first payload certificate request length overflow attempt"
  payload /.{15}\x07/
}

signature s2b-2377-3 {
  ip-proto == udp
  dst-port == 500
  # Not supported: byte_test: 4,>,2043,24,2,>,2043,-2,relative
  # Not supported: byte_jump: 2,30
  event "EXPLOIT ISAKMP second payload certificate request length overflow attempt"
  payload /.{27}\x07/
}

signature s2b-2378-3 {
  ip-proto == udp
  dst-port == 500
  # Not supported: byte_test: 4,>,2043,24,2,>,2043,-2,relative
  # Not supported: byte_jump: 2,30,relative,2,1,relative
  event "EXPLOIT ISAKMP third payload certificate request length overflow attempt"
  payload /\x07/
}

signature s2b-2379-3 {
  ip-proto == udp
  dst-port == 500
  # Not supported: byte_test: 4,>,2043,24,2,>,2043,-2,relative
  # Not supported: byte_jump: 2,30,relative,2,-2,relative,2,1,relative
  event "EXPLOIT ISAKMP forth payload certificate request length overflow attempt"
  payload /\x07/
}

signature s2b-2380-3 {
  ip-proto == udp
  dst-port == 500
  # Not supported: byte_test: 4,>,2043,24,2,>,2043,-2,relative
  # Not supported: byte_jump: 2,30,relative,2,-2,relative,2,-2,relative,2,1,relative
  event "EXPLOIT ISAKMP fifth payload certificate request length overflow attempt"
  payload /\x07/
}

signature s2b-2413-7 {
  ip-proto == udp
  dst-port == 500
  event "EXPLOIT ISAKMP delete hash with empty hash attempt"
  payload /.{15}\x08/
  payload /.{27}\x0C/
  payload /.{29}\x00\x04/
}

signature s2b-2414-7 {
  ip-proto == udp
  dst-port == 500
  event "EXPLOIT ISAKMP initial contact notification without SPI attempt"
  payload /.{15}\x0B/
  payload /.{29}\x00\x0C\x00\x00\x00\x01\x01\x00\x06\x02/
}

signature s2b-2415-7 {
  ip-proto == udp
  dst-port == 500
  # Not supported: byte_jump: 2,30
  event "EXPLOIT ISAKMP second payload initial contact notification without SPI attempt"
  payload /.{27}\x0B\x00\x0C\x00\x00\x00\x01\x01\x00`\x02/
}

signature s2b-2443-4 {
  ip-proto == udp
  src-port == 4000
  # Not supported: byte_test: 1,>,1,12,relative,2,>,128,18,relative,little
  event "EXPLOIT ICQ SRV_MULTI/SRV_META_USER first name overflow attempt"
  payload /\x05\x00.{5}\x12\x02.*.*\x05\x00.{5}n\x00/
  payload /.*\x05\x00.{5}\xDE\x03/
}

signature s2b-2444-4 {
  ip-proto == udp
  src-port == 4000
  # Not supported: byte_jump: 2,18,relative,little
  event "EXPLOIT ICQ SRV_MULTI/SRV_META_USER first name overflow attempt"
  # Not supported: byte_test: 1,>,1,12,relative,2,>,128,0,relative,little
  payload /\x05\x00.{5}\x12\x02.*.*\x05\x00.{5}n\x00/
  payload /.*\x05\x00.{5}\xDE\x03/
}

signature s2b-2445-4 {
  ip-proto == udp
  src-port == 4000
  # Not supported: byte_test: 2,>,128,0,relative,little,1,>,1,12,relative
  event "EXPLOIT ICQ SRV_MULTI/SRV_META_USER last name overflow attempt"
  # Not supported: byte_jump: 2,18,relative,little,2,0,relative,little
  payload /\x05\x00.{5}\x12\x02.*.*\x05\x00.{5}n\x00/
  payload /.*\x05\x00.{5}\xDE\x03/
}

signature s2b-2446-4 {
  ip-proto == udp
  src-port == 4000
  # Not supported: byte_jump: 2,0,relative,little,2,18,relative,little,2,0,relative,little
  event "EXPLOIT ICQ SRV_MULTI/SRV_META_USER email overflow attempt"
  # Not supported: byte_test: 2,>,128,0,relative,little,1,>,1,12,relative
  payload /\x05\x00.{5}\x12\x02.*.*\x05\x00.{5}n\x00/
  payload /.*\x05\x00.{5}\xDE\x03/
}

signature s2b-2462-6 {
  # Not supported: byte_test: 1,>,63,0,1,<,67,0,1,>,16,12
  header ip[9:1] == 2
  event "EXPLOIT IGMP IGAP account overflow attempt"
}

signature s2b-2463-6 {
  # Not supported: byte_test: 1,>,63,0,1,<,67,0,1,>,64,13
  header ip[9:1] == 2
  event "EXPLOIT IGMP IGAP message overflow attempt"
}

signature s2b-2464-6 {
  # Not supported: byte_test: 1,>,32,44
  header ip[9:1] == 88
  event "EXPLOIT EIGRP prefix length overflow attempt"
}

signature s2b-2489-2 {
  ip-proto == tcp
  dst-port == 80
  event "EXPLOIT esignal STREAMQUOTE buffer overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 1024,relative
  payload /.*<[sS][tT][rR][eE][aA][mM][qQ][uU][oO][tT][eE]><willnevermatch>/
}

signature s2b-2490-3 {
  ip-proto == tcp
  dst-port == 80
  event "EXPLOIT esignal SNAPQUOTE buffer overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 1024,relative
  payload /.*<[sS][nN][aA][pP][qQ][uU][oO][tT][eE]><willnevermatch>/
}

signature s2b-2545-4 {
  ip-proto == tcp
  dst-port == 548
  # Not supported: byte_jump: 2,1,relative,2,1,relative
  event "EXPLOIT AFP FPLoginExt username buffer overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 2,relative
  payload /\x00\x02.{14}\?/
  payload /.*[cC][lL][eE][aA][rR][tT][xX][tT] [pP][aA][sS][sS][wW][rR][dD]/
}

signature s2b-2550-2 {
  ip-proto == tcp
  src-port == 80
  event "EXPLOIT winamp XM module name overflow"
  tcp-state established,responder
  # Not supported: isdataat: 20,relative
  payload /.*[eE][xX][tT][eE][nN][dD][eE][dD] [mM][oO][dD][uU][lL][eE]\x3A[^\x1A]{21}/
}

signature s2b-2551-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^GET[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache GET overflow attempt"
  tcp-state established,originator
  payload /.*GET/
  payload /((^)|(\n+))GET[^s]{432}/
}

signature s2b-2552-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^HEAD[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache HEAD overflow attempt"
  tcp-state established,originator
  payload /.*HEAD/
  payload /((^)|(\n+))HEAD[^s]{432}/
}

signature s2b-2553-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^PUT[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache PUT overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))PUT[^s]{432}/
}

signature s2b-2554-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^POST[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache POST overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))POST[^s]{432}/
}

signature s2b-2555-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^TRACE[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache TRACE overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))TRACE[^s]{432}/
}

signature s2b-2556-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^DELETE[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache DELETE overflow attempt"
  tcp-state established,originator
  payload /.*DELETE/
  payload /((^)|(\n+))DELETE[^s]{432}/
}

signature s2b-2557-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^LOCK[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache LOCK overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))LOCK[^s]{432}/
}

signature s2b-2558-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^MKCOL[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache MKCOL overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))MKCOL[^s]{432}/
}

signature s2b-2559-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^COPY[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache COPY overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))COPY[^s]{432}/
}

signature s2b-2560-2 {
  ip-proto == tcp
  dst-port >= 7777
  dst-port <= 7778
  # Not supported: pcre: /^MOVE[^s]{432}/sm
  event "EXPLOIT Oracle Web Cache MOVE overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))MOVE[^s]{432}/
}

signature s2b-320-9 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER cmd_rootsh backdoor attempt"
  tcp-state established,originator
  payload /.*cmd_rootsh/
}

signature s2b-321-5 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER account enumeration attempt"
  tcp-state established,originator
  payload /.*[aA] [bB] [cC] [dD] [eE] [fF]/
}

signature s2b-322-10 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER search query"
  tcp-state established,originator
  payload /.*search/
}

signature s2b-323-5 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER root query"
  tcp-state established,originator
  payload /.*root/
}

signature s2b-324-5 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER null request"
  tcp-state established,originator
  payload /.*\x00/
}

signature s2b-326-9 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER remote command execution attempt"
  tcp-state established,originator
  payload /.*\x3B/
}

signature s2b-327-8 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER remote command pipe execution attempt"
  tcp-state established,originator
  payload /.*\x7C/
}

signature s2b-328-8 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER bomb attempt"
  tcp-state established,originator
  payload /.*@@/
}

signature s2b-330-9 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER redirection attempt"
  tcp-state established,originator
  payload /.*@/
}

signature s2b-331-10 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER cybercop query"
  tcp-state established,originator
  payload /.{0,4}\x0A     /
}

signature s2b-332-8 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER 0 query"
  tcp-state established,originator
  payload /.*0/
}

signature s2b-333-8 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER . query"
  tcp-state established,originator
  payload /.*\./
}

signature s2b-1541-4 {
  ip-proto == tcp
  dst-port == 79
  event "FINGER version query"
  tcp-state established,originator
  payload /.*version/
}

signature s2b-2546-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^MDTM\s[^\n]{100}/smi
  event "FTP MDTM overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  payload /((^)|(\n+))[mM][dD][tT][mM][\x20\x09\x0b][^\n]{100}/
}

signature s2b-2373-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^XMKD\s[^\n]{100}/smi
  event "FTP XMKD overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  payload /((^)|(\n+))[xXmMkKdD][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-2374-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^NLST\s[^\n]{100}/smi
  event "FTP NLST overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[nNlLsStT][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-2449-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^ALLO\s[^\n]{100}/smi
  event "FTP ALLO overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  payload /((^)|(\n+))[aAlLlLoO][\x20\x09\x0b][^\n]{100}/
}

signature s2b-2389-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^RNTO\s[^\n]{100}/smi
  event "FTP RNTO overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[rR][nN][tT][oO][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-2390-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^STOU\s[^\n]{100}/smi
  event "FTP STOU overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  payload /((^)|(\n+))[sS][tT][oO][uU][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-2391-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^APPE\s[^\n]{100}/smi
  event "FTP APPE overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  payload /((^)|(\n+))[aA][pP][pP][eE][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-2392-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^RETR\s[^\n]{100}/smi
  event "FTP RETR overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[rR][eE][tT][rR][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-2343-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^STOR\s[^\n]{100}/smi
  event "FTP STOR overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][tT][oO][rR][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-337-10 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^CEL\s[^\n]{100}/smi
  event "FTP CEL overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[cC][eE][lL][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-2344-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^XCWD\s[^\n]{100}/smi
  event "FTP XCWD overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[xX][cC][wW][dD][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1919-12 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^CWD\s[^\n]{100}/smi
  event "FTP CWD overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[cC][wW][dD][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1621-10 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^CMD\s[^\n]{100}/smi
  event "FTP CMD overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[cC][mM][dD][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1379-7 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^STAT\s[^\n]{100}/smi
  event "FTP STAT overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][tT][aA][tT][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-2340-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^SITE\s+CHMOD\s[^\n]{100}/smi
  event "FTP SITE CHMOD overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][iI][tT][eE][\x20\x09\x0b]+[cC][hH][mM][oO][dD][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1562-11 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^SITE\s+CHOWN\s[^\n]{100}/smi
  event "FTP SITE CHOWN overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][iI][tT][eE][\x20\x09\x0b]+[cC][hH][oO][wW][nN][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1920-6 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^SITE\s+NEWER\s[^\n]{100}/smi
  event "FTP SITE NEWER overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][iI][tT][eE][\x20\x09\x0b]+[nN][eE][wW][eE][rR][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1888-8 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^SITE\s+CPWD\s[^\n]{100}/smi
  event "FTP SITE CPWD overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][iI][tT][eE][\x20\x09\x0b]+[cC][pP][wW][dD][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1971-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^SITE\s+EXEC\s[^\n]*?%[^\n]*?%/smi
  event "FTP SITE EXEC format string attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][iI][tT][eE][\x20\x09\x0b]+[eE][xX][eE][cC][\x20\x09\x0b][^\n]*?%[^\n]*?%/
}

signature s2b-1529-10 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^SITE\s[^\n]{100}/smi
  event "FTP SITE overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][iI][tT][eE][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1734-16 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^USER\s[^\n]{100}/smi
  event "FTP USER overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[uU][sS][eE][rR][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1972-10 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^PASS\s[^\n]{100}/smi
  event "FTP PASS overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[pP][aA][sS][sS][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1942-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^RMDIR\s[^\n]{100}/smi
  event "FTP RMDIR overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[rR][mM][dD][iI][rR][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1973-6 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^MKD\s[^\n]{100}/smi
  event "FTP MKD overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[mM][kK][dD][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1974-6 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^REST\s[^\n]{100}/smi
  event "FTP REST overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[rR][eE][sS][tT][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1975-6 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^DELE\s[^\n]{100}/smi
  event "FTP DELE overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[dD][eE][lL][eE][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1976-6 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^RMD\s[^\n]{100}/smi
  event "FTP RMD overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[rR][mM][dD][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1623-6 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^MODE\s+[^ABSC]{1}/msi
  event "FTP invalid MODE"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[mM][oO][dD][eE][\x20\x09\x0b]+[^aAbBsScC]{1}/
}

signature s2b-1624-5 {
  ip-proto == tcp
  dst-port == 21
  payload-size == 10
  event "FTP large PWD command"
  tcp-state established,originator
  payload /.*[pP][wW][dD]/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-2125-8 {
  ip-proto == tcp
  dst-port == 21
  event "FTP CWD Root directory transversal attempt"
  tcp-state established,originator
  payload /.*[cC][wW][dD].{1}.*C\x3A\x5C/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-1921-5 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^SITE\s+ZIPCHK\s[^\n]{100}/smi
  event "FTP SITE ZIPCHK overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][iI][tT][eE][\x20\x09\x0b]+[zZ][iI][pP][cC][hH][kK][\x20\x09\x0b][^\n]{100}/
  eval dataSizeG100
}

signature s2b-1864-7 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^SITE\s+NEWER/smi
  event "FTP SITE NEWER attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[sS][iI][tT][eE][\x20\x09\x0b]+[nN][eE][wW][eE][rR]/
}

signature s2b-361-12 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^SITE\s+EXEC/smi
  event "FTP SITE EXEC attempt"
  tcp-state established,originator
  payload /.*[sS][iI][tT][eE].*.*[eE][xX][eE][cC]/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-1777-4 {
  ip-proto == tcp
  dst-port == 21
  event "FTP EXPLOIT STAT * dos attempt"
  tcp-state established,originator
  payload /.*[sS][tT][aA][tT].{1}.*\*/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-1778-4 {
  ip-proto == tcp
  dst-port == 21
  event "FTP EXPLOIT STAT ? dos attempt"
  tcp-state established,originator
  payload /.*[sS][tT][aA][tT].{1}.*\?/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-362-12 {
  ip-proto == tcp
  dst-port == 21
  event "FTP tar parameters"
  tcp-state established,originator
  payload /.* --[uU][sS][eE]-[cC][oO][mM][pP][rR][eE][sS][sS]-[pP][rR][oO][gG][rR][aA][mM] /
  requires-reverse-signature ! ftp_server_error
}

signature s2b-336-10 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^CWD\s+~root/smi
  event "FTP CWD ~root attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  payload /((^)|(\n+))[cC][wW][dD][\x20\x09\x0b]+~[rR][oO][oO][tT]/
}

signature s2b-1229-7 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^CWD\s[^\n]*?\.\.\./smi
  event "FTP CWD ..."
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  payload /((^)|(\n+))[cC][wW][dD][\x20\x09\x0b][^\n]*?\.\.\./
}

signature s2b-1672-10 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^CWD\s+~/smi
  event "FTP CWD ~ attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))CWD[\x20\x09\x0b]+~/
}

signature s2b-360-7 {
  ip-proto == tcp
  dst-port == 21
  event "FTP serv-u directory transversal"
  tcp-state established,originator
  payload /.*\.%20\./
  requires-reverse-signature ! ftp_server_error
}

signature s2b-1378-14 {
  ip-proto == tcp
  dst-port == 21
  event "FTP wu-ftp bad file completion attempt {"
  tcp-state established,originator
  ftp /.{2,} ~.?\{/
}

signature s2b-1992-5 {
  ip-proto == tcp
  dst-port == 21
  event "FTP LIST directory traversal attempt"
  tcp-state established,originator
  payload /.*LIST.{1}.*\.\..{1}.*\.\./
  requires-reverse-signature ! ftp_server_error
}

signature s2b-334-5 {
  ip-proto == tcp
  dst-port == 21
  event "FTP .forward"
  tcp-state established,originator
  payload /.*\.forward/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-335-5 {
  ip-proto == tcp
  dst-port == 21
  event "FTP .rhosts"
  tcp-state established,originator
  ftp /.*\.rhosts/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-1927-2 {
  ip-proto == tcp
  dst-port == 21
  event "FTP authorized_keys"
  tcp-state established,originator
  payload /.*authorized_keys/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-356-5 {
  ip-proto == tcp
  dst-port == 21
  event "FTP passwd retrieval attempt"
  tcp-state established,originator
  payload /.*[rR][eE][tT][rR]/
  payload /[\x20\x09\x0b\/.]*passwd[\x20\x09\x0b]*$/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-1928-3 {
  ip-proto == tcp
  dst-port == 21
  event "FTP shadow retrieval attempt"
  tcp-state established,originator
  payload /.*[rR][eE][tT][rR]/
  payload /.*shadow/
  requires-signature got_ftp_root
  requires-reverse-signature ! ftp_server_error
}

signature s2b-144-9 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^USER\s+w0rm/smi
  event "FTP ADMw0rm ftp login attempt"
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR].{1}.*[wW]0[rR][mM]/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-353-6 {
  ip-proto == tcp
  dst-port == 21
  event "FTP adm scan"
  tcp-state established,originator
  payload /.*PASS ddd@\x0A/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-354-5 {
  ip-proto == tcp
  dst-port == 21
  event "FTP iss scan"
  tcp-state established,originator
  payload /.*pass -iss@iss/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-355-5 {
  ip-proto == tcp
  dst-port == 21
  event "FTP pass wh00t"
  tcp-state established,originator
  payload /.*[pP][aA][sS][sS] [wW][hH]00[tT]/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-357-5 {
  ip-proto == tcp
  dst-port == 21
  event "FTP piss scan"
  tcp-state established,originator
  payload /.*pass -cklaus/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-358-5 {
  ip-proto == tcp
  dst-port == 21
  event "FTP saint scan"
  tcp-state established,originator
  payload /.*pass -saint/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-359-5 {
  ip-proto == tcp
  dst-port == 21
  event "FTP satan scan"
  tcp-state established,originator
  payload /.*pass -satan/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-2178-13 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^USER\s[^\n]*?%[^\n]*?%/smi
  event "FTP USER format string attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[uU][sS][eE][rR][\x20\x09\x0b][^\n]*?%[^\n]*?%/
}

signature s2b-2179-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^PASS\s[^\n]*?%[^\n]*?%/smi
  event "FTP PASS format string attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[pP][aA][sS][sS]\x20\x09\x0b][^\n]*?%[^\n]*?%/
}

signature s2b-2332-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^MKDIR\s[^\n]*?%[^\n]*?%/smi
  event "FTP MKDIR format string attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[mM][kK][dD][iI][rR][\x20\x09\x0b][^\n]*?%[^\n]*?%/
}

signature s2b-2333-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^RENAME\s[^\n]*?%[^\n]*?%/smi
  event "FTP RENAME format string attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[rR][eE][nN][aA][mM][eE][\x20\x09\x0b][^\n]*?%[^\n]*?%/
}

signature s2b-2338-5 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^LIST\s[^\n]{100,}/smi
  event "FTP LIST buffer overflow attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[lL][iI][sS][tT][\x20\x09\x0b][^\n]{100,}/
}

signature s2b-2272-4 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^LIST\s+\x22-W\s+\d+/smi
  event "FTP LIST integer overflow attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[lL][iI][sS][tT][\x20\x09\x0b]+\x22-W[\x20\x09\x0b]+[0-9]+/
}

signature s2b-2334-2 {
  ip-proto == tcp
  dst-port == 3535
  # Not supported: pcre: /^USER\s+y049575046/smi
  event "FTP Yak! FTP server default account login attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  payload /((^)|(\n+))USER[\x20\x09\x0b]+y049575046/
}

signature s2b-2335-2 {
  ip-proto == tcp
  dst-port == 3535
  # Not supported: pcre: /^RMD\s+\x2f$/smi
  event "FTP RMD / attempt"
  tcp-state established,originator
  payload /.*[rR][mM][dD]/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-2416-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^MDTM \d+[-+]\D/smi
  event "FTP invalid MDTM command attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[mMdDtTmM][0-9]+[-+][^0-9]/
}

signature s2b-2417-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /\s+.*?%.*?%/smi
  event "FTP format string attempt"
  tcp-state established,originator
  payload /.*%/
  ftp /[\x20\x09\x0b]+.*?%.*?%/
  requires-reverse-signature ! ftp_server_error
}

signature s2b-2574-1 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^RETR\s[^\n]*?%[^\n]*?%/smi
  event "FTP RETR format string attempt"
  tcp-state established,originator
  requires-reverse-signature ! ftp_server_error
  ftp /((^)|(\n+))[rR][eE][tT][rR][\x20\x09\x0b][^\n]*?%[^\n]*?%/
}

signature s2b-377-7 {
  ip-proto == icmp
  header icmp[0:1] == 8
  event "ICMP PING Network Toolbox 3 Windows"
  payload /.{0,16}================/
}

signature s2b-465-3 {
  ip-proto == icmp
  header icmp[0:1] == 8
  event "ICMP ISS Pinger"
  payload /.{0,24}ISSPNGRQ/
}

signature s2b-467-3 {
  ip-proto == icmp
  payload-size == 20
  header icmp[0:1] == 8
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "ICMP Nemesis v1.1 Echo"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 0
  payload /\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/
}

signature s2b-471-3 {
  ip-proto == icmp
  payload-size == 0
  header icmp[0:1] == 8
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "ICMP icmpenum v1.1.1"
  header ip[4:2] == 666
  header icmp[0:1] == 0,8
  header icmp[4:2] == 666
}

signature s2b-472-4 {
  ip-proto == icmp
  header icmp[1:1] == 1
  header icmp[0:1] == 5
  event "ICMP redirect host"
}

signature s2b-475-3 {
  ip-proto == icmp
  header icmp[0:1] == 0
  event "ICMP traceroute ipopts"
  ip-options rr
}

signature s2b-476-4 {
  ip-proto == icmp
  header icmp[1:1] == 0
  header icmp[0:1] == 8
  event "ICMP webtrends scanner"
  payload /.*\x00\x00\x00\x00EEEEEEEEEEEE/
}

signature s2b-478-3 {
  ip-proto == icmp
  payload-size == 4
  header icmp[0:1] == 8
  header icmp[0:1] == 0,8
  header icmp[6:2] == 0
  event "ICMP Broadscan Smurf Scanner"
  header icmp[0:1] == 0,8
  header icmp[4:2] == 0
}

signature s2b-481-5 {
  ip-proto == icmp
  header icmp[0:1] == 8
  event "ICMP TJPingPro1.1Build 2 Windows"
  payload /.{0,16}TJPingPro by Jim/
}

signature s2b-484-4 {
  ip-proto == icmp
  header icmp[0:1] == 8
  event "ICMP PING Sniffer Pro/NetXRay network scan"
  payload /.{0,13}Cinco Network, Inc\./
}

signature s2b-1813-5 {
  ip-proto == icmp
  event "ICMP digital island bandwidth query"
  payload /mailto\x3Aops@digisle\.com/
}

signature s2b-1993-4 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sLOGIN\s[^\n]*?\s\{/smi
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP login literal buffer overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[lL][oO][gG][iI][nN][\x20\x09\x0b][^\n]*?[\x20\x09\x0b]\{/
}

signature s2b-1842-9 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sLOGIN\s[^\n]{100}/smi
  event "IMAP login buffer overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  payload /((^)|(\n+))[\x20\x09\x0b]LOGIN[\x20\x09\x0b][^\n]{100}/
}

signature s2b-2105-4 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sAUTHENTICATE\s[^\n]*?\s\{/smi
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP authenticate literal overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[\x20\x09\x0b][aA][uU][tT][hH][eE][nN][tT][iI][cC][aA][tT][eE][\x20\x09\x0b][^\n]*?[\x20\x09\x0b]\{/
}

signature s2b-1844-9 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sAUTHENTICATE\s[^\n]{100}/smi
  event "IMAP authenticate overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  payload /((^)|(\n+))[\x20\x09\x0b][aA][uU][tT][hH][eE][nN][tT][iI][cC][aA][tT][eE][\x20\x09\x0b][^\n]{100}/
}

signature s2b-1930-3 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP auth literal overflow attempt"
  tcp-state established,originator
  payload /.* [aA][uU][tT][hH]/
  payload /.*\{/
}

signature s2b-2330-1 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /AUTH\s[^\n]{100}/smi
  event "IMAP auth overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[aA][uU][tT][hH][\x20\x09\x0b][^\n]{100}/
}

signature s2b-1902-9 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sLSUB\s[^\n]*?\s\{/smi
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP lsub literal overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[\x20\x09\x0b][lL][sS][uU][bB][\x20\x09\x0b][^\n]*?[\x20\x09\x0b]\{/
}

signature s2b-2106-7 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sLSUB\s[^\n]{100}/smi
  event "IMAP lsub overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  payload /((^)|(\n+))[\x20\x09\x0b][lL][sS][uU][bB][\x20\x09\x0b][^\n]{100}/
}

signature s2b-1845-15 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sLIST\s[^\n]*?\s\{/smi
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP list literal overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[\x20\x09\x0b][lL][iI][sS][tT][\x20\x09\x0b][^\n]*?[\x20\x09\x0b]\{/
}

signature s2b-2118-6 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sLIST\s[^\n]{100}/smi
  event "IMAP list overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  payload /((^)|(\n+))[\x20\x09\x0b][lL][iI][sS][tT][\x20\x09\x0b][^\n]{100}/
}

signature s2b-2119-5 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sRENAME\s[^\n]*?\s\{/smi
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP rename literal overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[\x20\x09\x0b][rR][eE][nN][aA][mM][eE][\x20\x09\x0b][^\n]*?[\x20\x09\x0b]\{/
}

signature s2b-1903-8 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sRENAME\s[^\n]{100}/smi
  event "IMAP rename overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  payload /((^)|(\n+))[\x20\x09\x0b][rR][eE][nN][aA][mM][eE][\x20\x09\x0b][^\n]{100}/
}

signature s2b-1904-7 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sFIND\s[^\n]{100}/smi
  event "IMAP find overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  payload /((^)|(\n+))[\x20\x09\x0b][fF][iI][nN][dD][\x20\x09\x0b][^\n]{100}/
}

signature s2b-1755-14 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sPARTIAL.*BODY\[[^\]]{1024}/smi
  event "IMAP partial body buffer overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[\x20\x09\x0b][pP][aA][rR][tT][iI][aA][lL].*[bB][oO][dD][yY]\[[^\]]{1024}/
}

signature s2b-2046-6 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sPARTIAL.*BODY\.PEEK\[[^\]]{1024}/smi
  event "IMAP partial body.peek buffer overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[\x20\x09\x0b][pP][aA][rR][tT][iI][aA][lL].*[bB][oO][dD][yY]\.[pP][eE][eE][kK]\[[^\]]{1024}/
}

signature s2b-2107-3 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sCREATE\s[^\n]{1024}/smi
  event "IMAP create buffer overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 1024,relative
  payload /((^)|(\n+))[\x20\x09\x0b][cC][rR][eE][aA][tT][eE][\x20\x09\x0b][^\n]{1024}/
}

signature s2b-2120-3 {
  ip-proto == tcp
  dst-port == 143
  # Not supported: pcre: /\sCREATE\s*\{/smi
  # Not supported: byte_test: 5,>,256,0,string,dec,relative
  event "IMAP create literal buffer overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[\x20\x09\x0b][cC][rR][eE][aA][tT][eE][\x20\x09\x0b][^\n]*?\s\{/
}

signature s2b-2497-6 {
  ip-proto == tcp
  dst-port == 993
  event "IMAP SSLv3 invalid data version attempt"
  tcp-state established,originator
  payload /\x16\x03/
  payload /.{4}\x01/
  payload /.{8}[^\x03]*/
}

signature s2b-2517-10 {
  ip-proto == tcp
  dst-port == 993
  # Not supported: byte_test: 2,>,0,6,2,!,0,8,2,!,16,8,2,>,20,10,2,>,32768,0,relative
  event "IMAP PCT Client_Hello overflow attempt"
  tcp-state established,originator
  payload /.{1}\x01/
  payload /.{10}\x8F/
}

signature s2b-2530-3 {
  ip-proto == tcp
  src-port == 993
  # Not supported: flowbits: isset,sslv3.client_hello.request,set,sslv3.server_hello.request,noalert
  event "IMAP SSLv3 Server_Hello request"
  tcp-state established,responder
  payload /\x16\x03/
  payload /.{4}\x02/
}

signature s2b-489-7 {
  ip-proto == tcp
  dst-port == 21
  # Not supported: pcre: /^PASS\s*\n/smi
  event "INFO FTP no password"
  tcp-state established,originator
  ftp /((^)|(\n+))[\x20\x09\x0b][pP][aA][sS][sS][\x20\x09\x0b]*\n/
}

signature s2b-491-8 {
  ip-proto == tcp
  src-port == 21
  # Not supported: pcre: /^530\s+(Login|User)/smi
  event "INFO FTP Bad login"
  tcp-state established,responder
  ftp /((^)|(\n+))530[\x20\x09\x0b]+([lL][oO][gG][iI][nN]|[uU][sS][eE][rR])/
}

signature s2b-1251-6 {
  ip-proto == tcp
  src-port == 23
  event "INFO TELNET Bad Login"
  tcp-state established,responder
  payload /.*[lL][oO][gG][iI][nN] [iI][nN][cC][oO][rR][rR][eE][cC][tT]/
}

signature s2b-500-4 {
  event "MISC source route lssr"
  ip-options lsrr
}

signature s2b-501-4 {
  event "MISC source route lssre"
  ip-options lsrre
}

signature s2b-502-2 {
  event "MISC source route ssrr"
  ip-options ssrr
}

signature s2b-503-6 {
  ip-proto == tcp
  src-port == 20
  dst-port >= 0
  dst-port <= 1023
  header tcp[13:1] & 255 == 2
  event "MISC Source Port 20 to <1024"
  tcp-state stateless
}

signature s2b-504-6 {
  ip-proto == tcp
  src-port == 53
  dst-port >= 0
  dst-port <= 1023
  header tcp[13:1] & 255 == 2
  event "MISC source port 53 to <1024"
  tcp-state stateless
}

signature s2b-505-5 {
  ip-proto == tcp
  dst-port == 1417
  event "MISC Insecure TIMBUKTU Password"
  tcp-state established,originator
  payload /.{0,13}\x05\x00>/
}

signature s2b-507-4 {
  ip-proto == tcp
  dst-port == 5631
  event "MISC PCAnywhere Attempted Administrator Login"
  tcp-state established,originator
  payload /.*ADMINISTRATOR/
}

signature s2b-508-7 {
  ip-proto == tcp
  dst-port == 70
  event "MISC gopher proxy"
  tcp-state established,originator
  payload /.*[fF][tT][pP]\x3A/
  payload /.*@\//
}

signature s2b-512-4 {
  ip-proto == tcp
  src-port >= 5631
  src-port <= 5632
  event "MISC PCAnywhere Failed Login"
  tcp-state established,responder
  payload /.{0,3}Invalid login/
}

signature s2b-513-10 {
  ip-proto == tcp
  src-port == 7161
  header tcp[13:1] & 255 == 18
  event "MISC Cisco Catalyst Remote Access"
  tcp-state stateless
}

signature s2b-514-5 {
  ip-proto == tcp
  dst-port == 27374
  event "MISC ramen worm"
  tcp-state established,originator
  payload /.{0,4}[gG][eE][tT] /
}

signature s2b-516-3 {
  ip-proto == udp
  dst-port == 161
  event "MISC SNMP NT UserList"
  payload /.*\+\x06\x10@\x14\xD1\x02\x19/
}

signature s2b-517-1 {
  ip-proto == udp
  dst-port == 177
  event "MISC xdmcp query"
  payload /.*\x00\x01\x00\x03\x00\x01\x00/
}

signature s2b-1867-1 {
  ip-proto == udp
  dst-port == 177
  event "MISC xdmcp info query"
  payload /.*\x00\x01\x00\x02\x00\x01\x00/
}

signature s2b-522-2 {
  header ip[6:1] & 224 == 32
  payload-size < 25
  event "MISC Tiny Fragments"
}

signature s2b-1384-8 {
  ip-proto == udp
  dst-port == 1900
  event "MISC UPnP malformed advertisement"
  payload /.*[nN][oO][tT][iI][fF][yY] \* /
}

signature s2b-1388-12 {
  ip-proto == udp
  dst-port == 1900
  # Not supported: pcre: /^Location\:[^\n]{128}/smi
  event "MISC UPnP Location overflow"
  payload /((^)|(\n+))[lL][oO][cC][aA][tT][iI][oO][nN]\x3a[^\n]{128}/
}

signature s2b-1393-12 {
  ip-proto == tcp
  event "MISC AIM AddGame attempt"
  tcp-state established,responder
  payload /.*[aA][iI][mM]\x3A[aA][dD][dD][gG][aA][mM][eE]\?/
}

signature s2b-1752-4 {
  ip-proto == tcp
  event "MISC AIM AddExternalApp attempt"
  tcp-state established,responder
  payload /.*[aA][iI][mM]\x3A[aA][dD][dD][eE][xX][tT][eE][rR][nN][aA][lL][aA][pP][pP]\?/
}

signature s2b-1636-8 {
  ip-proto == tcp
  dst-port == 32000
  # Not supported: pcre: /^Username\:[^\n]{100}/smi
  payload-size > 500
  event "MISC Xtramail Username overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 100,relative
  payload /((^)|(\n+))[uU][sS][eE][rR][nN][aA][mM][eE]\:[^\n]{100}/
}

signature s2b-1887-3 {
  ip-proto == tcp
  dst-port == 443
  event "MISC OpenSSL Worm traffic"
  tcp-state established,originator
  payload /.*[tT][eE][rR][mM]=[xX][tT][eE][rR][mM]/
}

signature s2b-1889-5 {
  ip-proto == udp
  src-port == 2002
  dst-port == 2002
  event "MISC slapper worm admin traffic"
  payload /\x00\x00E\x00\x00E\x00\x00@\x00/
}

signature s2b-1447-11 {
  ip-proto == tcp
  dst-port == 3389
  event "MISC MS Terminal server request RDP"
  tcp-state established,originator
  payload /\x03\x00\x00\x0B\x06\xE0\x00\x00\x00\x00\x00/
}

signature s2b-1448-10 {
  ip-proto == tcp
  dst-port == 3389
  event "MISC MS Terminal server request"
  tcp-state established,originator
  payload /\x03\x00\x00/
  payload /.{4}\xE0\x00\x00\x00\x00\x00/
}

signature s2b-2418-3 {
  ip-proto == tcp
  dst-port == 3389
  event "MISC MS Terminal Server no encryption session initiation attmept"
  tcp-state established,originator
  payload /\x03\x00\x01/
  payload /.{287}\x00/
}

signature s2b-1819-5 {
  ip-proto == tcp
  dst-port == 2533
  event "MISC Alcatel PABX 4400 connection attempt"
  tcp-state established,originator
  payload /\x00\x01C/
}

signature s2b-1939-4 {
  ip-proto == udp
  dst-port == 67
  # Not supported: byte_test: 1,>,6,2
  event "MISC bootp hardware address length overflow"
  payload /\x01/
}

signature s2b-1940-3 {
  ip-proto == udp
  dst-port == 67
  # Not supported: byte_test: 1,>,7,1
  event "MISC bootp invalid hardware type"
  payload /\x01/
}

signature s2b-2039-4 {
  ip-proto == udp
  dst-port == 67
  event "MISC bootp hostname format string attempt"
  payload /\x01.{240}.*\x0C.*.*%.{1}.{0,7}%.{1}.{0,7}%/
}

signature s2b-1966-2 {
  ip-proto == udp
  dst-port == 27155
  event "MISC GlobalSunTech Access Point Information Disclosure attempt"
  payload /.*gstsearch/
}

signature s2b-1987-6 {
  ip-proto == tcp
  dst-port == 7100
  payload-size > 512
  event "MISC xfs overflow attempt"
  tcp-state established,originator
  payload /B\x00\x02/
}

signature s2b-2041-2 {
  ip-proto == udp
  src-port == 49
  event "MISC xtacacs failed login response"
  payload /\x80\x02.{4}.*\x02/
}

signature s2b-2043-2 {
  ip-proto == udp
  src-port == 500
  dst-port == 500
  event "MISC isakmp login failed"
  payload /.{16}\x10\x05.{13}\x00\x00\x00\x01\x01\x00\x00\x18/
}

signature s2b-2048-2 {
  ip-proto == tcp
  dst-port == 873
  # Not supported: byte_test: 2,>,4000,0
  event "MISC rsyncd overflow attempt"
  tcp-state originator
  payload /.{1}\x00\x00/
}

signature s2b-2008-4 {
  ip-proto == tcp
  src-port == 2401
  event "MISC CVS invalid user authentication response"
  tcp-state established,responder
  payload /.*E Fatal error, aborting\./
  payload /.*\x3A no such user/
}

signature s2b-2009-2 {
  ip-proto == tcp
  src-port == 2401
  src-ip == local_nets
  event "MISC CVS invalid repository response"
  tcp-state established,responder
  payload /.*error /
  payload /.*\x3A no such repository/
  payload /.*I HATE YOU/
}

signature s2b-2010-4 {
  ip-proto == tcp
  src-port == 2401
  event "MISC CVS double free exploit attempt response"
  tcp-state established,responder
  payload /.*free\x28\x29\x3A warning\x3A chunk is already free/
}

signature s2b-2011-4 {
  ip-proto == tcp
  src-port == 2401
  event "MISC CVS invalid directory response"
  tcp-state established,responder
  payload /.*E protocol error\x3A invalid directory syntax in/
}

signature s2b-2012-2 {
  ip-proto == tcp
  src-port == 2401
  event "MISC CVS missing cvsroot response"
  tcp-state established,responder
  payload /.*E protocol error\x3A Root request missing/
}

signature s2b-2013-2 {
  ip-proto == tcp
  src-port == 2401
  event "MISC CVS invalid module response"
  tcp-state established,responder
  payload /.*cvs server\x3A cannot find module.{1}.*error/
}

signature s2b-2317-4 {
  ip-proto == tcp
  src-port == 2401
  event "MISC CVS non-relative path error response"
  tcp-state established,responder
  payload /.*E cvs server\x3A warning\x3A cannot make directory CVS in \//
}

signature s2b-2318-3 {
  ip-proto == tcp
  dst-port == 2401
  # Not supported: pcre: m?^Argument\s+/?smi,/^Directory/smiR
  event "MISC CVS non-relative path access attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[aA][Rr][Gg][Uu}[Mm][Ee][Nn][Tt][\x20\x09\x0b]]+/
  payload /.*[Dd][Ii][Rr][Ee][Cc][Tt][Oo][Rr][Yy]/
}

signature s2b-2159-8 {
  ip-proto == tcp
  src-port == 179
  event "MISC BGP invalid type 0"
  tcp-state stateless
  payload /\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF.{2}\x00/
}

signature s2b-2500-4 {
  ip-proto == tcp
  dst-port == 636
  event "MISC LDAP SSLv3 invalid data version attempt"
  tcp-state established,originator
  payload /\x16\x03/
  payload /.{4}\x01/
  payload /.{8}[^\x03]*/
}

signature s2b-2516-10 {
  ip-proto == tcp
  dst-port == 639
  # Not supported: byte_test: 2,>,0,6,2,!,0,8,2,!,16,8,2,>,20,10,2,>,32768,0,relative
  event "MISC LDAP PCT Client_Hello overflow attempt"
  tcp-state established,originator
  payload /.{1}\x01/
  payload /.{10}\x8F/
}

signature s2b-2533-5 {
  ip-proto == tcp
  src-port == 639
  # Not supported: flowbits: isset,sslv3.client_hello.request,set,sslv3.server_hello.request,noalert
  event "MISC LDAP SSLv3 Server_Hello request"
  tcp-state established,responder
  payload /\x16\x03/
  payload /.{4}\x02/
}

signature s2b-2534-3 {
  ip-proto == tcp
  dst-port == 639
  # Not supported: flowbits: isset,sslv3.server_hello.request
  event "MISC LDAP SSLv3 invalid Client_Hello attempt"
  tcp-state established,originator
  payload /\x16\x03/
  payload /.{4}\x01/
}

signature s2b-2547-2 {
  ip-proto == tcp
  dst-port == 8000
  event "MISC HP Web JetAdmin remote file upload attempt"
  tcp-state established,originator
  payload /.*\/[pP][lL][uU][gG][iI][nN][sS]\/[hH][pP][jJ][wW][jJ][aA]\/[sS][cC][rR][iI][pP][tT]\/[dD][eE][vV][iI][cC][eE][sS]_[uU][pP][dD][aA][tT][eE]_[pP][rR][iI][nN][tT][eE][rR]_[fF][wW]_[uU][pP][lL][oO][aA][dD]\.[hH][tT][sS]/
  payload /.*[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]\x3A.*.*[mM][uU][lL][tT][iI][pP][aA][rR][tT]/
}

signature s2b-2548-1 {
  ip-proto == tcp
  dst-port == 8000
  event "MISC HP Web JetAdmin setinfo access"
  tcp-state established,originator
  payload /.*\/[pP][lL][uU][gG][iI][nN][sS]\/[hH][pP][jJ][dD][wW][mM]\/[sS][cC][rR][iI][pP][tT]\/[tT][eE][sS][tT]\/[sS][eE][tT][iI][nN][fF][oO]\.[hH][tT][sS]/
}

signature s2b-2549-1 {
  ip-proto == tcp
  dst-port == 8000
  event "MISC HP Web JetAdmin file write attempt"
  tcp-state established,originator
  payload /.*\/[pP][lL][uU][gG][iI][nN][sS]\/[fF][rR][aA][mM][eE][wW][oO][rR][kK]\/[sS][cC][rR][iI][pP][tT]\/[tT][rR][eE][eE]\.[xX][mM][sS]/
  payload /.*[wW][rR][iI][tT][eE][tT][oO][fF][iI][lL][eE]/
}

signature s2b-2561-2 {
  ip-proto == tcp
  dst-port == 873
  # Not supported: pcre: /--backup-dir\s+\x2e\x2e\x2f/
  event "MISC rsync backup-dir directory traversal attempt"
  tcp-state established,originator
  payload /--backup-dir[\x20\x09\x0b]+\x2e\x2e\x2f/
}

signature s2b-1428-5 {
  ip-proto == tcp
  dst-ip == 64.245.58.0/23
  event "MULTIMEDIA audio galaxy keepalive"
  tcp-state established
  payload /E_\x00\x03\x05/
}

signature s2b-2423-2 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: flowbits: set,realplayer.playlist,noalert
  event "MULTIMEDIA realplayer .rp playlist download attempt"
  tcp-state established,originator
  http /((^)|(\n+))[tT][aA][kK][eE][tT][hH][iI][sS].*?[pP][Aa][Tt][Hh]\x3a.*?[\r]{0,1}?\n[\r]{0,1}\n/
}

signature s2b-1775-2 {
  ip-proto == tcp
  dst-port == 3306
  event "MYSQL root login attempt"
  tcp-state established,originator
  payload /.*\x0A\x00\x00\x01\x85\x04\x00\x00\x80root\x00/
}

signature s2b-1776-2 {
  ip-proto == tcp
  dst-port == 3306
  event "MYSQL show databases attempt"
  tcp-state established,originator
  payload /.*\x0F\x00\x00\x00\x03show databases/
}

signature s2b-537-11 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 1,<,128,6,relative
  event "NETBIOS SMB IPC$ share access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[iI][pP][cC]\x24\x00/
}

signature s2b-538-10 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB IPC$ share unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[iI]\x00[pP]\x00[cC]\x00\x24\x00\x00/
}

signature s2b-2465-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,<,128,6,relative
  event "NETBIOS SMB-DS IPC$ share access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[iI][pP][cC]\x24\x00/
}

signature s2b-2466-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB-DS IPC$ share unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[iI]\x00[pP]\x00[cC]\x00\x24\x00\x00/
}

signature s2b-536-7 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 1,<,128,6,relative
  event "NETBIOS SMB D$ share access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[dD]\x24\x00/
}

signature s2b-2467-3 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB D$ share unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[dD]\x00\x24\x00\x00/
}

signature s2b-2468-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,<,128,6,relative
  event "NETBIOS SMB-DS D$ share access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[dD]\x24\x00/
}

signature s2b-2469-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB-DS D$ share unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[dD]\x00\x24\x00\x00/
}

signature s2b-533-8 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 1,<,128,6,relative
  event "NETBIOS SMB C$ share access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[cC]\x24\x00/
}

signature s2b-2470-3 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB C$ share unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[cC]\x00\x24\x00\x00/
}

signature s2b-2471-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,<,128,6,relative
  event "NETBIOS SMB-DS C$ share access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[cC]\x24\x00/
}

signature s2b-2472-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB-DS C$ share unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[cC]\x00\x24\x00\x00/
}

signature s2b-532-8 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 1,<,128,6,relative
  event "NETBIOS SMB ADMIN$ share access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[aA][dD][mM][iI][nN]\x24\x00/
}

signature s2b-2473-3 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB ADMIN$ share unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[aA]\x00[dD]\x00[mM]\x00[iI]\x00[nN]\x00\x24\x00\x00/
}

signature s2b-2474-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,<,128,6,relative
  event "NETBIOS SMB-DS ADMIN$ share access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[aA][dD][mM][iI][nN]\x24\x00/
}

signature s2b-2475-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB-DS ADMIN$ share unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMBu.{32}.*[aA]\x00[dD]\x00[mM]\x00[iI]\x00[nN]\x00\x24\x00\x00/
}

signature s2b-2174-4 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS SMB winreg access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\xA2/
  payload /.{84}.*\x5C[wW][iI][nN][rR][eE][gG]\x00/
}

signature s2b-2175-5 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS SMB winreg unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\xA2/
  payload /.{84}.*\x5C\x00[wW]\x00[iI]\x00[nN]\x00[rR]\x00[eE]\x00[gG]\x00/
}

signature s2b-2476-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: flowbits: set,smb.winreg.create
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB-DS Create AndX Request winreg attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\xA2.{79}\x5C[wW][iI][nN][rR][eE][gG]\x00/
}

signature s2b-2477-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: flowbits: set,smb.winreg.create
  # Not supported: byte_test: 1,>,127,6,relative
  event "NETBIOS SMB-DS Create AndX Request winreg unicode attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB\xA2.{79}\x5C\x00[wW]\x00[iI]\x00[nN]\x00[rR]\x00[eE]\x00[gG]\x00\x00\x00/
}

signature s2b-2478-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: flowbits: set,smb.dce.bind.winreg,isset,smb.winreg.create
  # Not supported: byte_test: 1,<,128,6,relative,1,&,16,1,relative
  event "NETBIOS SMB-DS DCERPC bind winreg attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{5}\x5C[pP][iI][pP][eE]\x5C\x00\x05\x00\x0B.{29}\x01\xD0\x8C3D\x22\xF11\xAA\xAA\x90\x008\x00\x10\x03/
}

signature s2b-2480-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: flowbits: isset,smb.dce.bind.winreg
  # Not supported: byte_test: 1,>,127,6,relative,1,&,16,1,relative
  event "NETBIOS SMB-DS DCERPC shutdown unicode attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{5}\x5C\x00[pP]\x00[iI]\x00[pP]\x00[eE]\x00\x5C\x00\x00\x00\x05\x00\x00.{19}\x18\x00/
}

signature s2b-2481-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: flowbits: isset,smb.dce.bind.winreg
  # Not supported: byte_test: 1,>,127,6,relative,1,<,16,1,relative
  event "NETBIOS SMB-DS DCERPC shutdown unicode little endian attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{5}\x5C\x00[pP]\x00[iI]\x00[pP]\x00[eE]\x00\x5C\x00\x00\x00\x05\x00\x00.{19}\x00\x18/
}

signature s2b-1293-10 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS nimda .eml"
  tcp-state established,originator
  payload /.*\x00\.\x00E\x00M\x00L/
}

signature s2b-1294-10 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS nimda .nws"
  tcp-state established,originator
  payload /.*\x00\.\x00N\x00W\x00S/
}

signature s2b-1295-9 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS nimda RICHED20.DLL"
  tcp-state established,originator
  payload /.*R\x00I\x00C\x00H\x00E\x00D\x002\x000/
}

signature s2b-529-7 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS DOS RFPoison"
  tcp-state established,originator
  payload /.*\x5C\x00\x5C\x00\*\x00S\x00M\x00B\x00S\x00E\x00R\x00V\x00E\x00R\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00/
}

signature s2b-530-10 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS NT NULL session"
  tcp-state established,originator
  payload /.*\x00\x00\x00\x00W\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00N\x00T\x00 \x001\x003\x008\x001/
}

signature s2b-1239-5 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS RFParalyze Attempt"
  tcp-state established,originator
  payload /.*BEAVIS/
  payload /.*yep yep/
}

signature s2b-534-6 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS SMB CD.."
  tcp-state established,originator
  payload /.*\x5C\.\.\/\x00\x00\x00/
}

signature s2b-535-6 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS SMB CD..."
  tcp-state established,originator
  payload /.*\x5C\.\.\.\x00\x00\x00/
}

signature s2b-2176-4 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS SMB startup folder access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB2.*.*[dD][oO][cC][uU][mM][eE][nN][tT][sS] [aA][nN][dD] [sS][eE][tT][tT][iI][nN][gG][sS]\x5C[aA][lL][lL] [uU][sS][eE][rR][sS]\x5C[sS][tT][aA][rR][tT] [mM][eE][nN][uU]\x5C[pP][rR][oO][gG][rR][aA][mM][sS]\x5C[sS][tT][aA][rR][tT][uU][pP]\x00/
}

signature s2b-2177-4 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS SMB startup folder unicode access"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB2.*.*\x5C\x00[sS]\x00[tT]\x00[aA]\x00[rR]\x00[tT]\x00 \x00[mM]\x00[eE]\x00[nN]\x00[uU]\x00\x5C\x00[pP]\x00[rR]\x00[oO]\x00[gG]\x00[rR]\x00[aA]\x00[mM]\x00[sS]\x00\x5C\x00[sS]\x00[tT]\x00[aA]\x00[rR]\x00[tT]\x00[uU]\x00[pP]/
}

signature s2b-2101-9 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS SMB SMB_COM_TRANSACTION Max Parameter and Max Count of 0 DOS Attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB%/
  payload /.{42}\x00\x00\x00\x00/
}

signature s2b-2103-9 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 2,>,256,0,relative,little
  event "NETBIOS SMB trans2open buffer overflow attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFFSMB2/
  payload /.{59}\x00\x14/
}

signature s2b-2190-3 {
  ip-proto == tcp
  dst-port == 135
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS DCERPC invalid bind attempt"
  tcp-state established,originator
  payload /\x05.{1}\x0B.{21}\x00/
}

signature s2b-2191-3 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS SMB DCERPC invalid bind attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{5}\x5C\x00[pP]\x00[iI]\x00[pP]\x00[eE]\x00\x5C\x00.{2}\x05.{1}\x0B.{21}\x00/
}

signature s2b-2192-8 {
  ip-proto == tcp
  dst-port == 135
  # Not supported: flowbits: set,dce.isystemactivator.bind.attempt,noalert
  event "NETBIOS DCERPC ISystemActivator bind attempt"
  # Not supported: byte_test: 1,&,1,0,relative
  tcp-state established,originator
  payload /\x05.{1}\x0B.{29}\xA0\x01\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00F/
}

signature s2b-2193-9 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: flowbits: set,dce.isystemactivator.bind.call.attempt
  event "NETBIOS SMB-DS DCERPC ISystemActivator bind attempt"
  # Not supported: byte_test: 1,&,1,0,relative
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{5}\x5C\x00[pP]\x00[iI]\x00[pP]\x00[eE]\x00\x5C\x00\x05.{1}\x0B.{29}\xA0\x01\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00F/
}

signature s2b-2493-5 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: flowbits: set,dce.isystemactivator.bind.call.attempt
  event "NETBIOS SMB DCERPC ISystemActivator unicode bind attempt"
  # Not supported: byte_test: 2,&,1,5,relative,1,&,16,1,relative
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{4}\x5C\x00P\x00I\x00P\x00E\x00\x5C\x00\x05\x00\x0B.{29}\xA0\x01\x00\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00F/
}

signature s2b-2251-11 {
  ip-proto == tcp
  dst-port == 135
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS DCERPC Remote Activation bind attempt"
  tcp-state established,originator
  payload /\x05.{1}\x0B.{29}\xB8J\x9FM\x1C\}\xCF\x11\x86\x1E\x00 \xAFn\x7CW/
}

signature s2b-2252-11 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS SMB-DS DCERPC Remote Activation bind attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{5}\x5C\x00[pP]\x00[iI]\x00[pP]\x00[eE]\x00\x5C\x00\x05.{1}\x0B.{29}\xB8J\x9FM\x1C\}\xCF\x11\x86\x1E\x00 \xAFn\x7CW/
}

signature s2b-2257-5 {
  ip-proto == udp
  dst-port == 135
  # Not supported: byte_test: 1,>,15,2,relative,4,>,1024,0,little,relative
  # Not supported: byte_jump: 4,86,little,align,relative,4,8,little,align,relative
  event "NETBIOS DCERPC Messenger Service buffer overflow attempt"
  payload /\x04\x00/
}

signature s2b-2258-6 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 1,>,15,2,relative,4,>,1024,0,little,relative
  # Not supported: byte_jump: 4,86,little,align,relative,4,8,little,align,relative
  event "NETBIOS SMB-DS DCERPC Messenger Service buffer overflow attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{5}\x5C\x00[pP]\x00[iI]\x00[pP]\x00[eE]\x00\x5C\x00\x04\x00/
}

signature s2b-2308-6 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 2,&,1,5,relative,1,&,16,1,relative
  event "NETBIOS SMB DCERPC Workstation Service unicode bind attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{4}\x5C\x00P\x00I\x00P\x00E\x00\x5C\x00\x05\x00\x0B.{29}\x98\xD0\xFFk\x12\xA1\x106\x983F\xC3\xF8~4Z/
}

signature s2b-2309-6 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 2,^,1,5,relative,1,&,16,1,relative
  event "NETBIOS SMB DCERPC Workstation Service bind attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{4}\x5CPIPE\x5C\x00\x05\x00\x0B.{29}\x98\xD0\xFFk\x12\xA1\x106\x983F\xC3\xF8~4Z/
}

signature s2b-2310-8 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 2,&,1,5,relative,1,&,16,1,relative
  event "NETBIOS SMB-DS DCERPC Workstation Service unicode bind attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{4}\x5C\x00P\x00I\x00P\x00E\x00\x5C\x00\x05\x00\x0B.{29}\x98\xD0\xFFk\x12\xA1\x106\x983F\xC3\xF8~4Z/
}

signature s2b-2311-7 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 2,^,1,5,relative,1,&,16,1,relative
  event "NETBIOS SMB-DS DCERPC Workstation Service bind attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{4}\x5CPIPE\x5C\x00\x05\x00\x0B.{29}\x98\xD0\xFFk\x12\xA1\x106\x983F\xC3\xF8~4Z/
}

signature s2b-2315-6 {
  ip-proto == tcp
  dst-port >= 1024
  dst-port <= 65535
  # Not supported: byte_test: 1,&,16,1,relative
  event "NETBIOS DCERPC Workstation Service direct service bind attempt"
  tcp-state established,originator
  payload /\x05\x00\x0B.{29}\x98\xD0\xFFk\x12\xA1\x106\x983F\xC3\xF8~4Z/
}

signature s2b-2316-6 {
  ip-proto == udp
  dst-port >= 1024
  dst-port <= 65535
  # Not supported: byte_test: 1,&,16,2,relative
  event "NETBIOS DCERPC Workstation Service direct service access attempt"
  payload /\x04\x00.{22}\x98\xD0\xFFk\x12\xA1\x106\x983F\xC3\xF8~4Z/
}

signature s2b-2348-6 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: flowbits: set,dce.printer.bind,noalert
  # Not supported: byte_test: 1,&,16,1,relative
  event "NETBIOS SMB-DS DCERPC print spool bind attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]%.{56}&\x00.{5}\x5C\x00P\x00I\x00P\x00E\x00\x5C\x00\x00\x00\x05\x00\x0B.{29}xV4\x124\x12\xCD\xAB\xEF\x00\x01\x23Eg\x89\xAB/
}

signature s2b-2382-8 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS SMB NTLMSSP invalid mechtype attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB][sS]/
  payload /.{62}`.{1}\x06\x06\+\x06\x01\x05\x05\x02.*.*\x06\x0A\+\x06\x01\x04\x01\x827\x02\x02\x0A.*.*\xA1\x05\x23\x03\x03\x01\x07/
}

signature s2b-2383-9 {
  ip-proto == tcp
  dst-port == 445
  event "NETBIOS SMB-DS DCERPC NTLMSSP invalid mechtype attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB][sS]/
  payload /.{62}`.{1}\x06\x06\+\x06\x01\x05\x05\x02.*.*\x06\x0A\+\x06\x01\x04\x01\x827\x02\x02\x0A.*.*\xA1\x05\x23\x03\x03\x01\x07/
}

signature s2b-2384-8 {
  ip-proto == tcp
  dst-port == 139
  event "NETBIOS SMB NTLMSSP invalid mechlistMIC attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB][sS]/
  payload /.{62}`.{1}\x00\x00\x00b\x06\x83\x00\x00\x06\+\x06\x01\x05\x05\x02.*.*\x06\x0A\+\x06\x01\x04\x01\x827\x02\x02\x0A.*.*\xA3>0<\xA00/
}

signature s2b-2385-9 {
  ip-proto == tcp
  dst-port == 445
  event "NETBIOS SMB-DS DCERPC NTLMSSP invalid mechlistMIC attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB][sS]/
  payload /.{62}`.{1}\x00\x00\x00b\x06\x83\x00\x00\x06\+\x06\x01\x05\x05\x02.*.*\x06\x0A\+\x06\x01\x04\x01\x827\x02\x02\x0A.*.*\xA3>0<\xA00/
}

signature s2b-2401-4 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 2,>,322,2,1,<,128,6,relative,2,>,255,8,relative,little
  event "NETBIOS SMB Session Setup AndX request username overflow attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB][sS].{42}\x00\x00\x00\x00.{10}[^\x00]{255}/
}

signature s2b-2402-5 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 2,>,322,2,1,<,128,6,relative,2,>,255,8,relative,little
  event "NETBIOS SMB-DS Session Setup AndX request username overflow attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB][sS].{42}\x00\x00\x00\x00.{10}[^\x00]{255}/
}

signature s2b-2403-4 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: byte_test: 2,>,322,2,1,&,128,6,relative,2,>,255,54,relative,little
  event "NETBIOS SMB Session Setup AndX request unicode username overflow attempt"
  tcp-state established,originator
  payload /.*.*\x00\x00.*.*\x00\x00/
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB][sS].{56}.*\x00.{255}.*\x00\x00.*.*\x00\x00/
}

signature s2b-2404-5 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: byte_test: 2,>,322,2,1,&,128,6,relative,2,>,255,54,relative,little
  event "NETBIOS SMB-DS Session Setup AndX request unicode username overflow attempt"
  tcp-state established,originator
  payload /.*.*\x00\x00.*.*\x00\x00/
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB][sS].{56}.*\x00.{255}.*\x00\x00.*.*\x00\x00/
}

signature s2b-2495-5 {
  ip-proto == tcp
  dst-port == 139
  # Not supported: threshold: type both, track by_dst, count 20, seconds 60
  # Not supported: flowbits: isset,dce.isystemactivator.bind.call.attempt
  # Not supported: byte_test: 1,&,1,0,relative
  event "NETBIOS SMB DCEPRC ORPCThis request flood attempt"
  tcp-state established,originator
  payload /\x05.{1}\x00.{21}\x05/
  payload /.*MEOW/
}

signature s2b-2524-7 {
  ip-proto == tcp
  dst-port == 135
  # Not supported: flowbits: set,netbios.lsass.bind.attempt,noalert
  event "NETBIOS DCERPC LSASS direct bind attempt"
  tcp-state established,originator
  payload /\x00/
  payload /.{3}\xFF[sS][mM][bB]/
  payload /.*\x05.{1}\x0B.{29}j\x28\x199\x0C\xB1\xD0\x11\x9B\xA8\x00\xC0O\xD9\.\xF5/
}

signature s2b-2514-7 {
  ip-proto == tcp
  dst-port == 445
  # Not supported: flowbits: isset,netbios.lsass.bind.attempt
  event "NETBIOS SMB-DS DCERPC LSASS DsRolerUpgradeDownlevelServer exploit attempt"
  tcp-state established,originator
  payload /.{3}\xFF[sS][mM][bB].{59}.*\x05.{1}\x00.{19}\x09\x00/
}

signature s2b-2564-4 {
  ip-proto == udp
  src-port == 137
  dst-port == 137
  # Not supported: byte_test: 1,>,127,2
  payload-size < 56
  event "NETBIOS NS lookup short response attempt"
  payload /.{5}\x00\x01/
}

signature s2b-1792-8 {
  ip-proto == tcp
  src-port == 119
  # Not supported: pcre: /^200\s[^\n]{64}/smi
  event "NNTP return code buffer overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 64,relative
  payload /((^)|(\n+))200[\x20\x09\x0b][^\n]{64}/
}

signature s2b-1538-13 {
  ip-proto == tcp
  dst-port == 119
  # Not supported: pcre: /^AUTHINFO\s+USER\s[^\n]{200}/smi
  event "NNTP AUTHINFO USER overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 200,relative
  payload /((^)|(\n+))[aA][uU][tT][hH][iI][nN][fF][oO][\x20\x09\x0b]+[uU][sS][eE][rR][\x20\x09\x0b][^\n]{200}/
}

signature s2b-2424-3 {
  ip-proto == tcp
  dst-port == 119
  # Not supported: pcre: /^sendsys\x3a[^\n]{21}/smi
  event "NNTP sendsys overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[sS][eE][nN][dD][sS][yY][sS]\x3a[^\n]{21}/
}

signature s2b-2425-3 {
  ip-proto == tcp
  dst-port == 119
  # Not supported: pcre: /^senduuname\x3a[^\n]{21}/smi
  event "NNTP senduuname overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[sS][eE][nN][dD][uU][uU][nN][aA][mM][eE]\x3a[^\n]{21}/
}

signature s2b-2426-3 {
  ip-proto == tcp
  dst-port == 119
  # Not supported: pcre: /^version\x3a[^\n]{21}/smi
  event "NNTP version overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[vV][eE][rR][sS][iI][oO][nN]\x3a[^\n]{21}/
}

signature s2b-2427-3 {
  ip-proto == tcp
  dst-port == 119
  # Not supported: pcre: /^checkgroups\x3a[^\n]{21}/smi
  event "NNTP checkgroups overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[cC][hH][eE][cC][kK][gG][rR][oO][uU][pP][sS]\x3a[^\n]{21}/
}

signature s2b-2428-3 {
  ip-proto == tcp
  dst-port == 119
  # Not supported: pcre: /^ihave\x3a[^\n]{21}/smi
  event "NNTP ihave overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[iI][hH][aA][vV][eE]\x3a[^\n]{21}/
}

signature s2b-2429-3 {
  ip-proto == tcp
  dst-port == 119
  # Not supported: pcre: /^sendme\x3a[^\n]{21}/smi
  event "NNTP sendme overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[sS][eE][nN][dD][mM][eE]\x3a[^\n]{21}/
}

signature s2b-2430-3 {
  ip-proto == tcp
  dst-port == 119
  # Not supported: pcre: /^newgroup\x3a[^\n]{21}/smi
  event "NNTP newgroup overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[nN][eE][wW][gG][rR][oO][uU][pP]\x3a[^\n]{21}/
}

signature s2b-2431-3 {
  ip-proto == tcp
  dst-port == 119
  # Not supported: pcre: /^rmgroup\x3a[^\n]{21}/smi
  event "NNTP rmgroup overflow attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[rR][mM][gG][rR][oO][uU][pP]\x3a[^\n]{21}/
}

signature s2b-1673-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE EXECUTE_SYSTEM attempt"
  tcp-state established,originator
  payload /.*[eE][xX][eE][cC][uU][tT][eE]_[sS][yY][sS][tT][eE][mM]/
}

signature s2b-1674-5 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE connect_data remote version detection attempt"
  tcp-state established,originator
  payload /.*[cC][oO][nN][nN][eE][cC][tT]_[dD][aA][tT][aA]\x28[cC][oO][mM][mM][aA][nN][dD]=[vV][eE][rR][sS][iI][oO][nN]\x29/
}

signature s2b-1675-4 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE misparsed login response"
  tcp-state established,responder
  payload /.*[dD][eE][sS][cC][rR][iI][pP][tT][iI][oO][nN]=\x28/
  payload /.*<willnevermatch>/
  payload /.*<willnevermatch>/
}

signature s2b-1676-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE select union attempt"
  tcp-state established,originator
  payload /.*[sS][eE][lL][eE][cC][tT] /
  payload /.* [uU][nN][iI][oO][nN] /
}

signature s2b-1677-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE select like '%' attempt"
  tcp-state established,originator
  payload /.* [wW][hH][eE][rR][eE] /
  payload /.* [lL][iI][kK][eE] '%'/
}

signature s2b-1678-5 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE select like '%' attempt backslash escaped"
  tcp-state established,originator
  payload /.* [wW][hH][eE][rR][eE] /
  payload /.* [lL][iI][kK][eE] \x22%\x22/
}

signature s2b-1680-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE all_constraints access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[cC][oO][nN][sS][tT][rR][aA][iI][nN][tT][sS]/
}

signature s2b-1681-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE all_views access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[vV][iI][eE][wW][sS]/
}

signature s2b-1682-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE all_source access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[sS][oO][uU][rR][cC][eE]/
}

signature s2b-1683-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE all_tables access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[tT][aA][bB][lL][eE][sS]/
}

signature s2b-1684-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE all_tab_columns access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[tT][aA][bB]_[cC][oO][lL][uU][mM][nN][sS]/
}

signature s2b-1685-4 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE all_tab_privs access"
  tcp-state established,originator
  payload /.*[aA][lL][lL]_[tT][aA][bB]_[pP][rR][iI][vV][sS]/
}

signature s2b-1686-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE dba_tablespace access"
  tcp-state established,originator
  payload /.*[dD][bB][aA]_[tT][aA][bB][lL][eE][sS][pP][aA][cC][eE]/
}

signature s2b-1687-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE dba_tables access"
  tcp-state established,originator
  payload /.*[dD][bB][aA]_[tT][aA][bB][lL][eE][sS]/
}

signature s2b-1688-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE user_tablespace access"
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR]_[tT][aA][bB][lL][eE][sS][pP][aA][cC][eE]/
}

signature s2b-1689-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE sys.all_users access"
  tcp-state established,originator
  payload /.*[sS][yY][sS]\.[aA][lL][lL]_[uU][sS][eE][rR][sS]/
}

signature s2b-1690-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE grant attempt"
  tcp-state established,originator
  payload /.*[gG][rR][aA][nN][tT] /
  payload /.* [tT][oO] /
}

signature s2b-1691-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE ALTER USER attempt"
  tcp-state established,originator
  payload /.*[aA][lL][tT][eE][rR] [uU][sS][eE][rR]/
  payload /.* [iI][dD][eE][nN][tT][iI][fF][iI][eE][dD] [bB][yY] /
}

signature s2b-1692-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE drop table attempt"
  tcp-state established,originator
  payload /.*[dD][rR][oO][pP] [tT][aA][bB][lL][eE]/
}

signature s2b-1693-4 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE create table attempt"
  tcp-state established,originator
  payload /.*[cC][rR][eE][aA][tT][eE] [tT][aA][bB][lL][eE]/
}

signature s2b-1694-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE alter table attempt"
  tcp-state established,originator
  payload /.*[aA][lL][tT][eE][rR] [tT][aA][bB][lL][eE]/
}

signature s2b-1695-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE truncate table attempt"
  tcp-state established,originator
  payload /.*[tT][rR][uU][nN][cC][aA][tT][eE] [tT][aA][bB][lL][eE]/
}

signature s2b-1696-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE create database attempt"
  tcp-state established,originator
  payload /.*[cC][rR][eE][aA][tT][eE] [dD][aA][tT][aA][bB][aA][sS][eE]/
}

signature s2b-1697-3 {
  ip-proto == tcp
  dst-port == oracle_ports
  event "ORACLE alter database attempt"
  tcp-state established,originator
  payload /.*[aA][lL][tT][eE][rR] [dD][aA][tT][aA][bB][aA][sS][eE]/
}

signature s2b-2576-2 {
  ip-proto == tcp
  dst-port == oracle_ports
  # Not supported: pcre: /(package|procedure)_prefix[\s\r\n]*=>[\s\r\n]*('[^']{1000,}|"[^"]{1000,})/Rsmi
  event "ORACLE generate_replication_support prefix overflow attempt"
  tcp-state established,originator
  payload /.*[gG][eE][nN][eE][rR][aA][tT][eE]_[rR][eE][pP][lL][iI][cC][aA][tT][iI][oO][nN]_[sS][uU][pP][pP][oO][rR][tT]/
  payload /([pP][aA][cC][kK][aA][gG][eE]|[pP][rR][oO][cC][eE][dD][uU][rR][eE])_[pP][rR][eE][fF][iI][xX][\x20\x09\x0b\r\n]*=>[\x20\x09\x0b\r\n]*('[^']{1000,}|"[^"]{1000,})/
}

signature s2b-1760-3 {
  ip-proto == tcp
  src-port == 902
  event "OTHER-IDS ISS RealSecure 6 event collector connection attempt"
  tcp-state established,responder
  payload /.{29}6[iI][sS][sS] [eE][cC][nN][rR][aA] [bB][uU][iI][lL][tT]-[iI][nN] [pP][rR][oO][vV][iI][dD][eE][rR], [sS][tT][rR][oO][nN][gG] [eE][nN][cC][rR][yY][pP][tT][iI][oO][nN]/
}

signature s2b-1761-3 {
  ip-proto == tcp
  src-port == 2998
  event "OTHER-IDS ISS RealSecure 6 daemon connection attempt"
  tcp-state established,responder
  payload /.{29}6[iI][sS][sS] [eE][cC][nN][rR][aA] [bB][uU][iI][lL][tT]-[iI][nN] [pP][rR][oO][vV][iI][dD][eE][rR], [sS][tT][rR][oO][nN][gG] [eE][nN][cC][rR][yY][pP][tT][iI][oO][nN]/
}

signature s2b-1629-6 {
  ip-proto == tcp
  event "OTHER-IDS SecureNetPro traffic"
  tcp-state established
  payload /\x00g\x00\x01\x00\x03/
}

signature s2b-1934-6 {
  ip-proto == tcp
  dst-port == 109
  # Not supported: pcre: /^FOLD\s[^\n]{256}/smi
  event "POP2 FOLD overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 256,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[fF][oO][lL][dD][\x20\x09\x0b][^\n]{256}/
}

signature s2b-1935-4 {
  ip-proto == tcp
  dst-port == 109
  # Not supported: pcre: /^FOLD\s+\//smi
  event "POP2 FOLD arbitrary file attempt"
  tcp-state established,originator
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[fF][oO][lL][dD][\x20\x09\x0b]+\//
}

signature s2b-284-6 {
  ip-proto == tcp
  dst-port == 109
  event "POP2 x86 Linux overflow"
  tcp-state established,originator
  payload /.*\xEB,\[\x89\xD9\x80\xC1\x069\xD9\x7C\x07\x80\x01/
  requires-reverse-signature ! pop_return_error
}

signature s2b-285-6 {
  ip-proto == tcp
  dst-port == 109
  event "POP2 x86 Linux overflow"
  tcp-state established,originator
  payload /.*\xFF\xFF\xFF\/BIN\/SH\x00/
  requires-reverse-signature ! pop_return_error
}

signature s2b-2121-8 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^DELE\s+-\d/smi
  event "POP3 DELE negative arguement attempt"
  tcp-state established,originator
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[dD][eE][lL][eE]+-[0-9]/
}

signature s2b-2122-7 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^UIDL\s+-\d/smi
  event "POP3 UIDL negative arguement attempt"
  tcp-state established,originator
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[uU][iI][dD][lL][\x20\x09\x0b]+-[0-9]/
}

signature s2b-1866-10 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^USER\s[^\n]{50,}/smi
  event "POP3 USER overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 50,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[uU][sS][eE][rR][\x20\x09\x0b][^\n]{50,}/
}

signature s2b-2108-3 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^CAPA\s[^\n]{10}/smi
  event "POP3 CAPA overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 10,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[cC][aA][pP][aA][\x20\x09\x0b][^\n]{10}/
}

signature s2b-2109-3 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^TOP\s[^\n]{10}/smi
  event "POP3 TOP overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 10,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[tT][oO][pP][\x20\x09\x0b][^\n]{10}/
}

signature s2b-2110-3 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^STAT\s[^\n]{10}/smi
  event "POP3 STAT overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 10,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[sS][tT][aA][tT][\x20\x09\x0b][^\n]{10}/
}

signature s2b-2111-3 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^DELE\s[^\n]{10}/smi
  event "POP3 DELE overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 10,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[dD][eE][lL][eE][\x20\x09\x0b][^\n]{10}/
}

signature s2b-2112-3 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^RSET\s[^\n]{10}/smi
  event "POP3 RSET overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 10,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[rR][sS][eE][tT][\x20\x09\x0b][^\n]{10}/
}

signature s2b-1936-4 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^AUTH\s[^\n]{50}/smi
  event "POP3 AUTH overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 50,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[aA][uU][tT][hH][\x20\x09\x0b][^\n]{50}/
}

signature s2b-1937-5 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^LIST\s[^\n]{10}/smi
  event "POP3 LIST overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 10,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[lL][iI][sS][tT][\x20\x09\x0b][^\n]{10}/
}

signature s2b-1938-4 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^XTND\s[^\n]{50}/smi
  event "POP3 XTND overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 50,relative
  payload /.*[xX][tT][nN][dD]/
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[xX][tT][nN][dD][\x20\x09\x0b][^\n]{50}/
}

signature s2b-1634-11 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^PASS\s[^\n]{50}/smi
  event "POP3 PASS overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 50,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[pP][aA][sS][sS][\x20\x09\x0b][^\n]{50}/
}

signature s2b-1635-13 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^APOP\s[^\n]{256}/smi
  event "POP3 APOP overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 256,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[aA][pP][oO][pP][\x20\x09\x0b][^\n]{256}/
}

signature s2b-286-9 {
  ip-proto == tcp
  dst-port == 110
  event "POP3 EXPLOIT x86 BSD overflow"
  tcp-state established,originator
  payload /.*\^\x0E1\xC0\xB0\x3B\x8D~\x0E\x89\xFA\x89\xF9/
  requires-reverse-signature ! pop_return_error
}

signature s2b-287-6 {
  ip-proto == tcp
  dst-port == 110
  event "POP3 EXPLOIT x86 BSD overflow"
  tcp-state established,originator
  payload /.*h\]\^\xFF\xD5\xFF\xD4\xFF\xF5\x8B\xF5\x90f1/
  requires-reverse-signature ! pop_return_error
}

signature s2b-288-6 {
  ip-proto == tcp
  dst-port == 110
  event "POP3 EXPLOIT x86 Linux overflow"
  tcp-state established,originator
  payload /.*\xD8@\xCD\x80\xE8\xD9\xFF\xFF\xFF\/bin\/sh/
  requires-reverse-signature ! pop_return_error
}

signature s2b-289-6 {
  ip-proto == tcp
  dst-port == 110
  event "POP3 EXPLOIT x86 SCO overflow"
  tcp-state established,originator
  payload /.*V\x0E1\xC0\xB0\x3B\x8D~\x12\x89\xF9\x89\xF9/
  requires-reverse-signature ! pop_return_error
}

signature s2b-290-7 {
  ip-proto == tcp
  dst-port == 110
  event "POP3 EXPLOIT qpopper overflow"
  tcp-state established,originator
  payload /.*\xE8\xD9\xFF\xFF\xFF\/bin\/sh/
  requires-reverse-signature ! pop_return_error
}

signature s2b-2250-1 {
  ip-proto == tcp
  dst-port == 110
  event "POP3 USER format string attempt"
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR].{1}.*%.{1}.*%/
  requires-reverse-signature ! pop_return_error
}

signature s2b-2409-1 {
  ip-proto == tcp
  dst-port == 110
  # Not supported: pcre: /^APOP\s+USER\s[^\n]{256}/smi
  event "POP3 APOP USER overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 256,relative
  requires-reverse-signature ! pop_return_error
  payload /((^)|(\n+))[aA][pP][oO][pP][\x20\x09\x0b]+[uU][sS][eE][rR][\x20\x09\x0b][^\n]{2,56}/
}

signature s2b-2502-7 {
  ip-proto == tcp
  dst-port == 995
  event "POP3 SSLv3 invalid data version attempt"
  tcp-state established,originator
  payload /\x16\x03/
  payload /.{4}\x01/
  payload /.{8}[^\x03]*/
  requires-reverse-signature ! pop_return_error
}

signature s2b-2518-10 {
  ip-proto == tcp
  dst-port == 995
  # Not supported: byte_test: 2,>,0,6,2,!,0,8,2,!,16,8,2,>,20,10,2,>,32768,0,relative
  event "PO3 PCT Client_Hello overflow attempt"
  tcp-state established,originator
  payload /.{1}\x01/
  payload /.{10}\x8F/
  requires-reverse-signature ! pop_return_error
}

signature s2b-2536-3 {
  ip-proto == tcp
  src-port == 995
  # Not supported: flowbits: isset,sslv3.client_hello.request,set,sslv3.server_hello.request,noalert
  event "POP3 SSLv3 Server_Hello request"
  tcp-state established,responder
  payload /\x16\x03/
  payload /.{4}\x02/
  requires-reverse-signature ! pop_return_error
}

signature s2b-2537-3 {
  ip-proto == tcp
  dst-port == 993
  # Not supported: flowbits: isset,sslv3.server_hello.request
  event "POP3 SSLv3 invalid Client_Hello attempt"
  tcp-state established,originator
  payload /\x16\x03/
  payload /.{4}\x01/
  requires-reverse-signature ! pop_return_error
}

signature s2b-2093-5 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_test: 4,>,2048,12,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap proxy integer overflow attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0\x00.{3}\x00\x00\x00\x05/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1922-6 {
  ip-proto == tcp
  dst-port == 111
  event "RPC portmap proxy attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x05/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1923-6 {
  ip-proto == udp
  dst-port == 111
  event "RPC portmap proxy attempt UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x05/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1280-9 {
  ip-proto == udp
  dst-port == 111
  event "RPC portmap listing UDP 111"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x04/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-598-12 {
  ip-proto == tcp
  dst-port == 111
  event "RPC portmap listing TCP 111"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x04/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1949-5 {
  ip-proto == tcp
  dst-port == 111
  event "RPC portmap SET attempt TCP 111"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1950-5 {
  ip-proto == udp
  dst-port == 111
  event "RPC portmap SET attempt UDP 111"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2014-5 {
  ip-proto == tcp
  dst-port == 111
  event "RPC portmap UNSET attempt TCP 111"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x02/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2015-5 {
  ip-proto == udp
  dst-port == 111
  event "RPC portmap UNSET attempt UDP 111"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x02/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-599-11 {
  ip-proto == tcp
  dst-port == 32771
  event "RPC portmap listing TCP 32771"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x04/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1281-7 {
  ip-proto == udp
  dst-port == 32771
  event "RPC portmap listing UDP 32771"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x04/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1746-11 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap cachefsd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x8B/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1747-11 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap cachefsd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x8B/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1732-9 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rwalld request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA8/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1733-9 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rwalld request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA8/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-575-8 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap admind request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xF7/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-576-8 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap amountd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x03/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1263-11 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap amountd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x03/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1264-13 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap bootparam request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xBA/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-580-9 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap nisd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\xCC/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1267-11 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap nisd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\xCC/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-581-9 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap pcnfsd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x02I\xF1/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1268-12 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap pcnfsd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x02I\xF1/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-582-8 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rexd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB1/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1269-10 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rexd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB1/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-584-11 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rusers request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA2/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1271-14 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rusers request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA2/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-612-6 {
  ip-proto == udp
  event "RPC rusers query UDP"
  payload /.{11}\x00\x01\x86\xA2.{4}\x00\x00\x00\x02/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-586-8 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap selection_svc request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xAF/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1273-10 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap selection_svc request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xAF/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-587-8 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap status request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB8/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2016-6 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap status request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB8/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-593-18 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap snmpXdmi request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x99/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1279-14 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap snmpXdmi request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x99/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-569-14 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,1024,20,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC snmpXdmi overflow attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x87\x99.{4}\x00\x00\x01\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2045-8 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC snmpXdmi overflow attempt UDP"
  # Not supported: byte_test: 4,>,1024,20,relative
  payload /.{11}\x00\x01\x87\x99.{4}\x00\x00\x01\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2017-12 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap espd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x05\xF7u/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-595-16 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap espd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x05\xF7u/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1890-8 {
  ip-proto == udp
  dst-port >= 1024
  dst-port <= 65535
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC status GHBN format string attack"
  payload /.{11}\x00\x01\x86\xB8.{4}\x00\x00\x00\x02.{0,251}%x %x/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1891-8 {
  ip-proto == tcp
  dst-port >= 1024
  dst-port <= 65535
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC status GHBN format string attack"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xB8.{4}\x00\x00\x00\x02.{0,251}%x %x/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-579-8 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap mountd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA5/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1266-10 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap mountd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA5/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-574-8 {
  ip-proto == tcp
  event "RPC mountd TCP export request"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x05/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1924-6 {
  ip-proto == udp
  event "RPC mountd UDP export request"
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x05/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1926-6 {
  ip-proto == udp
  event "RPC mountd UDP exportall request"
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x06/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2184-7 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,1023,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC mountd TCP mount path overflow attempt"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA5\x00.{3}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2185-7 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC mountd UDP mount path overflow attempt"
  # Not supported: byte_test: 4,>,1023,0,relative
  payload /.{11}\x00\x01\x86\xA5\x00.{3}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1951-5 {
  ip-proto == tcp
  event "RPC mountd TCP mount request"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1952-5 {
  ip-proto == udp
  event "RPC mountd UDP mount request"
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2018-4 {
  ip-proto == tcp
  event "RPC mountd TCP dump request"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x02/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2019-4 {
  ip-proto == udp
  event "RPC mountd UDP dump request"
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x02/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2020-4 {
  ip-proto == tcp
  event "RPC mountd TCP unmount request"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x03/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2021-4 {
  ip-proto == udp
  event "RPC mountd UDP unmount request"
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x03/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2022-4 {
  ip-proto == tcp
  event "RPC mountd TCP unmountall request"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA5.{4}\x00\x00\x00\x04/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2023-4 {
  ip-proto == udp
  event "RPC mountd UDP unmountall request"
  payload /.{11}\x00\x01\x86\xA5.{4}\x00\x00\x00\x04/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1905-8 {
  ip-proto == udp
  dst-port >= 500
  dst-port <= 65535
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC AMD UDP amqproc_mount plog overflow attempt"
  # Not supported: byte_test: 4,>,512,0,relative
  payload /.{11}\x00\x04\x93\xF3.{4}\x00\x00\x00\x07/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1906-8 {
  ip-proto == tcp
  dst-port >= 500
  dst-port <= 65535
  # Not supported: byte_test: 4,>,512,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC AMD TCP amqproc_mount plog overflow attempt"
  tcp-state established,originator
  payload /.{15}\x00\x04\x93\xF3.{4}\x00\x00\x00\x07/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1953-5 {
  ip-proto == tcp
  dst-port >= 500
  dst-port <= 65535
  event "RPC AMD TCP pid request"
  tcp-state established,originator
  payload /.{15}\x00\x04\x93\xF3.{4}\x00\x00\x00\x09/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1954-5 {
  ip-proto == udp
  dst-port >= 500
  dst-port <= 65535
  event "RPC AMD UDP pid request"
  payload /.{11}\x00\x04\x93\xF3.{4}\x00\x00\x00\x09/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1955-6 {
  ip-proto == tcp
  dst-port >= 500
  dst-port <= 65535
  event "RPC AMD TCP version request"
  tcp-state established,originator
  payload /.{15}\x00\x04\x93\xF3.{4}\x00\x00\x00\x08/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-578-8 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap cmsd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xE4/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1265-9 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap cmsd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xE4/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1907-10 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC CMSD UDP CMSD_CREATE buffer overflow attempt"
  # Not supported: byte_test: 4,>,1024,0,relative
  payload /.{11}\x00\x01\x86\xE4.{4}\x00\x00\x00\x15/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1908-9 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,1024,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC CMSD TCP CMSD_CREATE buffer overflow attempt"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xE4.{4}\x00\x00\x00\x15/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2094-6 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC CMSD UDP CMSD_CREATE array buffer overflow attempt"
  # Not supported: byte_test: 4,>,1024,20,relative
  payload /.{11}\x00\x01\x86\xE4.{4}\x00\x00\x00\x15/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2095-6 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,1024,20,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC CMSD TCP CMSD_CREATE array buffer overflow attempt"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xE4.{4}\x00\x00\x00\x15/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1909-10 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,1000,28,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align
  event "RPC CMSD TCP CMSD_INSERT buffer overflow attempt"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xE4.{4}\x00\x00\x00\x06/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1910-10 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align
  event "RPC CMSD udp CMSD_INSERT buffer overflow attempt"
  # Not supported: byte_test: 4,>,1000,28,relative
  payload /.{11}\x00\x01\x86\xE4.{4}\x00\x00\x00\x06/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1272-10 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap sadmind request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x88/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-585-7 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap sadmind request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\x88/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1911-10 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,124,relative,align,4,20,relative,align
  event "RPC sadmind UDP NETMGT_PROC_SERVICE CLIENT_DOMAIN overflow attempt"
  # Not supported: byte_test: 4,>,512,4,relative
  payload /.{11}\x00\x01\x87\x88.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1912-9 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,512,4,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,124,relative,align,4,20,relative,align
  event "RPC sadmind TCP NETMGT_PROC_SERVICE CLIENT_DOMAIN overflow attempt"
  tcp-state established,originator
  payload /.{15}\x00\x01\x87\x88.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1957-5 {
  ip-proto == udp
  event "RPC sadmind UDP PING"
  payload /.{11}\x00\x01\x87\x88.{4}\x00\x00\x00\x00/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1958-5 {
  ip-proto == tcp
  event "RPC sadmind TCP PING"
  tcp-state established,originator
  payload /.{15}\x00\x01\x87\x88.{4}\x00\x00\x00\x00/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-583-9 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rstatd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA1/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1270-11 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rstatd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA1/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1913-10 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC STATD UDP stat mon_name format string exploit attempt"
  # Not supported: byte_test: 4,>,100,0,relative
  payload /.{11}\x00\x01\x86\xB8.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1914-10 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,100,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC STATD TCP stat mon_name format string exploit attempt"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xB8.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1915-9 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC STATD UDP monitor mon_name format string exploit attempt"
  # Not supported: byte_test: 4,>,100,0,relative
  payload /.{11}\x00\x01\x86\xB8.{4}\x00\x00\x00\x02/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1916-9 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,100,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC STATD TCP monitor mon_name format string exploit attempt"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xB8.{4}\x00\x00\x00\x02/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1277-9 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ypupdated request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xBC/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-591-10 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ypupdated request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xBC/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2088-5 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC ypupdated arbitrary command attempt UDP"
  payload /.{11}\x00\x01\x86\xBC.{4}\x00\x00\x00\x01.{4}.*\x7C/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2089-5 {
  ip-proto == tcp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC ypupdated arbitrary command attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xBC.{4}\x00\x00\x00\x01.{4}.*\x7C/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1959-7 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap NFS request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA3/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1960-7 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap NFS request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA3/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1961-7 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap RQUOTA request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xAB/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1962-7 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap RQUOTA request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xAB/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1963-9 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC RQUOTA getquota overflow attempt UDP"
  # Not supported: byte_test: 4,>,128,0,relative
  payload /.{11}\x00\x01\x86\xAB.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2024-8 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,128,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC RQUOTA getquota overflow attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xAB.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-588-17 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ttdbserv request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xF3/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1274-17 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ttdbserv request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xF3/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-1964-8 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC tooltalk UDP overflow attempt"
  # Not supported: byte_test: 4,>,128,0,relative
  payload /.{11}\x00\x01\x86\xF3.{4}\x00\x00\x00\x07/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1965-8 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,128,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC tooltalk TCP overflow attempt"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xF3.{4}\x00\x00\x00\x07/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-589-8 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap yppasswd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA9/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1275-10 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap yppasswd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA9/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2027-5 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  # Not supported: byte_test: 4,>,64,0,relative
  event "RPC yppasswd old password overflow attempt UDP"
  payload /.{11}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2028-5 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,64,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC yppasswd old password overflow attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2025-9 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align
  event "RPC yppasswd username overflow attempt UDP"
  # Not supported: byte_test: 4,>,64,0,relative
  payload /.{11}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2026-9 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,64,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align
  event "RPC yppasswd username overflow attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2029-5 {
  ip-proto == udp
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align,4,0,relative,align
  # Not supported: byte_test: 4,>,64,0,relative
  event "RPC yppasswd new password overflow attempt UDP"
  payload /.{11}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2030-6 {
  ip-proto == tcp
  # Not supported: byte_test: 4,>,64,0,relative
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align,4,0,relative,align,4,0,relative,align
  event "RPC yppasswd new password overflow attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2031-5 {
  ip-proto == udp
  event "RPC yppasswd user update UDP"
  payload /.{11}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2032-5 {
  ip-proto == tcp
  event "RPC yppasswd user update TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA9.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-590-12 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ypserv request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA4/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-1276-14 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap ypserv request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xA4/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2033-8 {
  ip-proto == udp
  event "RPC ypserv maplist request UDP"
  payload /.{11}\x00\x01\x86\xA4.{4}\x00\x00\x00\x0B/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2034-7 {
  ip-proto == tcp
  event "RPC ypserv maplist request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA4.{4}\x00\x00\x00\x0B/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2035-6 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap network-status-monitor request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x03\x0Dp/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2036-6 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap network-status-monitor request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x03\x0Dp/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2037-5 {
  ip-proto == udp
  event "RPC network-status-monitor mon-callback request UDP"
  payload /.{11}\x00\x03\x0Dp.{4}\x00\x00\x00\x01/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2038-5 {
  ip-proto == tcp
  event "RPC network-status-monitor mon-callback request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x03\x0Dp.{4}\x00\x00\x00\x01/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2079-6 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap nlockmgr request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB5/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2080-6 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap nlockmgr request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x86\xB5/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2081-9 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rpc.xfsmd request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x05\xF7h/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2082-9 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap rpc.xfsmd request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x05\xF7h/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2083-8 {
  ip-proto == udp
  event "RPC rpc.xfsmd xfs_export attempt UDP"
  payload /.{11}\x00\x05\xF7h.{4}\x00\x00\x00\x0D/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2084-8 {
  ip-proto == tcp
  event "RPC rpc.xfsmd xfs_export attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x05\xF7h.{4}\x00\x00\x00\x0D/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2005-10 {
  ip-proto == udp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap kcms_server request UDP"
  payload /.{11}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\}/
  payload /.{3}\x00\x00\x00\x00/
}

signature s2b-2006-10 {
  ip-proto == tcp
  dst-port == 111
  # Not supported: byte_jump: 4,4,relative,align,4,4,relative,align
  event "RPC portmap kcms_server request TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x86\xA0.{4}\x00\x00\x00\x03\x00\x01\x87\}/
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2007-10 {
  ip-proto == tcp
  dst-port >= 32771
  dst-port <= 34000
  # Not supported: byte_jump: 4,20,relative,align,4,4,relative,align
  event "RPC kcms_server directory traversal attempt"
  tcp-state established,originator
  payload /.{15}\x00\x01\x87\}.*.*\/\.\.\//
  payload /.{7}\x00\x00\x00\x00/
}

signature s2b-2255-3 {
  ip-proto == tcp
  # Not supported: byte_jump: 4,8,relative,align
  event "RPC sadmind query with root credentials attempt TCP"
  tcp-state established,originator
  payload /.{15}\x00\x01\x87\x88.{4}\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00/
}

signature s2b-2256-3 {
  ip-proto == udp
  # Not supported: byte_jump: 4,8,relative,align
  event "RPC sadmind query with root credentials attempt UDP"
  payload /.{11}\x00\x01\x87\x88.{4}\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00/
}

signature s2b-601-6 {
  ip-proto == tcp
  dst-port == 513
  event "RSERVICES rlogin LinuxNIS"
  tcp-state established,originator
  payload /.*\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x00\x3A\x3A\x3A\x3A\x3A\x3A\x3A\x3A/
}

signature s2b-602-5 {
  ip-proto == tcp
  dst-port == 513
  event "RSERVICES rlogin bin"
  tcp-state established,originator
  payload /.*bin\x00bin\x00/
}

signature s2b-603-5 {
  ip-proto == tcp
  dst-port == 513
  event "RSERVICES rlogin echo++"
  tcp-state established,originator
  payload /.*echo \x22 \+ \+ \x22/
}

signature s2b-604-5 {
  ip-proto == tcp
  dst-port == 513
  event "RSERVICES rsh froot"
  tcp-state established,originator
  payload /.*-froot\x00/
}

signature s2b-611-7 {
  ip-proto == tcp
  src-port == 513
  event "RSERVICES rlogin login failure"
  tcp-state established,responder
  payload /.*\x01rlogind\x3A Permission denied\./
}

signature s2b-605-6 {
  ip-proto == tcp
  src-port == 513
  event "RSERVICES rlogin login failure"
  tcp-state established,responder
  payload /.*login incorrect/
}

signature s2b-606-5 {
  ip-proto == tcp
  dst-port == 513
  event "RSERVICES rlogin root"
  tcp-state established,originator
  payload /.*root\x00root\x00/
}

signature s2b-607-5 {
  ip-proto == tcp
  dst-port == 514
  event "RSERVICES rsh bin"
  tcp-state established,originator
  payload /.*bin\x00bin\x00/
}

signature s2b-608-5 {
  ip-proto == tcp
  dst-port == 514
  event "RSERVICES rsh echo + +"
  tcp-state established,originator
  payload /.*echo \x22\+ \+\x22/
}

signature s2b-609-5 {
  ip-proto == tcp
  dst-port == 514
  event "RSERVICES rsh froot"
  tcp-state established,originator
  payload /.*-froot\x00/
}

signature s2b-610-5 {
  ip-proto == tcp
  dst-port == 514
  event "RSERVICES rsh root"
  tcp-state established,originator
  payload /.*root\x00root\x00/
}

signature s2b-2113-3 {
  ip-proto == tcp
  dst-port == 512
  dst-ip == local_nets
  event "RSERVICES rexec username overflow attempt"
  tcp-state established,originator
  payload /.{8}.*\x00.*.*\x00.*.*\x00/
}

signature s2b-2114-3 {
  ip-proto == tcp
  dst-port == 512
  event "RSERVICES rexec password overflow attempt"
  tcp-state established,originator
  payload /.*\x00.{33}.*\x00.*.*\x00/
}

signature s2b-616-4 {
  ip-proto == tcp
  dst-port == 113
  event "SCAN ident version request"
  tcp-state established,originator
  payload /.{0,8}VERSION\x0A/
}

signature s2b-619-5 {
  ip-proto == tcp
  dst-port == 80
  payload-size == 0
  header tcp[13:1] & 255 == 195
  event "SCAN cybercop os probe"
  tcp-state stateless
}

signature s2b-622-6 {
  ip-proto == tcp
  header tcp[13:1] & 255 == 2
  header tcp[4:4] == 1958810375
  event "SCAN ipEye SYN scan"
  tcp-state stateless
}

signature s2b-1228-6 {
  ip-proto == tcp
  header tcp[13:1] & 255 == 41
  event "SCAN nmap XMAS"
  tcp-state stateless
}

signature s2b-630-5 {
  ip-proto == tcp
  header tcp[13:1] & 255 == 3
  event "SCAN synscan portscan"
  tcp-state stateless
  header ip[4:2] == 39426
}

signature s2b-626-7 {
  ip-proto == tcp
  header tcp[13:1] & 255 == 216
  event "SCAN cybercop os PA12 attempt"
  tcp-state stateless
  payload /AAAAAAAAAAAAAAAA/
}

signature s2b-627-7 {
  ip-proto == tcp
  header tcp[8:4] == 0
  header tcp[13:1] & 255 == 227
  event "SCAN cybercop os SFU12 probe"
  tcp-state stateless
  payload /AAAAAAAAAAAAAAAA/
}

signature s2b-634-2 {
  ip-proto == udp
  dst-port >= 10080
  dst-port <= 10081
  event "SCAN Amanda client version request"
  payload /.*[aA][mM][aA][nN][dD][aA]/
}

signature s2b-635-3 {
  ip-proto == udp
  dst-port == 49
  event "SCAN XTACACS logout"
  payload /.*\x80\x07\x00\x00\x07\x00\x00\x04\x00\x00\x00\x00\x00/
}

signature s2b-636-1 {
  ip-proto == udp
  dst-port == 7
  event "SCAN cybercop udp bomb"
  payload /.*cybercop/
}

signature s2b-637-3 {
  ip-proto == udp
  event "SCAN Webtrends Scanner UDP Probe"
  payload /.*\x0Ahelp\x0Aquite\x0A/
}

signature s2b-1638-5 {
  ip-proto == tcp
  dst-port == 22
  event "SCAN SSH Version map attempt"
  tcp-state established,originator
  payload /.*[vV][eE][rR][sS][iI][oO][nN]_[mM][aA][pP][pP][eE][rR]/
}

signature s2b-1133-11 {
  ip-proto == tcp
  dst-port == http_ports
  header tcp[8:4] == 0
  header tcp[13:1] & 255 == 11
  event "SCAN cybercop os probe"
  tcp-state stateless
  payload /AAAAAAAAAAAAAAAA/
}

signature s2b-647-6 {
  src-port != non_shellcode_ports
  event "SHELLCODE sparc setuid 0"
  payload /.*\x82\x10 \x17\x91\xD0 \x08/
}

signature s2b-649-8 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 setgid 0"
  payload /.*\xB0\xB5\xCD\x80/
}

signature s2b-638-5 {
  src-port != non_shellcode_ports
  event "SHELLCODE SGI NOOP"
  payload /.*\x03\xE0\xF8%\x03\xE0\xF8%\x03\xE0\xF8%\x03\xE0\xF8%/
}

signature s2b-639-5 {
  src-port != non_shellcode_ports
  event "SHELLCODE SGI NOOP"
  payload /.*\x24\x0F\x124\x24\x0F\x124\x24\x0F\x124\x24\x0F\x124/
}

signature s2b-640-6 {
  src-port != non_shellcode_ports
  event "SHELLCODE AIX NOOP"
  payload /.*O\xFF\xFB\x82O\xFF\xFB\x82O\xFF\xFB\x82O\xFF\xFB\x82/
}

signature s2b-641-6 {
  src-port != non_shellcode_ports
  event "SHELLCODE Digital UNIX NOOP"
  payload /.*G\xFF\x04\x1FG\xFF\x04\x1FG\xFF\x04\x1FG\xFF\x04\x1F/
}

signature s2b-642-6 {
  src-port != non_shellcode_ports
  event "SHELLCODE HP-UX NOOP"
  payload /.*\x08!\x02\x80\x08!\x02\x80\x08!\x02\x80\x08!\x02\x80/
}

signature s2b-644-5 {
  src-port != non_shellcode_ports
  event "SHELLCODE sparc NOOP"
  payload /.*\x13\xC0\x1C\xA6\x13\xC0\x1C\xA6\x13\xC0\x1C\xA6\x13\xC0\x1C\xA6/
}

signature s2b-645-5 {
  src-port != non_shellcode_ports
  event "SHELLCODE sparc NOOP"
  payload /.*\x80\x1C@\x11\x80\x1C@\x11\x80\x1C@\x11\x80\x1C@\x11/
}

signature s2b-646-5 {
  src-port != non_shellcode_ports
  event "SHELLCODE sparc NOOP"
  payload /.*\xA6\x1C\xC0\x13\xA6\x1C\xC0\x13\xA6\x1C\xC0\x13\xA6\x1C\xC0\x13/
}

signature s2b-648-7 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 NOOP"
  payload /.{0,114}\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90/
}

signature s2b-651-8 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 stealth NOOP"
  payload /.*\xEB\x02\xEB\x02\xEB\x02/
}

signature s2b-653-8 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 unicode NOOP"
  payload /.*\x90\x00\x90\x00\x90\x00\x90\x00\x90\x00/
}

signature s2b-652-9 {
  src-port != non_shellcode_ports
  event "SHELLCODE Linux shellcode"
  payload /.*\x90\x90\x90\xE8\xC0\xFF\xFF\xFF\/bin\/sh/
}

signature s2b-1390-5 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 inc ebx NOOP"
  payload /.*CCCCCCCCCCCCCCCCCCCCCCCC/
}

signature s2b-1394-5 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 NOOP"
  payload /.*aaaaaaaaaaaaaaaaaaaaa/
}

signature s2b-1424-6 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 0xEB0C NOOP"
  payload /.*\xEB\x0C\xEB\x0C\xEB\x0C\xEB\x0C\xEB\x0C\xEB\x0C\xEB\x0C\xEB\x0C/
}

signature s2b-2312-2 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 0x71FB7BAB NOOP"
  payload /.*q\xFB\{\xABq\xFB\{\xABq\xFB\{\xABq\xFB\{\xAB/
}

signature s2b-2313-2 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 0x71FB7BAB NOOP unicode"
  payload /.*q\x00\xFB\x00\{\x00\xAB\x00q\x00\xFB\x00\{\x00\xAB\x00q\x00\xFB\x00\{\x00\xAB\x00q\x00\xFB\x00\{\x00\xAB\x00/
}

signature s2b-2314-1 {
  src-port != non_shellcode_ports
  event "SHELLCODE x86 0x90 NOOP unicode"
  payload /.*\x90\x00\x90\x00\x90\x00\x90\x00\x90\x00\x90\x00\x90\x00\x90\x00/
}

signature s2b-654-13 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^RCPT TO\s[^\n]{300}/ism
  event "SMTP RCPT TO overflow"
  tcp-state established,originator
  # Not supported: isdataat: 300,relative
  payload /.*[rR][cC][pP][tT] [tT][oO]\x3A/
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[rR][cC][pP][tT] [tT][oO][\x20\x09\x0b][^\n]{300}/
}

signature s2b-657-12 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^HELP\s[^\n]{500}/ism
  event "SMTP chameleon overflow"
  tcp-state established,originator
  # Not supported: isdataat: 500,relative
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[hH][eE][lL][pP][\x20\x09\x0b][^\n]{500}/
}

signature s2b-655-8 {
  ip-proto == tcp
  src-port == 113
  dst-port == 25
  event "SMTP sendmail 8.6.9 exploit"
  tcp-state established,originator
  payload /.*\x0AD\//
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-658-5 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP exchange mime DOS"
  tcp-state established,originator
  payload /.*charset = \x22\x22/
}

signature s2b-659-6 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^expn\s+decode/smi
  event "SMTP expn decode"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[eE][xX][pP][nN][\x20\x09\x0b][dD][eE][cC][oO][dD][eE]/
}

signature s2b-660-7 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^expn\s+root/smi
  event "SMTP expn root"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[eE][xX][pP][nN][\x20\x09\x0b][rR][oO][oO][tT]/
}

signature s2b-1450-5 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^expn\s+\*@/smi
  event "SMTP expn *@"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[eE][xX][pP][nN][\x20\x09\x0b]\*@/
}

signature s2b-661-6 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP majordomo ifs"
  tcp-state established,originator
  payload /.*eply-to\x3A a~\.`\/bin\//
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-662-5 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP sendmail 5.5.5 exploit"
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL] [fF][rR][oO][mM]\x3A \x22\x7C/
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-663-13 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^rcpt\s+to\:\s+[|\x3b]/smi
  event "SMTP rcpt to command attempt"
  tcp-state established,originator
  payload /((^)|(\n+))[rR][cC][pP][tT][\x20\x09\x0b][tT][oO]:[\x20\x09\x0b]+[|\x3b]/
}

signature s2b-664-13 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^rcpt to\:\s+decode/smi
  event "SMTP RCPT TO decode attempt"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[rR][cC][pP][tT][\x20\x09\x0b][tT][oO]:[\x20\x09\x0b]+[dD][eE][cC][oO][dD][eE]/
}

signature s2b-665-5 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP sendmail 5.6.5 exploit"
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL] [fF][rR][oO][mM]\x3A \x7C\/[uU][sS][rR]\/[uU][cC][bB]\/[tT][aA][iI][lL]/
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-667-5 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP sendmail 8.6.10 exploit"
  tcp-state established,originator
  payload /.*Croot\x0D\x0AMprog, P=\/bin\//
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-668-6 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP sendmail 8.6.10 exploit"
  tcp-state established,originator
  payload /.*Croot\x09\x09\x09\x09\x09\x09\x09Mprog,P=\/bin/
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-670-7 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP sendmail 8.6.9 exploit"
  tcp-state established,originator
  payload /.*\x0AC\x3Adaemon\x0AR/
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-671-8 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP sendmail 8.6.9c exploit"
  tcp-state established,originator
  payload /.*\x0ACroot\x0D\x0AMprog/
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-672-6 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^vrfy\s+decode/smi
  event "SMTP vrfy decode"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[vV][rR][fF][yY][\x20\x09\x0b]+[dD][eE][cC][oO][dD][eE]/
}

signature s2b-1446-6 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^vrfy\s+root/smi
  event "SMTP vrfy root"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[vV][rR][fF][yY][\x20\x09\x0b]+[rR][oO][oO][tT]/
}

signature s2b-631-6 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP ehlo cybercop attempt"
  tcp-state established,originator
  payload /.*ehlo cybercop\x0Aquit\x0A/
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-632-5 {
  ip-proto == tcp
  dst-port == 25
  event "SMTP expn cybercop attempt"
  tcp-state established,originator
  payload /.*expn cybercop/
}

signature s2b-1549-16 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^HELO\s[^\n]{500}/smi
  event "SMTP HELO overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 500,relative
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[hH][eE][lL][oO][\x20\x09\x0b][^\n]{500}/
}

signature s2b-1550-10 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^ETRN\s[^\n]{500}/smi
  event "SMTP ETRN overflow attempt"
  tcp-state established,originator
  # Not supported: isdataat: 500,relative
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[eE][tT][rR][nN]][\x20\x09\x0b][^\n]{500}/
}

signature s2b-2087-5 {
  ip-proto == tcp
  dst-port == 25
  event "Sendmail SMTP From comment overflow attempt"
  tcp-state established,originator
  payload /.*From\x3A<><><><><><><><><><><><><><><><><><><><><><>.{1}\x28.{1}\x29/
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-2253-3 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^XEXCH50\s+-\d/smi
  event "SMTP XEXCH50 overflow attempt"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[xX][eE][xX][cC][hH]50[\x20\x09\x0b]+-[0-9]/
}

signature s2b-2259-5 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^EXPN[^\n]{255,}/smi
  event "SMTP EXPN overflow attempt"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[eE][xX][pP][nN][^\n]{255,}/
}

signature s2b-2260-5 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^VRFY[^\n]{255,}/smi
  event "SMTP VRFY overflow attempt"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[vV][rR][fF][yY][^\n]{255,}/
}

signature s2b-2261-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^SEND FROM\x3a\s*[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</smi
  event "SMTP SEND FROM sendmail prescan too many addresses overflow"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[sS][eE][nN][dD] [fF][rR][oO][mM]\x3a[\x20\x09\x0b]*[^\n]*?<[^\n]*? <[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*? <[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*? <[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*? <[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*? <[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</
}

signature s2b-2262-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^SEND FROM\x3a\s+[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}/smi
  event "SMTP SEND FROM sendmail prescan too long addresses overflow"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[sS][eE][nN][dD] [fF][rR][oO][mM]:[\x20\x09\x0b]+[a-zA-Z0-9\x5f\x20\x09\x0b@\.]{0,200}\x3b[a-zA-Z0-9_\x20\x09\x0b@\.]{200,}\x3b[a-zA-Z0-9_\x20\x09\x0b@\.]{0,200}/
}

signature s2b-2263-6 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^SAML FROM\x3a\s*[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</smi
  event "SMTP SAML FROM sendmail prescan too many addresses overflow"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[sS][aA][mM][lL] [fF][rR][oO][mM]\x3a[\x20\x09\x0b]*[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</
}

signature s2b-2264-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^SAML FROM\x3a\s+[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}/smi
  event "SMTP SAML FROM sendmail prescan too long addresses overflow"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[sS][aA][mM][lL] [fF][rR][oO][mM]:[\x20\x09\x0b]+[a-zA-Z0-9_\x20\x09\x0b@\.]{0,200}\x3b[a-zA-Z0-9_\x20\x09\x0b@\.]{200,}\x3b[a-zA-Z0-9_\x20\x09\x0b@\.]{0,200}/
}

signature s2b-2265-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^SOML FROM\x3a\s*[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</smi
  event "SMTP SOML FROM sendmail prescan too many addresses overflow"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[sS][oO][mM][lL] [fF][rR][oO][mM]\x3a[\x20\x09\x0b]*[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</
}

signature s2b-2266-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^SOML FROM\x3a\s+[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}/smi
  event "SMTP SOML FROM sendmail prescan too long addresses overflow"
  tcp-state established,originator
  payload /((^)|(\n+))[sS][oO][mM][lL] [fF][rR][oO][mM]:[\x20\x09\x0b]+[a-zA-Z0-9_\x20\x09\x0b@\.]{0,200}\x3b[a-zA-Z0-9_\x20\x09\x0b@\.]{200,}\x3b[a-zA-Z0-9_\x20\x09\x0b@\.]{0,200}/
}

signature s2b-2267-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^MAIL FROM\x3a\s*[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</smi
  event "SMTP MAIL FROM sendmail prescan too many addresses overflow"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[mM][aA][iI][lL] [fF][rR][oO][mM]\x3a\x20*[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</
}

signature s2b-2268-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^MAIL FROM\x3a\s+[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}/smi
  event "SMTP MAIL FROM sendmail prescan too long addresses overflow"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[mM][aA][iI][lL] [fF][rR][oO][mM]:[\x20\x09\x0b]+[a-zA-Z0-9_\x20\x09\x0b@\.]{0,200}\x3b[a-zA-Z0-9_\x20\x09\x0b@\.]{200,}\x3b[a-zA-Z0-9_\x20\x09\x0b@\.]{0,200}/
}

signature s2b-2269-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^RCPT TO\x3a\s*[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</smi
  event "SMTP RCPT TO sendmail prescan too many addresses overflow"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[rR][cC][pP][tT] [tT][oO]\x3a\x20*[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?<[^\n]*?</
}

signature s2b-2270-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /^RCPT TO\x3a\s+[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}\x3b[\w\s@\.]{200,}/smi
  event "SMTP RCPT TO sendmail prescan too long addresses overflow"
  tcp-state established,originator
  requires-reverse-signature ! smtp_server_fail
  payload /((^)|(\n+))[rR][cC][pP][tT] [tT][oO]\x3a[\x20\x09\x0b]+[a-zA-Z0-9\x5f\x20\x09\x0b\x40\.]{0,200}\x3b[a-zA-Z0-9\x5f\x20\x09\x0b=x40\.]{200,}\x3b[a-zA-Z0-9\x5f\x20\x09\x0b\x40\.]{0,200}/
}

signature s2b-2275-2 {
  ip-proto == tcp
  src-port == 25
  # Not supported: threshold: type threshold, track by_dst, count 5, seconds 60
  event "SMTP AUTH LOGON brute force attempt"
  tcp-state established,responder
  payload /.{53}.*[aA][uU][tT][hH][eE][nN][tT][iI][cC][aA][tT][iI][oO][nN] [uU][nN][sS][uU][cC][cC][eE][sS][sS][fF][uU][lL]/
}

signature s2b-2487-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /name=[^\r\n]*?\.(mim|uue|uu|b64|bhx|hqx|xxe)/smi,/(name|id|number|total|boundary)=\s*[^\r\n\x3b\s\x2c]{300}/smi
  event "SMTP WinZip MIME content-type buffer overflow"
  tcp-state established,originator
  payload /.*[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]\x3A/
  requires-reverse-signature ! smtp_server_fail
  payload /[nN][aA][mM][eE]=[^\r\n]*?\.([mM][iI][mM]|[uU]{2}[eE]?|[bB]64|[bB][hH][xX]|[hH][qQ][xX]|[xX]{2}[eE])/
  payload /([nN][aA][mM][eE]|[iI][dD]|[nN][uU][mM][bB][eE][rR]|[tT][oO][tT][aA][lL]|[bB][oO][uU][nN][dD][aA][rR][yY])=[\x20\x09\x0b]*[^\r\n\x3b\s\x2c]{300}/
}

signature s2b-2488-4 {
  ip-proto == tcp
  dst-port == 25
  # Not supported: pcre: /name=[^\r\n]*?\.(mim|uue|uu|b64|bhx|hqx|xxe)/smi,/name=\s*[^\r\n\x3b\s\x2c]{300}/smi
  event "SMTP WinZip MIME content-disposition buffer overflow"
  tcp-state established,originator
  payload /.*[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]\x3A/
  payload /.*[cC][oO][nN][tT][eE][nN][tT]-[dD][iI][sS][pP][oO][sS][iI][tT][iI][oO][nN]\x3A/
  requires-reverse-signature ! smtp_server_fail
  payload /[nN][aA][mM][eE]=[^\r\n]*?\.(([mM][iI]]mM])|([uU]{2}[eE])|([uU]{2})|([bB]64)|([bB][hH][xX])|([hH][qQ][xX])|([xX]{2}[eE]))/
  payload /[nN][aA][mM][eE]=s*[^\r\n\x3b\x20\x09\x0b\x2c]{300}/
}

signature s2b-2504-6 {
  ip-proto == tcp
  dst-port == 465
  event "SMTP SSLv3 invalid data version attempt"
  tcp-state established,originator
  payload /\x16\x03/
  payload /.{4}\x01/
  payload /.{8}[^\x03]*/
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-2519-9 {
  ip-proto == tcp
  dst-port == 465
  # Not supported: byte_test: 2,>,0,6,2,!,0,8,2,!,16,8,2,>,20,10,2,>,32768,0,relative
  event "SMTP Client_Hello overflow attempt"
  tcp-state established,originator
  payload /.{1}\x01/
  payload /.{10}\x8F/
  requires-reverse-signature ! smtp_server_fail
}

signature s2b-1892-6 {
  ip-proto == udp
  dst-port == 161
  event "SNMP null community string attempt"
  payload /.{4}.{0,7}\x04\x01\x00/
  requires-reverse-signature snmp_userver_ok_return
}

signature s2b-1409-10 {
  ip-proto == udp
  dst-port >= 161
  dst-port <= 162
  event "SNMP community string buffer overflow attempt"
  payload /.{3}.*\x02\x01\x00\x04\x82\x01\x00/
  requires-reverse-signature snmp_userver_ok_return
}

signature s2b-1422-10 {
  ip-proto == udp
  dst-port >= 161
  dst-port <= 162
  event "SNMP community string buffer overflow attempt with evasion"
  payload /.{6} \x04\x82\x01\x00/
}

signature s2b-1411-10 {
  ip-proto == udp
  dst-port == 161
  event "SNMP public access udp"
  payload /.*public/
  requires-reverse-signature snmp_userver_ok_return
}

signature s2b-1412-13 {
  ip-proto == tcp
  dst-port == 161
  event "SNMP public access tcp"
  tcp-state established,originator
  payload /.*public/
  requires-reverse-signature snmp_userver_ok_return
}

signature s2b-1413-10 {
  ip-proto == udp
  dst-port == 161
  event "SNMP private access udp"
  payload /.*private/
}

signature s2b-1414-11 {
  ip-proto == tcp
  dst-port == 161
  event "SNMP private access tcp"
  tcp-state established,originator
  payload /.*private/
  requires-reverse-signature snmp_tserver_ok_return
}

signature s2b-1415-9 {
  ip-proto == udp
  dst-ip == 255.255.255.255
  dst-port == 161
  event "SNMP Broadcast request"
  requires-reverse-signature snmp_userver_ok_return
}

signature s2b-1416-9 {
  ip-proto == udp
  dst-ip == 255.255.255.255
  dst-port == 162
  event "SNMP broadcast trap"
  requires-reverse-signature snmp_userver_ok_return
}

signature s2b-1418-11 {
  ip-proto == tcp
  dst-port == 161
  event "SNMP request tcp"
  tcp-state stateless
  requires-reverse-signature snmp_tserver_ok_return
}

signature s2b-1419-9 {
  ip-proto == udp
  dst-port == 162
  event "SNMP trap udp"
  requires-reverse-signature snmp_userver_ok_return
}

signature s2b-1420-11 {
  ip-proto == tcp
  dst-port == 162
  event "SNMP trap tcp"
  tcp-state stateless
  requires-reverse-signature snmp_tserver_ok_return
}

signature s2b-1421-11 {
  ip-proto == tcp
  dst-port == 705
  event "SNMP AgentX/tcp request"
  tcp-state stateless
}

signature s2b-1426-5 {
  ip-proto == udp
  dst-port == 161
  event "SNMP PROTOS test-suite-req-app attempt"
  payload /.*0&\x02\x01\x00\x04\x06public\xA0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x000\x0E0\x0C\x06\x08\+\x06\x01\x02\x01\x01\x05\x00\x05\x00/
  requires-reverse-signature snmp_userver_ok_return
}

signature s2b-1427-4 {
  ip-proto == udp
  dst-port == 162
  event "SNMP PROTOS test-suite-trap-app attempt"
  payload /.*08\x02\x01\x00\x04\x06public\xA4\+\x06/
  requires-reverse-signature snmp_userver_ok_return
}

signature s2b-676-6 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB sp_start_job - program execution"
  tcp-state established,originator
  payload /.{31}[sS]\x00[pP]\x00_\x00[sS]\x00[tT]\x00[aA]\x00[rR]\x00[tT]\x00_\x00[jJ]\x00[oO]\x00[bB]\x00/
}

signature s2b-677-6 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB sp_password password change"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[pP]\x00[aA]\x00[sS]\x00[sS]\x00[wW]\x00[oO]\x00[rR]\x00[dD]\x00/
}

signature s2b-678-6 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB sp_delete_alert log file deletion"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[dD]\x00[eE]\x00[lL]\x00[eE]\x00[tT]\x00[eE]\x00_\x00[aA]\x00[lL]\x00[eE]\x00/
}

signature s2b-679-6 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB sp_adduser database user creation"
  tcp-state established,originator
  payload /.{31}[sS]\x00[pP]\x00_\x00[aA]\x00[dD]\x00[dD]\x00[uU]\x00[sS]\x00[eE]\x00[rR]\x00/
}

signature s2b-708-8 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_enumresultset possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[eE]\x00[nN]\x00[uU]\x00[mM]\x00[rR]\x00[eE]\x00[sS]\x00[uU]\x00[lL]\x00[tT]\x00[sS]\x00[eE]\x00[tT]\x00/
}

signature s2b-1386-8 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB raiserror possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[rR]\x00[aA]\x00[iI]\x00[sS]\x00[eE]\x00[rR]\x00[rR]\x00[oO]\x00[rR]\x00/
}

signature s2b-702-8 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_displayparamstmt possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[dD]\x00[iI]\x00[sS]\x00[pP]\x00[lL]\x00[aA]\x00[yY]\x00[pP]\x00[aA]\x00[rR]\x00[aA]\x00[mM]\x00[sS]\x00[tT]\x00[mM]\x00[tT]\x00/
}

signature s2b-681-6 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_cmdshell program execution"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[cC]\x00[mM]\x00[dD]\x00[sS]\x00[hH]\x00[eE]\x00[lL]\x00[lL]\x00/
}

signature s2b-689-6 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_reg* registry access"
  tcp-state established,originator
  payload /.{31}[xX]\x00[pP]\x00_\x00[rR]\x00[eE]\x00[gG]\x00/
}

signature s2b-690-7 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_printstatements possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[pP]\x00[rR]\x00[iI]\x00[nN]\x00[tT]\x00[sS]\x00[tT]\x00[aA]\x00[tT]\x00[eE]\x00[mM]\x00[eE]\x00[nN]\x00[tT]\x00[sS]\x00/
}

signature s2b-692-6 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB shellcode attempt"
  tcp-state established,originator
  payload /.*9 \xD0\x00\x92\x01\xC2\x00R\x00U\x009 \xEC\x00/
}

signature s2b-694-6 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB shellcode attempt"
  tcp-state established,originator
  payload /.*H\x00%\x00x\x00w\x00\x90\x00\x90\x00\x90\x00\x90\x00\x90\x003\x00\xC0\x00P\x00h\x00\.\x00/
}

signature s2b-695-7 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_sprintf possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[sS]\x00[pP]\x00[rR]\x00[iI]\x00[nN]\x00[tT]\x00[fF]\x00/
}

signature s2b-696-7 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_showcolv possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[sS]\x00[hH]\x00[oO]\x00[wW]\x00[cC]\x00[oO]\x00[lL]\x00[vV]\x00/
}

signature s2b-697-8 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_peekqueue possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[pP]\x00[eE]\x00[eE]\x00[kK]\x00[qQ]\x00[uU]\x00[eE]\x00[uU]\x00[eE]\x00/
}

signature s2b-698-8 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_proxiedmetadata possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[pP]\x00[rR]\x00[oO]\x00[xX]\x00[iI]\x00[eE]\x00[dD]\x00[mM]\x00[eE]\x00[tT]\x00[aA]\x00[dD]\x00[aA]\x00[tT]\x00[aA]\x00/
}

signature s2b-700-8 {
  ip-proto == tcp
  dst-port == 139
  event "MS-SQL/SMB xp_updatecolvbm possible buffer overflow"
  tcp-state established,originator
  payload /.{31}.*[xX]\x00[pP]\x00_\x00[uU]\x00[pP]\x00[dD]\x00[aA]\x00[tT]\x00[eE]\x00[cC]\x00[oO]\x00[lL]\x00[vV]\x00[bB]\x00[mM]\x00/
}

signature s2b-673-5 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL sp_start_job - program execution"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[sS]\x00[tT]\x00[aA]\x00[rR]\x00[tT]\x00_\x00[jJ]\x00[oO]\x00[bB]\x00/
}

signature s2b-674-6 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_displayparamstmt possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[dD]\x00[iI]\x00[sS]\x00[pP]\x00[lL]\x00[aA]\x00[yY]\x00[pP]\x00[aA]\x00[rR]\x00[aA]\x00[mM]\x00[sS]\x00[tT]\x00[mM]\x00[tT]/
}

signature s2b-675-6 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_setsqlsecurity possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[sS]\x00[eE]\x00[tT]\x00[sS]\x00[qQ]\x00[lL]\x00[sS]\x00[eE]\x00[cC]\x00[uU]\x00[rR]\x00[iI]\x00[tT]\x00[yY]\x00/
}

signature s2b-682-6 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_enumresultset possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[eE]\x00[nN]\x00[uU]\x00[mM]\x00[rR]\x00[eE]\x00[sS]\x00[uU]\x00[lL]\x00[tT]\x00[sS]\x00[eE]\x00[tT]\x00/
}

signature s2b-683-5 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL sp_password - password change"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[pP]\x00[aA]\x00[sS]\x00[sS]\x00[wW]\x00[oO]\x00[rR]\x00[dD]\x00/
}

signature s2b-684-5 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL sp_delete_alert log file deletion"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[dD]\x00[eE]\x00[lL]\x00[eE]\x00[tT]\x00[eE]\x00_\x00[aA]\x00[lL]\x00[eE]\x00[rR]\x00[tT]\x00/
}

signature s2b-685-5 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL sp_adduser - database user creation"
  tcp-state established,originator
  payload /.*[sS]\x00[pP]\x00_\x00[aA]\x00[dD]\x00[dD]\x00[uU]\x00[sS]\x00[eE]\x00[rR]\x00/
}

signature s2b-686-5 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_reg* - registry access"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[rR]\x00[eE]\x00[gG]\x00/
}

signature s2b-687-5 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_cmdshell - program execution"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[cC]\x00[mM]\x00[dD]\x00[sS]\x00[hH]\x00[eE]\x00[lL]\x00[lL]\x00/
}

signature s2b-691-5 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL shellcode attempt"
  tcp-state established,originator
  payload /.*9 \xD0\x00\x92\x01\xC2\x00R\x00U\x009 \xEC\x00/
}

signature s2b-693-5 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL shellcode attempt"
  tcp-state established,originator
  payload /.*H\x00%\x00x\x00w\x00\x90\x00\x90\x00\x90\x00\x90\x00\x90\x003\x00\xC0\x00P\x00h\x00\.\x00/
}

signature s2b-699-7 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_printstatements possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[pP]\x00[rR]\x00[iI]\x00[nN]\x00[tT]\x00[sS]\x00[tT]\x00[aA]\x00[tT]\x00[eE]\x00[mM]\x00[eE]\x00[nN]\x00[tT]\x00[sS]\x00/
}

signature s2b-701-7 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_updatecolvbm possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[uU]\x00[pP]\x00[dD]\x00[aA]\x00[tT]\x00[eE]\x00[cC]\x00[oO]\x00[lL]\x00[vV]\x00[bB]\x00[mM]\x00/
}

signature s2b-704-6 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_sprintf possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[sS]\x00[pP]\x00[rR]\x00[iI]\x00[nN]\x00[tT]\x00[fF]\x00/
}

signature s2b-705-7 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_showcolv possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[sS]\x00[hH]\x00[oO]\x00[wW]\x00[cC]\x00[oO]\x00[lL]\x00[vV]\x00/
}

signature s2b-706-7 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_peekqueue possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[pP]\x00[eE]\x00[eE]\x00[kK]\x00[qQ]\x00[uU]\x00[eE]\x00[uU]\x00[eE]\x00/
}

signature s2b-707-8 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL xp_proxiedmetadata possible buffer overflow"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[pP]\x00[rR]\x00[oO]\x00[xX]\x00[iI]\x00[eE]\x00[dD]\x00[mM]\x00[eE]\x00[tT]\x00[aA]\x00[dD]\x00[aA]\x00[tT]\x00[aA]\x00/
}

signature s2b-1387-7 {
  ip-proto == tcp
  dst-port == 1433
  event "MS-SQL raiserror possible buffer overflow"
  tcp-state established,originator
  payload /.*[rR]\x00[aA]\x00[iI]\x00[sS]\x00[eE]\x00[rR]\x00[rR]\x00[oO]\x00[rR]\x00/
}

signature s2b-1759-5 {
  ip-proto == tcp
  dst-port == 445
  event "MS-SQL xp_cmdshell program execution 445"
  tcp-state established,originator
  payload /.*[xX]\x00[pP]\x00_\x00[cC]\x00[mM]\x00[dD]\x00[sS]\x00[hH]\x00[eE]\x00[lL]\x00[lL]\x00/
}

signature s2b-688-6 {
  ip-proto == tcp
  src-port == 1433
  event "MS-SQL sa login failed"
  tcp-state established,responder
  payload /.*Login failed for user 'sa'/
}

signature s2b-680-6 {
  ip-proto == tcp
  src-port == 139
  event "MS-SQL/SMB sa login failed"
  tcp-state established,responder
  payload /.{82}.*Login failed for user 'sa'/
}

signature s2b-2050-5 {
  ip-proto == udp
  dst-port == 1434
  payload-size > 100
  event "MS-SQL version overflow attempt"
  payload /\x04/
}

signature s2b-2329-6 {
  ip-proto == udp
  dst-port == 1434
  dst-ip == local_nets
  # Not supported: byte_test: 2,>,512,1
  event "MS-SQL probe response overflow attempt"
  # Not supported: isdataat: 512,relative
  payload /\x05.*.*\x3B[^\x3B]{512}/
}

signature s2b-1430-7 {
  ip-proto == tcp
  dst-port == 23
  event "TELNET Solaris memory mismanagement exploit attempt"
  tcp-state established,originator
  payload /.*\xA0\x23\xA0\x10\xAE\x23\x80\x10\xEE\x23\xBF\xEC\x82\x05\xE0\xD6\x90%\xE0/
}

signature s2b-711-5 {
  ip-proto == tcp
  dst-port == 23
  event "TELNET SGI telnetd format bug"
  tcp-state established,originator
  payload /.*_RLD/
  payload /.*bin\/sh/
}

signature s2b-712-8 {
  ip-proto == tcp
  dst-port == 23
  event "TELNET ld_library_path"
  tcp-state established,originator
  payload /.*ld_library_path/
}

signature s2b-714-4 {
  ip-proto == tcp
  dst-port == 23
  event "TELNET resolv_host_conf"
  tcp-state established,originator
  payload /.*resolv_host_conf/
}

signature s2b-715-6 {
  ip-proto == tcp
  src-port == 23
  event "TELNET Attempted SU from wrong group"
  tcp-state established,responder
  payload /.*[tT][oO] [sS][uU] [rR][oO][oO][tT]/
}

signature s2b-717-6 {
  ip-proto == tcp
  src-port == 23
  event "TELNET not on console"
  tcp-state established,responder
  payload /.*[nN][oO][tT] [oO][nN] [sS][yY][sS][tT][eE][mM] [cC][oO][nN][sS][oO][lL][eE]/
}

signature s2b-718-7 {
  ip-proto == tcp
  src-port == 23
  event "TELNET login incorrect"
  tcp-state established,responder
  payload /.*Login incorrect/
}

signature s2b-719-7 {
  ip-proto == tcp
  src-port == 23
  event "TELNET root login"
  tcp-state established,responder
  payload /.*login\x3A root/
}

signature s2b-1252-13 {
  ip-proto == tcp
  src-port == 23
  event "TELNET bsd telnet exploit response"
  tcp-state established,responder
  payload /.*\x0D\x0A\[Yes\]\x0D\x0A\xFF\xFE\x08\xFF\xFD&/
}

signature s2b-1253-11 {
  ip-proto == tcp
  dst-port == 23
  payload-size > 200
  event "TELNET bsd exploit client finishing"
  tcp-state established,responder
  payload /.{199}\xFF\xF6\xFF\xF6\xFF\xFB\x08\xFF\xF6/
}

signature s2b-709-7 {
  ip-proto == tcp
  dst-port == 23
  event "TELNET 4Dgifts SGI account attempt"
  tcp-state established,originator
  payload /.*4Dgifts/
}

signature s2b-710-7 {
  ip-proto == tcp
  dst-port == 23
  event "TELNET EZsetup account attempt"
  tcp-state established,originator
  payload /.*OutOfBox/
}

signature s2b-2406-1 {
  ip-proto == tcp
  dst-port == 23
  event "TELNET APC SmartSlot default admin account attempt"
  tcp-state established,originator
  payload /.*TENmanUFactOryPOWER/
}

signature s2b-1941-8 {
  ip-proto == udp
  dst-port == 69
  event "TFTP GET filename overflow attempt"
  payload /\x00\x01[^\x00]{100}/
}

signature s2b-2337-7 {
  ip-proto == udp
  dst-port == 69
  event "TFTP PUT filename overflow attempt"
  payload /\x00\x02[^\x00]{100}/
}

signature s2b-1289-4 {
  ip-proto == udp
  dst-port == 69
  event "TFTP GET Admin.dll"
  payload /\x00\x01/
  payload /.{1}.*[aA][dD][mM][iI][nN]\.[dD][lL][lL]/
}

signature s2b-1441-4 {
  ip-proto == udp
  dst-port == 69
  event "TFTP GET nc.exe"
  payload /\x00\x01/
  payload /.{1}.*[nN][cC]\.[eE][xX][eE]/
}

signature s2b-1442-4 {
  ip-proto == udp
  dst-port == 69
  event "TFTP GET shadow"
  payload /\x00\x01/
  payload /.{1}.*[sS][hH][aA][dD][oO][wW]/
}

signature s2b-1443-4 {
  ip-proto == udp
  dst-port == 69
  event "TFTP GET passwd"
  payload /\x00\x01/
  payload /.{1}.*[pP][aA][sS][sS][wW][dD]/
}

signature s2b-519-6 {
  ip-proto == udp
  dst-port == 69
  event "TFTP parent directory"
  payload /.{1}.*\.\./
}

signature s2b-520-5 {
  ip-proto == udp
  dst-port == 69
  event "TFTP root directory"
  payload /\x00\x01\//
}

signature s2b-518-6 {
  ip-proto == udp
  dst-port == 69
  event "TFTP Put"
  payload /\x00\x02/
}

signature s2b-1444-3 {
  ip-proto == udp
  dst-port == 69
  event "TFTP Get"
  payload /\x00\x01/
}

signature s2b-2339-2 {
  ip-proto == udp
  dst-port == 69
  event "TFTP NULL command attempt"
  payload /\x00\x00/
}

signature s2b-1328-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS ps command attempt"
  http /.*[\/\\]bin[\/\\]ps([^_a-zA-Z0-9.\/-]|$)/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1330-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS wget command attempt"
  tcp-state established,originator
  payload /.*[wW][gG][eE][tT]%20/
  requires-reverse-signature ! http_error
  # would like to inspect contents of reply
}

signature s2b-1331-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS uname -a command attempt"
  tcp-state established,originator
  payload /.*[uU][nN][aA][mM][eE]%20-[aA]/
  requires-reverse-signature ! http_error
}

signature s2b-1332-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/id command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[iI][dD]/
  requires-reverse-signature ! http_error
}

signature s2b-1333-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS id command attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /.*;[iI][dD]([;|\x20\x09\x0b]|$)./
}

signature s2b-1334-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS echo command attempt"
  tcp-state established,originator
  payload /.*\/[bB][iI][nN]\/[eE][cC][hH][oO]/
  requires-reverse-signature ! http_error
}

signature s2b-1335-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS kill command attempt"
  tcp-state established,originator
  payload /.*\/[bB][iI][nN]\/[kK][iI][lL][lL]/
  requires-reverse-signature ! http_error
}

signature s2b-1336-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS chmod command attempt"
  tcp-state established,originator
  http /.*\/[cC][hH][mM][oO][dD]([^-a-zA-Z0-9_.]|$)/
  requires-reverse-signature ! http_error
}

signature s2b-1337-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS chgrp command attempt"
  tcp-state established,originator
  http /.*\/[cC][hH][gG][rR][pP]([^-a-zA-Z0-9_.]|$)/
  requires-reverse-signature ! http_error
}

signature s2b-1338-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS chown command attempt"
  tcp-state established,originator
  http /.*\/[cC][hH][oO][wW][nN]([^-a-zA-Z0-9_.]|$)/
  requires-reverse-signature ! http_error
}

signature s2b-1339-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS chsh command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[cC][hH][sS][hH]/
  requires-reverse-signature ! http_error
}

signature s2b-1340-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS tftp command attempt"
  tcp-state established,originator
  payload /.*[tT][fF][tT][pP]%20/
  requires-signature ! http_cool_dll
  requires-reverse-signature ! http_error
}

signature s2b-1341-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/gcc command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[gG][cC][cC]/
  requires-reverse-signature ! http_error
}

signature s2b-1342-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS gcc command attempt"
  tcp-state established,originator
  payload /.*[gG][cC][cC]%20-[oO]/
  requires-reverse-signature ! http_error
}

signature s2b-1343-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/cc command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[cC][cC]/
  requires-reverse-signature ! http_error
}

signature s2b-1344-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS cc command attempt"
  tcp-state established,originator
  payload /.*[cC][cC]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1345-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/cpp command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[cC][pP][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-1347-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/g++ command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[gG]\+\+/
  requires-reverse-signature ! http_error
}

signature s2b-1348-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS g++ command attempt"
  tcp-state established,originator
  payload /.*[gG]\+\+%20/
  requires-reverse-signature ! http_error
}

signature s2b-1351-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS bin/tclsh execution attempt"
  tcp-state established,originator
  payload /.*[bB][iI][nN]\/[tT][cC][lL][sS][hH]/
  requires-reverse-signature ! http_error
}

signature s2b-1352-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS tclsh execution attempt"
  tcp-state established,originator
  payload /.*[tT][cC][lL][sS][hH]8%20/
  requires-reverse-signature ! http_error
}

signature s2b-1353-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS bin/nasm command attempt"
  tcp-state established,originator
  payload /.*[bB][iI][nN]\/[nN][aA][sS][mM]/
  requires-reverse-signature ! http_error
}

signature s2b-1354-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS nasm command attempt"
  tcp-state established,originator
  payload /.*[nN][aA][sS][mM]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1355-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/perl execution attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[pP][eE][rR][lL]/
  requires-reverse-signature ! http_error
}

signature s2b-1356-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS perl execution attempt"
  tcp-state established,originator
  payload /.*[pP][eE][rR][lL]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1357-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS nt admin addition attempt"
  tcp-state established,originator
  payload /.*[nN][eE][tT] [lL][oO][cC][aA][lL][gG][rR][oO][uU][pP] [aA][dD][mM][iI][nN][iI][sS][tT][rR][aA][tT][oO][rR][sS] \/[aA][dD][dD]/
  requires-reverse-signature ! http_error
}

signature s2b-1358-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS traceroute command attempt"
  tcp-state established,originator
  payload /.*[tT][rR][aA][cC][eE][rR][oO][uU][tT][eE]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1359-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS ping command attempt"
  tcp-state established,originator
  payload /.*\/[bB][iI][nN]\/[pP][iI][nN][gG]/
  requires-reverse-signature ! http_error
}

signature s2b-1360-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS netcat command attempt"
  tcp-state established,originator
  payload /.*[nN][cC]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1361-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS nmap command attempt"
  tcp-state established,originator
  payload /.*[nN][mM][aA][pP]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1362-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS xterm command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[xX]11[rR]6\/[bB][iI][nN]\/[xX][tT][eE][rR][mM]/
  requires-reverse-signature ! http_error
}

signature s2b-1363-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS X application to remote host attempt"
  tcp-state established,originator
  payload /.*%20-[dD][iI][sS][pP][lL][aA][yY]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1364-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS lsof command attempt"
  tcp-state established,originator
  payload /.*[lL][sS][oO][fF]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1365-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS rm command attempt"
  tcp-state established,originator
  payload /.*[rR][mM]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1366-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS mail command attempt"
  tcp-state established,originator
  payload /.*\/[bB][iI][nN]\/[mM][aA][iI][lL]/
  requires-reverse-signature ! http_error
}

signature s2b-1367-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS mail command attempt"
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1368-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /bin/ls| command attempt"
  http /.*[\/\\]bin[\/\\]ls\x7C/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1369-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /bin/ls command attempt"
  http /.*[\/\\]bin[\/\\]ls[^a-zA-Z0-9_.-]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1370-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /etc/inetd.conf access"
  tcp-state established,originator
  payload /.*\/[eE][tT][cC]\/[iI][nN][eE][tT][dD]\.[cC][oO][nN][fF]/
  requires-reverse-signature ! http_error
}

signature s2b-1372-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS /etc/shadow access"
  tcp-state established,originator
  payload /.*\/[eE][tT][cC]\/[sS][hH][aA][dD][oO][wW].{1,}root:/
  requires-reverse-signature ! http_error
}

signature s2b-1373-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS conf/httpd.conf attempt"
  tcp-state established,originator
  payload /.*[cC][oO][nN][fF]\/[hH][tT][tT][pP][dD]\.[cC][oO][nN][fF]/
  requires-reverse-signature ! http_error
}

signature s2b-1374-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-ATTACKS .htgroup access"
  http /.*\.htgroup[\x20\x09\x0b]*$/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-803-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI HyperSeek hsx.cgi directory traversal attempt"
  http /.*[\/\\]hsx\.cgi/
  tcp-state established,originator
  payload /.*\.\.\/\.\.\/.{1}.*%00/
  requires-reverse-signature ! http_error
}

signature s2b-804-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI SWSoft ASPSeek Overflow attempt"
  http /.*[\/\\]s\.cgi/
  tcp-state established,originator
  payload /.*[tT][mM][pP][lL]=/
  requires-reverse-signature ! http_error
}

signature s2b-806-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI yabb directory traversal attempt"
  http /.*[\/\\]YaBB/
  tcp-state established,originator
  payload /.*\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-809-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI whois_raw.cgi arbitrary command execution attempt"
  http /.*[\/\\]whois_raw\.cgi\?/
  tcp-state established,originator
  payload /.*\x0A/
  requires-reverse-signature ! http_error
}

signature s2b-810-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI whois_raw.cgi access"
  http /.*[\/\\]whois_raw\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-813-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI webplus directory traversal"
  http /.*[\/\\]webplus\?script/
  tcp-state established,originator
  payload /.*\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1571-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI dcforum.cgi directory traversal attempt"
  http /.*[\/\\]dcforum\.cgi/
  tcp-state established,originator
  payload /.*forum=\.\.\/\.\./
  requires-reverse-signature ! http_error
}

signature s2b-817-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI dcboard.cgi invalid user addition attempt"
  http /.*[\/\\]dcboard\.cgi/
  tcp-state established,originator
  payload /.*command=register/
  payload /.*%7cadmin/
  requires-reverse-signature ! http_error
}

signature s2b-1410-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI dcboard.cgi access"
  http /.*[\/\\]dcboard\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-820-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI anaconda directory transversal attempt"
  http /.*[\/\\]apexec\.pl/
  tcp-state established,originator
  payload /.*[tT][eE][mM][pP][lL][aA][tT][eE]=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-821-12 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI imagemap.exe overflow attempt"
  http /.*[\/\\]imagemap\.exe\?/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1608-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI htmlscript attempt"
  http /.*[\/\\]htmlscript\?\.\.[\/\\]\.\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-826-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI htmlscript access"
  http /.*[\/\\]htmlscript/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-827-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI info2www access"
  http /.*[\/\\]info2www/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-828-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI maillist.pl access"
  http /.*[\/\\]maillist\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-829-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI nph-test-cgi access"
  http /.*[\/\\]nph-test-cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1451-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI NPH-publish access"
  http /.*[\/\\]nph-maillist\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-833-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI rguest.exe access"
  http /.*[\/\\]rguest\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-834-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI rwwwshell.pl access"
  http /.*[\/\\]rwwwshell\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1644-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI test-cgi attempt"
  http /.*[\/\\]test-cgi[\/\\]\*\?\*/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-835-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI test-cgi access"
  http /.*[\/\\]test-cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1645-6 {
  ip-proto == tcp
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-CGI testcgi access"
  http /.*[\/\\]testcgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1646-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI test.cgi access"
  http /.*[\/\\]test\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-836-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI textcounter.pl access"
  http /.*[\/\\]textcounter\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-837-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI uploader.exe access"
  http /.*[\/\\]uploader\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-838-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI webgais access"
  http /.*[\/\\]webgais/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-840-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI perlshop.cgi access"
  http /.*[\/\\]perlshop\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-841-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI pfdisplay.cgi access"
  http /.*[\/\\]pfdisplay\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-842-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI aglimpse access"
  http /.*[\/\\]aglimpse/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-843-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI anform2 access"
  http /.*[\/\\]AnForm2/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-844-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI args.bat access"
  http /.*[\/\\]args\.bat/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1452-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI args.cmd access"
  http /.*[\/\\]args\.cmd/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-845-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI AT-admin.cgi access"
  http /.*[\/\\]AT-admin\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1453-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI AT-generated.cgi access"
  http /.*[\/\\]AT-generated\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-846-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bnbform.cgi access"
  http /.*[\/\\]bnbform\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-847-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI campas access"
  http /.*[\/\\]campas/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-848-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI view-source directory traversal"
  http /.*[\/\\]view-source/
  tcp-state established,originator
  payload /.*\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-850-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI wais.pl access"
  http /.*[\/\\]wais\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1454-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI wwwwais access"
  http /.*[\/\\]wwwwais/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-851-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI files.pl access"
  http /.*[\/\\]files\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-852-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI wguest.exe access"
  http /.*[\/\\]wguest\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-854-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI classifieds.cgi access"
  http /.*[\/\\]classifieds\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-856-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI environ.cgi access"
  http /.*[\/\\]environ\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-857-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI faxsurvey access"
  http /.*[\/\\]faxsurvey/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-858-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI filemail access"
  http /.*[\/\\]filemail\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-859-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI man.sh access"
  http /.*[\/\\]man\.sh/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-860-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI snork.bat access"
  http /.*[\/\\]snork\.bat/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-861-12 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI w3-msql access"
  http /.*[\/\\]w3-msql[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-863-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI day5datacopier.cgi access"
  http /.*[\/\\]day5datacopier\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-864-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI day5datanotifier.cgi access"
  http /.*[\/\\]day5datanotifier\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-866-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI post-query access"
  http /.*[\/\\]post-query/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-867-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI visadmin.exe access"
  http /.*[\/\\]visadmin\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-869-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI dumpenv.pl access"
  http /.*[\/\\]dumpenv\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1536-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI calendar_admin.pl arbitrary command execution attempt"
  http /.*[\/\\]calendar_admin\.pl\?config=\x7C/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1537-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI calendar_admin.pl access"
  http /.*[\/\\]calendar_admin\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1701-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI calendar-admin.pl access"
  http /.*[\/\\]calendar-admin\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1457-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI user_update_admin.pl access"
  http /.*[\/\\]user_update_admin\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1458-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI user_update_passwd.pl access"
  http /.*[\/\\]user_update_passwd\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-870-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI snorkerz.cmd access"
  http /.*[\/\\]snorkerz\.cmd/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-871-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI survey.cgi access"
  http /.*[\/\\]survey\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-875-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI win-c-sample.exe access"
  http /.*[\/\\]win-c-sample\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-878-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI w3tvars.pm access"
  http /.*[\/\\]w3tvars\.pm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-879-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI admin.pl access"
  http /.*[\/\\]admin\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-880-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI LWGate access"
  http /.*[\/\\]LWGate/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-881-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI archie access"
  http /.*[\/\\]archie/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-883-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI flexform access"
  http /.*[\/\\]flexform/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1610-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI formmail arbitrary command execution attempt"
  http /.*[\/\\]formmail{0,5}\?/
  tcp-state established,originator
  payload /.*%0[aA]/
  requires-reverse-signature ! http_error
}

signature s2b-884-14 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI formmail access"
  http /.*[\/\\]formmail{0,5}\?/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1762-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI phf arbitrary command execution attempt"
  http /.*[\/\\]phf/
  tcp-state established,originator
  payload /.*[qQ][aA][lL][iI][aA][sS]/
  payload /.*%0a\//
  requires-reverse-signature ! http_error
}

signature s2b-887-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI www-sql access"
  http /.*[\/\\]www-sql/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-888-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI wwwadmin.pl access"
  http /.*[\/\\]wwwadmin\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-889-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ppdscgi.exe access"
  http /.*[\/\\]ppdscgi\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-890-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI sendform.cgi access"
  http /.*[\/\\]sendform\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-891-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI upload.pl access"
  http /.*[\/\\]upload\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-892-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI AnyForm2 access"
  http /.*[\/\\]AnyForm2/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-893-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI MachineInfo access"
  http /.*[\/\\]MachineInfo/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1531-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bb-hist.sh attempt"
  http /.*[\/\\]bb-hist\.sh\?HISTFILE=\.\.[\/\\]\.\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-894-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bb-hist.sh access"
  http /.*[\/\\]bb-hist\.sh/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1459-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bb-histlog.sh access"
  http /.*[\/\\]bb-histlog\.sh/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1460-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bb-histsvc.sh access"
  http /.*[\/\\]bb-histsvc\.sh/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1532-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bb-hostscv.sh attempt"
  http /.*[\/\\]bb-hostsvc\.sh\?HOSTSVC\?\.\.[\/\\]\.\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1533-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bb-hostscv.sh access"
  http /.*[\/\\]bb-hostsvc\.sh/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1461-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bb-rep.sh access"
  http /.*[\/\\]bb-rep\.sh/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1462-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bb-replog.sh access"
  http /.*[\/\\]bb-replog\.sh/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1397-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI wayboard attempt"
  http /.*[\/\\]way-board[\/\\]way-board\.cgi/
  tcp-state established,originator
  payload /.*db=/
  payload /.*\.\.\/\.\./
  requires-reverse-signature ! http_error
}

signature s2b-896-11 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI way-board access"
  http /.*[\/\\]way-board\?db\=.{2,}\x00/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1222-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI pals-cgi arbitrary file access attempt"
  http /.*[\/\\]pals-cgi/
  tcp-state established,originator
  payload /.*[dD][oO][cC][uU][mM][eE][nN][tT][nN][aA][mM][eE]=/
  requires-reverse-signature ! http_error
}

signature s2b-897-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI pals-cgi access"
  http /.*[\/\\]pals-cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1572-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI commerce.cgi arbitrary file access attempt"
  http /.*[\/\\]commerce\.cgi/
  tcp-state established,originator
  payload /.*page=/
  payload /.*\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-898-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI commerce.cgi access"
  http /.*[\/\\]commerce\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-899-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Amaya templates sendtemp.pl directory traversal attempt"
  http /.*[\/\\]sendtemp\.pl/
  tcp-state established,originator
  payload /.*[tT][eE][mM][pP][lL]=/
  requires-reverse-signature ! http_error
}

signature s2b-901-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI webspirs.cgi access"
  http /.*[\/\\]webspirs\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-902-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI tstisapi.dll access"
  http /.*tstisapi\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1308-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI sendmessage.cgi access"
  http /.*[\/\\]sendmessage\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1392-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI lastlines.cgi access"
  http /.*[\/\\]lastlines\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1395-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI zml.cgi attempt"
  http /.*[\/\\]zml\.cgi/
  tcp-state established,originator
  payload /.*file=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1396-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI zml.cgi access"
  http /.*[\/\\]zml\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1534-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI agora.cgi attempt"
  http /.*[\/\\]store[\/\\]agora\.cgi\?cart_id=<SCRIPT>/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1406-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI agora.cgi access"
  http /.*[\/\\]store[\/\\]agora\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-877-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI rksh access"
  http /.*[\/\\]rksh/
  tcp-state established,originator
  requires-signature ! http_shell_check
  requires-reverse-signature ! http_error
}

signature s2b-1648-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI perl.exe command attempt"
  http /.*[\/\\]perl\.exe\?/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-832-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI perl.exe access"
  http /.*[\/\\]perl\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1649-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI perl command attempt"
  http /.*[\/\\]perl\?/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1309-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI zsh access"
  http /.*[\/\\]zsh/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-862-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI csh access"
  http /.*[\/\\]csh/
  tcp-state established,originator
  requires-signature ! http_shell_check
  requires-reverse-signature ! http_error
}

signature s2b-872-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI tcsh access"
  http /.*[\/\\]tcsh/
  tcp-state established,originator
  requires-signature ! http_shell_check
  requires-reverse-signature ! http_error
}

signature s2b-868-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI rsh access"
  http /.*[\/\\]rsh/
  tcp-state established,originator
  requires-signature ! http_shell_check
  requires-reverse-signature ! http_error
}

signature s2b-865-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ksh access"
  http /.*[\/\\]ksh/
  tcp-state established,originator
  requires-signature ! http_shell_check
  requires-reverse-signature ! http_error
}

signature s2b-1703-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI auktion.cgi directory traversal attempt"
  http /.*[\/\\]auktion\.cgi/
  tcp-state established,originator
  payload /.*[mM][eE][nN][uU][eE]=\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1465-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI auktion.cgi access"
  http /.*[\/\\]auktion\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1573-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cgiforum.pl attempt"
  http /.*[\/\\]cgiforum\.pl\?thesection=\.\.[\/\\]\.\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1466-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cgiforum.pl access"
  http /.*[\/\\]cgiforum\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1574-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI directorypro.cgi attempt"
  http /.*[\/\\]directorypro\.cgi/
  tcp-state established,originator
  payload /.*show=.{1}.*\.\.\/\.\./
  requires-reverse-signature ! http_error
}

signature s2b-1467-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI directorypro.cgi access"
  http /.*[\/\\]directorypro\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1468-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Web Shopper shopper.cgi attempt"
  http /.*[\/\\]shopper\.cgi/
  tcp-state established,originator
  payload /.*[nN][eE][wW][pP][aA][gG][eE]=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1469-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Web Shopper shopper.cgi access"
  http /.*[\/\\]shopper\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1470-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI listrec.pl access"
  http /.*[\/\\]listrec\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1471-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI mailnews.cgi access"
  http /.*[\/\\]mailnews\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1879-5 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI book.cgi arbitrary command execution attempt"
  http /.*[\/]book.cgi\?.{1,}\|.{2,}\|/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1473-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI newsdesk.cgi access"
  http /.*[\/\\]newsdesk\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1704-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cal_make.pl directory traversal attempt"
  http /.*[\/\\]cal_make\.pl/
  tcp-state established,originator
  payload /.*[pP]0=\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1474-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cal_make.pl access"
  http /.*[\/\\]cal_make\.pl.{1,}(\.\.\/){2,}/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1475-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI mailit.pl access"
  http /.*[\/\\]mailit\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1476-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI sdbsearch.cgi access"
  http /.*[\/\\]sdbsearch\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1478-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI swc access"
  http /.*[\/\\]swc/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1479-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ttawebtop.cgi arbitrary file attempt"
  http /.*[\/\\]ttawebtop\.cgi/
  tcp-state established,originator
  payload /.*[pP][gG]=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1480-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ttawebtop.cgi access"
  http /.*[\/\\]ttawebtop\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1481-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI upload.cgi access"
  http /.*[\/\\]upload\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1482-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI view_source access"
  http /.*[\/\\]view_source/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1730-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ustorekeeper.pl directory traversal attempt"
  http /.*[\/\\]ustorekeeper\.pl/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE]=\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1483-9 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI ustorekeeper.pl access"
  http /.*[\/\\]ustorekeeper\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1617-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Bugzilla doeditvotes.cgi access"
  http /.*[\/\\]doeditvotes\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1600-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI htsearch arbitrary configuration file attempt"
  http /.*[\/\\]htsearch\?-c/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1601-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI htsearch arbitrary file read attempt"
  http /.*[\/\\]htsearch\?exclude=`/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1602-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI htsearch access"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /.*[\/\\]htsearch\x3f.*\x3d[\x22\x60].*[\x22\x60].* /
}

signature s2b-1501-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI a1stats a1disp3.cgi directory traversal attempt"
  http /.*[\/\\]a1disp3\.cgi\?[\/\\]\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1502-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI a1stats a1disp3.cgi access"
  http /.*[\/\\]a1disp3\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1731-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI a1stats access"
  http /.*[\/\\]a1stats[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1503-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI admentor admin.asp access"
  http /.*[\/\\]admentor[\/\\]admin[\/\\]admin\.asp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1505-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI alchemy http server PRN arbitrary command execution attempt"
  http /.*[\/\\]PRN[\/\\]\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1506-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI alchemy http server NUL arbitrary command execution attempt"
  http /.*[\/\\]NUL[\/\\]\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1507-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI alibaba.pl arbitrary command execution attempt"
  http /.*[\/\\]alibaba\.pl\x7C/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1508-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI alibaba.pl access"
  http /.*[\/\\]alibaba\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1509-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI AltaVista Intranet Search directory traversal attempt"
  http /.*[\/\\]query\?mss=\.\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1510-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI test.bat arbitrary command execution attempt"
  http /.*[\/\\]test\.bat\x7C/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1511-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI test.bat access"
  http /.*[\/\\]test\.bat/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1512-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI input.bat arbitrary command execution attempt"
  http /.*[\/\\]input\.bat\x7C/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1513-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI input.bat access"
  http /.*[\/\\]input\.bat/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1514-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI input2.bat arbitrary command execution attempt"
  http /.*[\/\\]input2\.bat\x7C/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1515-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI input2.bat access"
  http /.*[\/\\]input2\.bat/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1516-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI envout.bat arbitrary command execution attempt"
  http /.*[\/\\]envout\.bat\x7C/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1517-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI envout.bat access"
  http /.*[\/\\]envout\.bat/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1705-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI echo.bat arbitrary command execution attempt"
  http /.*[\/\\]echo\.bat/
  tcp-state established,originator
  payload /.*&/
  requires-reverse-signature ! http_error
}

signature s2b-1706-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI echo.bat access"
  http /.*[\/\\]echo\.bat/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1707-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI hello.bat arbitrary command execution attempt"
  http /.*[\/\\]hello\.bat/
  tcp-state established,originator
  payload /.*&/
  requires-reverse-signature ! http_error
}

signature s2b-1708-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI hello.bat access"
  http /.*[\/\\]hello\.bat/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1650-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI tst.bat access"
  http /.*[\/\\]tst\.bat/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1542-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cgimail access"
  http /.*[\/\\]cgimail/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1547-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI csSearch.cgi arbitrary command execution attempt"
  http /.*[\/\\]csSearch\.cgi/
  tcp-state established,originator
  payload /.*setup=/
  payload /.*`.{1}.*`/
  requires-reverse-signature ! http_error
}

signature s2b-1548-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI csSearch.cgi access"
  http /.*[\/\\]csSearch\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
  eval isApacheLt1325
}

signature s2b-1553-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI /cart/cart.cgi access"
  http /.*[\/\\]cart[\/\\]cart\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1554-9 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI dbman db.cgi access"
  http /.*[\/\\]dbman[\/\\]db\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1555-7 {
  ip-proto == tcp
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-CGI DCShop access"
  http /.*[\/\\]dcshop/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1556-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI DCShop orders.txt access"
  http /.*[\/\\]orders[\/\\]orders\.txt/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1557-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI DCShop auth_user_file.txt access"
  http /.*[\/\\]auth_data[\/\\]auth_user_file\.txt/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1565-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI eshop.pl arbitrary commane execution attempt"
  http /.*[\/\\]eshop\.pl\?seite=\x3B/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1566-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI eshop.pl access"
  http /.*[\/\\]eshop\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1569-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI loadpage.cgi directory traversal attempt"
  http /.*[\/\\]loadpage\.cgi/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE]=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1570-5 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI loadpage.cgi access"
  http /.*[\/\\]loadpage\.cgi\?{1,}\//
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1590-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI faqmanager.cgi arbitrary file access attempt"
  http /.*[\/\\]faqmanager\.cgi\?toc=/
  http /.*\x00/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1591-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI faqmanager.cgi access"
  http /.*[\/\\]faqmanager\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1592-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI /fcgi-bin/echo.exe access"
  http /.*[\/\\]fcgi-bin[\/\\]echo\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1628-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI FormHandler.cgi directory traversal attempt attempt"
  http /.*[\/\\]FormHandler\.cgi/
  tcp-state established,originator
  payload /.*[rR][eE][pP][lL][yY]_[mM][eE][sS][sS][aA][gG][eE]_[aA][tT][tT][aA][cC][hH]=/
  payload /.*\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1593-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI FormHandler.cgi external site redirection attempt"
  http /.*[\/\\]FormHandler\.cgi/
  tcp-state established,originator
  payload /.*[rR][eE][dD][iI][rR][eE][cC][tT]=[hH][tT][tT][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-1594-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI FormHandler.cgi access"
  http /.*[\/\\]FormHandler\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1598-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Home Free search.cgi directory traversal attempt"
  http /.*[\/\\]search\.cgi/
  tcp-state established,originator
  payload /.*[lL][eE][tT][tT][eE][rR]=\.\.\/\.\./
  requires-reverse-signature ! http_error
}

signature s2b-1599-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI search.cgi access"
  http /.*[\/\\]search\.cgi\?.*letter\=[^&]*?\.\.[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1651-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI enivorn.pl access"
  http /.*[\/\\]enivron\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1652-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI campus attempt"
  http /.*[\/\\]campus\?\x0A/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1654-4 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI cart32.exe access"
  http /.*[\/\\]cart32\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1655-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI pfdispaly.cgi arbitrary command execution attempt"
  http /.*[\/\\]pfdispaly\.cgi\?'/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1656-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI pfdispaly.cgi access"
  http /.*[\/\\]pfdispaly\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1657-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI pagelog.cgi directory traversal attempt"
  http /.*[\/\\]pagelog\.cgi/
  tcp-state established,originator
  payload /.*[nN][aA][mM][eE]=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1658-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI pagelog.cgi access"
  http /.*[\/\\]pagelog\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1710-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bbs_forum.cgi access"
  http /.*[\/\\]bbs_forum\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1711-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bsguest.cgi access"
  http /.*[\/\\]bsguest\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1712-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bslist.cgi access"
  http /.*[\/\\]bslist\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1714-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI newdesk access"
  http /.*[\/\\]newdesk/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1715-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI register.cgi access"
  http /.*[\/\\]register\.cgi/
  payload /SEND_MAIL/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1716-6 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI gbook.cgi access"
  http /.*[\/\\]gbook\.cgi/
  payload /_MAILTO.*\;/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1717-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI simplestguest.cgi access"
  http /.*[\/\\]simplestguest\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1718-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI statusconfig.pl access"
  http /.*[\/\\]statusconfig\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1719-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI talkback.cgi directory traversal attempt"
  http /.*[\/\\]talkbalk\.cgi/
  tcp-state established,originator
  payload /.*[aA][rR][tT][iI][cC][lL][eE]=\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1720-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI talkback.cgi access"
  http /.*[\/\\]talkbalk\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1721-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI adcycle access"
  http /.*[\/\\]adcycle/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1722-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI MachineInfo access"
  http /.*[\/\\]MachineInfo/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1723-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI emumail.cgi NULL attempt"
  http /.*[\/\\]emumail\.cgi/
  tcp-state established,originator
  payload /.*[tT][yY][pP][eE]=/
  payload /.*%00/
  requires-reverse-signature ! http_error
}

signature s2b-1724-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI emumail.cgi access"
  http /.*[\/\\]emumail\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1642-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI document.d2w access"
  http /.*[\/\\]document\.d2w/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1668-6 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI /cgi-bin/ access"
  http /.*[\/\\]cgi-bin[\/\\]$/
  tcp-state established,originator
  requires-reverse-signature ! http_error
  # under most conditions the root of cgi-bin should never return a list or valid document
  # tune for site specific
}

signature s2b-1669-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI /cgi-dos/ access"
  http /.*[\/\\]cgi-dos[\/\\]/
  tcp-state established,originator
  payload /.*\/[cC][gG][iI]-[dD][oO][sS]\/ [hH][tT][tT][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-1051-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI technote main.cgi file directory traversal attempt"
  http /.*[\/\\]technote[\/\\]main\.cgi/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE][nN][aA][mM][eE]=/
  payload /.*\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1052-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI technote print.cgi directory traversal attempt"
  http /.*[\/\\]technote[\/\\]print\.cgi/
  tcp-state established,originator
  payload /.*[bB][oO][aA][rR][dD]=/
  payload /.*\.\.\/\.\.\//
  payload /.*%00/
  requires-reverse-signature ! http_error
}

signature s2b-1053-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ads.cgi command execution attempt"
  http /.*[\/\\]ads\.cgi/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE]=/
  payload /.*\.\.\/\.\.\//
  payload /.*\x7C/
  requires-reverse-signature ! http_error
}

signature s2b-1088-9 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI eXtropia webstore directory traversal"
  http /.*[\/\\]web_store\.cgi\?.*page=\.\.\//
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1089-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI shopping cart directory traversal"
  http /.*[\/\\]shop\.cgi/
  tcp-state established,originator
  payload /.*page=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1090-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Allaire Pro Web Shell attempt"
  http /.*[\/\\]authenticate\.cgi\?PASSWORD/
  tcp-state established,originator
  payload /.*config\.ini/
  requires-reverse-signature ! http_error
}

signature s2b-1092-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Armada Style Master Index directory traversal"
  http /.*[\/\\]search\.cgi\?keys/
  tcp-state established,originator
  payload /.*catigory=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1093-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cached_feed.cgi moreover shopping cart directory traversal"
  http /.*[\/\\]cached_feed\.cgi/
  tcp-state established,originator
  payload /.*\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-2051-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cached_feed.cgi moreover shopping cart access"
  http /.*[\/\\]cached_feed\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1097-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Talentsoft Web+ exploit attempt"
  http /.*[\/\\]webplus\.cgi\?Script=[\/\\]webplus[\/\\]webping[\/\\]webping\.wml/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1106-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Poll-it access"
  http /.*[\/\\]pollit[\/\\]Poll_It_SSI_v2\.0\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1865-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI webdist.cgi arbitrary command attempt"
  http /.*[\/\\]webdist\.cgi/
  tcp-state established,originator
  payload /.*[dD][iI][sS][tT][lL][oO][cC]=\x3B/
  requires-reverse-signature ! http_error
}

signature s2b-1163-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI webdist.cgi access"
  http /.*[\/\\]webdist\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1172-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bigconf.cgi access"
  http /.*[\/\\]bigconf\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1174-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI /cgi-bin/jj access"
  http /.*[\/\\]cgi-bin[\/\\]jj/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1185-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bizdbsearch attempt"
  http /.*[\/\\]bizdb1-search\.cgi/
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL]/
  requires-reverse-signature ! http_error
}

signature s2b-1535-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI bizdbsearch access"
  http /.*[\/\\]bizdb1-search\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1194-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI sojourn.cgi File attempt"
  http /.*[\/\\]sojourn\.cgi\?cat=/
  tcp-state established,originator
  payload /.*%00/
  requires-reverse-signature ! http_error
}

signature s2b-1195-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI sojourn.cgi access"
  http /.*[\/\\]sojourn\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1196-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI SGI InfoSearch fname attempt"
  http /.*[\/\\]infosrch\.cgi\?/
  tcp-state established,originator
  payload /.*[fF][nN][aA][mM][eE]=/
  requires-reverse-signature ! http_error
}

signature s2b-1727-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI SGI InfoSearch fname access"
  http /.*[\/\\]infosrch\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1204-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ax-admin.cgi access"
  http /.*[\/\\]ax-admin\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1205-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI axs.cgi access"
  http /.*[\/\\]axs\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1206-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cachemgr.cgi access"
  http /.*[\/\\]cachemgr\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1208-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI responder.cgi access"
  http /.*[\/\\]responder\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1211-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI web-map.cgi access"
  http /.*[\/\\]web-map\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1215-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ministats admin access"
  http /.*[\/\\]ministats[\/\\]admin\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1219-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI dfire.cgi access"
  http /.*[\/\\]dfire\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1305-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI txt2html.cgi directory traversal attempt"
  http /.*[\/\\]txt2html\.cgi/
  tcp-state established,originator
  payload /.*\/\.\.\/\.\.\/\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1304-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI txt2html.cgi access"
  http /.*[\/\\]txt2html\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1488-8 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI store.cgi directory traversal attempt"
  http /.*[\/\\]store\.cgi/
  tcp-state established,originator
  payload /.*\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1307-9 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI store.cgi access"
  http /.*[\/\\]store\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1494-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI SIX webboard generate.cgi attempt"
  http /.*[\/\\]generate\.cgi/
  tcp-state established,originator
  payload /.*content=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1495-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI SIX webboard generate.cgi access"
  http /.*[\/\\]generate\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1496-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI spin_client.cgi access"
  http /.*[\/\\]spin_client\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1787-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI csPassword.cgi access"
  http /.*[\/\\]csPassword\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1788-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI csPassword password.cgi.tmp access"
  http /.*[\/\\]password\.cgi\.tmp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1763-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Nortel Contivity cgiproc DOS attempt"
  http /.*[\/\\]cgiproc\?Nocfile=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1764-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Nortel Contivity cgiproc DOS attempt"
  http /.*[\/\\]cgiproc\?\x24/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1765-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Nortel Contivity cgiproc access"
  http /.*[\/\\]cgiproc/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1805-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Oracle reports CGI access"
  http /.*[\/\\]rwcgi60/
  tcp-state established,originator
  payload /.*setauth=/
  requires-reverse-signature ! http_error
}

signature s2b-1823-7 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI AlienForm af.cgi directory traversal attempt"
  http /.*[\/\\](af|alienform)\.cgi\?.*\.\|\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1868-5 {
  ip-proto == tcp
  dst-port == 8080
  event "WEB-CGI story.pl arbitrary file read attempt"
  http /.*[\/\\]story\.pl/
  tcp-state established,originator
  payload /.*next=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1869-5 {
  ip-proto == tcp
  dst-port == 8080
  event "WEB-CGI story.pl access"
  http /.*[\/\\]story\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1870-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI siteUserMod.cgi access"
  http /.*[\/\\]\.cobalt[\/\\]siteUserMod[\/\\]siteUserMod\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1875-4 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI cgicso access"
  http /.*[\/\\]cgicso/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1876-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI nph-publish.cgi access"
  http /.*[\/\\]nph-publish\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1877-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI printenv access"
  http /.*\/cgi-bin[^\/]*\/printenv/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1878-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI sdbsearch.cgi access"
  http /.*[\/\\]sdbsearch\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1931-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI rpc-nlog.pl access"
  http /.*[\/\\]rpc-nlog\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1932-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI rpc-smb.pl access"
  http /.*[\/\\]rpc-smb\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1994-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI vpasswd.cgi access"
  http /.*[\/\\]vpasswd\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1995-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI alya.cgi access"
  http /.*[\/\\]alya\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1996-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI viralator.cgi access"
  http /.*[\/\\]viralator\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2001-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI smartsearch.cgi access"
  http /.*[\/\\]smartsearch\.cgi.*\|/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1862-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI mrtg.cgi directory traversal attempt"
  http /.*[\/\\]mrtg\.cgi/
  tcp-state established,originator
  payload /.*cfg=\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-2052-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI overflow.cgi access"
  http /.*[\/\\]overflow\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1850-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI way-board.cgi access"
  http /.*[\/\\]way-board\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2054-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI enter_bug.cgi arbitrary command attempt"
  http /.*[\/\\]enter_bug\.cgi/
  tcp-state established,originator
  payload /.*[wW][hH][oO]=.*.*\x3B/
  requires-reverse-signature ! http_error
}

signature s2b-2085-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI parse_xml.cgi access"
  http /.*[\/\\]parse_xml\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2086-4 {
  ip-proto == tcp
  dst-port == 1220
  event "WEB-CGI streaming server parse_xml.cgi access"
  tcp-state established,originator
  payload /.*\/[pP][aA][rR][sS][eE]_[xX][mM][lL]\.[cC][gG][iI]/
  requires-reverse-signature ! http_error
}

signature s2b-2115-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI album.pl access"
  tcp-state established,originator
  payload /.*\/[aA][lL][bB][uU][mM]\.[pP][lL]/
  requires-reverse-signature ! http_error
}

signature s2b-2116-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI chipcfg.cgi access"
  http /.*[\/\\]chipcfg\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2127-1 {
  ip-proto == tcp
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-CGI ikonboard.cgi access"
  http /.*[\/\\]ikonboard\.cgi/
  payload /Cookie: [^\=]{1,}\=\/[^\x0D\x0A]{2,}\x0D\x0A\x0D\x0A/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2128-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI swsrv.cgi access"
  http /.*[\/\\]srsrv\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2194-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI CSMailto.cgi access"
  http /.*[\/\\]CSMailto\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2195-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI alert.cgi access"
  http /.*[\/\\]alert\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2197-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cvsview2.cgi access"
  http /.*[\/\\]cvsview2\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2198-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI cvslog.cgi access"
  http /.*[\/\\]cvslog\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2199-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI multidiff.cgi access"
  http /.*[\/\\]multidiff\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2200-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI dnewsweb.cgi access"
  http /.*[\/\\]dnewsweb\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2201-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI download.cgi access"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /.*[\/\\]download\.cgi.*f\x3d\x2e\x2e\x2f.* /
}

signature s2b-2202-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI edit_action.cgi access"
  http /.*[\/\\]edit_action\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2203-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI everythingform.cgi access"
  http /.*[\/\\]everythingform\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2204-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ezadmin.cgi access"
  http /.*[\/\\]ezadmin\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2206-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ezman.cgi access"
  http /.*[\/\\]ezman\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2207-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI fileseek.cgi access"
  http /.*[\/\\]fileseek\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2208-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI fom.cgi access"
  http /.*[\/\\]fom\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2209-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI getdoc.cgi access"
  http /.*[\/\\]getdoc\.cgi\?.*form-attachment.*command/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2210-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI global.cgi access"
  http /.*[\/\\]global\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2211-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI guestserver.cgi access"
  http /.*[\/\\]guestserver\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2212-6 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI imageFolio.cgi access"
  http /.*[\/\\]imageFolio\.cgi\?.*<script>/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2213-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI mailfile.cgi access"
  http /.*[\/\\]mailfile\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2214-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI mailview.cgi access"
  http /.*[\/\\]mailview\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2215-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI nsManager.cgi access"
  http /.*[\/\\]nsManager\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2216-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI readmail.cgi access"
  http /.*[\/\\]readmail\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2217-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI printmail.cgi access"
  http /.*[\/\\]printmail\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2218-6 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-CGI service.cgi access"
  http /.*[\/\\]service\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2219-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI setpasswd.cgi access"
  http /.*[\/\\]setpasswd\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2220-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI simplestmail.cgi access"
  http /.*[\/\\]simplestmail\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2221-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI ws_mail.cgi access"
  http /.*[\/\\]ws_mail\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2222-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI nph-exploitscanget.cgi access"
  http /.*[\/\\]nph-exploitscanget\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2224-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI psunami.cgi access"
  http /.*[\/\\]psunami\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2225-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI gozila.cgi access"
  http /.*[\/\\]gozila\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2323-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI quickstore.cgi access"
  http /.*[\/\\]quickstore\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2387-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI view_broadcast.cgi access"
  http /.*[\/\\]view_broadcast\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2388-4 {
  ip-proto == tcp
  dst-port == 1220
  event "WEB-CGI streaming server view_broadcast.cgi access"
  http /.*[\/\\]view_broadcast\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2396-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI CCBill whereami.cgi arbitrary command execution attempt"
  http /.*[\/\\]whereami\.cgi\?g=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2397-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI CCBill whereami.cgi access"
  http /.*[\/\\]whereami\.cgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2433-1 {
  ip-proto == tcp
  dst-port == 3000
  # Not supported: pcre: /\Wfrom=[^\x3b&\n]{100}/si
  event "WEB-CGI MDaemon form2raw.cgi overflow attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /[^a-zA-Z0-9_][fF][rR][oO][mM]=[^\x3b&\n]{100}/
}

signature s2b-2434-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI MDaemon form2raw.cgi access"
  tcp-state established,originator
  payload /.*\/[fF][oO][rR][mM]2[rR][aA][wW]\.[cC][gG][iI]/
  requires-reverse-signature ! http_error
}

signature s2b-2567-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Emumail init.emu access"
  http /.*[\/\\]init\.emu/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2568-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CGI Emumail emumail.fcgi access"
  http /.*[\/\\]emumail\.fcgi\?./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1735-4 {
  ip-proto == tcp
  src-port == http_ports
  event "WEB-CLIENT XMLHttpRequest attempt"
  tcp-state established,responder
  payload /.*new XMLHttpRequest\x28/
  payload /.*[fF][iI][lL][eE]\x3A\/\//
}

signature s2b-1284-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-CLIENT readme.eml download attempt"
  http /.*[\/\\]readme\.eml/
  tcp-state established,originator
  requires-signature http_msie_client
}

signature s2b-1840-5 {
  ip-proto == tcp
  src-port == http_ports
  event "WEB-CLIENT Javascript document.domain attempt"
  tcp-state established,responder
  payload /.*[dD][oO][cC][uU][mM][eE][nN][tT]\.[dD][oO][mM][aA][iI][nN]\x28/
  requires-signature http_msie_client
}

signature s2b-1841-5 {
  ip-proto == tcp
  src-port == http_ports
  event "WEB-CLIENT Javascript URL host spoofing attempt"
  tcp-state established,responder
  payload /.*[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]\x3A\/\//
  requires-signature http_old_gecko_client
}

signature s2b-2437-5 {
  ip-proto == tcp
  src-port == http_ports
  # Not supported: pcre: /^Content-Type\x3a\s+application\x2fsmi.*?<area[\s\n\r]+href=[\x22\x27]file\x3ajavascript\x3a/smi
  event "WEB-CLIENT RealPlayer arbitrary javascript command attempt"
  tcp-state established,responder
  http /((^)|(\n+))[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]\x3a[\x20\x09\x0b][aA][pP][pP][lL][iI][cC][aA][tT][iI][oO][nN]\x2f[sS][mM][iI].*?<[aA][rR][eE][aA][\x20\x09\x0b\n\r]+href=[\x22\x27][fF][iI][lL][eE]\x3ajavascript\x3a/
  requires-signature http_real_client
}

signature s2b-2438-3 {
  ip-proto == tcp
  src-port == http_ports
  # Not supported: pcre: /^file\x3a\x2f\x2f[^\n]{400}/smi
  # Not supported: flowbits: isset,realplayer.playlist
  event "WEB-CLIENT RealPlayer playlist file URL overflow attempt"
  tcp-state established,responder
  payload /((^)|(\n+))[fF][iI][lL][eE]\x3a\x2f\x2f[^\n]{400}/
}

signature s2b-2439-3 {
  ip-proto == tcp
  src-port == http_ports
  # Not supported: pcre: /^http\x3a\x2f\x2f[^\n]{400}/smi
  # Not supported: flowbits: isset,realplayer.playlist
  event "WEB-CLIENT RealPlayer playlist http URL overflow attempt"
  tcp-state established,responder
  payload /.*[hH][tT][tT][pP]\x3A\/\//
  payload /((^)|(\n+))[hH][tT]{2}[pP]\x3a\x2f\x2f[^\n]{400}/
}

signature s2b-2440-3 {
  ip-proto == tcp
  src-port == http_ports
  # Not supported: pcre: /^http\x3a\x2f\x2f[^\n]{400}/smi
  # Not supported: flowbits: isset,realplayer.playlist
  event "WEB-CLIENT RealPlayer playlist rtsp URL overflow attempt"
  tcp-state established,responder
  payload /.*[rR][tT][sS][pP]\x3A\/\//
  payload /((^)|(\n+))[hH][tT]{2}[pP]\x3a\x2f\x2f[^\n]{400}/
}

signature s2b-2485-4 {
  ip-proto == tcp
  src-port == http_ports
  event "WEB-CLIENT Nortan antivirus sysmspam.dll load attempt"
  tcp-state established,responder
  payload /.*[cC][lL][sS][iI][dD]\x3A/
  payload /.*0534[cC][fF]61-83[cC]5-4765-[bB]19[bB]-45[fF]7[aA]4[eE]135[dD]0/
}

signature s2b-903-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION cfcache.map access"
  http /.*[\/\\]cfcache\.map/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-904-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION exampleapp application.cfm"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]email[\/\\]application\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-905-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION application.cfm access"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]publish[\/\\]admin[\/\\]application\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-906-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION getfile.cfm access"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]email[\/\\]getfile\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-907-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION addcontent.cfm access"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]publish[\/\\]admin[\/\\]addcontent\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-908-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION administrator access"
  http /.*[\/\\]cfide[\/\\]administrator[\/\\]index\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-909-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION datasource username attempt"
  tcp-state established,originator
  payload /.*[cC][fF]_[sS][eE][tT][dD][aA][tT][aA][sS][oO][uU][rR][cC][eE][uU][sS][eE][rR][nN][aA][mM][eE]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-910-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION fileexists.cfm access"
  http /.*[\/\\]cfdocs[\/\\]snippets[\/\\]fileexists\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-911-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION exprcalc access"
  http /.*[\/\\]cfdocs[\/\\]expeval[\/\\]exprcalc\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-912-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION parks access"
  http /.*[\/\\]cfdocs[\/\\]examples[\/\\]parks[\/\\]detail\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-913-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION cfappman access"
  http /.*[\/\\]cfappman[\/\\]index\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-914-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION beaninfo access"
  http /.*[\/\\]cfdocs[\/\\]examples[\/\\]cvbeans[\/\\]beaninfo\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-915-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION evaluate.cfm access"
  http /.*[\/\\]cfdocs[\/\\]snippets[\/\\]evaluate\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-916-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION getodbcdsn access"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[gG][eE][tT][oO][dD][bB][cC][dD][sS][nN]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-917-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION db connections flush attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[dD][bB][cC][oO][nN][nN][eE][cC][tT][iI][oO][nN][sS]_[fF][lL][uU][sS][hH]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-918-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION expeval access"
  http /.*[\/\\]cfdocs[\/\\]expeval[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-919-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION datasource passwordattempt"
  tcp-state established,originator
  payload /.*[cC][fF]_[sS][eE][tT][dD][aA][tT][aA][sS][oO][uU][rR][cC][eE][pP][aA][sS][sS][wW][oO][rR][dD]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-920-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION datasource attempt"
  tcp-state established,originator
  payload /.*[cC][fF]_[iI][sS][cC][oO][lL][dD][fF][uU][sS][iI][oO][nN][dD][aA][tT][aA][sS][oO][uU][rR][cC][eE]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-921-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION admin encrypt attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[eE][nN][cC][rR][yY][pP][tT]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-922-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION displayfile access"
  http /.*[\/\\]cfdocs[\/\\]expeval[\/\\]displayopenedfile\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-923-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION getodbcin attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[gG][eE][tT][oO][dD][bB][cC][iI][nN][iI]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-924-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION admin decrypt attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[dD][eE][cC][rR][yY][pP][tT]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-925-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION mainframeset access"
  http /.*[\/\\]cfdocs[\/\\]examples[\/\\]mainframeset\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-926-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION set odbc ini attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[sS][eE][tT][oO][dD][bB][cC][iI][nN][iI]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-927-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION settings refresh attempt"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[sS][eE][tT][tT][iI][nN][gG][sS]_[rR][eE][fF][rR][eE][sS][hH]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-928-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION exampleapp access"
  http /.*[\/\\]cfdocs[\/\\]exampleapp[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-929-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION CFUSION_VERIFYMAIL access"
  tcp-state established,originator
  payload /.*[cC][fF][uU][sS][iI][oO][nN]_[vV][eE][rR][iI][fF][yY][mM][aA][iI][lL]\x28\x29/
  requires-reverse-signature ! http_error
}

signature s2b-930-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION snippets attempt"
  http /.*[\/\\]cfdocs[\/\\]snippets[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-931-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION cfmlsyntaxcheck.cfm access"
  http /.*[\/\\]cfdocs[\/\\]cfmlsyntaxcheck\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-932-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION application.cfm access"
  http /.*[\/\\]application\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-933-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION onrequestend.cfm access"
  http /.*[\/\\]onrequestend\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-935-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION startstop DOS access"
  http /.*[\/\\]cfide[\/\\]administrator[\/\\]startstop\.html/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-936-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION gettempdirectory.cfm access "
  http /.*[\/\\]cfdocs[\/\\]snippets[\/\\]gettempdirectory\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1659-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-COLDFUSION sendmail.cfm access"
  http /.*[\/\\]sendmail\.cfm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1248-13 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE rad fp30reg.dll access"
  http /.*[\/\\]fp30reg\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1249-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE frontpage rad fp4areg.dll access"
  http /.*[\/\\]fp4areg\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-937-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE _vti_rpc access"
  http /.*[\/\\]_vti_rpc/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-939-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE posting"
  http /.*[\/\\]author\.dll/
  tcp-state established,originator
  payload /.*[pP][oO][sS][tT]/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-940-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE shtml.dll access"
  http /.*[\/\\]_vti_bin[\/\\]shtml\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-941-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE contents.htm access"
  http /.*[\/\\]admcgi[\/\\]contents\.htm/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-942-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE orders.htm access"
  http /.*[\/\\]_private[\/\\]orders\.htm/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-943-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE fpsrvadm.exe access"
  http /.*[\/\\]fpsrvadm\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-944-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE fpremadm.exe access"
  http /.*[\/\\]fpremadm\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-945-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE fpadmin.htm access"
  http /.*[\/\\]admisapi[\/\\]fpadmin\.htm/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-946-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE fpadmcgi.exe access"
  http /.*[\/\\]scripts[\/\\]Fpadmcgi\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-947-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE orders.txt access"
  http /.*[\/\\]_private[\/\\]orders\.txt/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-948-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE form_results access"
  http /.*[\/\\]_private[\/\\]form_results\.txt/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-949-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE registrations.htm access"
  http /.*[\/\\]_private[\/\\]registrations\.htm/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-950-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE cfgwiz.exe access"
  http /.*[\/\\]cfgwiz\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-951-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE authors.pwd access"
  http /.*[\/\\]authors\.pwd/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-952-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE author.exe access"
  http /.*[\/\\]_vti_bin[\/\\]_vti_aut[\/\\]author\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-953-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE administrators.pwd access"
  http /.*[\/\\]administrators\.pwd/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-954-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE form_results.htm access"
  http /.*[\/\\]_private[\/\\]form_results\.htm/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-955-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE access.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]access\.cnf/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-956-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE register.txt access"
  http /.*[\/\\]_private[\/\\]register\.txt/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-957-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE registrations.txt access"
  http /.*[\/\\]_private[\/\\]registrations\.txt/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-958-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE service.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]service\.cnf/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-959-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE service.pwd"
  http /.*[\/\\]service\.pwd/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-960-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE service.stp access"
  http /.*[\/\\]_vti_pvt[\/\\]service\.stp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-961-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE services.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]services\.cnf/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-962-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE shtml.exe access"
  http /.*[\/\\]_vti_bin[\/\\]shtml\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-963-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE svcacl.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]svcacl\.cnf/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-964-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE users.pwd access"
  http /.*[\/\\]users\.pwd/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-965-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE writeto.cnf access"
  http /.*[\/\\]_vti_pvt[\/\\]writeto\.cnf/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-966-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE .... request"
  http /.*\.\.\.\.[\/\\]/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-967-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE dvwssr.dll access"
  http /.*[\/\\]dvwssr\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-968-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE register.htm access"
  http /.*[\/\\]_private[\/\\]register\.htm/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1288-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-FRONTPAGE /_vti_bin/ access"
  http /.*[\/\\]_vti_bin[\/\\]/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1970-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS MDAC Content-Type overflow attempt"
  http /.*[\/\\]msadcs\.dll/
  tcp-state established,originator
  payload /.*[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]\x3A[^\x0A]{50}/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1076-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS repost.asp access"
  http /.*[\/\\]scripts[\/\\]repost\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1806-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS .htr chunked Transfer-Encoding"
  http /.*\.htr/
  tcp-state established,originator
  payload /.*[tT][rR][aA][nN][sS][fF][eE][rR]-[eE][nN][cC][oO][dD][iI][nN][gG]\x3A/
  payload /.*[cC][hH][uU][nN][kK][eE][dD]/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1618-14 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS .asp chunked Transfer-Encoding"
  http /.*\.asp/
  tcp-state established,originator
  payload /.*[tT][rR][aA][nN][sS][fF][eE][rR]-[eE][nN][cC][oO][dD][iI][nN][gG]\x3A/
  payload /.*[cC][hH][uU][nN][kK][eE][dD]/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1626-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS /StoreCSVS/InstantOrder.asmx request"
  http /.*[\/\\]StoreCSVS[\/\\]InstantOrder\.asmx/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1750-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS users.xml access"
  http /.*[\/\\]users\.xml/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1753-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS as_web.exe access"
  http /.*[\/\\]as_web\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1754-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS as_web4.exe access"
  http /.*[\/\\]as_web4\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1756-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS NewsPro administration authentication attempt"
  tcp-state established,originator
  payload /.*logged,true/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1772-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS pbserver access"
  http /.*[\/\\]pbserver[\/\\]pbserver\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1660-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS trace.axd access"
  http /.*[\/\\]trace\.axd/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1484-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS /isapi/tstisapi.dll access"
  http /.*[\/\\]isapi[\/\\]tstisapi\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1485-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS mkilog.exe access"
  http /.*[\/\\]mkilog\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1486-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ctss.idc access"
  http /.*[\/\\]ctss\.idc/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1487-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS /iisadmpwd/aexp2.htr access"
  http /.*[\/\\]iisadmpwd[\/\\]aexp2\.htr/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-969-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS WebDAV file lock attempt"
  tcp-state established,originator
  payload /LOCK /
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-971-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ISAPI .printer access"
  http /.*\.printer/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1243-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ISAPI .ida attempt"
  http /.*\.ida\?/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1242-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ISAPI .ida access"
  http /.*\.ida/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1244-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ISAPI .idq attempt"
  http /.*\.idq\?/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1245-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ISAPI .idq access"
  http /.*\.idq/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-973-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS *.idc attempt"
  http /.*[\/\\]\*\.idc/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-974-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS Directory transversal attempt"
  tcp-state established,originator
  payload /.*\.\.\x5C\.\./
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-975-12 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS Alternate Data streams ASP file access attempt"
  http /.*\.asp\x3A\x3A\x24DATA/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-976-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS .bat? access"
  http /.*\.bat\?/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-977-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS .cnf access"
  http /.*\.cnf/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-978-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ASP contents view"
  tcp-state established,originator
  payload /.*%20/
  payload /.*&[cC][iI][rR][eE][sS][tT][rR][iI][cC][tT][iI][oO][nN]=[nN][oO][nN][eE]/
  payload /.*&[cC][iI][hH][iI][lL][iI][tT][eE][tT][yY][pP][eE]=[fF][uU][lL][lL]/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-979-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ASP contents view"
  http /.*\.htw\?CiWebHitsFile/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-980-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS CGImail.exe access"
  http /.*[\/\\]scripts[\/\\]CGImail\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-981-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS unicode directory traversal attempt"
  tcp-state established,originator
  payload /.*\/\.\.%[cC]0%[aA][fF]\.\.\//
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-982-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS unicode directory traversal attempt"
  tcp-state established,originator
  payload /.*\/\.\.%[cC]1%1[cC]\.\.\//
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-983-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS unicode directory traversal attempt"
  tcp-state established,originator
  payload /.*\/\.\.%[cC]1%9[cC]\.\.\//
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1945-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS unicode directory traversal attempt"
  tcp-state established,originator
  payload /.*\/\.\.%255[cC]\.\./
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-986-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS MSProxy access"
  http /.*[\/\\]scripts[\/\\]proxy[\/\\]w3proxy\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1725-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS +.htr code fragment attempt"
  http /.*\+\.htr/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-987-12 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS .htr access"
  http /.*\.htr/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-988-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS SAM Attempt"
  tcp-state established,originator
  payload /.*[sS][aA][mM]\._/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-989-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS Unicode2.pl script File permission canonicalization"
  http /.*[\/\\]sensepost\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-990-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS _vti_inf access"
  http /.*_vti_inf\.html/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-991-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS achg.htr access"
  http /.*[\/\\]iisadmpwd[\/\\]achg\.htr/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-994-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS /scripts/iisadmin/default.htm access"
  http /.*[\/\\]scripts[\/\\]iisadmin[\/\\]default\.htm/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-995-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ism.dll access"
  http /.*[\/\\]scripts[\/\\]iisadmin[\/\\]ism\.dll\?http[\/\\]dir/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-996-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS anot.htr access"
  http /.*[\/\\]iisadmpwd[\/\\]anot/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-997-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS asp-dot attempt"
  http /.*\.asp\./
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-998-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS asp-srch attempt"
  http /.*\x23filename=\*\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1000-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS bdir.htr access"
  http /.*[\/\\]bdir\.htr/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1661-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS cmd32.exe access"
  tcp-state established,originator
  payload /.*[cC][mM][dD]32\.[eE][xX][eE]/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1002-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS cmd.exe access"
  tcp-state established,originator
  payload /.*[cC][mM][dD]\.[eE][xX][eE]/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1003-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS cmd? access"
  tcp-state established,originator
  payload /.*\.[cC][mM][dD]\?&/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1007-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS cross-site scripting attempt"
  http /.*[\/\\]Form_JScript\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1380-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS cross-site scripting attempt"
  http /.*[\/\\]Form_VBScript\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1008-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS del attempt"
  tcp-state established,originator
  payload /.*&[dD][eE][lL]\+\/[sS]\+[cC]\x3A\x5C\*\.\*/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1009-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS directory listing"
  http /.*[\/\\]ServerVariables_Jscript\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1010-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS encoding access"
  tcp-state established,originator
  payload /.*%1u/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1011-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS exec-src access"
  tcp-state established,originator
  payload /.*\x23[fF][iI][lL][eE][nN][aA][mM][eE]=\*\.[eE][xX][eE]/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1012-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS fpcount attempt"
  http /.*[\/\\]fpcount\.exe/
  tcp-state established,originator
  payload /.*[dD][iI][gG][iI][tT][sS]=/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1013-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS fpcount access"
  http /.*[\/\\]fpcount\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1015-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS getdrvs.exe access"
  http /.*[\/\\]scripts[\/\\]tools[\/\\]getdrvs\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1016-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS global.asa access"
  http /.*[\/\\]global\.asa/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1017-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS idc-srch attempt"
  tcp-state established,originator
  payload /.*\x23[fF][iI][lL][eE][nN][aA][mM][eE]=\*\.[iI][dD][cC]/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1018-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS iisadmpwd attempt"
  http /.*[\/\\]iisadmpwd[\/\\]aexp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1019-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS index server file source code attempt"
  http /.*\?CiWebHitsFile=[\/\\]/
  tcp-state established,originator
  payload /.*&CiRestriction=none&CiHiliteType=Full/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1020-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS isc$data attempt"
  http /.*\.idc\x3A\x3A\x24data/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1021-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS ism.dll attempt"
  http /.* \.htr/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1022-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS jet vba access"
  http /.*[\/\\]advworks[\/\\]equipment[\/\\]catalog_type\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1023-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS msadcs.dll access"
  http /.*[\/\\]msadcs\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1024-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS newdsn.exe access"
  http /.*[\/\\]scripts[\/\\]tools[\/\\]newdsn\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1025-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS perl access"
  http /.*[\/\\]scripts[\/\\]perl/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1026-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS perl-browse newline attempt"
  http /.*\x0A\.pl/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1027-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS perl-browse space attempt"
  http /.* \.pl/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1029-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS scripts-browse access"
  http /.*[\/\\]scripts[\/\\] /
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1030-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS search97.vts access"
  http /.*[\/\\]search97\.vts/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1037-10 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-IIS showcode.asp access"
  http /.*[\/\\]showcode\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1038-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS site server config access"
  http /.*[\/\\]adsamples[\/\\]config[\/\\]site\.csc/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1039-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS srch.htm access"
  http /.*[\/\\]samples[\/\\]isapi[\/\\]srch\.htm/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1040-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS srchadm access"
  http /.*[\/\\]srchadm/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1041-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS uploadn.asp access"
  http /.*[\/\\]scripts[\/\\]uploadn\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1042-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS view source via translate header"
  tcp-state established,originator
  payload /.*[tT][rR][aA][nN][sS][lL][aA][tT][eE]\x3A [fF]/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1043-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS viewcode.asp access"
  http /.*[\/\\]viewcode\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1044-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS webhits access"
  http /.*\.htw/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1726-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS doctodep.btr access"
  http /.*doctodep\.btr/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1046-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS site/iisamples access"
  http /.*[\/\\]site[\/\\]iisamples/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1256-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS CodeRed v2 root.exe access"
  http /.*[\/\\]root\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1283-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS outlook web dos"
  http /.*[\/\\]exchange[\/\\]LogonFrm\.asp\?/
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL][bB][oO][xX]=/
  payload /.*%%%/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1400-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS /scripts/samples/ access"
  http /.*[\/\\]scripts[\/\\]samples[\/\\]/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1401-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS /msadc/samples/ access"
  http /.*[\/\\]msadc[\/\\]samples[\/\\]/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1402-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS iissamples access"
  http /.*[\/\\]iissamples[\/\\]/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-993-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS iisadmin access"
  http /.*[\/\\]iisadmin/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1285-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS msdac access"
  http /.*[\/\\]msdac[\/\\]/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1286-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS _mem_bin access"
  http /.*[\/\\]_mem_bin[\/\\]/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1595-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS htimage.exe access"
  http /.*[\/\\]htimage\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1817-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS MS Site Server default login attempt"
  http /.*[\/\\]SiteServer[\/\\]Admin[\/\\]knowledge[\/\\]persmbr[\/\\]/
  tcp-state established,originator
  payload /.*[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]\x3A [bB][aA][sS][iI][cC] [tT][eE][rR][bB][uU][fF]9[bB][bB][mM]9[uU][eE][wW]1[vV][dD][xX][mM]6[tT][gG][rR][hH][cC][fF][bB][hH][cC]3[nN]3[bB]3[jJ][kK][xX][zZ][eE]=/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1818-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS MS Site Server admin attempt"
  http /.*[\/\\]Site Server[\/\\]Admin[\/\\]knowledge[\/\\]persmbr[\/\\]/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1075-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS postinfo.asp access"
  http /.*[\/\\]scripts[\/\\]postinfo\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1567-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS /exchange/root.asp attempt"
  http /.*[\/\\]exchange[\/\\]root\.asp\?acs=anon/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1568-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS /exchange/root.asp access"
  http /.*[\/\\]exchange[\/\\]root\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2090-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS WEBDAV exploit attempt"
  tcp-state established,originator
  payload /.*HTTP\/1\.1\x0AContent-type\x3A text\/xml\x0AHOST\x3A.{1}.*Accept\x3A \*\/\*\x0ATranslate\x3A f\x0AContent-length\x3A5276\x0A\x0A/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2091-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS WEBDAV nessus safe scan attempt"
  tcp-state established,originator
  payload /.*SEARCH \/ HTTP\/1\.1\x0D\x0AHost\x3A.{0,251}\x0D\x0A\x0D\x0A/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2117-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS Battleaxe Forum login.asp access"
  http /.*myaccount[\/\\]login\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2129-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS nsiislog.dll access"
  http /.*[\/\\]nsiislog\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2130-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS IISProtect siteadmin.asp access"
  http /.*[\/\\]iisprotect[\/\\]admin[\/\\]SiteAdmin\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2157-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS IISProtect globaladmin.asp access"
  http /.*[\/\\]iisprotect[\/\\]admin[\/\\]GlobalAdmin\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2131-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS IISProtect access"
  http /.*[\/\\]iisprotect[\/\\]admin[\/\\]/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2132-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS Synchrologic Email Accelerator userid list access attempt"
  http /.*[\/\\]en[\/\\]admin[\/\\]aggregate\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2133-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS MS BizTalk server access"
  http /.*[\/\\]biztalkhttpreceive\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2134-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS register.asp access"
  http /.*[\/\\]register\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2247-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS UploadScript11.asp access"
  http /.*[\/\\]UploadScript11\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2248-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS DirectoryListing.asp access"
  http /.*[\/\\]DirectoryListing\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2249-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS /pcadmin/login.asp access"
  http /.*[\/\\]pcadmin[\/\\]login\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2321-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS foxweb.exe access"
  http /.*[\/\\]foxweb\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2322-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS foxweb.dll access"
  http /.*[\/\\]foxweb\.dll/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2324-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS VP-ASP shopsearch.asp access"
  http /.*[\/\\]shopsearch\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2325-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS VP-ASP ShopDisplayProducts.asp access"
  http /.*[\/\\]ShopDisplayProducts\.asp/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2326-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS sgdynamo.exe access"
  http /.*[\/\\]sgdynamo\.exe/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2386-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS NTLM ASN.1 vulnerability scan attempt"
  tcp-state established,originator
  payload /.*Authorization\x3A Negotiate YIQAAABiBoMAAAYrBgEFBQKgggBTMIFQoA4wDAYKKwYBBAGCNwICCqM/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2571-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS SmarterTools SmarterMail frmGetAttachment.aspx access"
  http /.*[\/\\]frmGetAttachment\.aspx/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2572-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS SmarterTools SmarterMail login.aspx buffer overflow attempt"
  http /.*[\/\\]login\.aspx/
  tcp-state established,originator
  # Not supported: isdataat: 980,relative
  payload /.*[tT][xX][tT][uU][sS][eE][rR][nN][aA][mM][eE]=[^\x0A]{980}/
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-2573-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-IIS SmarterTools SmarterMail frmCompose.asp access"
  http /.*[\/\\]frmCompose\.aspx/
  tcp-state established,originator
  requires-signature http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1497-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cross site scripting attempt"
  tcp-state established,originator
  payload /.*<[sS][cC][rR][iI][pP][tT]>/
  requires-reverse-signature ! http_error
}

signature s2b-1667-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cross site scripting HTML Image tag set to javascript attempt"
  tcp-state established,originator
  payload /.*[iI][mM][gG] [sS][rR][cC]=[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]/
  requires-reverse-signature ! http_error
}

signature s2b-1250-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Cisco IOS HTTP configuration attempt"
  http /.*[\/\\]level[\/\\]/
  http /.*[\/\\]exec[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
  # would like to inspect contents of reply
}

signature s2b-1047-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise DOS"
  tcp-state established,originator
  payload /REVLOG \/ /
  requires-reverse-signature ! http_error
}

signature s2b-1048-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise directory listing attempt"
  tcp-state established,originator
  payload /INDEX /
  requires-reverse-signature ! http_error
}

signature s2b-1050-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC iPlanet GETPROPERTIES attempt"
  tcp-state established,originator
  payload /GETPROPERTIES/
  requires-reverse-signature ! http_error
}

signature s2b-1057-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ftp attempt"
  tcp-state established,originator
  http /.*[fF][tT][pP]\.[eE][xX][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1058-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC xp_enumdsn attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[eE][nN][uU][mM][dD][sS][nN]/
  requires-reverse-signature ! http_error
}

signature s2b-1059-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC xp_filelist attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[fF][iI][lL][eE][lL][iI][sS][tT]/
  requires-reverse-signature ! http_error
}

signature s2b-1060-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC xp_availablemedia attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[aA][vV][aA][iI][lL][aA][bB][lL][eE][mM][eE][dD][iI][aA]/
  requires-reverse-signature ! http_error
}

signature s2b-1061-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC xp_cmdshell attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[cC][mM][dD][sS][hH][eE][lL][lL]/
  requires-reverse-signature ! http_error
}

signature s2b-1062-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC nc.exe attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /.*[nN][cC]\.[eE][xX][eE]\x20.{5}/
}

signature s2b-1064-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC wsh attempt"
  tcp-state established,originator
  payload /.*[wW][sS][hH]\.[eE][xX][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1065-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC rcmd attempt"
  tcp-state established,originator
  payload /.*[rR][cC][mM][dD]\.[eE][xX][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1066-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC telnet attempt"
  tcp-state established,originator
  http /.*[tT][eE][lL][nN][eE][tT]\.[eE][xX][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1067-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC net attempt"
  tcp-state established,originator
  http /.*[^a-zA-Z0-9_.-][nN][eE][tT]\.[eE][xX][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1068-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC tftp attempt"
  tcp-state established,originator
  http /.*[tT][fF][tT][pP]\.[eE][xX][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1069-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC xp_regread attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[rR][eE][gG][rR][eE][aA][dD]/
  requires-reverse-signature ! http_error
}

signature s2b-1977-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC xp_regwrite attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[rR][eE][gG][wW][rR][iI][tT][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1978-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC xp_regdeletekey attempt"
  tcp-state established,originator
  payload /.*[xX][pP]_[rR][eE][gG][dD][eE][lL][eE][tT][eE][kK][eE][yY]/
  requires-reverse-signature ! http_error
}

signature s2b-1070-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC WebDAV search access"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /((^)|(\n+))[sS][eE][aA][rR][cC][hH]/
  requires-signature http_iis_server
}

signature s2b-1071-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC .htpasswd access"
  tcp-state established,originator
  http /.*\/\.[hH][tT][pP][aA][sS][sS][wW][dD]/
  requires-reverse-signature ! http_error
}

signature s2b-1072-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Lotus Domino directory traversal"
  http /.*\.nsf[\/\\].*(\.\.\/){1,}.{2,}/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1077-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC queryhit.htm access"
  http /.*[\/\\]samples[\/\\]search[\/\\]queryhit\.htm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1079-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC WebDAV propfind access"
  tcp-state established,originator
  payload /.*<[aA]\x3A[pP][rR][oO][pP][fF][iI][nN][dD]/
  payload /.*[xX][mM][lL][nN][sS]\x3A[aA]=\x22[dD][aA][vV]\x22>/
  requires-reverse-signature ! http_error
}

signature s2b-1080-13 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC unify eWave ServletExec upload"
  http /.*[\/\\]servlet[\/\\]com\.unify\.servletexec\.UploadServlet/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1081-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Servers suite DOS"
  http /.*[\/\\]dsgw[\/\\]bin[\/\\]search\?context=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1083-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC unify eWave ServletExec DOS"
  http /.*[\/\\]servlet[\/\\]ServletExec/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1084-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Allaire JRUN DOS attempt"
  http /.*servlet[\/\\]\.\.\.\.\.\.\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1095-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Talentsoft Web+ Source Code view access"
  http /.*[\/\\]webplus\.exe\?script=test\.wml/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1096-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Talentsoft Web+ internal IP Address access"
  http /.*[\/\\]webplus\.exe\?about/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1098-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC SmartWin CyberOffice Shopping Cart access"
  http /.*_private[\/\\]shopping_cart\.mdb/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1099-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cybercop scan"
  http /.*[\/\\]cybercop/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1100-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC L3retriever HTTP Probe"
  tcp-state established,originator
  payload /.*User-Agent\x3A Java1\.2\.1\x0D\x0A/
  requires-reverse-signature ! http_error
}

signature s2b-1101-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Webtrends HTTP probe"
  tcp-state established,originator
  payload /.*User-Agent\x3A Webtrends Security Analyzer\x0D\x0A/
  requires-reverse-signature ! http_error
}

signature s2b-1102-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Nessus 404 probe"
  http /.*[\/\\]nessus_is_probing_you_/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1103-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape admin passwd"
  http /.*[\/\\]admin-serv[\/\\]config[\/\\]admpw/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1105-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC BigBrother access"
  http /.*[\/\\]bb-hostsvc\.sh\?HOSTSVC/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1612-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ftp.pl attempt"
  http /.*[\/\\]ftp\.pl\?dir=\.\.[\/\\]\.\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1107-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ftp.pl access"
  http /.*[\/\\]ftp\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1108-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Tomcat server snoop access"
  http /.*[\/\\]jsp[\/\\]snp[\/\\]/
  http /.*\.snp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1109-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ROXEN directory list attempt"
  http /.*[\/\\]%00/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1110-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC apache source.asp file access"
  http /.*[\/\\]site[\/\\]eg[\/\\]source\.asp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1111-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Tomcat server exploit access"
  http /.*[\/\\]contextAdmin[\/\\]contextAdmin\.html/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1115-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ICQ webserver DOS"
  http /.*\.html[\/\\]\.\.\.\.\.\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1116-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Lotus DelDoc attempt"
  http /.*\?DeleteDocument/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1117-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Lotus EditDoc attempt"
  http /.*\?EditDocument/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1118-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ls%20-l"
  tcp-state established,originator
  payload /.*[lL][sS]%20-[lL]/
  requires-reverse-signature ! http_error
}

signature s2b-1119-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC mlog.phtml access"
  http /.*[\/\\]mlog\.phtml/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1120-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC mylog.phtml access"
  http /.*[\/\\]mylog\.phtml/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1122-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /etc/passwd"
  tcp-state established,originator
  payload /.*\/[eE][tT][cC]\/[sS][hH][aA][dD][oO][wW].{1,}root:.*:.*:.*:.*:.*:.*:/
  requires-reverse-signature ! http_error
}

signature s2b-1123-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ?PageServices access"
  http /.*\?PageServices/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1125-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC webcart access"
  http /.*[\/\\]webcart[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1126-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC AuthChangeUrl access"
  http /.*_AuthChangeUrl\?/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1127-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC convert.bas access"
  http /.*[\/\\]scripts[\/\\]convert\.bas/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1128-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cpshost.dll access"
  http /.*[\/\\]scripts[\/\\]cpshost\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1129-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC .htaccess access"
  tcp-state established,originator
  payload /.*\.[hH][tT][aA][cC][cC][eE][sS][sS]/
  requires-reverse-signature ! http_error
}

signature s2b-1130-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC .wwwacl access"
  http /.*\.wwwacl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1131-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC .wwwacl access"
  http /.*\.www_acl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1136-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cd.."
  tcp-state established,originator
  payload /.*[cC][dD]\.\./
  requires-reverse-signature ! http_error
}

signature s2b-1140-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC guestbook.pl access"
  http /.*[\/\\]guestbook\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1142-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /.... access"
  tcp-state established,originator
  payload /.*\/\.\.\.\./
  requires-reverse-signature ! http_error
}

signature s2b-1143-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ///cgi-bin access"
  http /.*[\/\\][\/\\][\/\\]cgi-bin/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1144-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /cgi-bin/// access"
  http /.*[\/\\]cgi-bin[\/\\][\/\\][\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1145-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /~root access"
  http /.*[\/\\]~root/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1662-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /~ftp access"
  http /.*[\/\\]~ftp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1146-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Ecommerce import.txt access"
  http /.*[\/\\]config[\/\\]import\.txt/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1147-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cat%20 access"
  tcp-state established,originator
  payload /.*[cC][aA][tT]%20/
  requires-reverse-signature ! http_error
}

signature s2b-1148-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Ecommerce import.txt access"
  http /.*[\/\\]orders[\/\\]import\.txt/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1150-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino catalog.nsf access"
  http /.*[\/\\]catalog\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1151-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino domcfg.nsf access"
  http /.*[\/\\]domcfg\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1152-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino domlog.nsf access"
  http /.*[\/\\]domlog\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1153-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino log.nsf access"
  http /.*[\/\\]log\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1154-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino names.nsf access"
  http /.*[\/\\]names\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1575-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino mab.nsf access"
  http /.*[\/\\]mab\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1576-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino cersvr.nsf access"
  http /.*[\/\\]cersvr\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1577-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino setup.nsf access"
  http /.*[\/\\]setup\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1579-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino webadmin.nsf access"
  http /.*[\/\\]webadmin\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1580-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino events4.nsf access"
  http /.*[\/\\]events4\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1581-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino ntsync4.nsf access"
  http /.*[\/\\]ntsync4\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1582-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino collect4.nsf access"
  http /.*[\/\\]collect4\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1583-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino mailw46.nsf access"
  http /.*[\/\\]mailw46\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1584-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino bookmark.nsf access"
  http /.*[\/\\]bookmark\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1585-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino agentrunner.nsf access"
  http /.*[\/\\]agentrunner\.nsf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1586-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Domino mail.box access"
  http /.*[\/\\]mail\.box/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1155-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Ecommerce checks.txt access"
  http /.*[\/\\]orders[\/\\]checks\.txt/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1156-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC apache DOS attempt"
  tcp-state established,originator
  payload /.*\/\/\/\/\/\/\/\//
  requires-signature ! http_iis_server
  requires-reverse-signature ! http_error
}

signature s2b-1157-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape PublishingXpert access"
  http /.*[\/\\]PSUser[\/\\]PSCOErrPage\.htm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1158-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC windmail.exe access"
  http /.*[\/\\]windmail\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1159-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC webplus access"
  http /.*[\/\\]webplus\?script/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1160-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape dir index wp"
  http /.*\?wp-/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1162-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cart 32 AdminPwd access"
  http /.*[\/\\]c32web\.exe[\/\\]ChangeAdminPassword/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1164-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC shopping cart access"
  http /.*[\/\\]quikstore\.cfg/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1614-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Novell Groupwise gwweb.exe attempt"
  http /.*[\/\\]GWWEB\.EXE\?HELP=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1165-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Novell Groupwise gwweb.exe access"
  tcp-state established,originator
  payload /.*\/[gG][wW][wW][eE][bB]\.[eE][xX][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1166-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ws_ftp.ini access"
  http /.*[\/\\]ws_ftp\.ini/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1167-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC rpm_query access"
  http /.*[\/\\]rpm_query/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1168-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC mall log order access"
  http /.*[\/\\]mall_log_files[\/\\]order\.log/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1173-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC architext_query.pl access"
  http /.*[\/\\]ews[\/\\]architext_query\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1175-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC wwwboard.pl access"
  http /.*[\/\\]wwwboard\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1176-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC order.log access"
  http /.*[\/\\]admin_files[\/\\]order\.log/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1177-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-verify-link/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1180-12 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC get32.exe access"
  http /.*[\/\\]get32\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1181-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Annex Terminal DOS attempt"
  http /.*[\/\\]ping\?query=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1182-17 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cgitest.exe attempt"
  http /.*[\/\\]cgitest\.exe\x0D\x0Auser/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1587-12 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cgitest.exe access"
  http /.*[\/\\]cgitest\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1183-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-cs-dump/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1184-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-ver-info/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1186-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-ver-diff/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1187-12 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC SalesLogix Eviewer web command attempt"
  http /.*[\/\\]slxweb\.dll[\/\\]admin\?command=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1588-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC SalesLogix Eviewer access"
  http /.*[\/\\]slxweb\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1188-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-start-ver/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1189-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-stop-ver/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1190-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-uncheckout/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1191-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-html-rend/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1381-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Trend Micro OfficeScan attempt"
  http /.*[\/\\]officescan[\/\\]cgi[\/\\]jdkRqNotify\.exe\?/
  http /.*domain=/
  http /.*event=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1192-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Trend Micro OfficeScan access"
  http /.*[\/\\]officescan[\/\\]cgi[\/\\]jdkRqNotify\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1193-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC oracle web arbitrary command execution attempt"
  http /.*[\/\\]ows-bin[\/\\]/
  http /.*\?&/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1880-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC oracle web application server access"
  http /.*[\/\\]ows-bin[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1198-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Netscape Enterprise Server directory view"
  http /.*\?wp-usr-prop/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1202-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC search.vts access"
  http /.*[\/\\]search\.vts/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1615-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC htgrep attempt"
  http /.*[\/\\]htgrep/
  tcp-state established,originator
  payload /.*hdr=\//
  requires-reverse-signature ! http_error
}

signature s2b-1207-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC htgrep access"
  http /.*[\/\\]htgrep/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1209-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC .nsconfig access"
  http /.*[\/\\]\.nsconfig/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1212-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Admin_files access"
  http /.*[\/\\]admin_files/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1213-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC backup access"
  http /.*[\/\\]backup/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1216-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC filemail access"
  http /.*[\/\\]filemail/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1217-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC plusmail access"
  http /.*[\/\\]plusmail/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1218-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC adminlogin access"
  http /.*[\/\\]adminlogin/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1220-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ultraboard access"
  http /.*[\/\\]ultraboard/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1589-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC musicat empower attempt"
  http /.*[\/\\]empower\?DB=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1221-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC musicat empower access"
  http /.*[\/\\]empower\?DB=.{1,}/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1224-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ROADS search.pl attempt"
  http /.*[\/\\]ROADS[\/\\]cgi-bin[\/\\]search\.pl/
  tcp-state established,originator
  payload /.*[fF][oO][rR][mM]=/
  requires-reverse-signature ! http_error
}

signature s2b-1230-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC VirusWall FtpSave access"
  http /.*[\/\\]FtpSave\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1234-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC VirusWall FtpSaveCSP access"
  http /.*[\/\\]FtpSaveCSP\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1235-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC VirusWall FtpSaveCVP access"
  http /.*[\/\\]FtpSaveCVP\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1054-7 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /^\w+\s+[^\n\s\?]*\.jsp/smi
  event "WEB-MISC weblogic/tomcat .jsp view source attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /((^)|(\n+))[a-zA-Z0-9_]+[\x20\x09\x0b]+[^\n\x20\x09\x0b\?]*\.[jJ][sS][pP]/
}

signature s2b-1241-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC SWEditServlet directory traversal attempt"
  http /.*[\/\\]SWEditServlet/
  tcp-state established,originator
  payload /.*template=\.\.\/\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1259-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC SWEditServlet access"
  http /.*[\/\\]SWEditServlet/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1139-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC whisker HEAD/./"
  tcp-state established,originator
  payload /.*HEAD\/\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1258-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC HP OpenView Manager DOS"
  http /.*[\/\\]OvCgi[\/\\]OpenView5\.exe\?Context=Snmp&Action=Snmp&Host=&Oid=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1260-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC long basic authorization string"
  tcp-state established,originator
  payload /.*[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]\x3A [bB][aA][sS][iI][cC] [^\x0A]{512}/
  requires-reverse-signature ! http_error
}

signature s2b-1291-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC sml3com access"
  http /.*[\/\\]graphics[\/\\]sml3com/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1001-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC carbo.dll access"
  http /.*[\/\\]carbo\.dll/
  tcp-state established,originator
  payload /.*[iI][cC][aA][tT][cC][oO][mM][mM][aA][nN][dD]=/
  requires-reverse-signature ! http_error
}

signature s2b-1302-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC console.exe access"
  http /.*[\/\\]cgi-bin[\/\\]console\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1303-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cs.exe access"
  http /.*[\/\\]cgi-bin[\/\\]cs\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1113-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC http directory traversal"
  tcp-state established,originator
  payload /.*\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1375-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC sadmind worm access"
  tcp-state established,originator
  payload /.{0,1}GET x HTTP\/1\.0/
  requires-reverse-signature ! http_error
}

signature s2b-1376-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC jrun directory browse attempt"
  http /.*[\/\\]\?\.jsp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1385-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC mod-plsql administration access"
  http /.*[\/\\]admin_[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1391-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Phorecast remote code execution attempt"
  tcp-state established,originator
  payload /.*includedir=/
  requires-reverse-signature ! http_error
}

signature s2b-1403-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC viewcode access"
  http /.*[\/\\]viewcode/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1433-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC .history access"
  http /.*[\/\\]\.history/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1434-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC .bash_history access"
  http /.*[\/\\]\.bash_history/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1489-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /~nobody access"
  http /.*[\/\\]~nobody/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1492-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC RBS ISP /newuser  directory traversal attempt"
  http /.*[\/\\]newuser\?Image=\.\.[\/\\]\.\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1493-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC RBS ISP /newuser access"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /.*\x3a8002.*[\/\\]newuser\x3f.*\x2e\x2e[\/\\]/
}

signature s2b-1663-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC *%0a.pl access"
  http /.*[\/\\]\*\x0A\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1664-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC mkplog.exe access"
  http /.*[\/\\]mkplog\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-509-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC PCCS mysql database admin tool access"
  tcp-state established,originator
  payload /.{0,5}[pP][cC][cC][sS][mM][yY][sS][qQ][lL][aA][dD][mM]\/[iI][nN][cC][sS]\/[dD][bB][cC][oO][nN][nN][eE][cC][tT]\.[iI][nN][cC]/
  requires-reverse-signature ! http_error
}

signature s2b-1769-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC .DS_Store access"
  http /.*[\/\\]\.DS_Store/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1770-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC .FBCIndex access"
  http /.*[\/\\]\.FBCIndex/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1500-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ExAir access"
  http /.*[\/\\]exair[\/\\]search[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1519-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC apache ?M=D directory list attempt"
  http /.*[\/\\]\?M=D/
  tcp-state established,originator
  http /Content-language:.* /
  requires-reverse-signature ! http_error
  eval isApacheLt1322
}

signature s2b-1520-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC server-info access"
  http /.*[\/\\]server-info/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1522-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ans.pl attempt"
  http /.*[\/\\]ans\.pl\?p=\.\.[\/\\]\.\.[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1523-10 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ans.pl access"
  http /.*[\/\\]ans\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1524-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC AxisStorpoint CD attempt"
  http /.*[\/\\]cd[\/\\]\.\.[\/\\]config[\/\\]html[\/\\]cnf_gi\.htm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1525-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Axis Storpoint CD access"
  http /.*[\/\\]config[\/\\]html[\/\\]cnf_gi\.htm/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1526-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC basilix sendmail.inc access"
  http /.*[\/\\]inc[\/\\]sendmail\.inc/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1527-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC basilix mysql.class access"
  http /.*[\/\\]class[\/\\]mysql\.class/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1528-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC BBoard access"
  http /.*[\/\\]servlet[\/\\]sunexamples\.BBoardServlet/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1544-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Cisco Catalyst command execution attempt"
  http /.*[\/\\]exec[\/\\]show[\/\\]config[\/\\]cr/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1552-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cvsweb version access"
  http /.*[\/\\]cvsweb[\/\\]version/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1563-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC login.htm attempt"
  http /.*[\/\\]login\.htm\?password=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1603-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC DELETE attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /.{0,7}[dD][eE][lL][eE][tT][eE] /
}

signature s2b-1670-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /home/ftp access"
  http /.*[\/\\]home[\/\\]ftp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1738-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC global.inc access"
  http /.*[\/\\]global\.inc/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1744-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC SecureSite authentication bypass attempt"
  tcp-state established,originator
  payload /.*[sS][eE][cC][uU][rR][eE]_[sS][iI][tT][eE], [oO][kK]/
  requires-reverse-signature ! http_error
}

signature s2b-1757-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC b2 arbitrary command execution attempt"
  http /.*[\/\\]b2[\/\\]b2-include[\/\\]/
  tcp-state established,originator
  payload /.*b2inc/
  payload /.*http\x3A\/\//
  requires-reverse-signature ! http_error
}

signature s2b-1758-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC b2 access"
  http /.*[\/\\]b2[\/\\]b2-include[\/\\]/
  tcp-state established,originator
  payload /.*b2inc/
  payload /.*http\x3A\/\//
  requires-reverse-signature ! http_error
}

signature s2b-1766-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC search.dll directory listing attempt"
  http /.*[\/\\]search\.dll/
  tcp-state established,originator
  payload /.*query=%00/
  requires-reverse-signature ! http_error
}

signature s2b-1767-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC search.dll access"
  http /.*[\/\\]search\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
  eval isNotIIS
  eval isNotApache
}

signature s2b-1498-4 {
  ip-proto == tcp
  dst-port == 8181
  event "WEB-MISC PIX firewall manager directory traversal attempt"
  tcp-state established,originator
  payload /.*\/\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1558-5 {
  ip-proto == tcp
  dst-port == 8080
  event "WEB-MISC Delegate whois overflow attempt"
  tcp-state established,originator
  payload /.*[wW][hH][oO][iI][sS]\x3A\/\//
  requires-reverse-signature ! http_error
}

signature s2b-1518-5 {
  ip-proto == tcp
  dst-port == 8000
  event "WEB-MISC nstelemetry.adp access"
  tcp-state established,originator
  payload /.*\/nstelemetry\.adp/
  requires-reverse-signature ! http_error
}

signature s2b-1132-6 {
  ip-proto == tcp
  dst-port == 457
  event "WEB-MISC Netscape Unixware overflow"
  tcp-state established,originator
  payload /.*\xEB_\x9A\xFF\xFF\xFF\xFF\x07\xFF\xC3\^1\xC0\x89F\x9D/
  requires-reverse-signature ! http_error
}

signature s2b-1199-11 {
  ip-proto == tcp
  dst-port == 2301
  event "WEB-MISC Compaq Insight directory traversal"
  tcp-state established,originator
  payload /.*\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1231-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC VirusWall catinfo access"
  http /.*[\/\\]catinfo/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1232-8 {
  ip-proto == tcp
  dst-port == 1812
  event "WEB-MISC VirusWall catinfo access"
  tcp-state established,originator
  payload /.*\/[cC][aA][tT][iI][nN][fF][oO]/
  requires-reverse-signature ! http_error
}

signature s2b-1809-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Apache Chunked-Encoding worm attempt"
  tcp-state established,originator
  payload /.*[cC][cC][cC][cC][cC][cC][cC]\x3A [aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA][aA]/
  requires-reverse-signature ! http_error
}

signature s2b-1807-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Chunked-Encoding transfer attempt"
  tcp-state established,originator
  payload /.*[tT][rR][aA][nN][sS][fF][eE][rR]-[eE][nN][cC][oO][dD][iI][nN][gG]\x3A/
  payload /.*[cC][hH][uU][nN][kK][eE][dD]/
  requires-reverse-signature ! http_error
  eval isApacheLt1322
}

signature s2b-1814-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC CISCO VoIP DOS ATTEMPT"
  http /.*[\/\\]StreamingStatistics/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1820-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC IBM Net.Commerce orderdspc.d2w access"
  http /.*[\/\\]ncommerce3[\/\\]ExecMacro[\/\\]orderdspc\.d2w/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1826-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC WEB-INF access"
  http /.*[\/\\]WEB-INF \.\/.{1,}/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1827-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Tomcat servlet mapping cross site scripting attempt"
  http /.*[\/\\]servlet[\/\\]/
  http /.*[\/\\]org\.apache\./
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1828-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC iPlanet Search directory traversal attempt"
  http /.*[\/\\]search/
  tcp-state established,originator
  payload /.*NS-query-pat=/
  payload /.*\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1829-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Tomcat TroubleShooter servlet access"
  http /.*[\/\\]examples[\/\\]servlet[\/\\]TroubleShooter/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1830-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Tomcat SnoopServlet servlet access"
  http /.*[\/\\]examples[\/\\]servlet[\/\\]SnoopServlet/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1831-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC jigsaw dos attempt"
  http /.*[\/\\]servlet[\/\\]con/
  tcp-state established,originator
  requires-reverse-signature ! http_error
  eval isNotIIS
  eval isNotApache
}

signature s2b-1835-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Macromedia SiteSpring cross site scripting attempt"
  http /.*[\/\\]error[\/\\]500error\.jsp/
  http /.*et=/
  http /.*<script/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1839-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC mailman cross site scripting attempt"
  http /.*[\/\\]mailman[\/\\]/
  http /.*\?/
  http /.*info=/
  http /.*<script/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1848-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC webcart-lite access"
  http /.*[\/\\]webcart-lite[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1849-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC webfind.exe access"
  http /.*[\/\\]webfind\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1851-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC active.log access"
  http /.*[\/\\]active\.log/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1858-5 {
  ip-proto == tcp
  dst-port == 8181
  event "WEB-MISC CISCO PIX Firewall Manager directory traversal attempt"
  tcp-state established,originator
  payload /.*\/pixfir~1\/how_to_login\.html/
  requires-reverse-signature ! http_error
}

signature s2b-1859-5 {
  ip-proto == tcp
  dst-port == 9090
  event "WEB-MISC Sun JavaServer default password login attempt"
  tcp-state established,originator
  payload /.*\/servlet\/admin/
  payload /.*ae9f86d6beaa3f9ecb9a5b7e072a4138/
  requires-reverse-signature ! http_error
}

signature s2b-1860-4 {
  ip-proto == tcp
  dst-port == 8080
  event "WEB-MISC Linksys router default password login attempt"
  tcp-state established,originator
  payload /.*Authorization\x3A Basic OmFkbWlu/
  requires-reverse-signature ! http_error
}

signature s2b-1861-7 {
  ip-proto == tcp
  dst-port == 8080
  event "WEB-MISC Linksys router default username and password login attempt"
  tcp-state established,originator
  payload /.*[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]\x3A /
  payload /.* [bB][aA][sS][iI][cC] /
  payload /.*YWRtaW46YWRtaW4/
  requires-reverse-signature ! http_error
}

signature s2b-2230-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC NetGear router default password login attempt admin/password"
  tcp-state established,originator
  payload /.*[aA][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]\x3A /
  payload /.* [bB][aA][sS][iI][cC] /
  payload /.*YWRtaW46cGFzc3dvcmQ/
  requires-reverse-signature ! http_error
}

signature s2b-1871-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Oracle XSQLConfig.xml access"
  http /.*[\/\\]XSQLConfig\.xml/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1872-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Oracle Dynamic Monitoring Services dms access"
  http /.*[\/\\]dms0/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1873-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC globals.jsa access"
  http /.*[\/\\]globals\.jsa/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1874-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Oracle Java Process Manager access"
  http /.*[\/\\]oprocmgr-status/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1881-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC bad HTTP/1.1 request, Potential worm attack"
  tcp-state established,originator
  payload /GET \/ HTTP\/1\.1\x0D\x0A\x0D\x0A/
  requires-reverse-signature ! http_error
}

signature s2b-1104-9 {
  ip-proto == tcp
  dst-port == http_ports
  payload-size == 1
  event "WEB-MISC whisker space splice attack"
  tcp-state established,originator
  payload / /
  requires-reverse-signature ! http_error
}

signature s2b-1087-8 {
  ip-proto == tcp
  dst-port == http_ports
  payload-size < 5
  event "WEB-MISC whisker tab splice attack"
  tcp-state established,originator
  payload /.*\x09/
  requires-reverse-signature ! http_error
}

signature s2b-1808-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC apache chunked encoding memory corruption exploit attempt"
  tcp-state established,originator
  payload /.*\xC0PR\x89\xE1PQRP\xB8\x3B\x00\x00\x00\xCD\x80/
  requires-signature ! http_msie_client
  requires-reverse-signature ! http_error
}

signature s2b-1943-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /Carello/add.exe access"
  http /.*[\/\\]Carello[\/\\]add\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1944-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /ecscripts/ecware.exe access"
  http /.*[\/\\]ecscripts[\/\\]ecware\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1969-3 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-MISC ion-p remote file access"
  http /.*[\/\\]ion-p\?.*(c:\\|\.\.\/)/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1499-5 {
  ip-proto == tcp
  dst-port == 8888
  event "WEB-MISC SiteScope Service access"
  tcp-state established,originator
  payload /.*\/SiteScope\/cgi\/go\.exe\/SiteScope/
  requires-reverse-signature ! http_error
}

signature s2b-1946-3 {
  ip-proto == tcp
  dst-port == 8888
  event "WEB-MISC answerbook2 admin attempt"
  tcp-state established,originator
  payload /.*\/cgi-bin\/admin\/admin/
  requires-reverse-signature ! http_error
}

signature s2b-1947-4 {
  ip-proto == tcp
  dst-port == 8888
  event "WEB-MISC answerbook2 arbitrary command execution attempt"
  tcp-state established,originator
  payload /.*\/ab2\/.{1}.*\x3B/
  requires-reverse-signature ! http_error
}

signature s2b-2056-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC TRACE attempt"
  tcp-state established,originator
  payload /TRACE/
  requires-reverse-signature ! http_error
}

signature s2b-2057-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC helpout.exe access"
  http /.*[\/\\]helpout\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2058-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC MsmMask.exe attempt"
  http /.*[\/\\]MsmMask\.exe/
  tcp-state established,originator
  payload /.*mask=/
  requires-reverse-signature ! http_error
}

signature s2b-2060-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC DB4Web access"
  http /.*[\/\\]DB4Web[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2061-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Tomcat null byte directory listing attempt"
  http /.*\x00\.jsp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2062-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC iPlanet .perf access"
  http /.*[\/\\]\.perf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2063-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Demarc SQL injection attempt"
  http /.*[\/\\]dm[\/\\]demarc/
  tcp-state established,originator
  payload /.*s_key=.*.*'.{1}.*'.*.*'/
  requires-reverse-signature ! http_error
}

signature s2b-2064-2 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-MISC Lotus Notes .csp script source download attempt"
  http /.*\.csp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2066-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Lotus Notes .pl script source download attempt"
  http /.*\.pl/
  tcp-state established,originator
  payload /.*\.pl\./
  requires-reverse-signature ! http_error
  eval isNotApache
  eval isNotIIS
}

signature s2b-2068-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC BitKeeper arbitrary command attempt"
  http /.*[\/\\]diffs[\/\\]/
  tcp-state established,originator
  payload /.*'.*.*\x3B.{1}.*'/
  requires-reverse-signature ! http_error
}

signature s2b-2069-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC chip.ini access"
  http /.*[\/\\]chip\.ini/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2070-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC post32.exe arbitrary command attempt"
  http /.*[\/\\]post32\.exe\x7C/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2071-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC post32.exe access"
  http /.*[\/\\]post32\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2072-3 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-MISC lyris.pl admin access"
  http /POST.*[\/\\]lyris\.pl/
  payload /list_admin=[Tt]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2073-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC globals.pl access"
  http /.*[\/\\]globals\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2135-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC philboard.mdb access"
  http /.*[\/\\]philboard\.mdb/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2136-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC philboard_admin.asp authentication bypass attempt"
  http /.*[\/\\]philboard_admin\.asp/
  tcp-state established,originator
  payload /.*[cC][oO][oO][kK][iI][eE].*.*philboard_admin=True/
  requires-reverse-signature ! http_error
}

signature s2b-2137-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC philboard_admin.asp access"
  http /.*[\/\\]philboard_admin\.asp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2138-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC logicworks.ini access"
  http /.*[\/\\]logicworks\.ini/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2139-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC /*.shtml access"
  http /.*[\/\\]\*\.shtml/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2156-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC mod_gzip_status access"
  http /.*[\/\\]mod_gzip_status/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2231-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC register.dll access"
  http /.*[\/\\]register\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2232-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ContentFilter.dll access"
  http /.*[\/\\]ContentFilter\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2233-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC SFNofitication.dll access"
  http /.*[\/\\]SFNofitication\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2234-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC TOP10.dll access"
  http /.*[\/\\]TOP10\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2235-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC SpamExcp.dll access"
  http /.*[\/\\]SpamExcp\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2236-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC spamrule.dll access"
  http /.*[\/\\]spamrule\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2237-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cgiWebupdate.exe access"
  http /.*[\/\\]cgiWebupdate\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2238-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC WebLogic ConsoleHelp view source attempt"
  http /.*[\/\\]ConsoleHelp[\/\\]/
  http /.*\.jsp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2239-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC redirect.exe access"
  http /.*[\/\\]redirect\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2240-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC changepw.exe access"
  http /.*[\/\\]changepw\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2241-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC cwmail.exe access"
  http /.*[\/\\]cwmail\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2242-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ddicgi.exe access"
  http /.*[\/\\]ddicgi\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2243-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ndcgi.exe access"
  http /.*[\/\\]ndcgi\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2244-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC VsSetCookie.exe access"
  http /.*[\/\\]VsSetCookie\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2245-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Webnews.exe access"
  http /.*[\/\\]Webnews\.exe/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2246-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC webadmin.dll access"
  http /.*[\/\\]webadmin\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2276-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC oracle portal demo access"
  http /.*[\/\\]pls[\/\\]portal[\/\\]PORTAL_DEMO/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2277-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC PeopleSoft PeopleBooks psdoccgi access"
  http /.*[\/\\]psdoccgi/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2278-6 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /^Content-Length\x3a\s+-\d+/smi
  event "WEB-MISC negative Content-Length attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /((^)|(\n+))[cC][oO][nN][tT][eE][nN][tT]-[lL][eE][nN][gG][tT][hH]\x3a[\x20\x09\x0b]+-[0-9]+\/+/
}

signature s2b-2327-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC bsml.pl access"
  http /.*[\/\\]bsml\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2369-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ISAPISkeleton.dll access"
  http /.*[\/\\]ISAPISkeleton\.dll/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2370-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC BugPort config.conf file access"
  http /.*[\/\\]config\.conf/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2371-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Sample_showcode.html access"
  http /.*[\/\\]Sample_showcode\.html/
  tcp-state established,originator
  payload /.*[fF][nN][aA][mM][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-2381-5 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /^[^\/]{14,}?\x3a\/\//U
  event "WEB-MISC schema overflow attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /^[^\/]{14,}?\x3a\/\//
}

signature s2b-2395-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC InteractiveQuery.jsp access"
  http /.*[\/\\]InteractiveQuery\.jsp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2400-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC edittag.pl access"
  http /.*[\/\\]edittag\.pl/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2411-5 {
  ip-proto == tcp
  dst-port == 554
  # Not supported: pcre: /^DESCRIBE\s[^\n]{300}/smi
  event "WEB-MISC Real Server DESCRIBE buffer overflow attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /((^)|(\n+))[dD][eE][sS][cC][rR][iI][bB][eE][\x20\x09\x0b][^\n]{300}/
}

signature s2b-2441-3 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /^Cookie\x3a[^\n]*?login=0/smi
  event "WEB-MISC NetObserve authentication bypass attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /((^)|(\n+))[cC][oO][oO][kK][iI][eE]\x3a[^\n]*?[lL][oO][gG][iI][nN]=0/
}

signature s2b-2442-6 {
  ip-proto == tcp
  dst-port >= 8000
  dst-port <= 8001
  # Not supported: pcre: /^User-Agent\x3a[^\n]{244,255}/smi
  event "WEB-MISC Quicktime User-Agent buffer overflow attempt"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /((^)|(\n+))[uU][sS][eE][rR]-[aA][gG][eE][nN][tT]\x3a[^\n]{244,255}/
}

signature s2b-2484-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC source.jsp access"
  http /.*[\/\\]source\.jsp/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2447-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC ServletManager access"
  http /.*[\/\\]servlet[\/\\]ServletManager/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2448-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC setinfo.hts access"
  http /.*[\/\\]setinfo\.hts/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2505-7 {
  ip-proto == tcp
  dst-port == 443
  event "WEB-MISC SSLv3 invalid data version attempt"
  tcp-state established,originator
  payload /\x16\x03/
  payload /.{4}\x01/
  payload /.{8}[^\x03]*/
  requires-reverse-signature ! http_error
}

signature s2b-2520-5 {
  ip-proto == tcp
  dst-port == 443
  # Not supported: flowbits: isnotset,sslv3.client_hello.request,set,sslv3.client_hello.request,noalert
  event "WEB-MISC SSLv3 Client_Hello request"
  tcp-state established,originator
  payload /\x16\x03/
  payload /.{4}\x01/
  requires-reverse-signature ! http_error
}

signature s2b-2562-3 {
  ip-proto == tcp
  dst-port == 81
  event "WEB-MISC McAfee ePO file upload attempt"
  tcp-state established,originator
  payload /.*\/[sS][pP][iI][pP][eE]\/[rR][eE][pP][lL]_[fF][iI][lL][eE]/
  payload /.*[cC][oO][mM][mM][aA][nN][dD]=[bB][eE][gG][iI][nN]/
  requires-reverse-signature ! http_error
}

signature s2b-2570-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-MISC Invalid HTTP Version String"
  tcp-state established,originator
  # Not supported: isdataat: 6,relative
  payload /.*HTTP\/[^\x0A]{5}/
  requires-reverse-signature ! http_error
}

signature s2b-1774-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP bb_smilies.php access"
  http /.*[\/\\]bb_smilies\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1423-12 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP content-disposition memchr overflow"
  tcp-state established,originator
  payload /.*[cC][oO][nN][tT][eE][nN][tT]-[dD][iI][sS][pP][oO][sS][iI][tT][iI][oO][nN]\x3A/
  payload /.*name=\x22\xCC\xCC\xCC\xCC\xCC/
  requires-reverse-signature ! http_error
}

signature s2b-1736-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP squirrel mail spell-check arbitrary command attempt"
  http /.*[\/\\]squirrelspell[\/\\]modules[\/\\]check_me\.mod\.php/
  tcp-state established,originator
  payload /.*[sS][qQ][sS][pP][eE][lL][lL]_[aA][pP][pP]\[/
  requires-reverse-signature ! http_error
}

signature s2b-1737-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP squirrel mail theme arbitrary command attempt"
  http /.*[\/\\]left_main\.php/
  tcp-state established,originator
  payload /.*[cC][mM][dD][dD]=/
  requires-reverse-signature ! http_error
}

signature s2b-1739-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP DNSTools administrator authentication bypass attempt"
  http /.*[\/\\]dnstools\.php/
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR]_[lL][oO][gG][gG][eE][dD]_[iI][nN]=[tT][rR][uU][eE]/
  payload /.*[uU][sS][eE][rR]_[dD][nN][sS][tT][oO][oO][lL][sS]_[aA][dD][mM][iI][nN][iI][sS][tT][rR][aA][tT][oO][rR]=[tT][rR][uU][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1740-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP DNSTools authentication bypass attempt"
  http /.*[\/\\]dnstools\.php/
  tcp-state established,originator
  payload /.*[uU][sS][eE][rR]_[lL][oO][gG][gG][eE][dD]_[iI][nN]=[tT][rR][uU][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-1741-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP DNSTools access"
  http /.*[\/\\]dnstools\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1742-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Blahz-DNS dostuff.php modify user attempt"
  http /.*[\/\\]dostuff\.php\?action=modify_user/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1743-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Blahz-DNS dostuff.php access"
  http /.*[\/\\]dostuff\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1745-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Messagerie supp_membre.php access"
  http /.*[\/\\]supp_membre\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1773-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP php.exe access"
  http /.*\/php\/php\.exe\?[cCdD]\:\//
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1815-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP directory.php arbitrary command attempt"
  http /.*[\/\\]directory\.php/
  tcp-state established,originator
  payload /.*dir=/
  payload /.*\x3B/
  requires-reverse-signature ! http_error
}

signature s2b-1816-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP directory.php access"
  http /.*[\/\\]directory\.php[\;\|]{1,}/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1834-5 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP PHP-Wiki cross site scripting attempt"
  http /.*[\/\\]modules\.php\?/
  http /.*name=Wiki/
  http /.*<script/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1967-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP phpbb quick-reply.php arbitrary command attempt"
  http /.*[\/\\]quick-reply\.php/
  tcp-state established,originator
  payload /.{1}.*phpbb_root_path=/
  requires-reverse-signature ! http_error
}

signature s2b-1968-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP phpbb quick-reply.php access"
  http /.*[\/\\]quick-reply\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1997-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP read_body.php access attempt"
  http /.*[\/\\]read_body\.php/
  tcp-state established,originator
  http /.*[fF][rR][oO][mM]\x3a.*\x3cscript\x3e.*document.cookie.*\x3c\x2fscript\x3e/
  requires-reverse-signature ! http_error
}

signature s2b-1999-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP edit_image.php access"
  http /.*[\/\\]edit_image\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2000-1 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-PHP readmsg.php access"
  http /.*[\/\\]readmsg\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
  # "Possible many false positives"
  # "If running this webmail server check version to make sure it's not vulnerable and then disable this signature or adjust the notice action."
}

signature s2b-2002-4 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /page=(http|https|ftp)/i
  event "WEB-PHP remote include path"
  tcp-state established,originator
  payload /.*path=/
  requires-reverse-signature ! http_error
  http /.*\.php.*[pP][aA][tT][hH]\x3d(http|https|ftp)\x2fi/
}

signature s2b-1134-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Phorum admin access"
  http /.*[\/\\]admin\.php3/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1161-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP piranha passwd.php3 access"
  http /.*[\/\\]passwd\.php3/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1178-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Phorum read access"
  http /.*[\/\\]read\.php3/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1179-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Phorum violation access"
  http /.*[\/\\]violation\.php3/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1197-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Phorum code access"
  http /.*[\/\\]code\.php3/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1300-7 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP admin.php file upload attempt"
  http /.*[\/\\]admin\.php/
  tcp-state established,originator
  payload /.*[fF][iI][lL][eE]_[nN][aA][mM][eE]=/
  requires-reverse-signature ! http_error
}

signature s2b-1301-11 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP admin.php access"
  http /.*[\/\\]admin\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1407-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP smssend.php access"
  http /.*[\/\\]smssend\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1399-11 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /file=(http|https|ftp)/i
  event "WEB-PHP PHP-Nuke remote file include attempt"
  http /.*[\/\\]index\.php.*[fF][iI][lL][eE]=([hH][tT][tT][pP][sS]?|[fF][tT][pP])/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1490-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Phorum /support/common.php attempt"
  http /.*[\/\\]support[\/\\]common\.php/
  tcp-state established,originator
  payload /.*ForumLang=\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-1491-6 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Phorum /support/common.php access"
  http /.*[\/\\]support[\/\\]common\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1137-9 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Phorum authentication access"
  tcp-state established,originator
  payload /.*[pP][hH][pP]_[aA][uU][tT][hH]_[uU][sS][eE][rR]=[bB][oO][oO][gG][iI][eE][mM][aA][nN]/
  requires-reverse-signature ! http_error
}

signature s2b-1085-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP strings overflow"
  tcp-state established,originator
  payload /.*\xBAI\xFE\xFF\xFF\xF7\xD2\xB9\xBF\xFF\xFF\xFF\xF7\xD1/
  requires-reverse-signature ! http_error
}

signature s2b-1086-12 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP strings overflow"
  http /.*\?STRENGUR/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-1254-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP PHPLIB remote command attempt"
  tcp-state established,originator
  payload /.*_PHPLIB\[libdir\]/
  requires-reverse-signature ! http_error
}

signature s2b-1255-8 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP PHPLIB remote command attempt"
  http /.*[\/\\]db_mysql\.inc/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2074-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Mambo uploadimage.php upload php file attempt"
  http /.*[\/\\]uploadimage\.php/
  tcp-state established,originator
  payload /.*userfile_name=.{1}.*\.php/
  requires-reverse-signature ! http_error
}

signature s2b-2075-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Mambo upload.php upload php file attempt"
  http /.*[\/\\]upload\.php/
  tcp-state established,originator
  payload /.*userfile_name=.{1}.*\.php/
  requires-reverse-signature ! http_error
}

signature s2b-2076-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Mambo uploadimage.php access"
  http /.*[\/\\]uploadimage\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2077-2 {
  ip-proto == tcp
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-PHP Mambo upload.php access"
  http /.*[\/\\]upload\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2078-2 {
  ip-proto == tcp
  dst-port == http_ports
  dst-ip == local_nets
  event "WEB-PHP phpBB privmsg.php access"
  http /.*[\/\\]privmsg\.php.{1,}\?[Ff][Oo][Ll][Dd][Ee][Rr]=.{1,}[Mm][Oo][Dd][Ee]=.{1,}[Cc][Oo][Nn][Ff][Ii][Rr][Mm]=[Yy][Ee][Ss]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2140-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP p-news.php access"
  http /.*[\/\\]p-news\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2141-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP shoutbox.php directory traversal attempt"
  http /.*[\/\\]shoutbox\.php/
  tcp-state established,originator
  payload /.*conf=.*.*\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-2143-3 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /b2inc=(http|https|ftp)/i
  event "WEB-PHP b2 cafelog gm-2-b2.php remote file include attempt"
  http /.*[\/\\]gm-2-b2\.php/
  tcp-state established,originator
  payload /.*b2inc=/
  requires-reverse-signature ! http_error
}

signature s2b-2144-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP b2 cafelog gm-2-b2.php access"
  http /.*[\/\\]gm-2-b2\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2145-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP TextPortal admin.php default password admin attempt"
  http /.*[\/\\]admin\.php/
  tcp-state established,originator
  payload /.*op=admin_enter/
  payload /.*password=admin/
  requires-reverse-signature ! http_error
}

signature s2b-2146-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP TextPortal admin.php default password 12345 attempt"
  http /.*[\/\\]admin\.php/
  tcp-state established,originator
  payload /.*op=admin_enter/
  payload /.*password=12345/
  requires-reverse-signature ! http_error
}

signature s2b-2147-7 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /Server\x5bpath\x5d=(http|https|ftp)/
  event "WEB-PHP BLNews objects.inc.php4 remote file include attempt"
  http /.*[\/\\]objects\.inc\.php4/
  tcp-state established,originator
  payload /.*Server\[path\]=/
  requires-reverse-signature ! http_error
}

signature s2b-2148-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP BLNews objects.inc.php4 access"
  http /.*[\/\\]objects\.inc\.php4/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2149-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Turba status.php access"
  http /.*[\/\\]turba[\/\\]status\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2150-7 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /admin_root=(http|https|ftp)/
  event "WEB-PHP ttCMS header.php remote file include attempt"
  http /.*[\/\\]admin[\/\\]templates[\/\\]header\.php/
  tcp-state established,originator
  payload /.*admin_root=/
  requires-reverse-signature ! http_error
}

signature s2b-2151-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP ttCMS header.php access"
  http /.*[\/\\]admin[\/\\]templates[\/\\]header\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2153-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP autohtml.php directory traversal attempt"
  http /.*[\/\\]autohtml\.php/
  tcp-state established,originator
  payload /.*name=.*.*\.\.\/\.\.\//
  requires-reverse-signature ! http_error
}

signature s2b-2154-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP autohtml.php access"
  http /.*[\/\\]autohtml\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2155-5 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /template=(http|https|ftp)/i
  event "WEB-PHP ttforum remote file include attempt"
  http /.*forum[\/\\]index\.php/
  tcp-state established,originator
  payload /.*template=/
  requires-reverse-signature ! http_error
}

signature s2b-2226-5 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /pm_path=(http|https|ftp)/
  event "WEB-PHP pmachine remote file include attempt"
  http /.*lib\.inc\.php/
  tcp-state established,originator
  payload /.*pm_path=/
  requires-reverse-signature ! http_error
}

signature s2b-2227-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP forum_details.php access"
  http /.*forum_details\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2228-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP phpMyAdmin db_details_importdocsql.php access"
  http /.*db_details_importdocsql\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2229-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP viewtopic.php access"
  http /.*viewtopic\.php/
  tcp-state established,originator
  http /.*[sS][uU][bB][sS][Ss][tT][rR][iI][nN][gG]\x28[uU][sS][eE][rR][pP][aA][sS][sS][wW][oO][rR][dD]*./
  requires-reverse-signature ! http_error
}

signature s2b-2279-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP UpdateClasses.php access"
  http /.*[\/\\]UpdateClasses\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2280-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Title.php access"
  http /.*[\/\\]Title\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2281-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Setup.php access"
  http /.*[\/\\]Setup\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2282-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP GlobalFunctions.php access"
  http /.*[\/\\]GlobalFunctions\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2283-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP DatabaseFunctions.php access"
  http /.*[\/\\]DatabaseFunctions\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2284-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP rolis guestbook remote file include attempt"
  http /.*[\/\\]insert\.inc\.php/
  tcp-state established,originator
  payload /.*[pP][aA][tT][hH]=/
  requires-reverse-signature ! http_error
}

signature s2b-2285-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP rolis guestbook access"
  http /.*[\/\\]insert\.inc\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2286-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP friends.php access"
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /.*[\/\\]friends\.php\x3fadmin\x3d[a-zA-Z0-9]{5,20}.* /
}

signature s2b-2287-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_comment.php access"
  http /.*[\/\\]admin_comment\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2288-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_edit.php access"
  http /.*[\/\\]admin_edit\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2289-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_embed.php access"
  http /.*[\/\\]admin_embed\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2290-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_help.php access"
  http /.*[\/\\]admin_help\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2291-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_license.php access"
  http /.*[\/\\]admin_license\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2292-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_logout.php access"
  http /.*[\/\\]admin_logout\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2293-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_password.php access"
  http /.*[\/\\]admin_password\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2295-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_settings.php access"
  http /.*[\/\\]admin_settings\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2296-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_stats.php access"
  http /.*[\/\\]admin_stats\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2297-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_templates_misc.php access"
  http /.*[\/\\]admin_templates_misc\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2298-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_templates.php access"
  http /.*[\/\\]admin_templates\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2299-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_tpl_misc_new.php access"
  http /.*[\/\\]admin_tpl_misc_new\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2300-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll admin_tpl_new.php access"
  http /.*[\/\\]admin_tpl_new\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2301-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll booth.php access"
  http /.*[\/\\]booth\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2302-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Advanced Poll poll_ssi.php access"
  http /.*[\/\\]poll_ssi\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2304-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP files.inc.php access"
  http /.*[\/\\]files\.inc\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2305-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP chatbox.php access"
  http /.*[\/\\]chatbox\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2306-4 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /GALLERY_BASEDIR=(http|https|ftp)/i
  event "WEB-PHP gallery remote file include attempt"
  http /.*[\/\\]setup[\/\\]/
  tcp-state established,originator
  requires-reverse-signature ! http_error
  http /.*[gG][aA][lL][lL][eE][rR][yY]_[bB][aA][sS][eE][dD][iI][rR]=(http|https|ftp)/
}

signature s2b-2307-5 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /page=(http|https|ftp)/i
  event "WEB-PHP PayPal Storefront remote file include attemtp"
  tcp-state established,originator
  payload /.*do=ext/
  requires-reverse-signature ! http_error
  http /[pP][aA][gG][eE]=(http|https|ftp)/
}

signature s2b-2328-3 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP authentication_index.php access"
  http /.*[\/\\]authentication_index\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2331-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP MatrikzGB privilege escalation attempt"
  tcp-state established,originator
  payload /.*[nN][eE][wW]_[rR][iI][gG][hH][tT][sS]=[aA][dD][mM][iI][nN]/
  requires-reverse-signature ! http_error
}

signature s2b-2341-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP DCP-Portal remote file include attempt"
  http /.*[\/\\]library[\/\\]editor[\/\\]editor\.php/
  tcp-state established,originator
  payload /.*[rR][oO][oO][tT]=/
  requires-reverse-signature ! http_error
}

signature s2b-2342-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP DCP-Portal remote file include attempt"
  http /.*[\/\\]library[\/\\]lib\.php/
  tcp-state established,originator
  payload /.*[rR][oO][oO][tT]=/
  requires-reverse-signature ! http_error
}

signature s2b-2345-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP PhpGedView search.php access"
  http /.*[\/\\]search\.php/
  http /.*action=soundex/
  http /.*firstname=/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2346-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP myPHPNuke chatheader.php access"
  http /.*[\/\\]chatheader\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2347-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP myPHPNuke partner.php access"
  http /.*[\/\\]partner\.php/
  tcp-state established,originator
  http /.*\x3d.*\x3cscript\x3e.*document.cookie.*\x3c\x2fscript\x3e/
  requires-reverse-signature ! http_error
}

signature s2b-2353-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP IdeaBox cord.php file include"
  http /.*[\/\\]index\.php/
  tcp-state established,originator
  payload /.*[iI][dD][eE][aA][dD][iI][rR]/
  payload /.*[cC][oO][rR][dD]\.[pP][hH][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-2354-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP IdeaBox notification.php file include"
  http /.*[\/\\]index\.php/
  tcp-state established,originator
  payload /.*[gG][oO][rR][uU][mM][dD][iI][rR]/
  payload /.*[nN][oO][tT][iI][fF][iI][cC][aA][tT][iI][oO][nN]\.[pP][hH][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-2355-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Invision Board emailer.php file include"
  http /.*[\/\\]ad_member\.php/
  tcp-state established,originator
  payload /.*[eE][mM][aA][iI][lL][eE][rR]\.[pP][hH][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-2356-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP WebChat db_mysql.php file include"
  http /.*[\/\\]defines\.php/
  tcp-state established,originator
  payload /.*[wW][eE][bB][cC][hH][aA][tT][pP][aA][tT][hH]/
  payload /.*[dD][bB]_[mM][yY][sS][qQ][lL]\.[pP][hH][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-2357-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP WebChat english.php file include"
  http /.*[\/\\]defines\.php/
  tcp-state established,originator
  payload /.*[wW][eE][bB][cC][hH][aA][tT][pP][aA][tT][hH]/
  payload /.*[eE][nN][gG][lL][iI][sS][hH]\.[pP][hH][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-2358-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Typo3 translations.php file include"
  http /.*[\/\\]translations\.php/
  tcp-state established,originator
  payload /.*[oO][nN][lL][yY]/
  requires-reverse-signature ! http_error
}

signature s2b-2359-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Invision Board ipchat.php file include"
  http /.*[\/\\]ipchat\.php/
  tcp-state established,originator
  payload /.*[rR][oO][oO][tT]_[pP][aA][tT][hH]/
  payload /.*[cC][oO][nN][fF]_[gG][lL][oO][bB][aA][lL]\.[pP][hH][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-2360-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP myphpPagetool pt_config.inc file include"
  http /.*[\/\\]doc[\/\\]admin/
  tcp-state established,originator
  payload /.*[pP][tT][iI][nN][cC][lL][uU][dD][eE]/
  payload /.*[pP][tT]_[cC][oO][nN][fF][iI][gG]\.[iI][nN][cC]/
  requires-reverse-signature ! http_error
}

signature s2b-2362-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP YaBB SE packages.php file include"
  http /.*[\/\\]packages\.php/
  tcp-state established,originator
  payload /.*[pP][aA][cC][kK][eE][rR]\.[pP][hH][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-2363-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Cyboards default_header.php access"
  http /.*[\/\\]default_header\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2364-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP Cyboards options_form.php access"
  http /.*[\/\\]options_form\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2365-2 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP newsPHP Language file include attempt"
  http /.*[\/\\]nphpd\.php/
  tcp-state established,originator
  payload /.*[lL][aA][nN][gG][fF][iI][lL][eE]/
  requires-reverse-signature ! http_error
}

signature s2b-2366-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP PhpGedView PGV authentication_index.php base directory manipulation attempt"
  http /.*[\/\\]authentication_index\.php/
  tcp-state established,originator
  payload /.*[pP][gG][vV]_[bB][aA][sS][eE]_[dD][iI][rR][eE][cC][tT][oO][rR][yY]/
  requires-reverse-signature ! http_error
}

signature s2b-2367-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP PhpGedView PGV functions.php base directory manipulation attempt"
  http /.*[\/\\]functions\.php/
  tcp-state established,originator
  payload /.*[pP][gG][vV]_[bB][aA][sS][eE]_[dD][iI][rR][eE][cC][tT][oO][rR][yY]/
  requires-reverse-signature ! http_error
}

signature s2b-2368-4 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP PhpGedView PGV config_gedcom.php base directory manipulation attempt"
  http /.*[\/\\]config_gedcom\.php/
  tcp-state established,originator
  payload /.*[pP][gG][vV]_[bB][aA][sS][eE]_[dD][iI][rR][eE][cC][tT][oO][rR][yY]/
  requires-reverse-signature ! http_error
}

signature s2b-2398-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP WAnewsletter newsletter.php file include attempt"
  http /.*newsletter\.php/
  tcp-state established,originator
  payload /.*[wW][aA][rR][oO][oO][tT]/
  payload /.*[sS][tT][aA][rR][tT]\.[pP][hH][pP]/
  requires-reverse-signature ! http_error
}

signature s2b-2399-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP WAnewsletter db_type.php access"
  http /.*[\/\\]sql[\/\\]db_type\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2405-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP phptest.php access"
  http /.*[\/\\]phptest\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2410-2 {
  ip-proto == tcp
  dst-ip == local_nets
  dst-port == http_ports
  event "WEB-PHP IGeneric Free Shopping Cart page.php access"
  http /.*[\/\\]page\.php\?.*script/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2565-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP modules.php access"
  http /.*[\/\\]modules\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2566-1 {
  ip-proto == tcp
  dst-port == http_ports
  event "WEB-PHP PHPBB viewforum.php access"
  http /.*[\/\\]viewforum\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
}

signature s2b-2575-1 {
  ip-proto == tcp
  dst-port == http_ports
  # Not supported: pcre: /systempath=(http|https|ftp)/i
  event "WEB-PHP Opt-X header.php remote file include attempt"
  http /.*[\/\\]header\.php/
  tcp-state established,originator
  requires-reverse-signature ! http_error
  payload /.*[sS][yY][sS][tT][eE][mM][pP][aA][tT][hH]=([hH][tT]{2}[pP][sS]?)|([fF][tT][pP])/
}

signature s2b-1225-4 {
  ip-proto == tcp
  dst-port == 6000
  event "X11 MIT Magic Cookie detected"
  tcp-state established
  payload /.*MIT-MAGIC-COOKIE-1/
}

signature s2b-1226-4 {
  ip-proto == tcp
  dst-port == 6000
  event "X11 xopen"
  tcp-state established
  payload /.*l\x00\x0B\x00\x00\x00\x00\x00\x00\x00\x00\x00/
}

