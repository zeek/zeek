# $Id: ex.web-rules.sig 6 2004-04-30 00:31:26Z jason $
#
# This is a subset of Snort's signatures (automatically converted into Bro's 
# language by snort2bro).
#
# [web-*.rules from snortrules-current.tar.gz as of Oct 9 19:15:02 2003 GMT]
#
# To use it, customize the variables contained in snort.bro and load snort.bro 
# and signatures.bro.

signature sid-1328 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS ps command attempt"
  http /.*[\/\\]bin[\/\\]ps/
  tcp-state established,originator
  }

signature sid-1329 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /bin/ps command attempt"
  http /.*ps%20/
  tcp-state established,originator
  }

signature sid-1330 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS wget command attempt"
  tcp-state established,originator
  payload /.*[wW][gG][eE][tT]%20/
  }

signature sid-1331 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS uname -a command attempt"
  tcp-state established,originator
  payload /.*[uU][nN][aA][mM][eE]%20-[aA]/
  }

signature sid-1332 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/id command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[iI][dD]/
  }

signature sid-1333 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS id command attempt"
  tcp-state established,originator
  payload /.*;[iI][dD]/
  }

signature sid-1334 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS echo command attempt"
  tcp-state established,originator
  payload /.*\/[bB][iI][nN]\/[eE][cC][hH][oO]/
  }

signature sid-1335 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS kill command attempt"
  tcp-state established,originator
  payload /.*\/[bB][iI][nN]\/[kK][iI][lL][lL]/
  }

signature sid-1336 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS chmod command attempt"
  tcp-state established,originator
  payload /.*\/[bB][iI][nN]\/[cC][hH][mM][oO][dD]/
  }

signature sid-1337 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS chgrp command attempt"
  tcp-state established,originator
  payload /.*\/[cC][hH][gG][rR][pP]/
  }

signature sid-1338 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS chown command attempt"
  tcp-state established,originator
  payload /.*\/[cC][hH][oO][wW][nN]/
  }

signature sid-1339 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS chsh command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[cC][hH][sS][hH]/
  }

signature sid-1340 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS tftp command attempt"
  tcp-state established,originator
  payload /.*[tT][fF][tT][pP]%20/
  }

signature sid-1341 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/gcc command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[gG][cC][cC]/
  }

signature sid-1342 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS gcc command attempt"
  tcp-state established,originator
  payload /.*[gG][cC][cC]%20-[oO]/
  }

signature sid-1343 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/cc command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[cC][cC]/
  }

signature sid-1344 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS cc command attempt"
  tcp-state established,originator
  payload /.*[cC][cC]%20/
  }

signature sid-1345 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/cpp command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[cC][pP][pP]/
  }

signature sid-1346 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS cpp command attempt"
  tcp-state established,originator
  payload /.*[cC][pP][pP]%20/
  }

signature sid-1347 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/g++ command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[gG]\+\+/
  }

signature sid-1348 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS g++ command attempt"
  tcp-state established,originator
  payload /.*[gG]\+\+%20/
  }

signature sid-1349 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS bin/python access attempt"
  tcp-state established,originator
  payload /.*[bB][iI][nN]\/[pP][yY][tT][hH][oO][nN]/
  }

signature sid-1350 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS python access attempt"
  tcp-state established,originator
  payload /.*[pP][yY][tT][hH][oO][nN]%20/
  }

signature sid-1351 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS bin/tclsh execution attempt"
  tcp-state established,originator
  payload /.*[bB][iI][nN]\/[tT][cC][lL][sS][hH]/
  }

signature sid-1352 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS tclsh execution attempt"
  tcp-state established,originator
  payload /.*[tT][cC][lL][sS][hH]8%20/
  }

signature sid-1353 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS bin/nasm command attempt"
  tcp-state established,originator
  payload /.*[bB][iI][nN]\/[nN][aA][sS][mM]/
  }

signature sid-1354 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS nasm command attempt"
  tcp-state established,originator
  payload /.*[nN][aA][sS][mM]%20/
  }

signature sid-1355 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /usr/bin/perl execution attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[bB][iI][nN]\/[pP][eE][rR][lL]/
  }

signature sid-1356 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS perl execution attempt"
  tcp-state established,originator
  payload /.*[pP][eE][rR][lL]%20/
  }

signature sid-1357 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS nt admin addition attempt"
  tcp-state established,originator
  payload /.*[nN][eE][tT] [lL][oO][cC][aA][lL][gG][rR][oO][uU][pP] [aA][dD][mM][iI][nN][iI][sS][tT][rR][aA][tT][oO][rR][sS] \/[aA][dD][dD]/
  }

signature sid-1358 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS traceroute command attempt"
  tcp-state established,originator
  payload /.*[tT][rR][aA][cC][eE][rR][oO][uU][tT][eE]%20/
  }

signature sid-1359 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS ping command attempt"
  tcp-state established,originator
  payload /.*\/[bB][iI][nN]\/[pP][iI][nN][gG]/
  }

signature sid-1360 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS netcat command attempt"
  tcp-state established,originator
  payload /.*[nN][cC]%20/
  }

signature sid-1361 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS nmap command attempt"
  tcp-state established,originator
  payload /.*[nN][mM][aA][pP]%20/
  }

signature sid-1362 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS xterm command attempt"
  tcp-state established,originator
  payload /.*\/[uU][sS][rR]\/[xX]11[rR]6\/[bB][iI][nN]\/[xX][tT][eE][rR][mM]/
  }

signature sid-1363 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS X application to remote host attempt"
  tcp-state established,originator
  payload /.*%20-[dD][iI][sS][pP][lL][aA][yY]%20/
  }

signature sid-1364 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS lsof command attempt"
  tcp-state established,originator
  payload /.*[lL][sS][oO][fF]%20/
  }

signature sid-1365 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS rm command attempt"
  tcp-state established,originator
  payload /.*[rR][mM]%20/
  }

signature sid-1366 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS mail command attempt"
  tcp-state established,originator
  payload /.*\/[bB][iI][nN]\/[mM][aA][iI][lL]/
  }

signature sid-1367 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS mail command attempt"
  tcp-state established,originator
  payload /.*[mM][aA][iI][lL]%20/
  }

signature sid-1368 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /bin/ls| command attempt"
  http /.*[\/\\]bin[\/\\]ls\|/
  tcp-state established,originator
  }

signature sid-1369 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /bin/ls command attempt"
  http /.*[\/\\]bin[\/\\]ls/
  tcp-state established,originator
  }

signature sid-1370 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /etc/inetd.conf access"
  tcp-state established,originator
  payload /.*\/[eE][tT][cC]\/[iI][nN][eE][tT][dD]\.[cC][oO][nN][fF]/
  }

signature sid-1371 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /etc/motd access"
  tcp-state established,originator
  payload /.*\/[eE][tT][cC]\/[mM][oO][tT][dD]/
  }

signature sid-1372 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS /etc/shadow access"
  tcp-state established,originator
  payload /.*\/[eE][tT][cC]\/[sS][hH][aA][dD][oO][wW]/
  }

signature sid-1373 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS conf/httpd.conf attempt"
  tcp-state established,originator
  payload /.*[cC][oO][nN][fF]\/[hH][tT][tT][pP][dD]\.[cC][oO][nN][fF]/
  }

signature sid-1374 {
  ip-proto == tcp
  src-ip != local_nets
  dst-ip == http_servers
  dst-port == http_ports
  event "WEB-ATTACKS .htgroup access"
  http /.*\.htgroup/
  tcp-state established,originator
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

