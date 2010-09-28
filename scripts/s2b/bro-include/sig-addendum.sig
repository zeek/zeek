# these are translations for pcre -> lex/bro
#
#       \w AN and _     : [a-zA-Z_]
#       \W not \w       : [^a-zA-Z_]
#       \s whitespace   : [\x20\x09\x0b]
#       \S not \s       : [^\x20\x09\x0b]
#       \d numeric      : [0-9]
#       \D not \d       : [^0-9]
#
#

# the sig error also will hold for the 3xx and 5xx series also(?)
# 304 not modified may be a problem here

signature http_error {
        ip-proto == tcp
        src-port == http_ports
        payload /.*HTTP\/1\.. *[3-5][0-9][0-9]/
        tcp-state established 
}

signature http_good {
        ip-proto == tcp
        src-port == http_ports
        payload /.*HTTP\/1\.. *2[0-9][0-9]/
        tcp-state established
}

signature http_shell_check {
        ip-proto == tcp
        src-port == http_ports
        # this should filter out most typical references to the various shell commands
        # from man pages and reference guides
        payload /((ksh)|(rsh)|(zsh)|(csh)|(tcsh)|(sh)|(bash))[a-zA-Z0-9\x2d\x2e\x5f\x2f]/
        tcp-state established
}

signature got_http_root {
        # this is to get around the 'permission denied' == response
        # == 200 reply problem for /etc/passwd checking
        # just a sanity check to see if there is some suggestion of success
        ip-proto == tcp
        src-port == 80
        payload /.*root:.*/
        tcp-state established
}

# the following sigs should give some idea of the server software type and
# version.  This assumes that the configuration has not been changed

signature http_apache_server {
	ip-proto == tcp
	src-port == http_ports
	# this should catch *most* apache instances that are normal
	# in behavior
	payload /.*\x0aServer: Apache.*/
	tcp-state established
}

signature http_apache1_server {
        ip-proto == tcp
        src-port == http_ports
        # this should catch *most* apache instances that are normal
        # in behavior
        payload /.*\x0aServer: Apache\/1\..*/
        tcp-state established
}

signature http_apache2_server {
        ip-proto == tcp
        src-port == http_ports
        # this should catch *most* apache instances that are normal
        # in behavior
        payload /.*\x0aServer: Apache\/2\..*/
        tcp-state established
}

signature http_iis_server {
	ip-proto == tcp
	src-port == http_ports
	payload /.*\x0aServer: Microsoft-IIS.*/
	tcp-state established
}

signature http_iis4_server {
        ip-proto == tcp
        src-port == http_ports
        payload /.*\x0aServer: Microsoft-IIS\/4\.0.*/
        tcp-state established
}

signature http_iis5_server {
        ip-proto == tcp
        src-port == http_ports
        payload /.*\x0aServer: Microsoft-IIS\/\5\.0.*/
        tcp-state established
}

signature http_iis6_server {
        ip-proto == tcp
        src-port == http_ports
        payload /.*\x0aServer: Microsoft-IIS\/\6\.0.*/
        tcp-state established
}

signature http_cool_dll {
  ip-proto == tcp
  dst-port == http_ports
  payload /.*cool.dll*./
  }

########################## client section #
#
#        "User-Agent: "
#        payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20/
#
#######

signature http_msie_client {
	ip-proto == tcp
	dst-port == http_ports
	# "User-Agent:...... MSIE #"
	payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20.{5,30}MSIE\x20[1-9]*./
	tcp-state established
}

signature http_real_client {
	ip-proto == tcp
	dst-port == http_ports
	# "User-Agent:.RMA/1.0.(compatible;.RealMedia)"
	payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x52\x4d\x41\x2f\x31\x2e\x30\x20\x28\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x3b\x20\x52\x65\x61\x6c\x4d\x65\x64\x69\x61\x29*./
	tcp-state established
}


signature http_opera_client {
	ip-proto == tcp
	dst-port == http_ports
	# "User-Agent: Opera/6.1"
	payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a.{3,50}\x4f\x70\x65\x72\x61\x2f.*/
	tcp-state established
}

signature http_netscape_client {
	ip-proto == tcp
	dst-port == http_ports
	# "User-Agent: ... Netscape/A
	payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20.{10,90}Netscape\x2f[4-7].*/
	tcp-state established
}

signature http_netscape_client4 {
        ip-proto == tcp
        dst-port == http_ports
        # "User-Agent: ... Netscape/A.B
        payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20.{10,90}Netscape\x2f4\x2e[0-9].*/
        tcp-state established
}

signature http_netscape_client7 {
        ip-proto == tcp
        dst-port == http_ports
        # "User-Agent: ... Netscape/A.B - note that for Netscape/7 there is no .X subversion
        payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20.{10,90}Netscape\x2f7.*/
        tcp-state established
}

signature http_netscape_client8 {
        ip-proto == tcp
        dst-port == http_ports
        # "User-Agent: ... Netscape/A.B
        payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20.{10,90}Netscape\x2f8\x2e[0-9].*/
        tcp-state established
}

signature http_moz_client {
	ip-proto == tcp
	dst-port == http_ports
	# "User-Agent: ... rv:A.B ... Gecko/"
	payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20.{10,70}rv\x3a[0-2]\x2e[0-9].{0,30}Gecko\x2f.*/
	tcp-state established
}

signature http_old_gecko_client  {
        ip-proto == tcp
        dst-port == http_ports
        # "User-Agent: ... rv:A.B ... Gecko/"
        payload /.*\x0a\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20.{10,70}rv\x3a[0-2]\x2e[0-9].{0,30}Gecko\x2f(2000|2001|2002).*/
        tcp-state established
}

## end client sigs ##


##  ftp based signatures ##

signature got_ftp_root {
        ip-proto == tcp
        src-port == 21
        payload /.*root:.*/
        tcp-state established
}

signature got_tftp_root {
        # this checks to see if a tftp get /etc/passwd or /etc/shadow
        # actually returns any data.  we assume that root will always
        # be in the file
        ip-proto == udp
        src-port == 69
        payload /.*root:.*/
}

# smtp return code checking
signature smtp_server_ok {
        ip-proto == tcp
        src-port == 25
        payload /. [2-3][0-9][0-9]../ # 2xx-3xx successful
        tcp-state established
}

signature smtp_server_pending {
        ip-proto == tcp
        src-port == 25
        payload /.4[0-9][0-9]../  # 4xx failure, ask sender to try later
        tcp-state established
}

signature smtp_server_fail {
        ip-proto == tcp
        src-port == 25
        payload /.5[0-9][0-9]../  # 5xx permanent failure
        tcp-state established
}       

# ftp server return code information.  a few assumptions made here
# in theory '150' is a good return, but I skip it here for simplicity
signature ftp_server_ok {
        ip-proto == tcp
        src-port == 21
        payload /.2[0-9][0-9]../ # 2xx ok
        tcp-state established
}

signature ftp_server_error {
        ip-proto == tcp
        src-port == 21
        payload /.5[0-9][0-9]../ # 5xx fail
        tcp-state established
}

# snmp return checker - we ought to expect a non-trivial quantity of data for a
# successful snmp connection
signature snmp_userver_ok_return {
        ip-proto == udp
        src-port >= 161
        src-port <= 162
        payload-size > 10
}

signature snmp_tserver_ok_return {
        ip-proto == tcp
        src-port >= 161
        src-port <= 162
        payload-size > 10
        tcp-state established
}

signature pop_return_ok {
        ip-proto == tcp
        src-port >= 109
        src-port <= 110
        payload /.\x2bOK/
        tcp-state established
}

signature pop_return_error {
        ip-proto == tcp
        src-port >= 109
        src-port <= 110
        payload /.\x2dERR/
        tcp-state established
}

# this series of sigs is provided by CIAC based on suckit rootkit
# backdoor traffic.  the 'signature' has only been seen on port 22
# up till now.
signature sid-ciac-sk1 {
  ip-proto == tcp
  event "CIAC-1 suckit backdoor"
  payload /.*\xd1\xe4\x22\x07\x57\xd3\xa9\x9a\x5a\xd5\xcc\xc7\x9d\xa1\xd5\xc5\xa6\xf1\x6d\x57/
  }
 
signature sid-ciac-sk2 {
  ip-proto == tcp
  event "CIAC-2 suckit backdoor"
  payload /.*\x7c\x83\x3b\x3f\x8a\x80\x59\xbf\x45\xbd\x5f\xf2\xa3\xc9\x36\x85\xa9\xd1\x15\xc3/
  }
 
signature sid-ciac-sk3 {
  ip-proto == tcp
  event "CIAC-3 suckit backdoor"
  payload /.*\x12\xc4\xf6\x62\x55\xe6\x36\xbd\xe4\x65\xbc\x24\xbe\xb0\x50\xac\xe0\xef\x9a\x4f/
  }
 
signature sid-ciac-sk6 {
  ip-proto == tcp
  event "CIAC-6 suckit backdoor"
  payload /.*\xd2\x9b\xec\xe0\x8c\x09\x28\xcb\x05\x60\x1b\xc5\x59\x34\xab\xbd\x56\xd6\x78\xaa/
  }
 
signature sid-ciac-sk7 {
  ip-proto == tcp
  event "CIAC-7 suckit backdoor"
  payload /.*\xdd\xbd\x4c\x7b\x35\x9a\x89\x88\xf0\x0d\xa8\xf1\x44\x67\x7b\xcd\x18\xf0\xe6\x70/
  }
 
signature sid-ciac-sk10 {
  ip-proto == tcp
  event "CIAC-10 suckit backdoor"
  payload /.*\xe7\xa7\x74\xb8\xb9\xfe\x9a\x6e\x6c\xe1\xd5\xde\x5f\x5c\xd5\x9d\x49\x69\x9a\xba/
  }

signature sid-ciac-sk11 {
  ip-proto == tcp
  event "CIAC-11 suckit backdoor"
  payload /.*\x4b\x56\xde\x0c\x47\xbf\x12\x9f\xc7\x24\x40\x64\x5c\xfd\xa8\x2b\xaf\x3f\x09\xc7/
  }

signature sid-ciac-sk12 {
  ip-proto == tcp
  event "CIAC-12 suckit backdoor"
  payload /\xe1\xac\x20\x5a\xda\x5a\xf7\x0c\x17\x24\x8e\xc2\x0e\xa0\x0b\xee\x7a\x77\xe0\x64/
  }

signature sid-ciac-sk13 {
  ip-proto == tcp
  event "CIAC-13 suckit backdoor"
  payload /\xc9\xe9\x36\xa1\xce\xae\x10\x3c\x32\x81\xac\x9b\x01\x81\x5a\x68\x01\x91\x82\xa4/
  }

signature sid-ciac-sk14 {
  ip-proto == tcp
  event "CIAC-14 suckit backdoor"
  payload /\x45\x2e\xe5\x01\x80\xb0\x0a\xca\xdb\x16\xa1\x8f\xc6\xcd\x97\x60\x92\x44\x93\x16/
  }
 
signature sid-ciac-7 {
  ip-proto == tcp
  event "HXDEF 1.0-0.84 backdoor"
  payload /.*\x01\x9A\x8C\x66\xAF\xC0\x4A\x11\x9E\x3F\x40\x88\x12\x2C\x3A\x4A\x84\x65\x38\xB0\xB4\x08\x0B\xAF\xDB\xCE\x02\x94\x34\x5F\x22\x00*./
  }

signature sid-ciac-8 {
  ip-proto == tcp
  event "HXDEF 0.73 backdoor"
  payload /.*\x01\xFE\x3C\x6C\x6A\xFF\x99\xA8\x34\x83\x38\x24\xA1\xA4\xF2\x11\x5A\xD3\x18\x8D\xBC\xC4\x3E\x40\x07\xA4\x28\xD4\x18\x48\xFE\x00*./
}

signature sid-ciac-modrootme-1 {
  ip-proto == tcp
  dst-port == http_ports
  tcp-state established
  requires-signature ! http_error
  http /GET root .*/
}

## end payload 

## misc sigs ##
signature dest_microsoft_address {
	dst-ip == 207.46.0.0/16
}

signature src_microsoft_address {
	src-ip == 207.46.0.0/16
}

# experimental phatbot sig
signature phatbot_sig {
        ip-proto == tcp
        dst-port == http_ports
        http /POST \0x20{1,10}\/ HTTP\/1\.0.*/
	http /Content-Length: 204800.*/
        tcp-state established
	requires-signature ! http_error
	event "phatbot sig"
}

signature thinstall_trojan {
        ip-proto == tcp
        dst-port == http_ports
        http /[pP][oO][sS][tT]\x20{1,}\/bi\/servlet\/ThinstallPre/
        tcp-state established,originator
        event "ThinstallPre Adware Trojan, personal and machine data theft, successful"
        # reference: http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=TROJ_REVOP.F&VSect=T
}

signature bagle-bc {
	ip-proto == tcp
	dst-port == http_ports
	src-ip == local_nets
	tcp-state established
	http /[\/][gG]\.[jJ][pP][gG]/
	event "bagle.bc g.jpg download attempt"
} 

## end misc ##

