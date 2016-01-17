# General purpose file magic signatures.

# Plaintext
# (Including BOMs for UTF-8, 16, and 32)
signature file-plaintext {
	file-mime "text/plain", -20
	file-magic /^(\xef\xbb\xbf|(\x00\x00)?\xfe\xff|\xff\xfe(\x00\x00)?)?[[:space:]\x20-\x7E]{10}/
}

signature file-json {
	file-mime "text/json", 1
	file-magic /^(\xef\xbb\xbf)?[\x0d\x0a[:blank:]]*\{[\x0d\x0a[:blank:]]*(["][^"]{1,}["]|[a-zA-Z][a-zA-Z0-9\\_]*)[\x0d\x0a[:blank:]]*:[\x0d\x0a[:blank:]]*(["]|\[|\{|[0-9]|true|false)/
}

signature file-json2 {
	file-mime "text/json", 1
	file-magic /^(\xef\xbb\xbf)?[\x0d\x0a[:blank:]]*\[[\x0d\x0a[:blank:]]*(((["][^"]{1,}["]|[0-9]{1,}(\.[0-9]{1,})?|true|false)[\x0d\x0a[:blank:]]*,)|\{|\[)[\x0d\x0a[:blank:]]*/
}

# Match empty JSON documents.
signature file-json3 {
	file-mime "text/json", 0
	file-magic /^(\xef\xbb\xbf)?[\x0d\x0a[:blank:]]*(\[\]|\{\})[\x0d\x0a[:blank:]]*$/
}

signature file-xml {
	file-mime "application/xml", 10
	file-magic /^(\xef\xbb\xbf)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<\?xml /
}

signature file-xhtml {
	file-mime "text/html", 100
	file-magic /^(\xef\xbb\xbf)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<(![dD][oO][cC][tT][yY][pP][eE] {1,}[hH][tT][mM][lL]|[hH][tT][mM][lL]|[mM][eE][tT][aA] {1,}[hH][tT][tT][pP]-[eE][qQ][uU][iI][vV])/
}

signature file-html {
	file-mime "text/html", 49
	file-magic /^(\xef\xbb\xbf)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<![dD][oO][cC][tT][yY][pP][eE] {1,}[hH][tT][mM][lL]/
}

signature file-html2 {
	file-mime "text/html", 20
	file-magic /^(\xef\xbb\xbf)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<([hH][eE][aA][dD]|[hH][tT][mM][lL]|[tT][iI][tT][lL][eE]|[bB][oO][dD][yY])/
}

signature file-rss {
	file-mime "text/rss", 90
	file-magic /^(\xef\xbb\xbf)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<[rR][sS][sS]/
}

signature file-atom {
	file-mime "text/atom", 100
	file-magic /^(\xef\xbb\xbf)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<([rR][sS][sS][^>]*xmlns:atom|[fF][eE][eE][dD][^>]*xmlns=["']?http:\/\/www.w3.org\/2005\/Atom["']?)/
}

signature file-soap {
	file-mime "application/soap+xml", 49
	file-magic /^(\xef\xbb\xbf)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<[sS][oO][aA][pP](-[eE][nN][vV])?:[eE][nN][vV][eE][lL][oO][pP][eE]/
}

signature file-cross-domain-policy {
	file-mime "text/x-cross-domain-policy", 49
	file-magic /^([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<![dD][oO][cC][tT][yY][pP][eE] {1,}[cC][rR][oO][sS][sS]-[dD][oO][mM][aA][iI][nN]-[pP][oO][lL][iI][cC][yY]/
}

signature file-cross-domain-policy2 {
	file-mime "text/x-cross-domain-policy", 49
	file-magic /^([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<[cC][rR][oO][sS][sS]-[dD][oO][mM][aA][iI][nN]-[pP][oO][lL][iI][cC][yY]/
}

signature file-xmlrpc {
	file-mime "application/xml-rpc", 49
	file-magic /^(\xef\xbb\xbf)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<[mM][eE][tT][hH][oO][dD][rR][eE][sS][pP][oO][nN][sS][eE]>/
}

signature file-coldfusion {
	file-mime "magnus-internal/cold-fusion", 20
	file-magic /^([\x0d\x0a[:blank:]]*(<!--.*-->)?)*<(CFPARAM|CFSET|CFIF)/
}

# Adobe Flash Media Manifest
signature file-f4m {
	file-mime "application/f4m", 49
	file-magic /^(\xef\xbb\xbf)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<[mM][aA][nN][iI][fF][eE][sS][tT][\x0d\x0a[:blank:]]{1,}xmlns=\"http:\/\/ns\.adobe\.com\/f4m\//
}

# Microsoft LNK files
signature file-lnk {
	file-mime "application/x-ms-shortcut", 49
	file-magic /^\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x10\x00\x00\x00\x46/
}

signature file-jar {
	file-mime "application/java-archive", 100
	file-magic /^PK\x03\x04.{1,200}\x14\x00..META-INF\/MANIFEST\.MF/
}

signature file-java-applet {
	file-mime "application/x-java-applet", 71
	file-magic /^\xca\xfe\xba\xbe...[\x2d-\x34]/
}

# OCSP requests over HTTP.
signature file-ocsp-request {
	file-magic /^.{11,19}\x06\x05\x2b\x0e\x03\x02\x1a/
	file-mime "application/ocsp-request", 71
}

# OCSP responses over HTTP.
signature file-ocsp-response {
	file-magic /^.{11,19}\x06\x09\x2B\x06\x01\x05\x05\x07\x30\x01\x01/
	file-mime "application/ocsp-response", 71
}

# Shockwave flash
signature file-swf {
	file-magic /^(F|C|Z)WS/
	file-mime "application/x-shockwave-flash", 60
}

# Microsoft Outlook's Transport Neutral Encapsulation Format
signature file-tnef {
	file-magic /^\x78\x9f\x3e\x22/
	file-mime "application/vnd.ms-tnef", 100
}

# Mac OS X Mach-O executable
signature file-mach-o {
	file-magic /^[\xce\xcf]\xfa\xed\xfe/
	file-mime "application/x-mach-o-executable", 100
}

# Mac OS X Universal Mach-O executable
signature file-mach-o-universal {
	file-magic /^\xca\xfe\xba\xbe..\x00[\x01-\x14]/
	file-mime "application/x-mach-o-executable", 100
}

signature file-pkcs7 {
	file-magic /^MIME-Version:.*protocol=\"application\/pkcs7-signature\"/
	file-mime "application/pkcs7-signature", 100
}

# Concatenated X.509 certificates in textual format.
signature file-pem {
	file-magic /^-----BEGIN CERTIFICATE-----/
	file-mime "application/x-pem"
}

# Java Web Start file.
signature file-jnlp {
	file-magic /^\<jnlp\x20/
	file-mime "application/x-java-jnlp-file", 100
}

signature file-pcap {
	file-magic /^(\xa1\xb2\xc3\xd4|\xd4\xc3\xb2\xa1)/
	file-mime "application/vnd.tcpdump.pcap", 70
}

signature file-pcap-ng {
	file-magic /^\x0a\x0d\x0d\x0a.{4}(\x1a\x2b\x3c\x4d|\x4d\x3c\x2b\x1a)/
	file-mime "application/vnd.tcpdump.pcap", 100
}

signature file-shellscript {
	file-mime "text/x-shellscript", 250
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?(ba|tc|c|z|fa|ae|k)?sh/
}

signature file-perl {
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?perl/
	file-mime "text/x-perl", 60
}

signature file-ruby {
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?ruby/
	file-mime "text/x-ruby", 60
}

signature file-python {
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?python/
	file-mime "text/x-python", 60
}

signature file-awk {
	file-mime "text/x-awk", 60
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?(g|n)?awk/
}

signature file-tcl {
	file-mime "text/x-tcl", 60
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?(wish|tcl)/
}

signature file-lua {
	file-mime "text/x-lua", 49
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?lua/
}

signature file-javascript {
	file-mime "application/javascript", 60
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?node(js)?/
}

signature file-javascript2 {
	file-mime "application/javascript", 60
	file-magic /^[\x0d\x0a[:blank:]]*<[sS][cC][rR][iI][pP][tT][[:blank:]]+([tT][yY][pP][eE]|[lL][aA][nN][gG][uU][aA][gG][eE])=['"]?([tT][eE][xX][tT]\/)?[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]/
}

signature file-javascript3 {
	file-mime "application/javascript", 60
	# This seems to be a somewhat common idiom in javascript.
	file-magic /^[\x0d\x0a[:blank:]]*for \(;;\);/
}

signature file-javascript4 {
	file-mime "application/javascript", 60
	file-magic /^[\x0d\x0a[:blank:]]*document\.write(ln)?[:blank:]?\(/
}

signature file-javascript5 {
	file-mime "application/javascript", 60
	file-magic /^\(function\(\)[[:blank:]\n]*\{/
}

signature file-javascript6 {
	file-mime "application/javascript", 60
	file-magic /^[\x0d\x0a[:blank:]]*<script>[\x0d\x0a[:blank:]]*(var|function) /
}

signature file-php {
	file-mime "text/x-php", 60
	file-magic /^\x23\x21[^\n]{1,15}bin\/(env[[:space:]]+)?php/
}

signature file-php2 {
	file-magic /^.*<\?php/
	file-mime "text/x-php", 40
}

# Stereolithography ASCII format
signature file-stl-ascii {
	file-magic /^solid\x20/
	file-mime "application/sla", 10
}

# Sketchup model file
signature file-skp {
	file-magic /^\xFF\xFE\xFF\x0E\x53\x00\x6B\x00\x65\x00\x74\x00\x63\x00\x68\x00\x55\x00\x70\x00\x20\x00\x4D\x00\x6F\x00\x64\x00\x65\x00\x6C\x00/
	file-mime "application/skp", 100
}

signature file-elf-object {
	file-mime "application/x-object", 50
	file-magic /\x7fELF[\x01\x02](\x01.{10}\x01\x00|\x02.{10}\x00\x01)/
}

signature file-elf {
	file-mime "application/x-executable", 50
	file-magic /\x7fELF[\x01\x02](\x01.{10}\x02\x00|\x02.{10}\x00\x02)/
}

signature file-elf-sharedlib {
	file-mime "application/x-sharedlib", 50
	file-magic /\x7fELF[\x01\x02](\x01.{10}\x03\x00|\x02.{10}\x00\x03)/
}

signature file-elf-coredump {
	file-mime "application/x-coredump", 50
	file-magic /\x7fELF[\x01\x02](\x01.{10}\x04\x00|\x02.{10}\x00\x04)/
}
