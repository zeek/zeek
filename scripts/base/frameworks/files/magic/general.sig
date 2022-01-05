# General purpose file magic signatures.

# Plaintext
# (Including BOMs for UTF-8, 16, and 32)
signature file-plaintext {
	file-mime "text/plain", -20
	file-magic /^(\xef\xbb\xbf|(\x00\x00)?\xfe\xff|\xff\xfe(\x00\x00)?)?[[:space:]\x20-\x7E]{10}/
}

signature file-json {
	file-mime "text/json", 1
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?[\x0d\x0a[:blank:]]*\{[\x0d\x0a[:blank:]]*(["][^"]{1,}["]|[a-zA-Z][a-zA-Z0-9\\_]*)[\x0d\x0a[:blank:]]*:[\x0d\x0a[:blank:]]*(["]|\[|\{|[0-9]|true|false)/
}

signature file-json2 {
	file-mime "text/json", 1
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?[\x0d\x0a[:blank:]]*\[[\x0d\x0a[:blank:]]*(((["][^"]{1,}["]|[0-9]{1,}(\.[0-9]{1,})?|true|false)[\x0d\x0a[:blank:]]*,)|\{|\[)[\x0d\x0a[:blank:]]*/
}

# Match empty JSON documents.
signature file-json3 {
	file-mime "text/json", 0
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?[\x0d\x0a[:blank:]]*(\[\]|\{\})[\x0d\x0a[:blank:]]*$/
}

signature file-xml {
	file-mime "application/xml", 10
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*\x00?<\x00?\?\x00?x\x00?m\x00?l\x00? \x00?/
}

signature file-xhtml {
	file-mime "text/html", 100
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<(![dD][oO][cC][tT][yY][pP][eE] {1,}[hH][tT][mM][lL]|[hH][tT][mM][lL]|[mM][eE][tT][aA] {1,}[hH][tT][tT][pP]-[eE][qQ][uU][iI][vV])/
}

signature file-html {
	file-mime "text/html", 49
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<![dD][oO][cC][tT][yY][pP][eE] {1,}[hH][tT][mM][lL]/
}

signature file-html2 {
	file-mime "text/html", 20
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<([hH][eE][aA][dD]|[hH][tT][mM][lL]|[tT][iI][tT][lL][eE]|[bB][oO][dD][yY])/
}

signature file-rss {
	file-mime "text/rss", 90
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<[rR][sS][sS]/
}

signature file-atom {
	file-mime "text/atom", 100
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<([rR][sS][sS][^>]*xmlns:atom|[fF][eE][eE][dD][^>]*xmlns=["']?http:\/\/www.w3.org\/2005\/Atom["']?)/
}

signature file-soap {
	file-mime "application/soap+xml", 49
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<[sS][oO][aA][pP](-[eE][nN][vV])?:[eE][nN][vV][eE][lL][oO][pP][eE]/
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
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<[mM][eE][tT][hH][oO][dD][rR][eE][sS][pP][oO][nN][sS][eE]>/
}

signature file-coldfusion {
	file-mime "magnus-internal/cold-fusion", 20
	file-magic /^([\x0d\x0a[:blank:]]*(<!--.*-->)?)*<(CFPARAM|CFSET|CFIF)/
}

# Adobe Flash Media Manifest
signature file-f4m {
	file-mime "application/f4m", 49
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*(<\?xml .*\?>)?([\x0d\x0a[:blank:]]*(<!--.*-->)?[\x0d\x0a[:blank:]]*)*<[mM][aA][nN][iI][fF][eE][sS][tT][\x0d\x0a[:blank:]]{1,}xmlns=\"http:\/\/ns\.adobe\.com\/f4m\//
}

# .ini style files
signature file-ini {
	file-mime "text/ini", 20
	file-magic /^(\xef\xbb\xbf|\xff\xfe|\xfe\xff)?[\x00\x0d\x0a[:blank:]]*\[[^\x0d\x0a]+\][[:blank:]\x00]*[\x0d\x0a]/
}

# Microsoft LNK files
signature file-lnk {
	file-mime "application/x-ms-shortcut", 49
	file-magic /^\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46/
}

# Microsoft Registry policies
signature file-pol {
	file-mime "application/vnd.ms-pol", 49
	file-magic /^PReg/
}

# Old style Windows registry file
signature file-reg {
	file-mime "application/vnd.ms-reg", 49
	file-magic /^REGEDIT4/
}

# Newer Windows registry file
signature file-reg-utf16 {
	file-mime "application/vnd.ms-reg", 49
	file-magic /^\xFF\xFEW\x00i\x00n\x00d\x00o\x00w\x00s\x00 \x00R\x00e\x00g\x00i\x00s\x00t\x00r\x00y\x00 \x00E\x00d\x00i\x00t\x00o\x00r\x00 \x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00 \x005\x00\.\x000\x000/
}

# Microsoft Registry format (typically DESKTOP.DAT)
signature file-regf {
	file-mime "application/vnd.ms-regf", 49
	file-magic /^\x72\x65\x67\x66/
}

# Microsoft Outlook PST files
signature file-pst {
	file-mime "application/vnd.ms-outlook", 49
	file-magic /!BDN......[\x0e\x0f\x15\x17][\x00-\x02]/
}

signature file-afpinfo {
	file-mime "application/vnd.apple-afpinfo"
	file-magic /^AFP/
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

signature file-pkcs7 {
	file-magic /^MIME-Version:.*protocol=\"application\/pkcs7-signature\"/
	file-mime "application/pkcs7-signature", 100
}

# Concatenated X.509 certificates in textual format.
signature file-pem {
	file-magic /^-----BEGIN CERTIFICATE-----/
	file-mime "application/x-pem"
}

signature file-pcap {
	file-magic /^(\xa1\xb2\xc3\xd4|\xd4\xc3\xb2\xa1)/
	file-mime "application/vnd.tcpdump.pcap", 70
}

signature file-pcap-ng {
	file-magic /^\x0a\x0d\x0d\x0a.{4}(\x1a\x2b\x3c\x4d|\x4d\x3c\x2b\x1a)/
	file-mime "application/vnd.tcpdump.pcap", 100
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

# Microsoft DirectDraw Surface
signature file-msdds {
	file-mime "application/x-ms-dds", 100
	file-magic /^DDS/
}

# bsdiff output
signature file-bsdiff {
	file-mime "application/bsdiff", 100
	file-magic /^BSDIFF/
}

# AV Update binary diffs (mostly kaspersky)
#     inferred from traffic analysis
signature file-binarydiff {
	file-mime "application/bindiff", 100
	file-magic /^DIFF/
}

# Kaspersky Database
#    inferred from traffic analysis
signature file-kaspdb {
	file-mime "application/x-kaspavdb", 100
	file-magic /^KLZF/
}

# Kaspersky AV Database diff
#     inferred from traffic analysis
signature file-kaspdbdif {
	file-mime "application/x-kaspavupdate", 100
	file-magic /^KLD2/
}

# MSSQL Backups
signature file-mssqlbak {
	file-mime "application/mssql-bak", 100
	file-magic /^MSSQLBAK/
}

# Microsoft Tape Format
# MSSQL transaction log
signature file-ms-tf {
	file-mime "application/mtf", 100
	file-magic /^TAPE/
}

# Binary property list (Apple)
signature file-bplist {
	file-mime "application/bplist", 100
	file-magic /^bplist0?/
}

# Microsoft Compiled HTML Help File
signature file-mshelp {
	file-mime "application/mshelp", 100
	file-magic /^ITSF/
}

# Blizzard game file MPQ Format
signature file-mpqgame {
	file-mime "application/x-game-mpq", 100
	file-magic /^MPQ\x1a/
}

# Blizzard CASC Format game file
signature file-blizgame {
	file-mime "application/x-blizgame", 100
	file-magic /^BLTE/
}

# iOS Mapkit tiles
# inferred from traffic analysis
signature file-mapkit-tile {
	file-mime "application/map-tile", 100
	file-magic /^VMP4/
}

# Google Chrome Extension file
signature file-chrome-extension {
	file-mime "application/chrome-ext", 100
	file-magic /^Cr24/
}

# Google Chrome Extension Update Delta
# not 100% sure about this identification
# this may be google chrome updates, not extensions
signature file-chrome-extension-update {
	file-mime "application/chrome-ext-upd", 70
	file-magic /^CrOD/
}

# Microsoft Message Queueing
# .net related
signature file-msqm {
	file-mime "application/msqm", 100
	file-magic /^MSQM/
}

signature file-vim-tmp {
	file-mime "application/x-vim-tmp", 100
	file-magic /^b0VIM/
}

# Windows Minidump
signature file-windows-minidump {
    file-mime "application/x-windows-minidump", 50
    file-magic /^MDMP/
}

# ISO 9660 disk image
signature file-iso9660 {
        file-mime "application/x-iso9660-image", 99
        file-magic /CD001/
}
