# General purpose file magic signatures.

signature file-plaintext {
    file-magic /^([[:print:][:space:]]{10})/
    file-mime "text/plain", -20
}

signature file-tar {
    file-magic /^([[:print:]\x00]){100}(([[:digit:]\x00\x20]){8}){3}/
    file-mime "application/x-tar", 150
}

signature file-zip {
	file-mime "application/zip", 10
	file-magic /^PK\x03\x04.{2}/
}

signature file-jar {
	file-mime "application/java-archive", 100
	file-magic /^PK\x03\x04.{1,200}\x14\x00..META-INF\/MANIFEST\.MF/
}

signature file-java-applet {
	file-magic /^\xca\xfe\xba\xbe...[\x2e-\x34]/
	file-mime "application/x-java-applet", 71
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

# Mac OS X DMG files
signature file-dmg {
	file-magic /^(\x78\x01\x73\x0D\x62\x62\x60|\x78\xDA\x63\x60\x18\x05|\x78\x01\x63\x60\x18\x05|\x78\xDA\x73\x0D|\x78[\x01\xDA]\xED[\xD0-\xD9])/
	file-mime "application/x-dmg", 100
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

# XAR (eXtensible ARchive) format. 
# Mac OS X uses this for the .pkg format.
signature file-xar {
	file-magic /^xar\!/
	file-mime "application/x-xar", 100
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

signature file-ico {
	file-magic /^\x00\x00\x01\x00/
	file-mime "image/x-icon", 70
}

signature file-cur {
	file-magic /^\x00\x00\x02\x00/
	file-mime "image/x-cursor", 70
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

signature file-php {
	file-magic /.*<\?php/
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
