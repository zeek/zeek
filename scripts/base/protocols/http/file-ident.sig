# These signatures are used as a replacement for libmagic.  The signature
# name needs to start with "matchfile" and the "event" directive takes 
# the mime type of the file matched by the http-reply-body pattern.
#
# Signatures from: http://www.garykessler.net/library/file_sigs.html

signature matchfile-exe {
	http-reply-body /\x4D\x5A/
	event "application/x-dosexec"
}

signature matchfile-elf {
	http-reply-body /\x7F\x45\x4C\x46/
	event "application/x-executable"
}

signature matchfile-script {
	# This is meant to match the interpreter declaration at the top of many 
	# interpreted scripts.
	http-reply-body /\#\![[:blank:]]?\//
	event "application/x-script"
}

signature matchfile-wmv {
	http-reply-body /\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C/
	event "video/x-ms-wmv"
}

signature matchfile-flv {
	http-reply-body /\x46\x4C\x56\x01/
	event "video/x-flv"
}

signature matchfile-swf {
	http-reply-body /[\x46\x43]\x57\x53/
	event "application/x-shockwave-flash"
}

signature matchfile-jar {
	http-reply-body /\x5F\x27\xA8\x89/
	event "application/java-archive"
}

signature matchfile-class {
	http-reply-body /\xCA\xFE\xBA\xBE/
	event "application/java-byte-code"
}

signature matchfile-msoffice-2007 {
	# MS Office 2007 XML documents
	http-reply-body /\x50\x4B\x03\x04\x14\x00\x06\x00/
	event "application/msoffice"
}

signature matchfile-msoffice {
	# Older MS Office files
	http-reply-body /\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1/
	event "application/msoffice"
}

signature matchfile-rtf {
	http-reply-body /\x7B\x5C\x72\x74\x66\x31/
	event "application/rtf"
}

signature matchfile-lnk {
	http-reply-body /\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46/
	event "application/x-ms-shortcut"
}

signature matchfile-torrent {
	http-reply-body /\x64\x38\x3A\x61\x6E\x6E\x6F\x75\x6E\x63\x65/
	event "application/x-bittorrent"
}

signature matchfile-pdf {
	http-reply-body /\x25\x50\x44\x46/
	event "application/pdf"
}

signature matchfile-html {
	http-reply-body /<[hH][tT][mM][lL]/
	event "text/html"
}

signature matchfile-html2 {
	http-reply-body /<![dD][oO][cC][tT][yY][pP][eE][[:blank:]][hH][tT][mM][lL]/
	event "text/html"
}

signature matchfile-xml {
	http-reply-body /<\??[xX][mM][lL]/
	event "text/xml"
}

signature matchfile-gif {
	http-reply-body /\x47\x49\x46\x38[\x37\x39]\x61/
	event "image/gif"
}

signature matchfile-jpg {
	http-reply-body /\xFF\xD8\xFF[\xDB\xE0\xE1\xE2\xE3\xE8]..[\x4A\x45\x53][\x46\x78\x50][\x49\x69][\x46\x66]/
	event "image/jpeg"
}

signature matchfile-tiff {
	http-reply-body /\x4D\x4D\x00[\x2A\x2B]/
	event "image/tiff"
}

signature matchfile-png {
	http-reply-body /\x89\x50\x4e\x47/
	event "image/png"
}

signature matchfile-zip {
	http-reply-body /\x50\x4B\x03\x04/
	event "application/zip"
}

signature matchfile-bzip {
	http-reply-body /\x42\x5A\x68/
	event "application/bzip2"
}

signature matchfile-gzip {
	http-reply-body /\x1F\x8B\x08/
	event "application/x-gzip"
}

signature matchfile-cab {
	http-reply-body /\x4D\x53\x43\x46/
	event "application/vnd.ms-cab-compressed"
}

signature matchfile-rar {
	http-reply-body /\x52\x61\x72\x21\x1A\x07\x00/
	event "application/x-rar-compressed"
}

signature matchfile-7z {
	http-reply-body /\x37\x7A\xBC\xAF\x27\x1C/
	event "application/x-7z-compressed"
}
