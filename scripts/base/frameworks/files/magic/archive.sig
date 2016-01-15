
signature file-tar {
    file-magic /^[[:print:]\x00]{100}([[:digit:]\x20]{7}\x00){3}([[:digit:]\x20]{11}\x00){2}([[:digit:]\x00\x20]{7}[\x20\x00])[0-7\x00]/
    file-mime "application/x-tar", 100
}

# This is low priority so that files using zip as a
# container will be identified correctly.
signature file-zip {
	file-mime "application/zip", 10
	file-magic /^PK\x03\x04.{2}/
}

# Multivolume Zip archive
signature file-multi-zip {
	file-mime "application/zip", 10
	file-magic /^PK\x07\x08PK\x03\x04/
}

# RAR
signature file-rar {
	file-mime "application/x-rar", 70
	file-magic /^Rar!/
}

# GZIP
signature file-gzip {
	file-mime "application/x-gzip", 100
	file-magic /\x1f\x8b/
}

# Microsoft Cabinet
signature file-ms-cab {
	file-mime "application/vnd.ms-cab-compressed", 110
	file-magic /^MSCF\x00\x00\x00\x00/
}

# Mac OS X DMG files
signature file-dmg {
	file-magic /^(\x78\x01\x73\x0D\x62\x62\x60|\x78\xDA\x63\x60\x18\x05|\x78\x01\x63\x60\x18\x05|\x78\xDA\x73\x0D|\x78[\x01\xDA]\xED[\xD0-\xD9])/
	file-mime "application/x-dmg", 100
}

# XAR (eXtensible ARchive) format.
# Mac OS X uses this for the .pkg format.
signature file-xar {
	file-magic /^xar\!/
	file-mime "application/x-xar", 100
}

# RPM
signature file-magic-auto352 {
	file-mime "application/x-rpm", 70
	file-magic /^(drpm|\xed\xab\xee\xdb)/
}

# StuffIt
signature file-stuffit {
	file-mime "application/x-stuffit", 70
	file-magic /^(SIT\x21|StuffIt)/
}

# Archived data
signature file-x-archive {
	file-mime "application/x-archive", 70
	file-magic /^!?<ar(ch)?>/
}

# ARC archive data
signature file-arc {
	file-mime "application/x-arc", 70
	file-magic /^[\x00-\x7f]{2}[\x02-\x0a\x14\x48]\x1a/
}

# EET archive
signature file-eet {
	file-mime "application/x-eet", 70
	file-magic /^\x1e\xe7\xff\x00/
}

# Zoo archive
signature file-zoo {
	file-mime "application/x-zoo", 70
	file-magic /^.{20}\xdc\xa7\xc4\xfd/
}

# LZ4 compressed data (legacy format)
signature file-lz4-legacy {
	file-mime "application/x-lz4", 70
	file-magic /(\x02\x21\x4c\x18)/
}

# LZ4 compressed data
signature file-lz4 {
	file-mime "application/x-lz4", 70
	file-magic /^\x04\x22\x4d\x18/
}

# LRZIP compressed data
signature file-lrzip {
	file-mime "application/x-lrzip", 1
	file-magic /^LRZI/
}

# LZIP compressed data
signature file-lzip {
	file-mime "application/x-lzip", 70
	file-magic /^LZIP/
}

# Self-extracting PKZIP archive
signature file-magic-auto434 {
	file-mime "application/zip", 340
	file-magic /^MZ.{28}(Copyright 1989\x2d1990 PKWARE Inc|PKLITE Copr)\x2e/
}

# LHA archive (LZH)
signature file-lzh {
	file-mime "application/x-lzh", 80
	file-magic /^.{2}-(lh[ abcdex0-9]|lz[s2-8]|lz[s2-8]|pm[s012]|pc1)-/
}

# WARC Archive
signature file-warc {
	file-mime "application/warc", 50
	file-magic /^WARC\x2f/
}

# 7-zip archive data
signature file-7zip {
	file-mime "application/x-7z-compressed", 50
	file-magic /^7z\xbc\xaf\x27\x1c/
}

# XZ compressed data
signature file-xz {
	file-mime "application/x-xz", 90
	file-magic /^\xfd7zXZ\x00/
}

# LHa self-extracting archive
signature file-magic-auto436 {
	file-mime "application/x-lha", 120
	file-magic /^MZ.{34}LH[aA]\x27s SFX/
}

# ARJ archive data
signature file-arj {
	file-mime "application/x-arj", 50
	file-magic /^\x60\xea/
}

# Byte-swapped cpio archive
signature file-bs-cpio {
	file-mime "application/x-cpio", 50
	file-magic /(\x71\xc7|\xc7\x71)/
}

# CPIO archive
signature file-cpio {
	file-mime "application/x-cpio", 50
	file-magic /^(\xc7\x71|\x71\xc7)/
}

# Compress'd data
signature file-compress {
	file-mime "application/x-compress", 50
	file-magic /^\x1f\x9d/
}

# LZMA compressed data
signature file-lzma {
	file-mime "application/x-lzma", 71
	file-magic /^\x5d\x00\x00/
}

