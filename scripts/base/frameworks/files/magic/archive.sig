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

signature file-rar {
	file-mime "application/x-rar", 70
	file-magic /^Rar!/
}

signature file-gzip {
	file-mime "application/x-gzip", 100
	file-magic /\x1f\x8b/
}

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

signature file-stuffit {
	file-mime "application/x-stuffit", 70
	file-magic /^(SIT\x21|StuffIt)/
}

signature file-x-archive {
	file-mime "application/x-archive", 70
	file-magic /^!?<ar(ch)?>/
}

# ARC archive data
signature file-arc {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})([\x02-\x0a\x14\x48]\x1a)/
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

# >0  lelong&,=407642370 (0x184c2102), ["LZ4 compressed data, legacy format"], swap_endian=0
signature file-magic-auto382 {
	file-mime "application/x-lz4", 70
	file-magic /(\x02\x21\x4c\x18)/
}

# >0  lelong&,=407708164 (0x184d2204), ["LZ4 compressed data"], swap_endian=0
signature file-magic-auto383 {
	file-mime "application/x-lz4", 70
	file-magic /(\x04\x22\x4d\x18)/
}

# >0  string,=LRZI (len=4), ["LRZIP compressed data"], swap_endian=0
# >>5  byte&,x, [".%d"], swap_endian=0
signature file-magic-auto384 {
	file-mime "application/x-lrzip", 1
	file-magic /(LRZI)(.{1})(.{1})/
}

# >0  string,=LZIP (len=4), ["lzip compressed data"], swap_endian=0
signature file-magic-auto386 {
	file-mime "application/x-lzip", 70
	file-magic /(LZIP)/
}

# >0  string/b,=MZ (len=2), [""], swap_endian=0
# >>30  string,=Copyright 1989-1990 PKWARE Inc. (len=31), ["Self-extracting PKZIP archive"], swap_endian=0
signature file-magic-auto434 {
	file-mime "application/zip", 340
	file-magic /(MZ)(.{28})(Copyright 1989\x2d1990 PKWARE Inc\x2e)/
}

# >0  string/b,=MZ (len=2), [""], swap_endian=0
# >>30  string,=PKLITE Copr. (len=12), ["Self-extracting PKZIP archive"], swap_endian=0
signature file-magic-auto435 {
	file-mime "application/zip", 150
	file-magic /(MZ)(.{28})(PKLITE Copr\x2e)/
}

# LHA archive (LZH)
signature file-lzh {
	file-mime "application/x-lzh", 80
	file-magic /^.{2}-(lh[ abcdex0-9]|lz[s2-8]|lz[s2-8]|pm[s012]|pc1)-/
}

# >0  string,=WARC/ (len=5), ["WARC Archive"], swap_endian=0
# >>5  string,x, ["version %.4s"], swap_endian=0
signature file-magic-auto177 {
	file-mime "application/warc", 1
	file-magic /(WARC\x2f)(.{0})/
}

# >0  string,=7z\274\257'\034 (len=6), ["7-zip archive data,"], swap_endian=0
# >>7  byte&,x, [".%d"], swap_endian=0
signature file-magic-auto150 {
	file-mime "application/x-7z-compressed", 1
	file-magic /(7z\xbc\xaf\x27\x1c)(.{1})(.{1})/
}

# >0  ustring,=\3757zXZ\000 (len=6), ["XZ compressed data"], swap_endian=0
signature file-magic-auto151 {
	file-mime "application/x-xz", 90
	file-magic /(\xfd7zXZ\x00)/
}
# >0  string/b,=MZ (len=2), [""], swap_endian=0
# >>36  string,=LHa's SFX (len=9), [", LHa self-extracting archive"], swap_endian=0
signature file-magic-auto436 {
	file-mime "application/x-lha", 120
	file-magic /(MZ)(.{34})(LHa\x27s SFX)/
}

# >0  string/b,=MZ (len=2), [""], swap_endian=0
# >>36  string,=LHA's SFX (len=9), [", LHa self-extracting archive"], swap_endian=0
signature file-magic-auto437 {
	file-mime "application/x-lha", 120
	file-magic /(MZ)(.{34})(LHA\x27s SFX)/
}

# >0  leshort&,=-5536 (0xea60), ["ARJ archive data"], swap_endian=0
signature file-magic-auto467 {
	file-mime "application/x-arj", 50
	file-magic /(\x60\xea)/
}

# >0  short&,=-14479 (0xc771), ["byte-swapped cpio archive"], swap_endian=0
signature file-magic-auto479 {
	file-mime "application/x-cpio", 50
	file-magic /((\x71\xc7)|(\xc7\x71))/
}

# >0  short&,=29127 (0x71c7), ["cpio archive"], swap_endian=0
signature file-magic-auto480 {
	file-mime "application/x-cpio", 50
	file-magic /((\xc7\x71)|(\x71\xc7))/
}

# >0  string,=\037\235 (len=2), ["compress'd data"], swap_endian=0
signature file-magic-auto500 {
	file-mime "application/x-compress", 50
	file-magic /(\x1f\x9d)/
}

# >0  lelong&00ffffff,=93 (0x0000005d), [""], swap_endian=0
signature file-magic-auto218 {
	file-mime "application/x-lzma", 71
	file-magic /(\x5d\x00\x00.)/
}

