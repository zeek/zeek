
# >0  beshort&fffffffffffffffe,=-30 (0xffe2), ["MPEG ADTS, layer III,  v2.5"], swap_endian=0
signature file-magic-auto487 {
	file-mime "audio/mpeg", 50
	file-magic /(\xff[\xe2\xe3])/
}

# >0  beshort&fffffffffffffffe,=-10 (0xfff6), ["MPEG ADTS, layer I, v2"], swap_endian=0
signature file-magic-auto488 {
	file-mime "audio/mpeg", 50
	file-magic /(\xff[\xf6\xf7])/
}

# >0  beshort&fffffffffffffffe,=-14 (0xfff2), ["MPEG ADTS, layer III, v2"], swap_endian=0
signature file-magic-auto489 {
	file-mime "audio/mpeg", 50
	file-magic /(\xff[\xf2\xf3])/
}

# >0  beshort&fffffffffffffffe,=-4 (0xfffc), ["MPEG ADTS, layer II, v1"], swap_endian=0
signature file-magic-auto490 {
	file-mime "audio/mpeg", 50
	file-magic /(\xff[\xfc\xfd])/
}
# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0x10, ["MPEG ADTS, layer III, v1,  32 kbps"], swap_endian=0
signature file-magic-auto438 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0x20, ["MPEG ADTS, layer III, v1,  40 kbps"], swap_endian=0
signature file-magic-auto439 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0x30, ["MPEG ADTS, layer III, v1,  48 kbps"], swap_endian=0
signature file-magic-auto440 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0x40, ["MPEG ADTS, layer III, v1,  56 kbps"], swap_endian=0
signature file-magic-auto441 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0x50, ["MPEG ADTS, layer III, v1,  64 kbps"], swap_endian=0
signature file-magic-auto442 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0x60, ["MPEG ADTS, layer III, v1,  80 kbps"], swap_endian=0
signature file-magic-auto443 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0x70, ["MPEG ADTS, layer III, v1,  96 kbps"], swap_endian=0
signature file-magic-auto444 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0x80, ["MPEG ADTS, layer III, v1, 112 kbps"], swap_endian=0
signature file-magic-auto445 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0x90, ["MPEG ADTS, layer III, v1, 128 kbps"], swap_endian=0
signature file-magic-auto446 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0xa0, ["MPEG ADTS, layer III, v1, 160 kbps"], swap_endian=0
signature file-magic-auto447 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0xb0, ["MPEG ADTS, layer III, v1, 192 kbps"], swap_endian=0
signature file-magic-auto448 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0xc0, ["MPEG ADTS, layer III, v1, 224 kbps"], swap_endian=0
signature file-magic-auto449 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0xd0, ["MPEG ADTS, layer III, v1, 256 kbps"], swap_endian=0
signature file-magic-auto450 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf])/
}

# >0  beshort&fffffffffffffffe,=-6 (0xfffa), [""], swap_endian=0
# >>2  byte&fffffffffffffff0,=0xe0, ["MPEG ADTS, layer III, v1, 320 kbps"], swap_endian=0
signature file-magic-auto451 {
	file-mime "audio/mpeg", 40
	file-magic /(\xff[\xfa\xfb])([\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef])/
}
