# >0  string,=FLV (len=3), ["Macromedia Flash Video"], swap_endian=0
signature file-magic-auto400 {
	file-mime "video/x-flv", 60
	file-magic /(FLV)/
}

# >4  leshort&,=-20719 (0xaf11), [""], swap_endian=0
# >>8  leshort&,=320 (0x0140), [""], swap_endian=0
# >>>10  leshort&,=200 (0x00c8), [""], swap_endian=0
# >>>>12  leshort&,=8 (0x0008), ["FLI animation, 320x200x8"], swap_endian=0
signature file-magic-auto452 {
	file-mime "video/x-fli", 50
	file-magic /(.{4})(\x11\xaf)(.{2})(\x40\x01)(\xc8\x00)(\x08\x00)/
}

# >4  leshort&,=-20718 (0xaf12), [""], swap_endian=0
# >>12  leshort&,=8 (0x0008), ["FLC animation"], swap_endian=0
signature file-magic-auto453 {
	file-mime "video/x-flc", 50
	file-magic /(.{4})(\x12\xaf)(.{6})(\x08\x00)/
}

# Motion JPEG 2000
signature file-mj2 {
	file-mime "video/mj2", 70
	file-magic /\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a.{8}mjp2/
}

# >0  string,=\212MNG (len=4), ["MNG video data,"], swap_endian=0
signature file-magic-auto274 {
	file-mime "video/x-mng", 70
	file-magic /(\x8aMNG)/
}

# >0  string,=\213JNG (len=4), ["JNG video data,"], swap_endian=0
signature file-magic-auto275 {
	file-mime "video/x-jng", 70
	file-magic /(\x8bJNG)/
}

# >0  belong&,=443 (0x000001bb), [""], swap_endian=0
signature file-magic-auto204 {
	file-mime "video/mpeg", 71
	file-magic /(\x00\x00\x01\xbb)/
}

# >0  belong&,=432 (0x000001b0), [""], swap_endian=0
signature file-magic-auto206 {
	file-mime "video/mp4v-es", 71
	file-magic /(\x00\x00\x01\xb0)/
}

# >0  belong&,=437 (0x000001b5), [""], swap_endian=0
signature file-magic-auto207 {
	file-mime "video/mp4v-es", 71
	file-magic /(\x00\x00\x01\xb5)/
}

# >0  belong&,=435 (0x000001b3), [""], swap_endian=0
signature file-magic-auto209 {
	file-mime "video/mpv", 71
	file-magic /(\x00\x00\x01\xb3)/
}

# >0  belong&,=1 (0x00000001), [""], swap_endian=0
# >>4  byte&0000001f,=0x07, [""], swap_endian=0
signature file-magic-auto211 {
	file-mime "video/h264", 41
	file-magic /(\x00\x00\x00\x01)([\x07\x27\x47\x67\x87\xa7\xc7\xe7])/
}

# >0  belong&ffffffffffffff00,=256 (0x00000100), [""], swap_endian=0
# >>3  byte&,=0xba, ["MPEG sequence"], swap_endian=0
signature file-magic-auto213 {
	file-mime "video/mpeg", 40
	file-magic /(\x00\x00\x01\xba)/
}

# >0  belong&ffffffffffffff00,=256 (0x00000100), [""], swap_endian=0
# >>3  byte&,=0xb0, ["MPEG sequence, v4"], swap_endian=0
signature file-magic-auto214 {
	file-mime "video/mpeg4-generic", 40
	file-magic /(\x00\x00\x01\xb0)/
}

# >0  belong&ffffffffffffff00,=256 (0x00000100), [""], swap_endian=0
# >>3  byte&,=0xb5, ["MPEG sequence, v4"], swap_endian=0
signature file-magic-auto215 {
	file-mime "video/mpeg4-generic", 40
	file-magic /(\x00\x00\x01\xb5)/
}

# >0  belong&ffffffffffffff00,=256 (0x00000100), [""], swap_endian=0
# >>3  byte&,=0xb3, ["MPEG sequence"], swap_endian=0
signature file-magic-auto216 {
	file-mime "video/mpeg", 40
	file-magic /(\x00\x00\x01\xb3)/
}

# >0  belong&,=442 (0x000001ba), [""], swap_endian=0
# >>4  byte&,^0x40, [""], swap_endian=0
signature file-magic-auto251 {
	file-mime "video/mpeg", 21
	file-magic /(\x00\x00\x01\xba)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf])/
}

# >0  belong&,=440786851 (0x1a45dfa3), [""], swap_endian=0
# >>4  search/4096,=B\202 (len=2), [""], swap_endian=0
# >>>&1  string,=webm (len=4), ["WebM"], swap_endian=0
signature file-magic-auto224 {
	file-mime "video/webm", 70
	file-magic /(\x1a\x45\xdf\xa3)(.*)(B\x82)(.{1})(webm)/
}

# >0  belong&,=440786851 (0x1a45dfa3), [""], swap_endian=0
# >>4  search/4096,=B\202 (len=2), [""], swap_endian=0
# >>>&1  string,=matroska (len=8), ["Matroska data"], swap_endian=0
signature file-magic-auto225 {
	file-mime "video/x-matroska", 110
	file-magic /(\x1a\x45\xdf\xa3)(.*)(B\x82)(.{1})(matroska)/
}

# >0  belong&,=442 (0x000001ba), [""], swap_endian=0
# >>4  byte&,&0x40, [""], swap_endian=0
signature file-magic-auto250 {
	file-mime "video/mp2p", 21
	file-magic /(\x00\x00\x01\xba)([\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  string,=MOVI (len=4), ["Silicon Graphics movie file"], swap_endian=0
signature file-magic-auto252 {
	file-mime "video/x-sgi-movie", 70
	file-magic /(MOVI)/
}

# >4  string,=moov (len=4), ["Apple QuickTime"], swap_endian=0
signature file-magic-auto253 {
	file-mime "video/quicktime", 70
	file-magic /(.{4})(moov)/
}

# >4  string,=mdat (len=4), ["Apple QuickTime movie (unoptimized)"], swap_endian=0
signature file-magic-auto254 {
	file-mime "video/quicktime", 70
	file-magic /(.{4})(mdat)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=isom (len=4), [", MPEG v4 system, version 1"], swap_endian=0
signature file-magic-auto257 {
	file-mime "video/mp4", 70
	file-magic /(.{4})(ftyp)(isom)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=mp41 (len=4), [", MPEG v4 system, version 1"], swap_endian=0
signature file-magic-auto258 {
	file-mime "video/mp4", 70
	file-magic /(.{4})(ftyp)(mp41)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=mp42 (len=4), [", MPEG v4 system, version 2"], swap_endian=0
signature file-magic-auto259 {
	file-mime "video/mp4", 70
	file-magic /(.{4})(ftyp)(mp42)/
}


# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=3ge (len=3), [", MPEG v4 system, 3GPP"], swap_endian=0
signature file-magic-auto261 {
	file-mime "video/3gpp", 60
	file-magic /(.{4})(ftyp)(3ge)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=3gg (len=3), [", MPEG v4 system, 3GPP"], swap_endian=0
signature file-magic-auto262 {
	file-mime "video/3gpp", 60
	file-magic /(.{4})(ftyp)(3gg)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=3gp (len=3), [", MPEG v4 system, 3GPP"], swap_endian=0
signature file-magic-auto263 {
	file-mime "video/3gpp", 60
	file-magic /(.{4})(ftyp)(3gp)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=3gs (len=3), [", MPEG v4 system, 3GPP"], swap_endian=0
signature file-magic-auto264 {
	file-mime "video/3gpp", 60
	file-magic /(.{4})(ftyp)(3gs)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=3g2 (len=3), [", MPEG v4 system, 3GPP2"], swap_endian=0
signature file-magic-auto265 {
	file-mime "video/3gpp2", 60
	file-magic /(.{4})(ftyp)(3g2)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=mmp4 (len=4), [", MPEG v4 system, 3GPP Mobile"], swap_endian=0
signature file-magic-auto266 {
	file-mime "video/mp4", 70
	file-magic /(.{4})(ftyp)(mmp4)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string,=avc1 (len=4), [", MPEG v4 system, 3GPP JVT AVC"], swap_endian=0
signature file-magic-auto267 {
	file-mime "video/3gpp", 70
	file-magic /(.{4})(ftyp)(avc1)/
}

