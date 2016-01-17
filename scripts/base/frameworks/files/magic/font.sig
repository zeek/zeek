
# Web Open Font Format
signature file-woff {
	file-magic /^wOFF/
	file-mime "application/font-woff", 70
}

# TrueType font
signature file-ttf {
	file-mime "application/x-font-ttf", 80
	file-magic /^\x00\x01\x00\x00\x00/
}

signature file-embedded-opentype {
	file-mime "application/vnd.ms-fontobject", 50
	file-magic /^.{34}LP/
}

# X11 SNF font
signature file-snf {
	file-mime "application/x-font-sfn", 70
	file-magic /^(\x04\x00\x00\x00|\x00\x00\x00\x04).{100}(\x04\x00\x00\x00|\x00\x00\x00\x04)/
}

# OpenType font
signature file-opentype {
	file-mime "application/vnd.ms-opentype", 70
	file-magic /^OTTO/
}

# FrameMaker Font file
signature file-maker-screen-font {
	file-mime "application/x-mif", 190
	file-magic /^\x3cMakerScreenFont/
}

# >0  string,=SplineFontDB: (len=13), ["Spline Font Database "], swap_endian=0
signature file-spline-font-db {
	file-mime "application/vnd.font-fontforge-sfd", 160
	file-magic /^SplineFontDB\x3a/
}
