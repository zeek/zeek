
# Macromedia Flash Video
signature file-flv {
	file-mime "video/x-flv", 60
	file-magic /^FLV/
}

# FLI animation
signature file-fli {
	file-mime "video/x-fli", 50
	file-magic /^.{4}\x11\xaf/
}

# FLC animation
signature file-flc {
	file-mime "video/x-flc", 50
	file-magic /^.{4}\x12\xaf/
}

# Motion JPEG 2000
signature file-mj2 {
	file-mime "video/mj2", 70
	file-magic /\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a.{8}mjp2/
}

# MNG video
signature file-mng {
	file-mime "video/x-mng", 70
	file-magic /^\x8aMNG/
}

# JNG video
signature file-jng {
	file-mime "video/x-jng", 70
	file-magic /^\x8bJNG/
}

# Generic MPEG container
signature file-mpeg {
	file-mime "video/mpeg", 50
	file-magic /(\x00\x00\x01[\xb0-\xbb])/
}

# MPV
signature file-mpv {
	file-mime "video/mpv", 71
	file-magic /(\x00\x00\x01\xb3)/
}

# H.264
signature file-h264 {
	file-mime "video/h264", 41
	file-magic /(\x00\x00\x00\x01)([\x07\x27\x47\x67\x87\xa7\xc7\xe7])/
}

# WebM video
signature file-webm {
	file-mime "video/webm", 70
	file-magic /(\x1a\x45\xdf\xa3)(.*)(B\x82)(.{1})(webm)/
}

# Matroska video
signature file-matroska {
	file-mime "video/x-matroska", 110
	file-magic /(\x1a\x45\xdf\xa3)(.*)(B\x82)(.{1})(matroska)/
}

# MP2P
signature file-mp2p {
	file-mime "video/mp2p", 21
	file-magic /\x00\x00\x01\xba([\x40-\x7f\xc0-\xff])/
}

# MPEG transport stream data. These files typically have the extension "ts".
# Note: The 0x47 repeats every 188 bytes. Using four as the number of
# occurrences for the test here is arbitrary.
signature file-mp2t {
	file-mime "video/mp2t", 40
	file-magic /^(\x47.{187}){4}/
}

# Silicon Graphics video
signature file-sgi-movie {
	file-mime "video/x-sgi-movie", 70
	file-magic /^MOVI/
}

# Apple QuickTime movie
signature file-quicktime {
	file-mime "video/quicktime", 70
	file-magic /^....(mdat|moov)/
}

# MPEG v4 video
signature file-mp4 {
	file-mime "video/mp4", 70
	file-magic /^....ftyp(isom|mp4[12])/
}

# 3GPP Video
signature file-3gpp {
	file-mime "video/3gpp", 60
	file-magic /^....ftyp(3g[egps2]|avc1|mmp4)/
}

