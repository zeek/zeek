
# MPEG v3 audio
signature file-mpeg-audio {
	file-mime "audio/mpeg", 20
	file-magic /^\xff[\xe2\xe3\xf2\xf3\xf6\xf7\xfa\xfb\xfc\xfd]/
}

# MPEG v4 audio
signature file-m4a {
	file-mime "audio/m4a", 70
	file-magic /^....ftyp(m4a)/
}

