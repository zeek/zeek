
signature file-tiff {
	file-mime "image/tiff", 70
	file-magic /^(MM\x00[\x2a\x2b]|II[\x2a\x2b]\x00)/
}

signature file-gif {
	file-mime "image/gif", 70
	file-magic /^GIF8/
}

# JPEG image
signature file-jpeg {
	file-mime "image/jpeg", 52
	file-magic /^\xff\xd8/
}

signature file-bmp {
	file-mime "image/x-ms-bmp", 50
	file-magic /BM.{12}[\x0c\x28\x40\x6c\x7c\x80]\x00/
}

signature file-ico {
	file-magic /^\x00\x00\x01\x00/
	file-mime "image/x-icon", 70
}

signature file-cur {
	file-magic /^\x00\x00\x02\x00/
	file-mime "image/x-cursor", 70
}

signature file-magic-auto289 {
	file-mime "image/vnd.adobe.photoshop", 70
	file-magic /^8BPS/
}

signature file-png {
	file-mime "image/png", 110
	file-magic /^\x89PNG/
}

# JPEG 2000
signature file-jp2 {
	file-mime "image/jp2", 60
	file-magic /.{4}ftypjp2/
}

# JPEG 2000
signature file-jp22 {
	file-mime "image/jp2", 70
	file-magic /\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a.{8}jp2 /
}

# JPEG 2000
signature file-jpx {
	file-mime "image/jpx", 70
	file-magic /\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a.{8}jpx /
}

# JPEG 2000
signature file-jpm {
	file-mime "image/jpm", 70
	file-magic /\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a.{8}jpm /
}

# Xcursor image
signature file-x-cursor {
	file-mime "image/x-xcursor", 70
	file-magic /^Xcur/
}

# NIFF image
signature file-niff {
	file-mime "image/x-niff", 70
	file-magic /^IIN1/
}

# OpenEXR image
signature file-openexr {
	file-mime "image/x-exr", 70
	file-magic /^\x76\x2f\x31\x01/
}

# DPX image
signature file-dpx {
	file-mime "image/x-dpx", 70
	file-magic /^SDPX/
}

# Cartesian Perceptual Compression image
signature file-cpi {
	file-mime "image/x-cpi", 70
	file-magic /(CPC\xb2)/
}

signature file-orf {
	file-mime "image/x-olympus-orf", 70
	file-magic /IIR[OS]|MMOR/
}

# Foveon X3F raw image
signature file-x3r {
	file-mime "image/x-x3f", 70
	file-magic /^FOVb/
}

# Paint.NET image
signature file-paint-net {
	file-mime "image/x-paintnet", 70
	file-magic /^PDN3/
}

# Corel Draw Picture
signature file-coreldraw {
	file-mime "image/x-coreldraw", 70
	file-magic /^RIFF....CDR[A6]/
}

# Netpbm PAM image
signature file-netbpm{
	file-mime "image/x-portable-pixmap", 50
	file-magic /^P7/
}

# JPEG 2000 image
signature file-jpeg-2000 {
	file-mime "image/jp2", 50
	file-magic /^....jP/
}

# DjVU Images
signature file-djvu {
	file-mime "image/vnd.djvu", 70
	file-magic /AT\x26TFORM.{4}(DJV[MUI]|THUM)/
}

# DWG AutoDesk AutoCAD
signature file-dwg {
	file-mime "image/vnd.dwg", 90
	file-magic /^(AC[12]\.|AC10)/
}

# GIMP XCF image
signature file-gimp-xcf {
	file-mime "image/x-xcf", 110
	file-magic /^gimp xcf/
}

# Polar Monitor Bitmap text
signature file-polar-monitor-bitmap {
	file-mime "image/x-polar-monitor-bitmap", 160
	file-magic /^\x5bBitmapInfo2\x5d/
}

# Award BIOS bitmap
signature file-award-bitmap {
	file-mime "image/x-award-bmp", 20
	file-magic /^AWBM/
}

# Award BIOS Logo, 136 x 84
signature file-award-bios-logo {
	file-mime "image/x-award-bioslogo", 50
	file-magic /^\x11[\x06\x09]/
}
