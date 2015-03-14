
signature file-tiff {
	file-mime "image/tiff", 70
	file-magic /^(MM\x00[\x2a\x2b]|II[\x2a\x2b]\x00)/
}

signature file-gif {
	file-mime "image/gif", 70
	file-magic /^GIF8/
}


# >0  beshort&,=-40 (0xffd8), ["JPEG image data"], swap_endian=0
signature file-magic-auto427 {
	file-mime "image/jpeg", 52
	file-magic /(\xff\xd8)/
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

# >0  string,=8BPS (len=4), ["Adobe Photoshop Image"], swap_endian=0
signature file-magic-auto289 {
	file-mime "image/vnd.adobe.photoshop", 70
	file-magic /(8BPS)/
}

signature file-png {
	file-mime "image/png", 110
	file-magic /^\x89PNG\x0d\x0a\x1a\x0a/
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

# >0  string,=Xcur (len=4), ["Xcursor data"], swap_endian=0
signature file-magic-auto271 {
	file-mime "image/x-xcursor", 70
	file-magic /(Xcur)/
}

# >0  string,=IIN1 (len=4), ["NIFF image data"], swap_endian=0
signature file-magic-auto282 {
	file-mime "image/x-niff", 70
	file-magic /(IIN1)/
}

# >0  lelong&,=20000630 (0x01312f76), ["OpenEXR image data,"], swap_endian=0
signature file-magic-auto291 {
	file-mime "image/x-exr", 70
	file-magic /(\x76\x2f\x31\x01)/
}

# >0  string,=SDPX (len=4), ["DPX image data, big-endian,"], swap_endian=0
signature file-magic-auto292 {
	file-mime "image/x-dpx", 70
	file-magic /(SDPX)/
}

# >0  string,=CPC\262 (len=4), ["Cartesian Perceptual Compression image"], swap_endian=0
signature file-magic-auto294 {
	file-mime "image/x-cpi", 70
	file-magic /(CPC\xb2)/
}


signature file-orf {
	file-mime "image/x-olympus-orf", 70
	file-magic /IIR[OS]|MMOR/
}

# >0  string,=FOVb (len=4), ["Foveon X3F raw image data"], swap_endian=0
signature file-magic-auto298 {
	file-mime "image/x-x3f", 70
	file-magic /(FOVb)/
}

# >0  string,=PDN3 (len=4), ["Paint.NET image data"], swap_endian=0
signature file-magic-auto299 {
	file-mime "image/x-paintnet", 70
	file-magic /(PDN3)/
}

# >0  string,=RIFF (len=4), ["RIFF (little-endian) data"], swap_endian=0
# >>8  string,=CDRA (len=4), [", Corel Draw Picture"], swap_endian=0
signature file-magic-auto355 {
	file-mime "image/x-coreldraw", 70
	file-magic /(RIFF)(.{4})(CDRA)/
}

# >0  string,=RIFF (len=4), ["RIFF (little-endian) data"], swap_endian=0
# >>8  string,=CDR6 (len=4), [", Corel Draw Picture, version 6"], swap_endian=0
signature file-magic-auto356 {
	file-mime "image/x-coreldraw", 70
	file-magic /(RIFF)(.{4})(CDR6)/
}

# >0  string,=P7 (len=2), ["Netpbm PAM image file"], swap_endian=0
signature file-magic-auto484 {
	file-mime "image/x-portable-pixmap", 50
	file-magic /(P7)/
}

# >4  string/W,=jP (len=2), ["JPEG 2000 image"], swap_endian=0
signature file-magic-auto497 {
	file-mime "image/jp2", 50
	file-magic /(.{4})(jP)/
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

# >0  string,=gimp xcf (len=8), ["GIMP XCF image data,"], swap_endian=0
signature file-magic-auto115 {
	file-mime "image/x-xcf", 110
	file-magic /(gimp xcf)/
}

# >0  string/t,=[BitmapInfo2] (len=13), ["Polar Monitor Bitmap text"], swap_endian=0
signature file-magic-auto62 {
	file-mime "image/x-polar-monitor-bitmap", 160
	file-magic /(\x5bBitmapInfo2\x5d)/
}

# >0  string,=AWBM (len=4), [""], swap_endian=0
# >>4  leshort&,<1981 (0x07bd), ["Award BIOS bitmap"], swap_endian=0
signature file-magic-auto208 {
	file-mime "image/x-award-bmp", 20
	file-magic /(AWBM)(.{2})/
}

# >0  string,=\021\006 (len=2), ["Award BIOS Logo, 136 x 84"], swap_endian=0
signature file-magic-auto483 {
	file-mime "image/x-award-bioslogo", 50
	file-magic /^\x11[\x06\x09]/
}
