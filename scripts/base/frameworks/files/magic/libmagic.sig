# These signatures were semi-automatically generated from libmagic's
# (~ v5.17) magic database rules that have an associated mime type.
# After generating, they were all manually reviewed and occassionally
# needed minor modifications by hand or were just ommited depending on
# the complexity of the original magic rules.
#
# The instrumented version of the `file` command used to generate these
# is located at: https://github.com/jsiwek/file/tree/bro-signatures.

# >2080  string,=Foglio di lavoro Microsoft Exce (len=31), ["%s"], swap_endian=0
signature file-magic-auto0 {
	file-mime "application/vnd.ms-excel", 340
	file-magic /(.{2080})(Foglio di lavoro Microsoft Exce)/
}

# >2  string,=---BEGIN PGP PUBLIC KEY BLOCK- (len=30), ["PGP public key block"], swap_endian=0
signature file-magic-auto1 {
	file-mime "application/pgp-keys", 330
	file-magic /(.{2})(\x2d\x2d\x2dBEGIN PGP PUBLIC KEY BLOCK\x2d)/
}

# >2080  string,=Microsoft Excel 5.0 Worksheet (len=29), ["%s"], swap_endian=0
signature file-magic-auto2 {
	file-mime "application/vnd.ms-excel", 320
	file-magic /(.{2080})(Microsoft Excel 5\x2e0 Worksheet)/
}

# >11  string,=must be converted with BinHex (len=29), ["BinHex binary text"], swap_endian=0
signature file-magic-auto3 {
	file-mime "application/mac-binhex40", 320
	file-magic /(.{11})(must be converted with BinHex)/
}

# >2080  string,=Microsoft Word 6.0 Document (len=27), ["%s"], swap_endian=0
signature file-magic-auto4 {
	file-mime "application/msword", 300
	file-magic /(.{2080})(Microsoft Word 6\x2e0 Document)/
}

# >2080  string,=Documento Microsoft Word 6 (len=26), ["Spanish Microsoft Word 6 document data"], swap_endian=0
signature file-magic-auto5 {
	file-mime "application/msword", 290
	file-magic /(.{2080})(Documento Microsoft Word 6)/
}

# >0  string,=-----BEGIN PGP SIGNATURE- (len=25), ["PGP signature"], swap_endian=0
signature file-magic-auto6 {
	file-mime "application/pgp-signature", 280
	file-magic /(\x2d\x2d\x2d\x2d\x2dBEGIN PGP SIGNATURE\x2d)/
}

# >10  string,=# This is a shell archive (len=25), ["shell archive text"], swap_endian=0
signature file-magic-auto7 {
	file-mime "application/x-shar", 280
	file-magic /(.{10})(\x23 This is a shell archive)/
}

# >0  string,=-----BEGIN PGP MESSAGE- (len=23), ["PGP message"], swap_endian=0
signature file-magic-auto8 {
	file-mime "application/pgp", 260
	file-magic /(\x2d\x2d\x2d\x2d\x2dBEGIN PGP MESSAGE\x2d)/
}

# >0  string,=<SCRIBUSUTF8NEW Version (len=23), ["Scribus Document"], swap_endian=0
signature file-magic-auto9 {
	file-mime "application/x-scribus", 260
	file-magic /(\x3cSCRIBUSUTF8NEW Version)/
}

# >0  string,=<?php /* Smarty version (len=23), ["Smarty compiled template"], swap_endian=0
# >>24  regex,=[0-9.]+ (len=7), [", version %s"], swap_endian=0
signature file-magic-auto10 {
	file-mime "text/x-php", 37
	file-magic /(\x3c\x3fphp \x2f\x2a Smarty version)(.{1})([0-9.]+)/
}

# >0  string/w,=<map version="freeplane (len=23), ["Freeplane document"], swap_endian=0
signature file-magic-auto11 {
	file-mime "application/x-freeplane", 260
	file-magic /(\x3cmap ?version\x3d\x22freeplane)/
}

# >0  string/wt,=#! /usr/local/bin/nawk (len=22), ["new awk script text executable"], swap_endian=0
signature file-magic-auto12 {
	file-mime "text/x-nawk", 250
	file-magic /(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fnawk)/
}

# >0  string/wt,=#! /usr/local/bin/gawk (len=22), ["GNU awk script text executable"], swap_endian=0
signature file-magic-auto13 {
	file-mime "text/x-gawk", 250
	file-magic /(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fgawk)/
}

# >0  string/wt,=#! /usr/local/bin/bash (len=22), ["Bourne-Again shell script text executable"], swap_endian=0
signature file-magic-auto14 {
	file-mime "text/x-shellscript", 250
	file-magic /(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fbash)/
}

# >0  string/wt,=#! /usr/local/bin/tcsh (len=22), ["Tenex C shell script text executable"], swap_endian=0
signature file-magic-auto15 {
	file-mime "text/x-shellscript", 250
	file-magic /(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2ftcsh)/
}

# >0  string/wt,=#! /usr/local/bin/zsh (len=21), ["Paul Falstad's zsh script text executable"], swap_endian=0
signature file-magic-auto16 {
	file-mime "text/x-shellscript", 240
	file-magic /(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fzsh)/
}

# >0  string/wt,=#! /usr/local/bin/ash (len=21), ["Neil Brown's ash script text executable"], swap_endian=0
signature file-magic-auto17 {
	file-mime "text/x-shellscript", 240
	file-magic /(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fash)/
}

# >0  string/wt,=#! /usr/local/bin/ae (len=20), ["Neil Brown's ae script text executable"], swap_endian=0
signature file-magic-auto18 {
	file-mime "text/x-shellscript", 230
	file-magic /(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fae)/
}

# >0  string,=# PaCkAgE DaTaStReAm (len=20), ["pkg Datastream (SVR4)"], swap_endian=0
signature file-magic-auto19 {
	file-mime "application/x-svr4-package", 230
	file-magic /(\x23 PaCkAgE DaTaStReAm)/
}

# >0  string,=Creative Voice File (len=19), ["Creative Labs voice data"], swap_endian=0
signature file-magic-auto20 {
	file-mime "audio/x-unknown", 220
	file-magic /(Creative Voice File)/
}

# >0  string/t,=[KDE Desktop Entry] (len=19), ["KDE desktop entry"], swap_endian=0
signature file-magic-auto21 {
	file-mime "application/x-kdelnk", 220
	file-magic /(\x5bKDE Desktop Entry\x5d)/
}

# >512  string,=R\000o\000o\000t\000 \000E\000n\000t\000r\000y (len=19), ["Microsoft Word Document"], swap_endian=0
signature file-magic-auto22 {
	file-mime "application/msword", 220
	file-magic /(.{512})(R\x00o\x00o\x00t\x00 \x00E\x00n\x00t\x00r\x00y)/
}

# >0  string,=!<arch>\n__________E (len=19), ["MIPS archive"], swap_endian=0
signature file-magic-auto23 {
	file-mime "application/x-archive", 220
	file-magic /(\x21\x3carch\x3e\x0a\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5f\x5fE)/
}

# >0  string/wt,=#! /usr/local/tcsh (len=18), ["Tenex C shell script text executable"], swap_endian=0
signature file-magic-auto24 {
	file-mime "text/x-shellscript", 210
	file-magic /(\x23\x21 ?\x2fusr\x2flocal\x2ftcsh)/
}

# >0  string/wt,=#! /usr/local/bash (len=18), ["Bourne-Again shell script text executable"], swap_endian=0
signature file-magic-auto25 {
	file-mime "text/x-shellscript", 210
	file-magic /(\x23\x21 ?\x2fusr\x2flocal\x2fbash)/
}

# >0  string/t,=# KDE Config File (len=17), ["KDE config file"], swap_endian=0
signature file-magic-auto26 {
	file-mime "application/x-kdelnk", 200
	file-magic /(\x23 KDE Config File)/
}

# >0  string,=RF64\377\377\377\377WAVEds64 (len=16), ["MBWF/RF64 audio"], swap_endian=0
signature file-magic-auto27 {
	file-mime "audio/x-wav", 190
	file-magic /(RF64\xff\xff\xff\xffWAVEds64)/
}

# >0  string,=riff.\221\317\021\245\326(\333\004\301\000\000 (len=16), ["Sony Wave64 RIFF data"], swap_endian=0
# >>24  string,=wave\363\254\323\021\214\321\000\300O\216\333\212 (len=16), [", WAVE 64 audio"], swap_endian=0
signature file-magic-auto28 {
	file-mime "audio/x-w64", 190
	file-magic /(riff\x2e\x91\xcf\x11\xa5\xd6\x28\xdb\x04\xc1\x00\x00)(.{8})(wave\xf3\xac\xd3\x11\x8c\xd1\x00\xc0O\x8e\xdb\x8a)/
}

# >0  string/wt,=#! /usr/bin/nawk (len=16), ["new awk script text executable"], swap_endian=0
signature file-magic-auto29 {
	file-mime "text/x-nawk", 190
	file-magic /(\x23\x21 ?\x2fusr\x2fbin\x2fnawk)/
}

# >0  string/wt,=#! /usr/bin/tcsh (len=16), ["Tenex C shell script text executable"], swap_endian=0
signature file-magic-auto30 {
	file-mime "text/x-shellscript", 190
	file-magic /(\x23\x21 ?\x2fusr\x2fbin\x2ftcsh)/
}

# >0  string/wt,=#! /usr/bin/gawk (len=16), ["GNU awk script text executable"], swap_endian=0
signature file-magic-auto31 {
	file-mime "text/x-gawk", 190
	file-magic /(\x23\x21 ?\x2fusr\x2fbin\x2fgawk)/
}

# >369  string,=MICROSOFT PIFEX\000 (len=16), ["Windows Program Information File"], swap_endian=0
signature file-magic-auto32 {
	file-mime "application/x-dosexec", 190
	file-magic /(.{369})(MICROSOFT PIFEX\x00)/
}

# >0  string/wt,=#! /usr/bin/bash (len=16), ["Bourne-Again shell script text executable"], swap_endian=0
signature file-magic-auto33 {
	file-mime "text/x-shellscript", 190
	file-magic /(\x23\x21 ?\x2fusr\x2fbin\x2fbash)/
}

# >0  string/w,=#VRML V1.0 ascii (len=16), ["VRML 1 file"], swap_endian=0
signature file-magic-auto34 {
	file-mime "model/vrml", 190
	file-magic /(\x23VRML ?V1\x2e0 ?ascii)/
}

# >0  string,=<MakerScreenFont (len=16), ["FrameMaker Font file"], swap_endian=0
signature file-magic-auto35 {
	file-mime "application/x-mif", 190
	file-magic /(\x3cMakerScreenFont)/
}

# >0  string,=Extended Module: (len=16), ["Fasttracker II module sound data"], swap_endian=0
signature file-magic-auto36 {
	file-mime "audio/x-mod", 190
	file-magic /(Extended Module\x3a)/
}

# >0  string/t,=<?xml version " (len=15), ["XML"], swap_endian=0
signature file-magic-auto37 {
	file-mime "application/xml", 185
	file-magic /(\x3c\x3fxml version \x22)/
}

# >0  string/t,=<?xml version=" (len=15), ["XML"], swap_endian=0
signature file-magic-auto38 {
	file-mime "application/xml", 185
	file-magic /(\x3c\x3fxml version\x3d\x22)/
}

# >0  string,=<?xml version=' (len=15), ["XML"], swap_endian=0
signature file-magic-auto39 {
	file-mime "application/xml", 185
	file-magic /(\x3c\x3fxml version\x3d\x27)/
}

# >0  string/t,=<?xml version=" (len=15), [""], swap_endian=0
# >>20  search/wc/1000,=<!DOCTYPE X3D (len=13), ["X3D (Extensible 3D) model xml text"], swap_endian=0
signature file-magic-auto40 {
	file-mime "model/x3d", 43
	file-magic /(\x3c\x3fxml version\x3d\x22)(.{5})(.*)(\x3c\x21DOCTYPE ?X3D)/
}

# >0  string/t,=<?xml version=' (len=15), [""], swap_endian=0
# >>15  string,>\000 (len=1), [""], swap_endian=0
# >>>19  search/Wctb/4096,=<!doctype html (len=14), ["XHTML document text"], swap_endian=0
signature file-magic-auto41 {
	file-mime "text/html", 44
	file-magic /(\x3c\x3fxml version\x3d\x27)([^\x00])(.{3})(.*)(\x3c\x21[dD][oO][cC][tT][yY][pP][eE] {1,}[hH][tT][mM][lL])/
}

# >0  string/t,=<?xml version=" (len=15), [""], swap_endian=0
# >>15  string,>\000 (len=1), [""], swap_endian=0
# >>>19  search/Wctb/4096,=<!doctype html (len=14), ["XHTML document text"], swap_endian=0
signature file-magic-auto42 {
	file-mime "text/html", 44
	file-magic /(\x3c\x3fxml version\x3d\x22)([^\x00])(.{3})(.*)(\x3c\x21[dD][oO][cC][tT][yY][pP][eE] {1,}[hH][tT][mM][lL])/
}

# >0  string/t,=<?xml version=" (len=15), [""], swap_endian=0
# >>15  string,>\000 (len=1), [""], swap_endian=0
# >>>19  search/4096,=<urlset (len=7), ["XML Sitemap document text"], swap_endian=0
signature file-magic-auto43 {
	file-mime "application/xml-sitemap", 37
	file-magic /(\x3c\x3fxml version\x3d\x22)([^\x00])(.{3})(.*)(\x3curlset)/
}

# >0  string,=<?xml version=" (len=15), [""], swap_endian=0
# >>15  string,>\000 (len=1), [""], swap_endian=0
# >>>19  search/4096,=<svg (len=4), ["SVG Scalable Vector Graphics image"], swap_endian=0
signature file-magic-auto44 {
	file-mime "image/svg+xml", 38
	file-magic /(\x3c\x3fxml version\x3d\x22)([^\x00])(.{3})(.*)(\x3csvg)/
}

# >0  string,=<?xml version=" (len=15), [""], swap_endian=0
# >>15  string,>\000 (len=1), [""], swap_endian=0
# >>>19  search/4096,=<gnc-v2 (len=7), ["GnuCash file"], swap_endian=0
signature file-magic-auto45 {
	file-mime "application/x-gnucash", 37
	file-magic /(\x3c\x3fxml version\x3d\x22)([^\x00])(.{3})(.*)(\x3cgnc\x2dv2)/
}

# >0  string/t,=<?xml version=" (len=15), [""], swap_endian=0
# >>15  string,>\000 (len=1), [""], swap_endian=0
# >>>19  search/Wctb/4096,=<html (len=5), ["broken XHTML document text"], swap_endian=0
signature file-magic-auto46 {
	file-mime "text/html", 40
	file-magic /(\x3c\x3fxml version\x3d\x22)([^\x00])(.{3})(.*)(\x3c[hH][tT][mM][lL])/
}

# >0  string/c,=BEGIN:VCALENDAR (len=15), ["vCalendar calendar file"], swap_endian=0
signature file-magic-auto47 {
	file-mime "text/calendar", 180
	file-magic /(BEGIN\x3aVCALENDAR)/
}

# >4  string,=Standard Jet DB (len=15), ["Microsoft Access Database"], swap_endian=0
signature file-magic-auto48 {
	file-mime "application/x-msaccess", 180
	file-magic /(.{4})(Standard Jet DB)/
}

# >4  string,=Standard ACE DB (len=15), ["Microsoft Access Database"], swap_endian=0
signature file-magic-auto49 {
	file-mime "application/x-msaccess", 180
	file-magic /(.{4})(Standard ACE DB)/
}

# >0  string/w,=#VRML V2.0 utf8 (len=15), ["ISO/IEC 14772 VRML 97 file"], swap_endian=0
signature file-magic-auto50 {
	file-mime "model/vrml", 180
	file-magic /(\x23VRML ?V2\x2e0 ?utf8)/
}

# >0  string/wt,=#! /usr/bin/awk (len=15), ["awk script text executable"], swap_endian=0
signature file-magic-auto51 {
	file-mime "text/x-awk", 180
	file-magic /(\x23\x21 ?\x2fusr\x2fbin\x2fawk)/
}

# >0  string/wt,=#! /usr/bin/zsh (len=15), ["Paul Falstad's zsh script text executable"], swap_endian=0
signature file-magic-auto52 {
	file-mime "text/x-shellscript", 180
	file-magic /(\x23\x21 ?\x2fusr\x2fbin\x2fzsh)/
}

# >0  string,=MAS_UTrack_V00 (len=14), [""], swap_endian=0
# >>14  string,>/0 (len=2), ["ultratracker V1.%.1s module sound data"], swap_endian=0
signature file-magic-auto53 {
	file-mime "audio/x-mod", 20
	file-magic /(MAS\x5fUTrack\x5fV00)(\x2f0)/
}

# >0  string,=!<arch>\ndebian (len=14), [""], swap_endian=0
signature file-magic-auto54 {
	file-mime "application/x-debian-package", 171
	file-magic /(\x21\x3carch\x3e\x0adebian)/
}

# >0  string,=II\032\000\000\000HEAPCCDR (len=14), ["Canon CIFF raw image data"], swap_endian=0
signature file-magic-auto55 {
	file-mime "image/x-canon-crw", 170
	file-magic /(II\x1a\x00\x00\x00HEAPCCDR)/
}

# >0  string/t,=Relay-Version: (len=14), ["old news text"], swap_endian=0
signature file-magic-auto56 {
	file-mime "message/rfc822", 170
	file-magic /(Relay\x2dVersion\x3a)/
}

# >0  string,=ToKyO CaBiNeT\n (len=14), ["Tokyo Cabinet"], swap_endian=0
# >>32  byte&,=0x00, [", Hash"], swap_endian=0
signature file-magic-auto57 {
	file-mime "application/x-tokyocabinet-hash", 40
	file-magic /(ToKyO CaBiNeT\x0a)(.{18})([\x00])/
}

# >0  string,=ToKyO CaBiNeT\n (len=14), ["Tokyo Cabinet"], swap_endian=0
# >>32  byte&,=0x01, [", B+ tree"], swap_endian=0
signature file-magic-auto58 {
	file-mime "application/x-tokyocabinet-btree", 40
	file-magic /(ToKyO CaBiNeT\x0a)(.{18})([\x01])/
}

# >0  string,=ToKyO CaBiNeT\n (len=14), ["Tokyo Cabinet"], swap_endian=0
# >>32  byte&,=0x02, [", Fixed-length"], swap_endian=0
signature file-magic-auto59 {
	file-mime "application/x-tokyocabinet-fixed", 40
	file-magic /(ToKyO CaBiNeT\x0a)(.{18})([\x02])/
}

# >0  string,=ToKyO CaBiNeT\n (len=14), ["Tokyo Cabinet"], swap_endian=0
# >>32  byte&,=0x03, [", Table"], swap_endian=0
signature file-magic-auto60 {
	file-mime "application/x-tokyocabinet-table", 40
	file-magic /(ToKyO CaBiNeT\x0a)(.{18})([\x03])/
}

# >39  string,=<gmr:Workbook (len=13), ["Gnumeric spreadsheet"], swap_endian=0
signature file-magic-auto61 {
	file-mime "application/x-gnumeric", 160
	file-magic /(.{39})(\x3cgmr\x3aWorkbook)/
}

# >0  string/t,=[BitmapInfo2] (len=13), ["Polar Monitor Bitmap text"], swap_endian=0
signature file-magic-auto62 {
	file-mime "image/x-polar-monitor-bitmap", 160
	file-magic /(\x5bBitmapInfo2\x5d)/
}

# >0  string,=SplineFontDB: (len=13), ["Spline Font Database "], swap_endian=0
signature file-magic-auto63 {
	file-mime "application/vnd.font-fontforge-sfd", 160
	file-magic /(SplineFontDB\x3a)/
}

# >0  string/ct,=delivered-to: (len=13), ["SMTP mail text"], swap_endian=0
signature file-magic-auto64 {
	file-mime "message/rfc822", 160
	file-magic /([dD][eE][lL][iI][vV][eE][rR][eE][dD]\x2d[tT][oO]\x3a)/
}

# >0  string/ct,=return-path: (len=12), ["SMTP mail text"], swap_endian=0
signature file-magic-auto65 {
	file-mime "message/rfc822", 150
	file-magic /([rR][eE][tT][uU][rR][nN]\x2d[pP][aA][tT][hH]\x3a)/
}

# >0  string,=\000\000\000\fjP  \r\n\207\n (len=12), ["JPEG 2000"], swap_endian=0
# >>20  string,=jp2  (len=4), ["Part 1 (JP2)"], swap_endian=0
signature file-magic-auto66 {
	file-mime "image/jp2", 70
	file-magic /(\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a)(.{8})(jp2 )/
}

# >0  string,=\000\000\000\fjP  \r\n\207\n (len=12), ["JPEG 2000"], swap_endian=0
# >>20  string,=jpx  (len=4), ["Part 2 (JPX)"], swap_endian=0
signature file-magic-auto67 {
	file-mime "image/jpx", 70
	file-magic /(\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a)(.{8})(jpx )/
}

# >0  string,=\000\000\000\fjP  \r\n\207\n (len=12), ["JPEG 2000"], swap_endian=0
# >>20  string,=jpm  (len=4), ["Part 6 (JPM)"], swap_endian=0
signature file-magic-auto68 {
	file-mime "image/jpm", 70
	file-magic /(\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a)(.{8})(jpm )/
}

# >0  string,=\000\000\000\fjP  \r\n\207\n (len=12), ["JPEG 2000"], swap_endian=0
# >>20  string,=mjp2 (len=4), ["Part 3 (MJ2)"], swap_endian=0
signature file-magic-auto69 {
	file-mime "video/mj2", 70
	file-magic /(\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a)(.{8})(mjp2)/
}

# >0  string/w,=<map version (len=12), ["Freemind document"], swap_endian=0
signature file-magic-auto70 {
	file-mime "application/x-freemind", 150
	file-magic /(\x3cmap ?version)/
}

# >0  string/wt,=#! /bin/tcsh (len=12), ["Tenex C shell script text executable"], swap_endian=0
signature file-magic-auto71 {
	file-mime "text/x-shellscript", 150
	file-magic /(\x23\x21 ?\x2fbin\x2ftcsh)/
}

# >0  string/wt,=#! /bin/nawk (len=12), ["new awk script text executable"], swap_endian=0
signature file-magic-auto72 {
	file-mime "text/x-nawk", 150
	file-magic /(\x23\x21 ?\x2fbin\x2fnawk)/
}

# >0  string/wt,=#! /bin/gawk (len=12), ["GNU awk script text executable"], swap_endian=0
signature file-magic-auto73 {
	file-mime "text/x-gawk", 150
	file-magic /(\x23\x21 ?\x2fbin\x2fgawk)/
}

# >0  string/wt,=#! /bin/bash (len=12), ["Bourne-Again shell script text executable"], swap_endian=0
signature file-magic-auto74 {
	file-mime "text/x-shellscript", 150
	file-magic /(\x23\x21 ?\x2fbin\x2fbash)/
}

# >0  string/wt,=#! /bin/awk (len=11), ["awk script text executable"], swap_endian=0
signature file-magic-auto75 {
	file-mime "text/x-awk", 140
	file-magic /(\x23\x21 ?\x2fbin\x2fawk)/
}

# >0  string,=filedesc:// (len=11), ["Internet Archive File"], swap_endian=0
signature file-magic-auto76 {
	file-mime "application/x-ia-arc", 140
	file-magic /(filedesc\x3a\x2f\x2f)/
}

# >38  string,=Spreadsheet (len=11), ["sc spreadsheet file"], swap_endian=0
signature file-magic-auto77 {
	file-mime "application/x-sc", 140
	file-magic /(.{38})(Spreadsheet)/
}

# >0  string,=d8:announce (len=11), ["BitTorrent file"], swap_endian=0
signature file-magic-auto78 {
	file-mime "application/x-bittorrent", 140
	file-magic /(d8\x3aannounce)/
}

# >0  string/wt,=#! /bin/csh (len=11), ["C shell script text executable"], swap_endian=0
signature file-magic-auto79 {
	file-mime "text/x-shellscript", 140
	file-magic /(\x23\x21 ?\x2fbin\x2fcsh)/
}

# >0  string/wt,=#! /bin/ksh (len=11), ["Korn shell script text executable"], swap_endian=0
signature file-magic-auto80 {
	file-mime "text/x-shellscript", 140
	file-magic /(\x23\x21 ?\x2fbin\x2fksh)/
}

# >0  string/wt,=#! /bin/zsh (len=11), ["Paul Falstad's zsh script text executable"], swap_endian=0
signature file-magic-auto81 {
	file-mime "text/x-shellscript", 140
	file-magic /(\x23\x21 ?\x2fbin\x2fzsh)/
}

# >0  string/c,=BEGIN:VCARD (len=11), ["vCard visiting card"], swap_endian=0
signature file-magic-auto82 {
	file-mime "text/x-vcard", 140
	file-magic /(BEGIN\x3aVCARD)/
}

# >0  string,=HEADER     (len=10), [""], swap_endian=0
# >>&0  regex/1,=^.{40} (len=6), [""], swap_endian=0
# >>>&0  regex/1,=[0-9]{2}-[A-Z]{3}-[0-9]{2} {3} (len=30), [""], swap_endian=0
# >>>>&0  regex/s/1,=[A-Z0-9]{4}.{14}$ (len=17), [""], swap_endian=0
# >>>>>&0  regex/1,=[A-Z0-9]{4} (len=11), ["Protein Data Bank data, ID Code %s"], swap_endian=0
signature file-magic-auto83 {
	file-mime "chemical/x-pdb", 41
	file-magic /(HEADER    )(^.{40})([0-9]{2}-[A-Z]{3}-[0-9]{2} {3})([A-Z0-9]{4}.{14}$)([A-Z0-9]{4})/
}

# >0  string/t,=Forward to (len=10), ["mail forwarding text"], swap_endian=0
signature file-magic-auto84 {
	file-mime "message/rfc822", 130
	file-magic /(Forward to)/
}

# >0  string/wt,=#! /bin/sh (len=10), ["POSIX shell script text executable"], swap_endian=0
signature file-magic-auto85 {
	file-mime "text/x-shellscript", 130
	file-magic /(\x23\x21 ?\x2fbin\x2fsh)/
}

# >0  string,=II*\000\020\000\000\000CR (len=10), ["Canon CR2 raw image data"], swap_endian=0
signature file-magic-auto86 {
	file-mime "image/x-canon-cr2", 130
	file-magic /(II\x2a\x00\x10\x00\x00\x00CR)/
}

# >0  string,=<MakerFile (len=10), ["FrameMaker document"], swap_endian=0
signature file-magic-auto87 {
	file-mime "application/x-mif", 130
	file-magic /(\x3cMakerFile)/
}

# >0  search/4096,=---  (len=4), [""], swap_endian=0
# >>&0  search/1024,=\n (len=1), [""], swap_endian=0
# >>>&0  search/1,=+++  (len=4), [""], swap_endian=0
# >>>>&0  search/1024,=\n (len=1), [""], swap_endian=0
# >>>>>&0  search/1,=@@ (len=2), ["unified diff output text"], swap_endian=0
signature file-magic-auto88 {
	file-mime "text/x-diff", 55
	file-magic /(.*)(\x2d\x2d\x2d )(.*)(\x0a)(.*)(\x2b\x2b\x2b )(.*)(\x0a)(.*)(\x40\x40)/
}

# >0  string/t,=Received: (len=9), ["RFC 822 mail text"], swap_endian=0
signature file-magic-auto89 {
	file-mime "message/rfc822", 120
	file-magic /(Received\x3a)/
}

# >0  string,=<BookFile (len=9), ["FrameMaker Book file"], swap_endian=0
signature file-magic-auto90 {
	file-mime "application/x-mif", 120
	file-magic /(\x3cBookFile)/
}

# >2112  string,=MSWordDoc (len=9), ["Microsoft Word document data"], swap_endian=0
signature file-magic-auto91 {
	file-mime "application/msword", 120
	file-magic /(.{2112})(MSWordDoc)/
}

# >0  string/t,=N#! rnews (len=9), ["mailed, batched news text"], swap_endian=0
signature file-magic-auto92 {
	file-mime "message/rfc822", 120
	file-magic /(N\x23\x21 rnews)/
}

# >0  string/b,=WordPro\r\373 (len=9), ["Lotus WordPro"], swap_endian=0
signature file-magic-auto93 {
	file-mime "application/vnd.lotus-wordpro", 120
	file-magic /(WordPro\x0d\xfb)/
}

# >0  string,=LPKSHHRH (len=8), [""], swap_endian=0
# >>16  ubyte&000000fc,=0x00, [""], swap_endian=0
# >>>24  ubequad&,>0 (0x0000000000000000), [""], swap_endian=0
# >>>>32  ubequad&,>0 (0x0000000000000000), [""], swap_endian=0
# >>>>>40  ubequad&,>0 (0x0000000000000000), [""], swap_endian=0
# >>>>>>48  ubequad&,>0 (0x0000000000000000), [""], swap_endian=0
# >>>>>>>56  ubequad&,>0 (0x0000000000000000), [""], swap_endian=0
# >>>>>>>>64  ubequad&,>0 (0x0000000000000000), ["Journal file"], swap_endian=0
signature file-magic-auto94 {
	file-mime "application/vnd.fdo.journal", 80
	file-magic /(LPKSHHRH)(.{8})([\x00\x01\x02\x03])(.{7})([^\x00]{8})([^\x00]{8})([^\x00]{8})([^\x00]{8})([^\x00]{8})([^\x00]{8})/
}

# >0  string,=AT&TFORM (len=8), [""], swap_endian=0
# >>12  string,=DJVM (len=4), ["DjVu multiple page document"], swap_endian=0
signature file-magic-auto95 {
	file-mime "image/vnd.djvu", 70
	file-magic /(AT\x26TFORM)(.{4})(DJVM)/
}

# >0  string,=AT&TFORM (len=8), [""], swap_endian=0
# >>12  string,=DJVU (len=4), ["DjVu image or single page document"], swap_endian=0
signature file-magic-auto96 {
	file-mime "image/vnd.djvu", 70
	file-magic /(AT\x26TFORM)(.{4})(DJVU)/
}

# >0  string,=AT&TFORM (len=8), [""], swap_endian=0
# >>12  string,=DJVI (len=4), ["DjVu shared document"], swap_endian=0
signature file-magic-auto97 {
	file-mime "image/vnd.djvu", 70
	file-magic /(AT\x26TFORM)(.{4})(DJVI)/
}

# >0  string,=AT&TFORM (len=8), [""], swap_endian=0
# >>12  string,=THUM (len=4), ["DjVu page thumbnails"], swap_endian=0
signature file-magic-auto98 {
	file-mime "image/vnd.djvu", 70
	file-magic /(AT\x26TFORM)(.{4})(THUM)/
}

# >0  string/t,=#! rnews (len=8), ["batched news text"], swap_endian=0
signature file-magic-auto99 {
	file-mime "message/rfc822", 110
	file-magic /(\x23\x21 rnews)/
}

# >0  string/b,=MSCF\000\000\000\000 (len=8), ["Microsoft Cabinet archive data"], swap_endian=0
signature file-magic-auto100 {
	file-mime "application/vnd.ms-cab-compressed", 110
	file-magic /(MSCF\x00\x00\x00\x00)/
}

# >0  string/b,=\320\317\021\340\241\261\032\341 (len=8), ["Microsoft Office Document"], swap_endian=0
signature file-magic-auto101 {
	file-mime "application/msword", 110
	file-magic /(\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1)/
}

# >21  string/c,=!SCREAM! (len=8), ["Screamtracker 2 module sound data"], swap_endian=0
signature file-magic-auto102 {
	file-mime "audio/x-mod", 110
	file-magic /(.{21})(\x21SCREAM\x21)/
}

# >21  string,=BMOD2STM (len=8), ["Screamtracker 2 module sound data"], swap_endian=0
signature file-magic-auto103 {
	file-mime "audio/x-mod", 110
	file-magic /(.{21})(BMOD2STM)/
}

# >0  string/b,=ITOLITLS (len=8), ["Microsoft Reader eBook Data"], swap_endian=0
# >>8  lelong&,x, [", version %u"], swap_endian=0
signature file-magic-auto104 {
	file-mime "application/x-ms-reader", 1
	file-magic /(ITOLITLS)(.{4})/
}

# >4096  string,=\211HDF\r\n\032\n (len=8), ["Hierarchical Data Format (version 5) with 4k user block"], swap_endian=0
signature file-magic-auto105 {
	file-mime "application/x-hdf", 110
	file-magic /(.{4096})(\x89HDF\x0d\x0a\x1a\x0a)/
}

# >2048  string,=\211HDF\r\n\032\n (len=8), ["Hierarchical Data Format (version 5) with 2k user block"], swap_endian=0
signature file-magic-auto106 {
	file-mime "application/x-hdf", 110
	file-magic /(.{2048})(\x89HDF\x0d\x0a\x1a\x0a)/
}

# >1024  string,=\211HDF\r\n\032\n (len=8), ["Hierarchical Data Format (version 5) with 1k user block"], swap_endian=0
signature file-magic-auto107 {
	file-mime "application/x-hdf", 110
	file-magic /(.{1024})(\x89HDF\x0d\x0a\x1a\x0a)/
}

# >512  string,=\211HDF\r\n\032\n (len=8), ["Hierarchical Data Format (version 5) with 512 bytes user block"], swap_endian=0
signature file-magic-auto108 {
	file-mime "application/x-hdf", 110
	file-magic /(.{512})(\x89HDF\x0d\x0a\x1a\x0a)/
}

# >0  string,=\211HDF\r\n\032\n (len=8), ["Hierarchical Data Format (version 5) data"], swap_endian=0
signature file-magic-auto109 {
	file-mime "application/x-hdf", 110
	file-magic /(\x89HDF\x0d\x0a\x1a\x0a)/
}

# >0  string,=\211PNG\r\n\032\n (len=8), ["PNG image data"], swap_endian=0
signature file-magic-auto110 {
	file-mime "image/png", 110
	file-magic /(\x89PNG\x0d\x0a\x1a\x0a)/
}

# >36  string,=acspSUNW (len=8), ["Sun KCMS ICC Profile"], swap_endian=0
signature file-magic-auto111 {
	file-mime "application/vnd.iccprofile", 110
	file-magic /(.{36})(acspSUNW)/
}

# >36  string,=acspSGI  (len=8), ["SGI ICC Profile"], swap_endian=0
signature file-magic-auto112 {
	file-mime "application/vnd.iccprofile", 110
	file-magic /(.{36})(acspSGI )/
}

# >36  string,=acspMSFT (len=8), ["Microsoft ICM Color Profile"], swap_endian=0
signature file-magic-auto113 {
	file-mime "application/vnd.iccprofile", 110
	file-magic /(.{36})(acspMSFT)/
}

# >36  string,=acspAPPL (len=8), ["ColorSync ICC Profile"], swap_endian=0
signature file-magic-auto114 {
	file-mime "application/vnd.iccprofile", 110
	file-magic /(.{36})(acspAPPL)/
}

# >0  string,=gimp xcf (len=8), ["GIMP XCF image data,"], swap_endian=0
signature file-magic-auto115 {
	file-mime "image/x-xcf", 110
	file-magic /(gimp xcf)/
}

# >512  string,=R\000o\000o\000t\000 (len=8), ["Hangul (Korean) Word Processor File 2000"], swap_endian=0
signature file-magic-auto116 {
	file-mime "application/x-hwp", 110
	file-magic /(.{512})(R\x00o\x00o\x00t\x00)/
}

# >257  string,=ustar  \000 (len=8), ["GNU tar archive"], swap_endian=0
signature file-magic-auto117 {
	file-mime "application/x-tar", 110
	file-magic /(.{257})(ustar  \x00)/
}

# >0  string,=<MIFFile (len=8), ["FrameMaker MIF (ASCII) file"], swap_endian=0
signature file-magic-auto118 {
	file-mime "application/x-mif", 110
	file-magic /(\x3cMIFFile)/
}

# >0  string,=PK\a\bPK\003\004 (len=8), ["Zip multi-volume archive data, at least PKZIP v2.50 to extract"], swap_endian=0
signature file-magic-auto119 {
	file-mime "application/zip", 110
	file-magic /(PK\x07\x08PK\x03\x04)/
}

# >0  string/b,=\t\004\006\000\000\000\020\000 (len=8), ["Microsoft Excel Worksheet"], swap_endian=0
signature file-magic-auto120 {
	file-mime "application/vnd.ms-excel", 110
	file-magic /(\x09\x04\x06\x00\x00\x00\x10\x00)/
}

# >0  string/b,=WordPro\000 (len=8), ["Lotus WordPro"], swap_endian=0
signature file-magic-auto121 {
	file-mime "application/vnd.lotus-wordpro", 110
	file-magic /(WordPro\x00)/
}

# >0  string/t,=Article (len=7), ["saved news text"], swap_endian=0
signature file-magic-auto122 {
	file-mime "message/news", 100
	file-magic /(Article)/
}

# >0  string,=\037\213 (len=2), ["gzip compressed data"], swap_endian=0
signature file-magic-auto123 {
	file-mime "application/x-gzip", 100
	file-magic /(\x1f\x8b)/
}

# >0  string/t,=Pipe to (len=7), ["mail piping text"], swap_endian=0
signature file-magic-auto124 {
	file-mime "message/rfc822", 100
	file-magic /(Pipe to)/
}

# >0  string,=.RMF\000\000\000 (len=7), ["RealMedia file"], swap_endian=0
signature file-magic-auto125 {
	file-mime "application/vnd.rn-realmedia", 100
	file-magic /(\x2eRMF\x00\x00\x00)/
}

# >0  string,=StuffIt (len=7), ["StuffIt Archive"], swap_endian=0
signature file-magic-auto126 {
	file-mime "application/x-stuffit", 100
	file-magic /(StuffIt)/
}

# >0  string,=!<arch> (len=7), ["current ar archive"], swap_endian=0
signature file-magic-auto127 {
	file-mime "application/x-archive", 100
	file-magic /(\x21\x3carch\x3e)/
}

# >0  string,=P5 (len=2), [""], swap_endian=0
# >>3  regex,=[0-9]{1,50}  (len=12), [", size = %sx"], swap_endian=0
# >>>3  regex,= [0-9]{1,50} (len=12), ["%s"], swap_endian=0
signature file-magic-auto128 {
	file-mime "image/x-portable-greymap", 42
	file-magic /(P5)(.{1})([0-9]{1,50} )( [0-9]{1,50})/
}

# >0  string,=P6 (len=2), [""], swap_endian=0
# >>3  regex,=[0-9]{1,50}  (len=12), [", size = %sx"], swap_endian=0
# >>>3  regex,= [0-9]{1,50} (len=12), ["%s"], swap_endian=0
signature file-magic-auto129 {
	file-mime "image/x-portable-pixmap", 42
	file-magic /(P6)(.{1})([0-9]{1,50} )( [0-9]{1,50})/
}

# >0  string,=P4 (len=2), [""], swap_endian=0
# >>3  regex,=[0-9]{1,50}  (len=12), [", size = %sx"], swap_endian=0
# >>>3  regex,= [0-9]{1,50} (len=12), ["%s"], swap_endian=0
signature file-magic-auto130 {
	file-mime "image/x-portable-bitmap", 42
	file-magic /(P4)(.{1})([0-9]{1,50} )( [0-9]{1,50})/
}

# >257  string,=ustar\000 (len=6), ["POSIX tar archive"], swap_endian=0
signature file-magic-auto131 {
	file-mime "application/x-tar", 90
	file-magic /(.{257})(ustar\x00)/
}

# >0  string,=AC1.40 (len=6), ["DWG AutoDesk AutoCAD Release 1.40"], swap_endian=0
signature file-magic-auto132 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1\x2e40)/
}

# >0  string,=AC1.50 (len=6), ["DWG AutoDesk AutoCAD Release 2.05"], swap_endian=0
signature file-magic-auto133 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1\x2e50)/
}

# >0  string,=AC2.10 (len=6), ["DWG AutoDesk AutoCAD Release 2.10"], swap_endian=0
signature file-magic-auto134 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC2\x2e10)/
}

# >0  string,=AC2.21 (len=6), ["DWG AutoDesk AutoCAD Release 2.21"], swap_endian=0
signature file-magic-auto135 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC2\x2e21)/
}

# >0  string,=AC2.22 (len=6), ["DWG AutoDesk AutoCAD Release 2.22"], swap_endian=0
signature file-magic-auto136 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC2\x2e22)/
}

# >0  string,=AC1001 (len=6), ["DWG AutoDesk AutoCAD Release 2.22"], swap_endian=0
signature file-magic-auto137 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1001)/
}

# >0  string,=AC1002 (len=6), ["DWG AutoDesk AutoCAD Release 2.50"], swap_endian=0
signature file-magic-auto138 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1002)/
}

# >0  string,=AC1003 (len=6), ["DWG AutoDesk AutoCAD Release 2.60"], swap_endian=0
signature file-magic-auto139 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1003)/
}

# >0  string,=AC1004 (len=6), ["DWG AutoDesk AutoCAD Release 9"], swap_endian=0
signature file-magic-auto140 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1004)/
}

# >0  string,=AC1006 (len=6), ["DWG AutoDesk AutoCAD Release 10"], swap_endian=0
signature file-magic-auto141 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1006)/
}

# >0  string,=AC1009 (len=6), ["DWG AutoDesk AutoCAD Release 11/12"], swap_endian=0
signature file-magic-auto142 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1009)/
}

# >0  string,=AC1012 (len=6), ["DWG AutoDesk AutoCAD Release 13"], swap_endian=0
signature file-magic-auto143 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1012)/
}

# >0  string,=AC1014 (len=6), ["DWG AutoDesk AutoCAD Release 14"], swap_endian=0
signature file-magic-auto144 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1014)/
}

# >0  string,=AC1015 (len=6), ["DWG AutoDesk AutoCAD 2000/2002"], swap_endian=0
signature file-magic-auto145 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1015)/
}

# >0  string,=AC1018 (len=6), ["DWG AutoDesk AutoCAD 2004/2005/2006"], swap_endian=0
signature file-magic-auto146 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1018)/
}

# >0  string,=AC1021 (len=6), ["DWG AutoDesk AutoCAD 2007/2008/2009"], swap_endian=0
signature file-magic-auto147 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1021)/
}

# >0  string,=AC1024 (len=6), ["DWG AutoDesk AutoCAD 2010/2011/2012"], swap_endian=0
signature file-magic-auto148 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1024)/
}

# >0  string,=AC1027 (len=6), ["DWG AutoDesk AutoCAD 2013/2014"], swap_endian=0
signature file-magic-auto149 {
	file-mime "image/vnd.dwg", 90
	file-magic /(AC1027)/
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

# >0  string,=<Maker (len=6), ["Intermediate Print File	FrameMaker IPL file"], swap_endian=0
signature file-magic-auto152 {
	file-mime "application/x-mif", 90
	file-magic /(\x3cMaker)/
}

# >0  string,=GIF94z (len=6), ["ZIF image (GIF+deflate alpha)"], swap_endian=0
signature file-magic-auto153 {
	file-mime "image/x-unknown", 90
	file-magic /(GIF94z)/
}

# >0  string,=FGF95a (len=6), ["FGF image (GIF+deflate beta)"], swap_endian=0
signature file-magic-auto154 {
	file-mime "image/x-unknown", 90
	file-magic /(FGF95a)/
}

# >0  string/t,=# xmcd (len=6), ["xmcd database file for kscd"], swap_endian=0
signature file-magic-auto155 {
	file-mime "text/x-xmcd", 90
	file-magic /(\x23 xmcd)/
}

# >0  string/b,=\333\245-\000\000\000 (len=6), ["Microsoft Office Document"], swap_endian=0
signature file-magic-auto156 {
	file-mime "application/msword", 90
	file-magic /(\xdb\xa5\x2d\x00\x00\x00)/
}

# >2  string,=MMXPR3 (len=6), ["Motorola Quark Express Document (English)"], swap_endian=0
signature file-magic-auto157 {
	file-mime "application/x-quark-xpress-3", 90
	file-magic /(.{2})(MMXPR3)/
}

# >0  search/1,=P1 (len=2), [""], swap_endian=0
# >>3  regex,=[0-9]{1,50}  (len=12), [", size = %sx"], swap_endian=0
# >>>3  regex,= [0-9]{1,50} (len=12), ["%s"], swap_endian=0
signature file-magic-auto158 {
	file-mime "image/x-portable-bitmap", 42
	file-magic /(.*)(P1)([0-9]{1,50} )( [0-9]{1,50})/
}

# >0  search/1,=P3 (len=2), [""], swap_endian=0
# >>3  regex,=[0-9]{1,50}  (len=12), [", size = %sx"], swap_endian=0
# >>>3  regex,= [0-9]{1,50} (len=12), ["%s"], swap_endian=0
signature file-magic-auto159 {
	file-mime "image/x-portable-pixmap", 42
	file-magic /(.*)(P3)([0-9]{1,50} )( [0-9]{1,50})/
}

# >0  search/1,=P2 (len=2), [""], swap_endian=0
# >>3  regex,=[0-9]{1,50}  (len=12), [", size = %sx"], swap_endian=0
# >>>3  regex,= [0-9]{1,50} (len=12), ["%s"], swap_endian=0
signature file-magic-auto160 {
	file-mime "image/x-portable-greymap", 42
	file-magic /(.*)(P2)([0-9]{1,50} )( [0-9]{1,50})/
}

# >0  string/t,=<?xml (len=5), [""], swap_endian=0
# >>20  search/400,= xmlns= (len=7), [""], swap_endian=0
# >>>&0  regex,=['"]http://earth.google.com/kml (len=31), ["Google KML document"], swap_endian=0
signature file-magic-auto161 {
	file-mime "application/vnd.google-earth.kml+xml", 61
	file-magic /(\x3c\x3fxml)(.{15})(.*)( xmlns\x3d)(['"]http:\x2f\x2fearth.google.com\x2fkml)/
}

# >0  string/t,=<?xml (len=5), [""], swap_endian=0
# >>20  search/400,= xmlns= (len=7), [""], swap_endian=0
# >>>&0  regex,=['"]http://www.opengis.net/kml (len=30), ["OpenGIS KML document"], swap_endian=0
signature file-magic-auto162 {
	file-mime "application/vnd.google-earth.kml+xml", 60
	file-magic /(\x3c\x3fxml)(.{15})(.*)( xmlns\x3d)(['"]http:\x2f\x2fwww.opengis.net\x2fkml)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>30  regex,=[Content_Types].xml|_rels/.rels (len=31), [""], swap_endian=0
# >>>18 (lelong,+49), search/2000,=PK\003\004 (len=4), [""], swap_endian=0
# >>>>&26  search/1000,=PK\003\004 (len=4), [""], swap_endian=0
# >>>>>&26  string,=word/ (len=5), ["Microsoft Word 2007+"], swap_endian=0
signature file-magic-auto163 {
	file-mime "application/vnd.openxmlformats-officedocument.wordprocessingml.document", 80
	file-magic /(PK\x03\x04)(.{26})(\[Content_Types\].xml|_rels\x2f.rels)(.*)(PK\x03\x04)(.{26})(.*)(PK\x03\x04)(.{26})(word\x2f)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>30  regex,=[Content_Types].xml|_rels/.rels (len=31), [""], swap_endian=0
# >>>18 (lelong,+49), search/2000,=PK\003\004 (len=4), [""], swap_endian=0
# >>>>&26  search/1000,=PK\003\004 (len=4), [""], swap_endian=0
# >>>>>&26  string,=ppt/ (len=4), ["Microsoft PowerPoint 2007+"], swap_endian=0
signature file-magic-auto164 {
	file-mime "application/vnd.openxmlformats-officedocument.presentationml.presentation", 70
	file-magic /(PK\x03\x04)(.{26})(\[Content_Types\].xml|_rels\x2f.rels)(.*)(PK\x03\x04)(.{26})(.*)(PK\x03\x04)(.{26})(ppt\x2f)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>30  regex,=[Content_Types].xml|_rels/.rels (len=31), [""], swap_endian=0
# >>>18 (lelong,+49), search/2000,=PK\003\004 (len=4), [""], swap_endian=0
# >>>>&26  search/1000,=PK\003\004 (len=4), [""], swap_endian=0
# >>>>>&26  string,=xl/ (len=3), ["Microsoft Excel 2007+"], swap_endian=0
signature file-magic-auto165 {
	file-mime "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 60
	file-magic /(PK\x03\x04)(.{26})(\[Content_Types\].xml|_rels\x2f.rels)(.*)(PK\x03\x04)(.{26})(.*)(PK\x03\x04)(.{26})(xl\x2f)/
}

# >60  string,=RINEX (len=5), [""], swap_endian=0
# >>80  search/256,=XXRINEXB (len=8), ["RINEX Data, GEO SBAS Broadcast"], swap_endian=0
# >>>5  string,x, [", version %6.6s"], swap_endian=0
signature file-magic-auto166 {
	file-mime "rinex/broadcast", 1
	file-magic /(.{60})(RINEX)(.{15})(.*)(XXRINEXB)/
}

# >60  string,=RINEX (len=5), [""], swap_endian=0
# >>80  search/256,=XXRINEXD (len=8), ["RINEX Data, Observation (Hatanaka comp)"], swap_endian=0
# >>>5  string,x, [", version %6.6s"], swap_endian=0
signature file-magic-auto167 {
	file-mime "rinex/observation", 1
	file-magic /(.{60})(RINEX)(.{15})(.*)(XXRINEXD)/
}

# >60  string,=RINEX (len=5), [""], swap_endian=0
# >>80  search/256,=XXRINEXC (len=8), ["RINEX Data, Clock"], swap_endian=0
# >>>5  string,x, [", version %6.6s"], swap_endian=0
signature file-magic-auto168 {
	file-mime "rinex/clock", 1
	file-magic /(.{60})(RINEX)(.{15})(.*)(XXRINEXC)/
}

# >60  string,=RINEX (len=5), [""], swap_endian=0
# >>80  search/256,=XXRINEXH (len=8), ["RINEX Data, GEO SBAS Navigation"], swap_endian=0
# >>>5  string,x, [", version %6.6s"], swap_endian=0
signature file-magic-auto169 {
	file-mime "rinex/navigation", 1
	file-magic /(.{60})(RINEX)(.{15})(.*)(XXRINEXH)/
}

# >60  string,=RINEX (len=5), [""], swap_endian=0
# >>80  search/256,=XXRINEXG (len=8), ["RINEX Data, GLONASS Navigation"], swap_endian=0
# >>>5  string,x, [", version %6.6s"], swap_endian=0
signature file-magic-auto170 {
	file-mime "rinex/navigation", 1
	file-magic /(.{60})(RINEX)(.{15})(.*)(XXRINEXG)/
}

# >60  string,=RINEX (len=5), [""], swap_endian=0
# >>80  search/256,=XXRINEXL (len=8), ["RINEX Data, Galileo Navigation"], swap_endian=0
# >>>5  string,x, [", version %6.6s"], swap_endian=0
signature file-magic-auto171 {
	file-mime "rinex/navigation", 1
	file-magic /(.{60})(RINEX)(.{15})(.*)(XXRINEXL)/
}

# >60  string,=RINEX (len=5), [""], swap_endian=0
# >>80  search/256,=XXRINEXM (len=8), ["RINEX Data, Meteorological"], swap_endian=0
# >>>5  string,x, [", version %6.6s"], swap_endian=0
signature file-magic-auto172 {
	file-mime "rinex/meteorological", 1
	file-magic /(.{60})(RINEX)(.{15})(.*)(XXRINEXM)/
}

# >60  string,=RINEX (len=5), [""], swap_endian=0
# >>80  search/256,=XXRINEXN (len=8), ["RINEX Data, Navigation	"], swap_endian=0
# >>>5  string,x, [", version %6.6s"], swap_endian=0
signature file-magic-auto173 {
	file-mime "rinex/navigation", 1
	file-magic /(.{60})(RINEX)(.{15})(.*)(XXRINEXN)/
}

# >60  string,=RINEX (len=5), [""], swap_endian=0
# >>80  search/256,=XXRINEXO (len=8), ["RINEX Data, Observation"], swap_endian=0
# >>>5  string,x, [", version %6.6s"], swap_endian=0
signature file-magic-auto174 {
	file-mime "rinex/observation", 1
	file-magic /(.{60})(RINEX)(.{15})(.*)(XXRINEXO)/
}

# Doubt it's going to be common to have this many bytes buffered.
# >37633  string,=CD001 (len=5), ["ISO 9660 CD-ROM filesystem data (raw 2352 byte sectors)"], swap_endian=0
#signature file-magic-auto175 {
#	file-mime "application/x-iso9660-image", 80
#	file-magic /(.{37633})(CD001)/
#}

# >2  string,=-lhd- (len=5), ["LHa 2.x? archive data [lhd]"], swap_endian=0
signature file-magic-auto176 {
	file-mime "application/x-lha", 80
	file-magic /(.{2})(\x2dlhd\x2d)/
}

# >0  string,=WARC/ (len=5), ["WARC Archive"], swap_endian=0
# >>5  string,x, ["version %.4s"], swap_endian=0
signature file-magic-auto177 {
	file-mime "application/warc", 1
	file-magic /(WARC\x2f)(.{0})/
}

# >0  string,=AC1.3 (len=5), ["DWG AutoDesk AutoCAD Release 1.3"], swap_endian=0
signature file-magic-auto178 {
	file-mime "image/vnd.dwg", 80
	file-magic /(AC1\x2e3)/
}

# >2  string,=-lh - (len=5), ["LHa 2.x? archive data [lh ]"], swap_endian=0
signature file-magic-auto179 {
	file-mime "application/x-lha", 80
	file-magic /(.{2})(\x2dlh \x2d)/
}

# >0  string,=AC1.2 (len=5), ["DWG AutoDesk AutoCAD Release 1.2"], swap_endian=0
signature file-magic-auto180 {
	file-mime "image/vnd.dwg", 80
	file-magic /(AC1\x2e2)/
}

# >0  string,=MC0.0 (len=5), ["DWG AutoDesk AutoCAD Release 1.0"], swap_endian=0
signature file-magic-auto181 {
	file-mime "image/vnd.dwg", 80
	file-magic /(MC0\x2e0)/
}

# >2  string,=-lzs- (len=5), ["LHa/LZS archive data [lzs]"], swap_endian=0
signature file-magic-auto182 {
	file-mime "application/x-lha", 80
	file-magic /(.{2})(\x2dlzs\x2d)/
}

# >2  string,=-lz5- (len=5), ["LHarc 1.x archive data [lz5]"], swap_endian=0
signature file-magic-auto183 {
	file-mime "application/x-lharc", 80
	file-magic /(.{2})(\x2dlz5\x2d)/
}

# Doubt it's going to be common to have this many bytes buffered.
# >32769  string,=CD001 (len=5), ["#"], swap_endian=0
#signature file-magic-auto184 {
#	file-mime "application/x-iso9660-image", 80
#	file-magic /(.{32769})(CD001)/
#}

# >2  string,=-lh3- (len=5), ["LHa 2.x? archive data [lh3]"], swap_endian=0
signature file-magic-auto185 {
	file-mime "application/x-lha", 80
	file-magic /(.{2})(\x2dlh3\x2d)/
}

# >2  string,=-lh2- (len=5), ["LHa 2.x? archive data [lh2]"], swap_endian=0
signature file-magic-auto186 {
	file-mime "application/x-lha", 80
	file-magic /(.{2})(\x2dlh2\x2d)/
}

# >0  string,=\000\001\000\000\000 (len=5), ["TrueType font data"], swap_endian=0
signature file-magic-auto187 {
	file-mime "application/x-font-ttf", 80
	file-magic /(\x00\x01\x00\x00\x00)/
}

# >0  string/b,=PO^Q` (len=5), ["Microsoft Word 6.0 Document"], swap_endian=0
signature file-magic-auto188 {
	file-mime "application/msword", 80
	file-magic /(PO\x5eQ\x60)/
}

# >0  string,=%PDF- (len=5), ["PDF document"], swap_endian=0
signature file-magic-auto189 {
	file-mime "application/pdf", 80
	file-magic /(\x25PDF\x2d)/
}

# >2114  string,=Biff5 (len=5), ["Microsoft Excel 5.0 Worksheet"], swap_endian=0
signature file-magic-auto190 {
	file-mime "application/vnd.ms-excel", 80
	file-magic /(.{2114})(Biff5)/
}

# >2121  string,=Biff5 (len=5), ["Microsoft Excel 5.0 Worksheet"], swap_endian=0
signature file-magic-auto191 {
	file-mime "application/vnd.ms-excel", 80
	file-magic /(.{2121})(Biff5)/
}

# >0  string/t,=Path: (len=5), ["news text"], swap_endian=0
signature file-magic-auto192 {
	file-mime "message/news", 80
	file-magic /(Path\x3a)/
}

# >0  string/t,=Xref: (len=5), ["news text"], swap_endian=0
signature file-magic-auto193 {
	file-mime "message/news", 80
	file-magic /(Xref\x3a)/
}

# >0  string/t,=From: (len=5), ["news or mail text"], swap_endian=0
signature file-magic-auto194 {
	file-mime "message/rfc822", 80
	file-magic /(From\x3a)/
}

# >2  string,=-lh7- (len=5), ["LHa (2.x)/LHark archive data [lh7]"], swap_endian=0
signature file-magic-auto195 {
	file-mime "application/x-lha", 80
	file-magic /(.{2})(\x2dlh7\x2d)/
}

# >0  string,={\rtf (len=5), ["Rich Text Format data,"], swap_endian=0
signature file-magic-auto196 {
	file-mime "text/rtf", 80
	file-magic /(\x7b\x5crtf)/
}

# >2  string,=-lh6- (len=5), ["LHa (2.x) archive data [lh6]"], swap_endian=0
signature file-magic-auto197 {
	file-mime "application/x-lha", 80
	file-magic /(.{2})(\x2dlh6\x2d)/
}

# >2  string,=-lh5- (len=5), ["LHa (2.x) archive data [lh5]"], swap_endian=0
signature file-magic-auto198 {
	file-mime "application/x-lha", 80
	file-magic /(.{2})(\x2dlh5\x2d)/
}

# >2  string,=-lh4- (len=5), ["LHa (2.x) archive data [lh4]"], swap_endian=0
signature file-magic-auto199 {
	file-mime "application/x-lha", 80
	file-magic /(.{2})(\x2dlh4\x2d)/
}

# >2  string,=-lz4- (len=5), ["LHarc 1.x archive data [lz4]"], swap_endian=0
signature file-magic-auto200 {
	file-mime "application/x-lharc", 80
	file-magic /(.{2})(\x2dlz4\x2d)/
}

# >2  string,=-lh1- (len=5), ["LHarc 1.x/ARX archive data [lh1]"], swap_endian=0
signature file-magic-auto201 {
	file-mime "application/x-lharc", 80
	file-magic /(.{2})(\x2dlh1\x2d)/
}

# >2  string,=-lh0- (len=5), ["LHarc 1.x/ARX archive data [lh0]"], swap_endian=0
signature file-magic-auto202 {
	file-mime "application/x-lharc", 80
	file-magic /(.{2})(\x2dlh0\x2d)/
}

# >0  string,=%FDF- (len=5), ["FDF document"], swap_endian=0
signature file-magic-auto203 {
	file-mime "application/vnd.fdf", 80
	file-magic /(\x25FDF\x2d)/
}

# >0  belong&,=443 (0x000001bb), [""], swap_endian=0
signature file-magic-auto204 {
	file-mime "video/mpeg", 71
	file-magic /(\x00\x00\x01\xbb)/
}

# The non-sequential offsets and use of bitmask and relational operators
# made this difficult to autogenerate.  Can see about manually creating
# the correct character class later.
# >0  ubelong&fff8fe00,=167772160 (0x0a000000), [""], swap_endian=0
# >>3  ubyte&,>0x00, [""], swap_endian=0
# >>>1  ubyte&,<0x06, [""], swap_endian=0
# >>>>1  ubyte&,!0x01, ["PCX"], swap_endian=0
#signature file-magic-auto205 {
#	file-mime "image/x-pcx", 1
#	file-magic /(.{4})(.*)([\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])(.*)([\x00\x01\x02\x03\x04\x05])(.*)([\x00\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
#}

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

# >0  string,=AWBM (len=4), [""], swap_endian=0
# >>4  leshort&,<1981 (0x07bd), ["Award BIOS bitmap"], swap_endian=0
signature file-magic-auto208 {
	file-mime "image/x-award-bmp", 20
	file-magic /(AWBM)(.{2})/
}

# >0  belong&,=435 (0x000001b3), [""], swap_endian=0
signature file-magic-auto209 {
	file-mime "video/mpv", 71
	file-magic /(\x00\x00\x01\xb3)/
}

# Converting bitmask to character class might make the regex
# unfriendly to humans.
# >0  belong&ffffffffff5fff10,=1195376656 (0x47400010), [""], swap_endian=0
#signature file-magic-auto210 {
#	file-mime "video/mp2t", 71
#	file-magic /(.{4})/
#}

# >0  belong&,=1 (0x00000001), [""], swap_endian=0
# >>4  byte&0000001f,=0x07, [""], swap_endian=0
signature file-magic-auto211 {
	file-mime "video/h264", 41
	file-magic /(\x00\x00\x00\x01)([\x07\x27\x47\x67\x87\xa7\xc7\xe7])/
}

# >0  belong&,=-889275714 (0xcafebabe), [""], swap_endian=0
signature file-magic-auto212 {
	file-mime "application/x-java-applet", 71
	file-magic /(\xca\xfe\xba\xbe)/
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

# >0  lelong&,=4 (0x00000004), [""], swap_endian=0
# >>104  lelong&,=4 (0x00000004), ["X11 SNF font data, LSB first"], swap_endian=0
signature file-magic-auto217 {
	file-mime "application/x-font-sfn", 70
	file-magic /(\x04\x00\x00\x00)(.{100})(\x04\x00\x00\x00)/
}

# >0  lelong&00ffffff,=93 (0x0000005d), [""], swap_endian=0
signature file-magic-auto218 {
	file-mime "application/x-lzma", 71
	file-magic /(\x5d\x00\x00.)/
}

# This didn't auto-generate correctly due to non-sequential offsets and
# use of bitwise/relational comparisons.  At a glance: may not be
# that common/useful, leaving for later.
# >512  ubelong&e0ffff00,=3774873344 (0xe0ffff00), [""], swap_endian=0
# >>21  ubyte&,<0xe5, ["floppy with old FAT filesystem"], swap_endian=0
# >>>512  ubyte&,=0xfc, ["180k"], swap_endian=0
# >>>>2574  ubequad&,=0 (0x0000000000000000), [""], swap_endian=0
# >>>>>2560  ubequad&,!0 (0x0000000000000000), [""], swap_endian=0
#signature file-magic-auto219 {
#	file-mime "application/x-ima", 2
#	file-magic /(.{512})(.{4})(.*)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4])(.{490})([\xfc])(.{2061})(\x00\x00\x00\x00\x00\x00\x00\x00)(.*)(.{8})/
#}

# This didn't auto-generate correctly due to non-sequential offsets and
# use of bitwise/relational comparisons.  At a glance: may not be
# that common/useful, leaving for later.
# >512  ubelong&e0ffff00,=3774873344 (0xe0ffff00), [""], swap_endian=0
# >>21  ubyte&,<0xe5, ["floppy with old FAT filesystem"], swap_endian=0
# >>>512  ubyte&,=0xfd, [""], swap_endian=0
# >>>>2574  ubequad&,=0 (0x0000000000000000), [""], swap_endian=0
#signature file-magic-auto220 {
#	file-mime "application/x-ima", 111
#	file-magic /(.{512})(.{4})(.*)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4])(.{490})([\xfd])(.{2061})(\x00\x00\x00\x00\x00\x00\x00\x00)/
#}

# This didn't auto-generate correctly due to non-sequential offsets and
# use of bitwise/relational comparisons.  At a glance: may not be
# that common/useful, leaving for later.
# >512  ubelong&e0ffff00,=3774873344 (0xe0ffff00), [""], swap_endian=0
# >>21  ubyte&,<0xe5, ["floppy with old FAT filesystem"], swap_endian=0
# >>>512  ubyte&,=0xfe, [""], swap_endian=0
# >>>>1024  ubelong&e0ffff00,=3774873344 (0xe0ffff00), ["160k"], swap_endian=0
# >>>>>1550  ubequad&,=0 (0x0000000000000000), [""], swap_endian=0
# >>>>>>1536  ubequad&,!0 (0x0000000000000000), [""], swap_endian=0
#signature file-magic-auto221 {
#	file-mime "application/x-ima", 2
#	file-magic /(.{512})(.{4})(.*)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4])(.{490})([\xfe])(.{511})(.{4})(.{522})(\x00\x00\x00\x00\x00\x00\x00\x00)(.*)(.{8})/
#}

# This didn't auto-generate correctly due to non-sequential offsets and
# use of bitwise/relational comparisons.  At a glance: may not be
# that common/useful, leaving for later.
# >512  ubelong&e0ffff00,=3774873344 (0xe0ffff00), [""], swap_endian=0
# >>21  ubyte&,<0xe5, ["floppy with old FAT filesystem"], swap_endian=0
# >>>512  ubyte&,=0xff, ["320k"], swap_endian=0
# >>>>1550  ubequad&,=0 (0x0000000000000000), [""], swap_endian=0
# >>>>>1536  ubequad&,!0 (0x0000000000000000), [""], swap_endian=0
#signature file-magic-auto222 {
#	file-mime "application/x-ima", 2
#	file-magic /(.{512})(.{4})(.*)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4])(.{490})([\xff])(.{1037})(\x00\x00\x00\x00\x00\x00\x00\x00)(.*)(.{8})/
#}

# >0  string,=;ELC (len=4), [""], swap_endian=0
# >>4  byte&,<0x20, ["Emacs/XEmacs v%d byte-compiled Lisp data"], swap_endian=0
signature file-magic-auto223 {
	file-mime "application/x-elc", 10
	file-magic /(\x3bELC)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
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

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>4  byte&,=0x14, [""], swap_endian=0
# >>>30  string,=doc.kml (len=7), ["Compressed Google KML Document, including resources."], swap_endian=0
signature file-magic-auto226 {
	file-mime "application/vnd.google-earth.kmz", 100
	file-magic /(PK\x03\x04)([\x14])(.{25})(doc\x2ekml)/
}

# The indirect offset in the last magic rule means this has little chance
# Also plenty of bitmasking/relational comparisons that weren't auto-generated.
# of working.
# >0  ulelong&804000e9,=233 (0x000000e9), [""], swap_endian=0
# >>11  uleshort&000f001f,=0 (0x0000), [""], swap_endian=0
# >>>11  uleshort&,<32769 (0x8001), [""], swap_endian=0
# >>>>11  uleshort&,>31 (0x001f), [""], swap_endian=0
# >>>>>21  ubyte&000000f0,=0xf0, [""], swap_endian=0
# >>>>>>21  ubyte&,!0xf8, [""], swap_endian=0
# >>>>>>>54  string,!FAT16 (len=5), [""], swap_endian=0
# >>>>>>>>11 (leshort,&0), ulelong&00fffff0,=16777200 (0x00fffff0), [", followed by FAT"], swap_endian=0
#signature file-magic-auto227 {
#	file-mime "application/x-ima", 70
#	file-magic /(.{4})(.{7})(.{2})(.*)(.{2})(.*)(.{2})(.{8})([\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])(.*)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf9\xfa\xfb\xfc\xfd\xfe\xff])(.{32})(FAT16)(.{4})/
#}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=text (len=4), [""], swap_endian=0
# >>>>>77  byte&,!0x2d, ["Text"], swap_endian=0
signature file-magic-auto228 {
	file-mime "application/vnd.oasis.opendocument.text", 110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(text)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=text (len=4), [""], swap_endian=0
# >>>>>77  string,=-template (len=9), ["Text Template"], swap_endian=0
signature file-magic-auto229 {
	file-mime "application/vnd.oasis.opendocument.text-template", 120
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(text)(\x2dtemplate)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=text (len=4), [""], swap_endian=0
# >>>>>77  string,=-web (len=4), ["HTML Document Template"], swap_endian=0
signature file-magic-auto230 {
	file-mime "application/vnd.oasis.opendocument.text-web", 70
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(text)(\x2dweb)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=text (len=4), [""], swap_endian=0
# >>>>>77  string,=-master (len=7), ["Master Document"], swap_endian=0
signature file-magic-auto231 {
	file-mime "application/vnd.oasis.opendocument.text-master", 100
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(text)(\x2dmaster)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=graphics (len=8), [""], swap_endian=0
# >>>>>81  byte&,!0x2d, ["Drawing"], swap_endian=0
signature file-magic-auto232 {
	file-mime "application/vnd.oasis.opendocument.graphics", 110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(graphics)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=graphics (len=8), [""], swap_endian=0
# >>>>>81  string,=-template (len=9), ["Template"], swap_endian=0
signature file-magic-auto233 {
	file-mime "application/vnd.oasis.opendocument.graphics-template", 120
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(graphics)(\x2dtemplate)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=presentation (len=12), [""], swap_endian=0
# >>>>>85  byte&,!0x2d, ["Presentation"], swap_endian=0
signature file-magic-auto234 {
	file-mime "application/vnd.oasis.opendocument.presentation", 110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(presentation)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=presentation (len=12), [""], swap_endian=0
# >>>>>85  string,=-template (len=9), ["Template"], swap_endian=0
signature file-magic-auto235 {
	file-mime "application/vnd.oasis.opendocument.presentation-template", 120
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(presentation)(\x2dtemplate)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=spreadsheet (len=11), [""], swap_endian=0
# >>>>>84  byte&,!0x2d, ["Spreadsheet"], swap_endian=0
signature file-magic-auto236 {
	file-mime "application/vnd.oasis.opendocument.spreadsheet", 110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(spreadsheet)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=spreadsheet (len=11), [""], swap_endian=0
# >>>>>84  string,=-template (len=9), ["Template"], swap_endian=0
signature file-magic-auto237 {
	file-mime "application/vnd.oasis.opendocument.spreadsheet-template", 120
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(spreadsheet)(\x2dtemplate)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=chart (len=5), [""], swap_endian=0
# >>>>>78  byte&,!0x2d, ["Chart"], swap_endian=0
signature file-magic-auto238 {
	file-mime "application/vnd.oasis.opendocument.chart", 110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(chart)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=chart (len=5), [""], swap_endian=0
# >>>>>78  string,=-template (len=9), ["Template"], swap_endian=0
signature file-magic-auto239 {
	file-mime "application/vnd.oasis.opendocument.chart-template", 120
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(chart)(\x2dtemplate)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=formula (len=7), [""], swap_endian=0
# >>>>>80  byte&,!0x2d, ["Formula"], swap_endian=0
signature file-magic-auto240 {
	file-mime "application/vnd.oasis.opendocument.formula", 1110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(formula)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=formula (len=7), [""], swap_endian=0
# >>>>>80  string,=-template (len=9), ["Template"], swap_endian=0
signature file-magic-auto241 {
	file-mime "application/vnd.oasis.opendocument.formula-template", 120
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(formula)(\x2dtemplate)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=database (len=8), ["Database"], swap_endian=0
signature file-magic-auto242 {
	file-mime "application/vnd.oasis.opendocument.database", 110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(database)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=image (len=5), [""], swap_endian=0
# >>>>>78  byte&,!0x2d, ["Image"], swap_endian=0
signature file-magic-auto243 {
	file-mime "application/vnd.oasis.opendocument.image", 110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(image)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=vnd.oasis.opendocument. (len=23), ["OpenDocument"], swap_endian=0
# >>>>73  string,=image (len=5), [""], swap_endian=0
# >>>>>78  string,=-template (len=9), ["Template"], swap_endian=0
signature file-magic-auto244 {
	file-mime "application/vnd.oasis.opendocument.image-template", 120
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(vnd\x2eoasis\x2eopendocument\x2e)(image)(\x2dtemplate)/
}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,=epub+zip (len=8), ["EPUB document"], swap_endian=0
signature file-magic-auto245 {
	file-mime "application/epub+zip", 110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(epub\x2bzip)/
}

# Seems redundant with other zip signature below.
# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetypeapplication/ (len=24), [""], swap_endian=0
# >>>50  string,!epub+zip (len=8), [""], swap_endian=0
# >>>>50  string,!vnd.oasis.opendocument. (len=23), [""], swap_endian=0
# >>>>>50  string,!vnd.sun.xml. (len=12), [""], swap_endian=0
# >>>>>>50  string,!vnd.kde. (len=8), [""], swap_endian=0
# >>>>>>>38  regex,=[!-OQ-~]+ (len=9), ["Zip data (MIME type "%s"?)"], swap_endian=0
#signature file-magic-auto246 {
#	file-mime "application/zip", 39
#	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)/
#}

# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26  string,=\b\000\000\000mimetype (len=12), [""], swap_endian=0
# >>>38  string,!application/ (len=12), [""], swap_endian=0
# >>>>38  regex,=[!-OQ-~]+ (len=9), ["Zip data (MIME type "%s"?)"], swap_endian=0
signature file-magic-auto247 {
	file-mime "application/zip", 39
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetype)/
}

# The indirect offset makes this difficult to convert.
# The (.*) may be too generous.
# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26 (leshort,+30), leshort&,=-13570 (0xcafe), ["Java archive data (JAR)"], swap_endian=0
signature file-magic-auto248 {
	file-mime "application/java-archive", 50
	file-magic /(PK\x03\x04)(.*)(\xfe\xca)/
}

# The indeirect offset and string inequality make this difficult to convert.
# >0  string,=PK\003\004 (len=4), [""], swap_endian=0
# >>26 (leshort,+30), leshort&,!-13570 (0xcafe), [""], swap_endian=0
# >>>26  string,!\b\000\000\000mimetype (len=12), ["Zip archive data"], swap_endian=0
signature file-magic-auto249 {
	file-mime "application/zip", 10
	file-magic /(PK\x03\x04)(.{2})/
}

# >0  belong&,=442 (0x000001ba), [""], swap_endian=0
# >>4  byte&,&0x40, [""], swap_endian=0
signature file-magic-auto250 {
	file-mime "video/mp2p", 21
	file-magic /(\x00\x00\x01\xba)([\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  belong&,=442 (0x000001ba), [""], swap_endian=0
# >>4  byte&,^0x40, [""], swap_endian=0
signature file-magic-auto251 {
	file-mime "video/mpeg", 21
	file-magic /(\x00\x00\x01\xba)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf])/
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

# >4  string,=idsc (len=4), ["Apple QuickTime image (fast start)"], swap_endian=0
signature file-magic-auto255 {
	file-mime "image/x-quicktime", 70
	file-magic /(.{4})(idsc)/
}

# >4  string,=pckg (len=4), ["Apple QuickTime compressed archive"], swap_endian=0
signature file-magic-auto256 {
	file-mime "application/x-quicktime-player", 70
	file-magic /(.{4})(pckg)/
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
# >>8  string/W,=jp2 (len=3), [", JPEG 2000"], swap_endian=0
signature file-magic-auto260 {
	file-mime "image/jp2", 60
	file-magic /(.{4})(ftyp)(jp2)/
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

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string/W,=M4A (len=3), [", MPEG v4 system, iTunes AAC-LC"], swap_endian=0
signature file-magic-auto268 {
	file-mime "audio/mp4", 60
	file-magic /(.{4})(ftyp)(M4A)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string/W,=M4V (len=3), [", MPEG v4 system, iTunes AVC-LC"], swap_endian=0
signature file-magic-auto269 {
	file-mime "video/mp4", 60
	file-magic /(.{4})(ftyp)(M4V)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string/W,=qt (len=2), [", Apple QuickTime movie"], swap_endian=0
signature file-magic-auto270 {
	file-mime "video/quicktime", 50
	file-magic /(.{4})(ftyp)(qt)/
}

# >0  string,=Xcur (len=4), ["Xcursor data"], swap_endian=0
signature file-magic-auto271 {
	file-mime "image/x-xcursor", 70
	file-magic /(Xcur)/
}

# >0  string,=ADIF (len=4), ["MPEG ADIF, AAC"], swap_endian=0
signature file-magic-auto272 {
	file-mime "audio/x-hx-aac-adif", 70
	file-magic /(ADIF)/
}

# >0  belong&,=807842421 (0x3026b275), ["Microsoft ASF"], swap_endian=0
signature file-magic-auto273 {
	file-mime "video/x-ms-asf", 70
	file-magic /(\x30\x26\xb2\x75)/
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

# >0  string,=MAC  (len=4), ["Monkey's Audio compressed format"], swap_endian=0
signature file-magic-auto276 {
	file-mime "audio/x-ape", 70
	file-magic /(MAC )/
}

# >36  string,=acsp (len=4), ["ICC Profile"], swap_endian=0
signature file-magic-auto277 {
	file-mime "application/vnd.iccprofile", 70
	file-magic /(.{36})(acsp)/
}

# >0  string,=FORM (len=4), ["IFF data"], swap_endian=0
# >>8  string,=AIFF (len=4), [", AIFF audio"], swap_endian=0
signature file-magic-auto278 {
	file-mime "audio/x-aiff", 70
	file-magic /(FORM)(.{4})(AIFF)/
}

# >0  string,=FORM (len=4), ["IFF data"], swap_endian=0
# >>8  string,=AIFC (len=4), [", AIFF-C compressed audio"], swap_endian=0
signature file-magic-auto279 {
	file-mime "audio/x-aiff", 70
	file-magic /(FORM)(.{4})(AIFC)/
}

# >0  string,=FORM (len=4), ["IFF data"], swap_endian=0
# >>8  string,=8SVX (len=4), [", 8SVX 8-bit sampled sound voice"], swap_endian=0
signature file-magic-auto280 {
	file-mime "audio/x-aiff", 70
	file-magic /(FORM)(.{4})(8SVX)/
}

# >0  string,=fLaC (len=4), ["FLAC audio bitstream data"], swap_endian=0
signature file-magic-auto281 {
	file-mime "audio/x-flac", 70
	file-magic /(fLaC)/
}

# >0  string,=IIN1 (len=4), ["NIFF image data"], swap_endian=0
signature file-magic-auto282 {
	file-mime "image/x-niff", 70
	file-magic /(IIN1)/
}

# >0  string,=MM\000* (len=4), ["TIFF image data, big-endian"], swap_endian=0
signature file-magic-auto283 {
	file-mime "image/tiff", 70
	file-magic /(MM\x00\x2a)/
}

# >0  string,=II*\000 (len=4), ["TIFF image data, little-endian"], swap_endian=0
signature file-magic-auto284 {
	file-mime "image/tiff", 70
	file-magic /(II\x2a\x00)/
}

# >0  string,=MM\000+ (len=4), ["Big TIFF image data, big-endian"], swap_endian=0
signature file-magic-auto285 {
	file-mime "image/tiff", 70
	file-magic /(MM\x00\x2b)/
}

# >0  string,=II+\000 (len=4), ["Big TIFF image data, little-endian"], swap_endian=0
signature file-magic-auto286 {
	file-mime "image/tiff", 70
	file-magic /(II\x2b\x00)/
}

# >0  string,=GIF8 (len=4), ["GIF image data"], swap_endian=0
signature file-magic-auto287 {
	file-mime "image/gif", 70
	file-magic /(GIF8)/
}

# >128  string,=DICM (len=4), ["DICOM medical imaging data"], swap_endian=0
signature file-magic-auto288 {
	file-mime "application/dicom", 70
	file-magic /(.{128})(DICM)/
}

# >0  string,=8BPS (len=4), ["Adobe Photoshop Image"], swap_endian=0
signature file-magic-auto289 {
	file-mime "image/vnd.adobe.photoshop", 70
	file-magic /(8BPS)/
}

# >0  string,=IMPM (len=4), ["Impulse Tracker module sound data -"], swap_endian=0
signature file-magic-auto290 {
	file-mime "audio/x-mod", 70
	file-magic /(IMPM)/
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

# >0  belong&,=235082497 (0x0e031301), ["Hierarchical Data Format (version 4) data"], swap_endian=0
signature file-magic-auto293 {
	file-mime "application/x-hdf", 70
	file-magic /(\x0e\x03\x13\x01)/
}

# >0  string,=CPC\262 (len=4), ["Cartesian Perceptual Compression image"], swap_endian=0
signature file-magic-auto294 {
	file-mime "image/x-cpi", 70
	file-magic /(CPC\xb2)/
}

# >0  string,=MMOR (len=4), ["Olympus ORF raw image data, big-endian"], swap_endian=0
signature file-magic-auto295 {
	file-mime "image/x-olympus-orf", 70
	file-magic /(MMOR)/
}

# >0  string,=IIRO (len=4), ["Olympus ORF raw image data, little-endian"], swap_endian=0
signature file-magic-auto296 {
	file-mime "image/x-olympus-orf", 70
	file-magic /(IIRO)/
}

# >0  string,=IIRS (len=4), ["Olympus ORF raw image data, little-endian"], swap_endian=0
signature file-magic-auto297 {
	file-mime "image/x-olympus-orf", 70
	file-magic /(IIRS)/
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

# >0  ulelong&,=2712847316 (0xa1b2c3d4), ["tcpdump capture file (little-endian)"], swap_endian=0
signature file-magic-auto300 {
	file-mime "application/vnd.tcpdump.pcap", 70
	file-magic /(\xd4\xc3\xb2\xa1)/
}

# >0  ubelong&,=2712847316 (0xa1b2c3d4), ["tcpdump capture file (big-endian)"], swap_endian=0
signature file-magic-auto301 {
	file-mime "application/vnd.tcpdump.pcap", 70
	file-magic /(\xa1\xb2\xc3\xd4)/
}

# >0  belong&,=-17957139 (0xfeedfeed), ["Java KeyStore"], swap_endian=0
signature file-magic-auto302 {
	file-mime "application/x-java-keystore", 70
	file-magic /(\xfe\xed\xfe\xed)/
}

# >0  belong&,=-825307442 (0xcececece), ["Java JCE KeyStore"], swap_endian=0
signature file-magic-auto303 {
	file-mime "application/x-java-jce-keystore", 70
	file-magic /(\xce\xce\xce\xce)/
}

# >1080  string,=32CN (len=4), ["32-channel Taketracker module sound data"], swap_endian=0
signature file-magic-auto304 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(32CN)/
}

# >1080  string,=16CN (len=4), ["16-channel Taketracker module sound data"], swap_endian=0
signature file-magic-auto305 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(16CN)/
}

# >1080  string,=OKTA (len=4), ["8-channel Octalyzer module sound data"], swap_endian=0
signature file-magic-auto306 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(OKTA)/
}

# >1080  string,=CD81 (len=4), ["8-channel Octalyser module sound data"], swap_endian=0
signature file-magic-auto307 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(CD81)/
}

# >1080  string,=8CHN (len=4), ["8-channel Fasttracker module sound data"], swap_endian=0
signature file-magic-auto308 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(8CHN)/
}

# >1080  string,=6CHN (len=4), ["6-channel Fasttracker module sound data"], swap_endian=0
signature file-magic-auto309 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(6CHN)/
}

# >1080  string,=4CHN (len=4), ["4-channel Fasttracker module sound data"], swap_endian=0
signature file-magic-auto310 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(4CHN)/
}

# >1080  string,=FLT8 (len=4), ["8-channel Startracker module sound data"], swap_endian=0
signature file-magic-auto311 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(FLT8)/
}

# >1080  string,=FLT4 (len=4), ["4-channel Startracker module sound data"], swap_endian=0
signature file-magic-auto312 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(FLT4)/
}

# >1080  string,=M!K! (len=4), ["4-channel Protracker module sound data"], swap_endian=0
signature file-magic-auto313 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(M\x21K\x21)/
}

# >1080  string,=M.K. (len=4), ["4-channel Protracker module sound data"], swap_endian=0
signature file-magic-auto314 {
	file-mime "audio/x-mod", 70
	file-magic /(.{1080})(M\x2eK\x2e)/
}

# >0  lelong&,=336851773 (0x1413f33d), ["SYSLINUX' LSS16 image data"], swap_endian=0
signature file-magic-auto315 {
	file-mime "image/x-lss16", 70
	file-magic /(\x3d\xf3\x13\x14)/
}

# >0  belong&,=779248125 (0x2e7261fd), ["RealAudio sound file"], swap_endian=0
signature file-magic-auto316 {
	file-mime "audio/x-pn-realaudio", 70
	file-magic /(\x2e\x72\x61\xfd)/
}

# >0  string,=CTMF (len=4), ["Creative Music (CMF) data"], swap_endian=0
signature file-magic-auto317 {
	file-mime "audio/x-unknown", 70
	file-magic /(CTMF)/
}

# >0  string,=MThd (len=4), ["Standard MIDI data"], swap_endian=0
signature file-magic-auto318 {
	file-mime "audio/midi", 70
	file-magic /(MThd)/
}

# >0  lelong&,=6583086 (0x0064732e), ["DEC audio data:"], swap_endian=0
# >>12  lelong&,=1 (0x00000001), ["8-bit ISDN mu-law,"], swap_endian=0
signature file-magic-auto319 {
	file-mime "audio/x-dec-basic", 70
	file-magic /(\x2e\x73\x64\x00)(.{8})(\x01\x00\x00\x00)/
}

# >0  lelong&,=6583086 (0x0064732e), ["DEC audio data:"], swap_endian=0
# >>12  lelong&,=2 (0x00000002), ["8-bit linear PCM [REF-PCM],"], swap_endian=0
signature file-magic-auto320 {
	file-mime "audio/x-dec-basic", 70
	file-magic /(\x2e\x73\x64\x00)(.{8})(\x02\x00\x00\x00)/
}

# >0  lelong&,=6583086 (0x0064732e), ["DEC audio data:"], swap_endian=0
# >>12  lelong&,=3 (0x00000003), ["16-bit linear PCM,"], swap_endian=0
signature file-magic-auto321 {
	file-mime "audio/x-dec-basic", 70
	file-magic /(\x2e\x73\x64\x00)(.{8})(\x03\x00\x00\x00)/
}

# >0  lelong&,=6583086 (0x0064732e), ["DEC audio data:"], swap_endian=0
# >>12  lelong&,=4 (0x00000004), ["24-bit linear PCM,"], swap_endian=0
signature file-magic-auto322 {
	file-mime "audio/x-dec-basic", 70
	file-magic /(\x2e\x73\x64\x00)(.{8})(\x04\x00\x00\x00)/
}

# >0  lelong&,=6583086 (0x0064732e), ["DEC audio data:"], swap_endian=0
# >>12  lelong&,=5 (0x00000005), ["32-bit linear PCM,"], swap_endian=0
signature file-magic-auto323 {
	file-mime "audio/x-dec-basic", 70
	file-magic /(\x2e\x73\x64\x00)(.{8})(\x05\x00\x00\x00)/
}

# >0  lelong&,=6583086 (0x0064732e), ["DEC audio data:"], swap_endian=0
# >>12  lelong&,=6 (0x00000006), ["32-bit IEEE floating point,"], swap_endian=0
signature file-magic-auto324 {
	file-mime "audio/x-dec-basic", 70
	file-magic /(\x2e\x73\x64\x00)(.{8})(\x06\x00\x00\x00)/
}

# >0  lelong&,=6583086 (0x0064732e), ["DEC audio data:"], swap_endian=0
# >>12  lelong&,=7 (0x00000007), ["64-bit IEEE floating point,"], swap_endian=0
signature file-magic-auto325 {
	file-mime "audio/x-dec-basic", 70
	file-magic /(\x2e\x73\x64\x00)(.{8})(\x07\x00\x00\x00)/
}

# >0  lelong&,=6583086 (0x0064732e), ["DEC audio data:"], swap_endian=0
# >>12  lelong&,=23 (0x00000017), ["8-bit ISDN mu-law compressed (CCITT G.721 ADPCM voice enc.),"], swap_endian=0
signature file-magic-auto326 {
	file-mime "audio/x-dec-basic", 70
	file-magic /(\x2e\x73\x64\x00)(.{8})(\x17\x00\x00\x00)/
}

# >0  string,=.snd (len=4), ["Sun/NeXT audio data:"], swap_endian=0
# >>12  belong&,=1 (0x00000001), ["8-bit ISDN mu-law,"], swap_endian=0
signature file-magic-auto327 {
	file-mime "audio/basic", 70
	file-magic /(\x2esnd)(.{8})(\x00\x00\x00\x01)/
}

# >0  string,=.snd (len=4), ["Sun/NeXT audio data:"], swap_endian=0
# >>12  belong&,=2 (0x00000002), ["8-bit linear PCM [REF-PCM],"], swap_endian=0
signature file-magic-auto328 {
	file-mime "audio/basic", 70
	file-magic /(\x2esnd)(.{8})(\x00\x00\x00\x02)/
}

# >0  string,=.snd (len=4), ["Sun/NeXT audio data:"], swap_endian=0
# >>12  belong&,=3 (0x00000003), ["16-bit linear PCM,"], swap_endian=0
signature file-magic-auto329 {
	file-mime "audio/basic", 70
	file-magic /(\x2esnd)(.{8})(\x00\x00\x00\x03)/
}

# >0  string,=.snd (len=4), ["Sun/NeXT audio data:"], swap_endian=0
# >>12  belong&,=4 (0x00000004), ["24-bit linear PCM,"], swap_endian=0
signature file-magic-auto330 {
	file-mime "audio/basic", 70
	file-magic /(\x2esnd)(.{8})(\x00\x00\x00\x04)/
}

# >0  string,=.snd (len=4), ["Sun/NeXT audio data:"], swap_endian=0
# >>12  belong&,=5 (0x00000005), ["32-bit linear PCM,"], swap_endian=0
signature file-magic-auto331 {
	file-mime "audio/basic", 70
	file-magic /(\x2esnd)(.{8})(\x00\x00\x00\x05)/
}

# >0  string,=.snd (len=4), ["Sun/NeXT audio data:"], swap_endian=0
# >>12  belong&,=6 (0x00000006), ["32-bit IEEE floating point,"], swap_endian=0
signature file-magic-auto332 {
	file-mime "audio/basic", 70
	file-magic /(\x2esnd)(.{8})(\x00\x00\x00\x06)/
}

# >0  string,=.snd (len=4), ["Sun/NeXT audio data:"], swap_endian=0
# >>12  belong&,=7 (0x00000007), ["64-bit IEEE floating point,"], swap_endian=0
signature file-magic-auto333 {
	file-mime "audio/basic", 70
	file-magic /(\x2esnd)(.{8})(\x00\x00\x00\x07)/
}

# >0  string,=.snd (len=4), ["Sun/NeXT audio data:"], swap_endian=0
# >>12  belong&,=23 (0x00000017), ["8-bit ISDN mu-law compressed (CCITT G.721 ADPCM voice enc.),"], swap_endian=0
signature file-magic-auto334 {
	file-mime "audio/x-adpcm", 70
	file-magic /(\x2esnd)(.{8})(\x00\x00\x00\x17)/
}

# >0  string,=SIT! (len=4), ["StuffIt Archive (data)"], swap_endian=0
signature file-magic-auto335 {
	file-mime "application/x-stuffit", 70
	file-magic /(SIT\x21)/
}

# >0  lelong&,=574529400 (0x223e9f78), ["Transport Neutral Encapsulation Format"], swap_endian=0
signature file-magic-auto336 {
	file-mime "application/vnd.ms-tnef", 70
	file-magic /(\x78\x9f\x3e\x22)/
}

# >0  string,=<ar> (len=4), ["System V Release 1 ar archive"], swap_endian=0
signature file-magic-auto337 {
	file-mime "application/x-archive", 70
	file-magic /(\x3car\x3e)/
}

# >0  lelong&ffffffff8080ffff,=2074 (0x0000081a), ["ARC archive data, dynamic LZW"], swap_endian=0
signature file-magic-auto338 {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})(\x08\x1a)/
}

# >0  lelong&ffffffff8080ffff,=2330 (0x0000091a), ["ARC archive data, squashed"], swap_endian=0
signature file-magic-auto339 {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})(\x09\x1a)/
}

# >0  lelong&ffffffff8080ffff,=538 (0x0000021a), ["ARC archive data, uncompressed"], swap_endian=0
signature file-magic-auto340 {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})(\x02\x1a)/
}

# >0  lelong&,=270539386 (0x10201a7a), ["Symbian installation file (Symbian OS 9.x)"], swap_endian=0
signature file-magic-auto341 {
	file-mime "x-epoc/x-sisx-app", 70
	file-magic /(\x7a\x1a\x20\x10)/
}

# >8  lelong&,=268436505 (0x10000419), ["Symbian installation file"], swap_endian=0
signature file-magic-auto342 {
	file-mime "application/vnd.symbian.install", 70
	file-magic /(.{8})(\x19\x04\x00\x10)/
}

# >0  lelong&ffffffff8080ffff,=794 (0x0000031a), ["ARC archive data, packed"], swap_endian=0
signature file-magic-auto343 {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})(\x03\x1a)/
}

# >0  belong&,=518520576 (0x1ee7ff00), ["EET archive"], swap_endian=0
signature file-magic-auto344 {
	file-mime "application/x-eet", 70
	file-magic /(\x1e\xe7\xff\x00)/
}

# >0  lelong&ffffffff8080ffff,=1050 (0x0000041a), ["ARC archive data, squeezed"], swap_endian=0
signature file-magic-auto345 {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})(\x04\x1a)/
}

# >0  lelong&ffffffff8080ffff,=1562 (0x0000061a), ["ARC archive data, crunched"], swap_endian=0
signature file-magic-auto346 {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})(\x06\x1a)/
}

# >0  lelong&ffffffff8080ffff,=2586 (0x00000a1a), ["PAK archive data"], swap_endian=0
signature file-magic-auto347 {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})(\x0a\x1a)/
}

# >0  lelong&ffffffff8080ffff,=5146 (0x0000141a), ["ARC+ archive data"], swap_endian=0
signature file-magic-auto348 {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})(\x14\x1a)/
}

# >20  lelong&,=-37443620 (0xfdc4a7dc), ["Zoo archive data"], swap_endian=0
signature file-magic-auto349 {
	file-mime "application/x-zoo", 70
	file-magic /(.{20})(\xdc\xa7\xc4\xfd)/
}

# >0  string,=Rar! (len=4), ["RAR archive data,"], swap_endian=0
signature file-magic-auto350 {
	file-mime "application/x-rar", 70
	file-magic /(Rar\x21)/
}

# >0  lelong&ffffffff8080ffff,=18458 (0x0000481a), ["HYP archive data"], swap_endian=0
signature file-magic-auto351 {
	file-mime "application/x-arc", 70
	file-magic /([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f]{2})(\x48\x1a)/
}

# >0  string,=drpm (len=4), ["Delta RPM"], swap_endian=0
signature file-magic-auto352 {
	file-mime "application/x-rpm", 70
	file-magic /(drpm)/
}

# >0  belong&,=-307499301 (0xedabeedb), ["RPM"], swap_endian=0
signature file-magic-auto353 {
	file-mime "application/x-rpm", 70
	file-magic /(\xed\xab\xee\xdb)/
}

# >0  string,=RIFF (len=4), ["RIFF (little-endian) data"], swap_endian=0
# >>8  string,=WAVE (len=4), [", WAVE audio"], swap_endian=0
signature file-magic-auto354 {
	file-mime "audio/x-wav", 70
	file-magic /(RIFF)(.{4})(WAVE)/
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

# >0  string,=RIFF (len=4), ["RIFF (little-endian) data"], swap_endian=0
# >>8  string,=AVI  (len=4), [", AVI"], swap_endian=0
signature file-magic-auto357 {
	file-mime "video/x-msvideo", 70
	file-magic /(RIFF)(.{4})(AVI )/
}

# >0  belong&,=834535424 (0x31be0000), ["Microsoft Word Document"], swap_endian=0
signature file-magic-auto358 {
	file-mime "application/msword", 70
	file-magic /(\x31\xbe\x00\x00)/
}

# >0  string/b,=\3767\000# (len=4), ["Microsoft Office Document"], swap_endian=0
signature file-magic-auto359 {
	file-mime "application/msword", 70
	file-magic /(\xfe7\x00\x23)/
}

# >0  string/b,=\333\245-\000 (len=4), ["Microsoft WinWord 2.0 Document"], swap_endian=0
signature file-magic-auto360 {
	file-mime "application/msword", 70
	file-magic /(\xdb\xa5\x2d\x00)/
}

# >0  string/b,=\333\245-\000 (len=4), ["Microsoft WinWord 2.0 Document"], swap_endian=0
signature file-magic-auto361 {
	file-mime "application/msword", 70
	file-magic /(\xdb\xa5\x2d\x00)/
}

# >0  belong&,=6656 (0x00001a00), ["Lotus 1-2-3"], swap_endian=0
signature file-magic-auto362 {
	file-mime "application/x-123", 70
	file-magic /(\x00\x00\x1a\x00)/
}

# >0  belong&,=512 (0x00000200), ["Lotus 1-2-3"], swap_endian=0
signature file-magic-auto363 {
	file-mime "application/x-123", 70
	file-magic /(\x00\x00\x02\x00)/
}

# >0  string/b,=\000\000\001\000 (len=4), ["MS Windows icon resource"], swap_endian=0
signature file-magic-auto364 {
	file-mime "image/x-icon", 70
	file-magic /(\x00\x00\x01\x00)/
}

# >0  lelong&,=268435536 (0x10000050), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435565 (0x1000006d), ["database"], swap_endian=0
# >>>8  lelong&,=268435588 (0x10000084), ["Agenda file"], swap_endian=0
signature file-magic-auto365 {
	file-mime "application/x-epoc-agenda", 70
	file-magic /(\x50\x00\x00\x10)(\x6d\x00\x00\x10)(\x84\x00\x00\x10)/
}

# >0  lelong&,=268435536 (0x10000050), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435565 (0x1000006d), ["database"], swap_endian=0
# >>>8  lelong&,=268435590 (0x10000086), ["Data file"], swap_endian=0
signature file-magic-auto366 {
	file-mime "application/x-epoc-data", 70
	file-magic /(\x50\x00\x00\x10)(\x6d\x00\x00\x10)(\x86\x00\x00\x10)/
}

# >0  lelong&,=268435536 (0x10000050), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435565 (0x1000006d), ["database"], swap_endian=0
# >>>8  lelong&,=268438762 (0x10000cea), ["Jotter file"], swap_endian=0
signature file-magic-auto367 {
	file-mime "application/x-epoc-jotter", 70
	file-magic /(\x50\x00\x00\x10)(\x6d\x00\x00\x10)(\xea\x0c\x00\x10)/
}

# >0  lelong&,=268435511 (0x10000037), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435522 (0x10000042), ["multi-bitmap image"], swap_endian=0
signature file-magic-auto368 {
	file-mime "image/x-epoc-mbm", 70
	file-magic /(\x37\x00\x00\x10)(\x42\x00\x00\x10)/
}

# >0  lelong&,=268435511 (0x10000037), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435565 (0x1000006d), [""], swap_endian=0
# >>>8  lelong&,=268435581 (0x1000007d), ["Sketch image"], swap_endian=0
signature file-magic-auto369 {
	file-mime "image/x-epoc-sketch", 70
	file-magic /(\x37\x00\x00\x10)(\x6d\x00\x00\x10)(\x7d\x00\x00\x10)/
}

# >0  lelong&,=268435511 (0x10000037), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435565 (0x1000006d), [""], swap_endian=0
# >>>8  lelong&,=268435583 (0x1000007f), ["Word file"], swap_endian=0
signature file-magic-auto370 {
	file-mime "application/x-epoc-word", 70
	file-magic /(\x37\x00\x00\x10)(\x6d\x00\x00\x10)(\x7f\x00\x00\x10)/
}

# >0  lelong&,=268435511 (0x10000037), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435565 (0x1000006d), [""], swap_endian=0
# >>>8  lelong&,=268435589 (0x10000085), ["OPL program (TextEd)"], swap_endian=0
signature file-magic-auto371 {
	file-mime "application/x-epoc-opl", 70
	file-magic /(\x37\x00\x00\x10)(\x6d\x00\x00\x10)(\x85\x00\x00\x10)/
}

# >0  lelong&,=268435511 (0x10000037), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435565 (0x1000006d), [""], swap_endian=0
# >>>8  lelong&,=268435592 (0x10000088), ["Sheet file"], swap_endian=0
signature file-magic-auto372 {
	file-mime "application/x-epoc-sheet", 70
	file-magic /(\x37\x00\x00\x10)(\x6d\x00\x00\x10)(\x88\x00\x00\x10)/
}

# >0  lelong&,=268435511 (0x10000037), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435571 (0x10000073), ["OPO module"], swap_endian=0
signature file-magic-auto373 {
	file-mime "application/x-epoc-opo", 70
	file-magic /(\x37\x00\x00\x10)(\x73\x00\x00\x10)/
}

# >0  lelong&,=268435511 (0x10000037), ["Psion Series 5"], swap_endian=0
# >>4  lelong&,=268435572 (0x10000074), ["OPL application"], swap_endian=0
signature file-magic-auto374 {
	file-mime "application/x-epoc-app", 70
	file-magic /(\x37\x00\x00\x10)(\x74\x00\x00\x10)/
}

# >0  long&,=398689 (0x00061561), ["Berkeley DB"], swap_endian=0
signature file-magic-auto375 {
	file-mime "application/x-dbm", 70
	file-magic /((\x61\x15\x06\x00)|(\x00\x06\x15\x61))/
}

# >0  string,=GDBM (len=4), ["GNU dbm 2.x database"], swap_endian=0
signature file-magic-auto376 {
	file-mime "application/x-gdbm", 70
	file-magic /(GDBM)/
}

# >0  lelong&,=324508366 (0x13579ace), ["GNU dbm 1.x or ndbm database, little endian"], swap_endian=0
signature file-magic-auto377 {
	file-mime "application/x-gdbm", 70
	file-magic /(\xce\x9a\x57\x13)/
}

# >0  belong&,=324508366 (0x13579ace), ["GNU dbm 1.x or ndbm database, big endian"], swap_endian=0
signature file-magic-auto378 {
	file-mime "application/x-gdbm", 70
	file-magic /(\x13\x57\x9a\xce)/
}

# >0  belong&,=4 (0x00000004), ["X11 SNF font data, MSB first"], swap_endian=0
signature file-magic-auto379 {
	file-mime "application/x-font-sfn", 70
	file-magic /(\x00\x00\x00\x04)/
}

# >0  string,=OTTO (len=4), ["OpenType font data"], swap_endian=0
signature file-magic-auto380 {
	file-mime "application/vnd.ms-opentype", 70
	file-magic /(OTTO)/
}

# >0  string,=<MML (len=4), ["FrameMaker MML file"], swap_endian=0
signature file-magic-auto381 {
	file-mime "application/x-mif", 70
	file-magic /(\x3cMML)/
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

# >0  string,=OggS (len=4), ["Ogg data"], swap_endian=0
signature file-magic-auto385 {
	file-mime "application/ogg", 70
	file-magic /(OggS)/
}

# >0  string,=LZIP (len=4), ["lzip compressed data"], swap_endian=0
signature file-magic-auto386 {
	file-mime "application/x-lzip", 70
	file-magic /(LZIP)/
}

# >0  belong&,=-889270259 (0xcafed00d), ["JAR compressed with pack200,"], swap_endian=0
# >>4  byte&,x, ["%d"], swap_endian=0
signature file-magic-auto387 {
	file-mime "application/x-java-pack200", 1
	file-magic /(\xca\xfe\xd0\x0d)(.{1})/
}

# >0  belong&,=-889270259 (0xcafed00d), ["JAR compressed with pack200,"], swap_endian=0
# >>4  byte&,x, ["%d"], swap_endian=0
signature file-magic-auto388 {
	file-mime "application/x-java-pack200", 1
	file-magic /(\xca\xfe\xd0\x0d)(.{1})/
}

# >0  regex,=^( |\t){0,50}def {1,50}[a-zA-Z]{1,100} (len=38), [""], swap_endian=0
# >>&0  regex,= {0,50}\(([a-zA-Z]|,| ){1,500}\):$ (len=34), ["Python script text executable"], swap_endian=0
signature file-magic-auto389 {
	file-mime "text/x-python", 64
	file-magic /(.*)(( |\t){0,50}def {1,50}[a-zA-Z]{1,100})( {0,50}\(([a-zA-Z]|,| ){1,500}\):$)/
}

# >0  search/4096,=\documentstyle (len=14), ["LaTeX document text"], swap_endian=0
signature file-magic-auto390 {
	file-mime "text/x-tex", 62
	file-magic /(.*)(\x5cdocumentstyle)/
}

# >0  string,=DOC (len=3), [""], swap_endian=0
# >>43  byte&,=0x14, ["Just System Word Processor Ichitaro v4"], swap_endian=0
signature file-magic-auto391 {
	file-mime "application/x-ichitaro4", 40
	file-magic /(DOC)(.{40})([\x14])/
}

# >0  string,=DOC (len=3), [""], swap_endian=0
# >>43  byte&,=0x15, ["Just System Word Processor Ichitaro v5"], swap_endian=0
signature file-magic-auto392 {
	file-mime "application/x-ichitaro5", 40
	file-magic /(DOC)(.{40})([\x15])/
}

# >1  string,=SaR (len=3), [""], swap_endian=0
# >>0  string,=3 (len=1), ["Cups Raster version 3, Little Endian"], swap_endian=0
signature file-magic-auto393 {
	file-mime "application/vnd.cups-raster", 40
	file-magic /(3)(SaR)/
}

# >0  string,=RaS (len=3), [""], swap_endian=0
# >>3  string,=3 (len=1), ["Cups Raster version 3, Big Endian"], swap_endian=0
signature file-magic-auto394 {
	file-mime "application/vnd.cups-raster", 40
	file-magic /(RaS)(3)/
}

# >0  string,=DOC (len=3), [""], swap_endian=0
# >>43  byte&,=0x16, ["Just System Word Processor Ichitaro v6"], swap_endian=0
signature file-magic-auto395 {
	file-mime "application/x-ichitaro6", 40
	file-magic /(DOC)(.{40})([\x16])/
}

# >0  search/w/1,=#! /usr/local/bin/php (len=21), ["PHP script text executable"], swap_endian=0
signature file-magic-auto396 {
	file-mime "text/x-php", 61
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fphp)/
}

# >0  search/1,=eval '(exit $?0)' && eval 'exec (len=31), ["Perl script text"], swap_endian=0
signature file-magic-auto397 {
	file-mime "text/x-perl", 61
	file-magic /(.*)(eval \x27\x28exit \x24\x3f0\x29\x27 \x26\x26 eval \x27exec)/
}

# >0  regex,=^[ \t]*require[ \t]'[A-Za-z_/]+' (len=30), [""], swap_endian=0
# >>0  regex,=include [A-Z]|def [a-z]| do$ (len=28), [""], swap_endian=0
# >>>0  regex,=^[ \t]*end([ \t]*[;#].*)?$ (len=24), ["Ruby script text"], swap_endian=0
signature file-magic-auto398 {
	file-mime "text/x-ruby", 54
	file-magic /(.*)([ \x09]*require[ \x09]'[A-Za-z_\x2f]+')(include [A-Z]|def [a-z]| do$)(^[ \x09]*end([ \x09]*[;#].*)?$)/
}

# >0  search/1,=eval "exec /usr/local/bin/perl (len=30), ["Perl script text"], swap_endian=0
signature file-magic-auto399 {
	file-mime "text/x-perl", 60
	file-magic /(.*)(eval \x22exec \x2fusr\x2flocal\x2fbin\x2fperl)/
}

# >0  string,=FLV (len=3), ["Macromedia Flash Video"], swap_endian=0
signature file-magic-auto400 {
	file-mime "video/x-flv", 60
	file-magic /(FLV)/
}

# >0  string,=MP+ (len=3), ["Musepack audio"], swap_endian=0
signature file-magic-auto401 {
	file-mime "audio/x-musepack", 60
	file-magic /(MP\x2b)/
}

# >0  string,=PBF (len=3), ["PBF image (deflate compression)"], swap_endian=0
signature file-magic-auto402 {
	file-mime "image/x-unknown", 60
	file-magic /(PBF)/
}

# >0  string,=SBI (len=3), ["SoundBlaster instrument data"], swap_endian=0
signature file-magic-auto403 {
	file-mime "audio/x-unknown", 60
	file-magic /(SBI)/
}

# >0  string/b,=\224\246. (len=3), ["Microsoft Word Document"], swap_endian=0
signature file-magic-auto404 {
	file-mime "application/msword", 60
	file-magic /(\x94\xa6\x2e)/
}

# >0  string,=\004%! (len=3), ["PostScript document text"], swap_endian=0
signature file-magic-auto405 {
	file-mime "application/postscript", 60
	file-magic /(\x04\x25\x21)/
}

# >0  string,=BZh (len=3), ["bzip2 compressed data"], swap_endian=0
signature file-magic-auto406 {
	file-mime "application/x-bzip2", 60
	file-magic /(BZh)/
}

# >0  regex,=^[ \t]*(class|module)[ \t][A-Z] (len=29), [""], swap_endian=0
# >>0  regex,=(modul|includ)e [A-Z]|def [a-z] (len=31), [""], swap_endian=0
# >>>0  regex,=^[ \t]*end([ \t]*[;#].*)?$ (len=24), ["Ruby module source text"], swap_endian=0
signature file-magic-auto407 {
	file-mime "text/x-ruby", 54
	file-magic /(.*)([ \x09]*(class|module)[ \x09][A-Z])((modul|includ)e [A-Z]|def [a-z])(^[ \x09]*end([ \x09]*[;#].*)?$)/
}

# >512  string/b,=\354\245\301 (len=3), ["Microsoft Word Document"], swap_endian=0
signature file-magic-auto408 {
	file-mime "application/msword", 60
	file-magic /(.{512})(\xec\xa5\xc1)/
}

# >0  string,=FWS (len=3), ["Macromedia Flash data,"], swap_endian=0
# >>3  byte&,x, ["version %d"], swap_endian=0
signature file-magic-auto409 {
	file-mime "application/x-shockwave-flash", 1
	file-magic /(FWS)(.{1})/
}

# >0  string,=CWS (len=3), ["Macromedia Flash data (compressed),"], swap_endian=0
signature file-magic-auto410 {
	file-mime "application/x-shockwave-flash", 60
	file-magic /(CWS)/
}

# >0  regex/20,=^\.[A-Za-z0-9][A-Za-z0-9][ \t] (len=29), ["troff or preprocessor input text"], swap_endian=0
signature file-magic-auto411 {
	file-mime "text/troff", 59
	file-magic /(^\.[A-Za-z0-9][A-Za-z0-9][ \x09])/
}

# >0  search/4096,=\documentclass (len=14), ["LaTeX 2e document text"], swap_endian=0
signature file-magic-auto412 {
	file-mime "text/x-tex", 59
	file-magic /(.*)(\x5cdocumentclass)/
}

# >0  regex,=^from\s+(\w|\.)+\s+import.*$ (len=28), ["Python script text executable"], swap_endian=0
signature file-magic-auto413 {
	file-mime "text/x-python", 58
	file-magic /(.*)(from\s+(\w|\.)+\s+import.*$)/
}

# >0  search/4096,=\contentsline (len=13), ["LaTeX table of contents"], swap_endian=0
signature file-magic-auto414 {
	file-mime "text/x-tex", 58
	file-magic /(.*)(\x5ccontentsline)/
}

# >0  search/4096,=\chapter (len=8), ["LaTeX document text"], swap_endian=0
signature file-magic-auto415 {
	file-mime "text/x-tex", 56
	file-magic /(.*)(\x5cchapter)/
}

# >0  search/4096,=\section (len=8), ["LaTeX document text"], swap_endian=0
signature file-magic-auto416 {
	file-mime "text/x-tex", 56
	file-magic /(.*)(\x5csection)/
}

# >0  regex/20,=^\.[A-Za-z0-9][A-Za-z0-9]$ (len=26), ["troff or preprocessor input text"], swap_endian=0
signature file-magic-auto417 {
	file-mime "text/troff", 56
	file-magic /(^\.[A-Za-z0-9][A-Za-z0-9]$)/
}

# >0  search/w/1,=#! /usr/bin/php (len=15), ["PHP script text executable"], swap_endian=0
signature file-magic-auto418 {
	file-mime "text/x-php", 55
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2fbin\x2fphp)/
}

# >0  search/4096,=\setlength (len=10), ["LaTeX document text"], swap_endian=0
signature file-magic-auto419 {
	file-mime "text/x-tex", 55
	file-magic /(.*)(\x5csetlength)/
}

# >0  search/1,=eval "exec /usr/bin/perl (len=24), ["Perl script text"], swap_endian=0
signature file-magic-auto420 {
	file-mime "text/x-perl", 54
	file-magic /(.*)(eval \x22exec \x2fusr\x2fbin\x2fperl)/
}

# >0  search/w/1,=#! /usr/local/bin/python (len=24), ["Python script text executable"], swap_endian=0
signature file-magic-auto421 {
	file-mime "text/x-python", 54
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fpython)/
}

# >0  search/1,=Common subdirectories:  (len=23), ["diff output text"], swap_endian=0
signature file-magic-auto422 {
	file-mime "text/x-diff", 53
	file-magic /(.*)(Common subdirectories\x3a )/
}

# >0  search/1,=#! /usr/bin/env python (len=22), ["Python script text executable"], swap_endian=0
signature file-magic-auto423 {
	file-mime "text/x-python", 52
	file-magic /(.*)(\x23\x21 \x2fusr\x2fbin\x2fenv python)/
}

# >0  search/w/1,=#! /usr/local/bin/ruby (len=22), ["Ruby script text executable"], swap_endian=0
signature file-magic-auto424 {
	file-mime "text/x-ruby", 52
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fruby)/
}

# >0  search/w/1,=#! /usr/local/bin/wish (len=22), ["Tcl/Tk script text executable"], swap_endian=0
signature file-magic-auto425 {
	file-mime "text/x-tcl", 52
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2fwish)/
}

# >0  search/4096,=(custom-set-variables  (len=22), ["Lisp/Scheme program text"], swap_endian=0
signature file-magic-auto426 {
	file-mime "text/x-lisp", 52
	file-magic /(.*)(\x28custom\x2dset\x2dvariables )/
}

# >0  beshort&,=-40 (0xffd8), ["JPEG image data"], swap_endian=0
signature file-magic-auto427 {
	file-mime "image/jpeg", 52
	file-magic /(\xff\xd8)/
}

# >0  search/1,=#!/usr/bin/env python (len=21), ["Python script text executable"], swap_endian=0
signature file-magic-auto428 {
	file-mime "text/x-python", 51
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fenv python)/
}

# >0  search/1,=#!/usr/bin/env nodejs (len=21), ["Node.js script text executable"], swap_endian=0
signature file-magic-auto429 {
	file-mime "application/javascript", 51
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fenv nodejs)/
}

# >0  search/w/1,=#! /usr/local/bin/tcl (len=21), ["Tcl script text executable"], swap_endian=0
signature file-magic-auto430 {
	file-mime "text/x-tcl", 51
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2ftcl)/
}

# This didn't autogenerate well due to indirect offset, bitmasking, and
# relational comparisons.
# >0  leshort&fffffffffffffefe,=0 (0x0000), [""], swap_endian=0
# >>4  ulelong&fcfffe00,=0 (0x00000000), [""], swap_endian=0
# >>>68  ulelong&,>87 (0x00000057), [""], swap_endian=0
# >>>>68 (lelong,-1), ubelong&ffe0c519,=4194328 (0x00400018), ["Windows Precompiled iNF"], swap_endian=0
#signature file-magic-auto431 {
#	file-mime "application/x-pnf", 70
#	file-magic /(.{2})(.{2})(.{4})(.{60})(.{4})(.{4})/
#}

# >0  search/w/1,=#! /usr/local/bin/lua (len=21), ["Lua script text executable"], swap_endian=0
signature file-magic-auto432 {
	file-mime "text/x-lua", 51
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2flocal\x2fbin\x2flua)/
}

# >0  string/b,=MZ (len=2), [""], swap_endian=0
signature file-magic-auto433 {
	file-mime "application/x-dosexec", 51
	file-magic /(MZ)/
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

# >0  string,=BM (len=2), [""], swap_endian=0
# >>14  leshort&,=12 (0x000c), ["PC bitmap, OS/2 1.x format"], swap_endian=0
signature file-magic-auto454 {
	file-mime "image/x-ms-bmp", 50
	file-magic /(BM)(.{12})(\x0c\x00)/
}

# >0  string,=BM (len=2), [""], swap_endian=0
# >>14  leshort&,=64 (0x0040), ["PC bitmap, OS/2 2.x format"], swap_endian=0
signature file-magic-auto455 {
	file-mime "image/x-ms-bmp", 50
	file-magic /(BM)(.{12})(\x40\x00)/
}

# >0  string,=BM (len=2), [""], swap_endian=0
# >>14  leshort&,=40 (0x0028), ["PC bitmap, Windows 3.x format"], swap_endian=0
signature file-magic-auto456 {
	file-mime "image/x-ms-bmp", 50
	file-magic /(BM)(.{12})(\x28\x00)/
}

# >0  string,=BM (len=2), [""], swap_endian=0
# >>14  leshort&,=124 (0x007c), ["PC bitmap, Windows 98/2000 and newer format"], swap_endian=0
signature file-magic-auto457 {
	file-mime "image/x-ms-bmp", 50
	file-magic /(BM)(.{12})(\x7c\x00)/
}

# >0  string,=BM (len=2), [""], swap_endian=0
# >>14  leshort&,=108 (0x006c), ["PC bitmap, Windows 95/NT4 and newer format"], swap_endian=0
signature file-magic-auto458 {
	file-mime "image/x-ms-bmp", 50
	file-magic /(BM)(.{12})(\x6c\x00)/
}

# >0  string,=BM (len=2), [""], swap_endian=0
# >>14  leshort&,=128 (0x0080), ["PC bitmap, Windows NT/2000 format"], swap_endian=0
signature file-magic-auto459 {
	file-mime "image/x-ms-bmp", 50
	file-magic /(BM)(.{12})(\x80\x00)/
}

# >20  string,=45 (len=2), [""], swap_endian=0
# >>0  regex/1,=(^[0-9]{5})[acdnp][^bhlnqsu-z] (len=30), ["MARC21 Bibliographic"], swap_endian=0
signature file-magic-auto460 {
	file-mime "application/marc", 60
	file-magic /(.{20})(45)(.*)((^[0-9]{5})[acdnp][^bhlnqsu-z])/
}

# >20  string,=45 (len=2), [""], swap_endian=0
# >>0  regex/1,=(^[0-9]{5})[acdnosx][z] (len=23), ["MARC21 Authority"], swap_endian=0
signature file-magic-auto461 {
	file-mime "application/marc", 53
	file-magic /(.{20})(45)(.*)((^[0-9]{5})[acdnosx][z])/
}

# >20  string,=45 (len=2), [""], swap_endian=0
# >>0  regex/1,=(^[0-9]{5})[cdn][uvxy] (len=22), ["MARC21 Holdings"], swap_endian=0
signature file-magic-auto462 {
	file-mime "application/marc", 52
	file-magic /(.{20})(45)(.*)((^[0-9]{5})[cdn][uvxy])/
}

# >0  search/4096,=\relax (len=6), ["LaTeX auxiliary file"], swap_endian=0
signature file-magic-auto463 {
	file-mime "text/x-tex", 51
	file-magic /(.*)(\x5crelax)/
}

# >0  search/4096,=\begin (len=6), ["LaTeX document text"], swap_endian=0
signature file-magic-auto464 {
	file-mime "text/x-tex", 51
	file-magic /(.*)(\x5cbegin)/
}

# >0  search/4096,=\input (len=6), ["TeX document text"], swap_endian=0
signature file-magic-auto465 {
	file-mime "text/x-tex", 51
	file-magic /(.*)(\x5cinput)/
}

# >0  leshort&,=-24712 (0x9f78), ["TNEF"], swap_endian=0
signature file-magic-auto466 {
	file-mime "application/vnd.ms-tnef", 50
	file-magic /(\x78\x9f)/
}

# >0  leshort&,=-5536 (0xea60), ["ARJ archive data"], swap_endian=0
signature file-magic-auto467 {
	file-mime "application/x-arj", 50
	file-magic /(\x60\xea)/
}

# >0  search/1,=eval "exec /bin/perl (len=20), ["Perl script text"], swap_endian=0
signature file-magic-auto468 {
	file-mime "text/x-perl", 50
	file-magic /(.*)(eval \x22exec \x2fbin\x2fperl)/
}

# >0  search/1,=#! /usr/bin/env perl (len=20), ["Perl script text executable"], swap_endian=0
signature file-magic-auto469 {
	file-mime "text/x-perl", 50
	file-magic /(.*)(\x23\x21 \x2fusr\x2fbin\x2fenv perl)/
}

# >0  beshort&,=-26368 (0x9900), ["PGP key public ring"], swap_endian=0
signature file-magic-auto470 {
	file-mime "application/x-pgp-keyring", 50
	file-magic /(\x99\x00)/
}

# >0  beshort&,=-27391 (0x9501), ["PGP key security ring"], swap_endian=0
signature file-magic-auto471 {
	file-mime "application/x-pgp-keyring", 50
	file-magic /(\x95\x01)/
}

# >0  beshort&,=-27392 (0x9500), ["PGP key security ring"], swap_endian=0
signature file-magic-auto472 {
	file-mime "application/x-pgp-keyring", 50
	file-magic /(\x95\x00)/
}

# >0  beshort&,=-23040 (0xa600), ["PGP encrypted data"], swap_endian=0
signature file-magic-auto473 {
	file-mime "text/PGP", 50
	file-magic /(\xa6\x00)/
}

# >0  string,=%! (len=2), ["PostScript document text"], swap_endian=0
signature file-magic-auto474 {
	file-mime "application/postscript", 50
	file-magic /(\x25\x21)/
}

# >0  search/1,=#! /usr/bin/env ruby (len=20), ["Ruby script text executable"], swap_endian=0
signature file-magic-auto475 {
	file-mime "text/x-ruby", 50
	file-magic /(.*)(\x23\x21 \x2fusr\x2fbin\x2fenv ruby)/
}

# >0  regex/1,=(^[0-9]{5})[acdn][w] (len=20), ["MARC21 Classification"], swap_endian=0
signature file-magic-auto476 {
	file-mime "application/marc", 50
	file-magic /((^[0-9]{5})[acdn][w])/
}

# >0  regex/1,=(^[0-9]{5})[acdn][w] (len=20), ["MARC21 Classification"], swap_endian=0
# >>0  regex/1,=(^[0-9]{5})[cdn][q] (len=19), ["MARC21 Community"], swap_endian=0
signature file-magic-auto477 {
	file-mime "application/marc", 49
	file-magic /((^[0-9]{5})[acdn][w])((^[0-9]{5})[cdn][q])/
}

# >0  regex/1,=(^[0-9]{5})[acdn][w] (len=20), ["MARC21 Classification"], swap_endian=0
# >>0  regex/1,=(^.{21})([^0]{2}) (len=17), ["(non-conforming)"], swap_endian=0
signature file-magic-auto478 {
	file-mime "application/marc", 47
	file-magic /((^[0-9]{5})[acdn][w])((^.{21})([^0]{2}))/
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

# >0  string,=\n( (len=2), ["Emacs v18 byte-compiled Lisp data"], swap_endian=0
signature file-magic-auto481 {
	file-mime "application/x-elc", 50
	file-magic /(\x0a\x28)/
}

# >0  string,=\021\t (len=2), ["Award BIOS Logo, 136 x 126"], swap_endian=0
signature file-magic-auto482 {
	file-mime "image/x-award-bioslogo", 50
	file-magic /(\x11\x09)/
}

# >0  string,=\021\006 (len=2), ["Award BIOS Logo, 136 x 84"], swap_endian=0
signature file-magic-auto483 {
	file-mime "image/x-award-bioslogo", 50
	file-magic /(\x11\x06)/
}

# >0  string,=P7 (len=2), ["Netpbm PAM image file"], swap_endian=0
signature file-magic-auto484 {
	file-mime "image/x-portable-pixmap", 50
	file-magic /(P7)/
}

# >0  beshort&ffffffffffffffe0,=22240 (0x56e0), ["MPEG-4 LOAS"], swap_endian=0
signature file-magic-auto485 {
	file-mime "audio/x-mp4a-latm", 50
	file-magic /(\x56[\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  beshort&fffffffffffffff6,=-16 (0xfff0), ["MPEG ADTS, AAC"], swap_endian=0
signature file-magic-auto486 {
	file-mime "audio/x-hx-aac-adts", 50
	file-magic /(\xff[\xf0\xf1\xf8\xf9])/
}

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

# >0  search/1,=#! /usr/bin/env wish (len=20), ["Tcl/Tk script text executable"], swap_endian=0
signature file-magic-auto491 {
	file-mime "text/x-tcl", 50
	file-magic /(.*)(\x23\x21 \x2fusr\x2fbin\x2fenv wish)/
}

# >0  beshort&,=-26367 (0x9901), ["GPG key public ring"], swap_endian=0
signature file-magic-auto492 {
	file-mime "application/x-gnupg-keyring", 50
	file-magic /(\x99\x01)/
}

# >0  string,=\367\002 (len=2), ["TeX DVI file"], swap_endian=0
signature file-magic-auto493 {
	file-mime "application/x-dvi", 50
	file-magic /(\xf7\x02)/
}

# >2  string,=\000\021 (len=2), ["TeX font metric data"], swap_endian=0
signature file-magic-auto494 {
	file-mime "application/x-tex-tfm", 50
	file-magic /(.{2})(\x00\x11)/
}

# >2  string,=\000\022 (len=2), ["TeX font metric data"], swap_endian=0
signature file-magic-auto495 {
	file-mime "application/x-tex-tfm", 50
	file-magic /(.{2})(\x00\x12)/
}

# >0  beshort&,=-31486 (0x8502), ["GPG encrypted data"], swap_endian=0
signature file-magic-auto496 {
	file-mime "text/PGP", 50
	file-magic /(\x85\x02)/
}

# >4  string/W,=jP (len=2), ["JPEG 2000 image"], swap_endian=0
signature file-magic-auto497 {
	file-mime "image/jp2", 50
	file-magic /(.{4})(jP)/
}

# Not specific enough.
# >0  regex,=^template[ \t\n]+ (len=15), ["C++ source text"], swap_endian=0
#signature file-magic-auto498 {
#	file-mime "text/x-c++", 50
#	file-magic /(.*)(template[ \x09\x0a]+)/
#}

# >0  search/c/1,=<?php (len=5), ["PHP script text"], swap_endian=0
signature file-magic-auto499 {
	file-mime "text/x-php", 50
	file-magic /(.*)(\x3c\x3f[pP][hH][pP])/
}

# >0  string,=\037\235 (len=2), ["compress'd data"], swap_endian=0
signature file-magic-auto500 {
	file-mime "application/x-compress", 50
	file-magic /(\x1f\x9d)/
}

# >0  string,=\037\036 (len=2), ["packed data"], swap_endian=0
#signature file-magic-auto501 {
#	file-mime "application/octet-stream", 50
#	file-magic /(\x1f\x1e)/
#}

# >0  short&,=7967 (0x1f1f), ["old packed data"], swap_endian=0
#signature file-magic-auto502 {
#	file-mime "application/octet-stream", 50
#	file-magic /((\x1f\x1f)|(\x1f\x1f))/
#}

# >0  short&,=8191 (0x1fff), ["compacted data"], swap_endian=0
#signature file-magic-auto503 {
#	file-mime "application/octet-stream", 50
#	file-magic /((\xff\x1f)|(\x1f\xff))/
#}

# >0  string,=\377\037 (len=2), ["compacted data"], swap_endian=0
#signature file-magic-auto504 {
#	file-mime "application/octet-stream", 50
#	file-magic /(\xff\x1f)/
#}

# >0  short&,=-13563 (0xcb05), ["huf output"], swap_endian=0
#signature file-magic-auto505 {
#	file-mime "application/octet-stream", 50
#	file-magic /((\x05\xcb)|(\xcb\x05))/
#}

# >34  string,=LP (len=2), ["Embedded OpenType (EOT)"], swap_endian=0
signature file-magic-auto506 {
	file-mime "application/vnd.ms-fontobject", 50
	file-magic /(.{34})(LP)/
}

# >0  beshort&,=2935 (0x0b77), ["ATSC A/52 aka AC-3 aka Dolby Digital stream,"], swap_endian=0
signature file-magic-auto507 {
	file-mime "audio/vnd.dolby.dd-raw", 50
	file-magic /(\x0b\x77)/
}

# >0  search/1,=#!/usr/bin/env node (len=19), ["Node.js script text executable"], swap_endian=0
signature file-magic-auto508 {
	file-mime "application/javascript", 49
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fenv node)/
}

# >0  search/1,=#!/usr/bin/env wish (len=19), ["Tcl/Tk script text executable"], swap_endian=0
signature file-magic-auto509 {
	file-mime "text/x-tcl", 49
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fenv wish)/
}

# >0  regex,=^[ \t]{0,50}\.asciiz (len=19), ["assembler source text"], swap_endian=0
signature file-magic-auto510 {
	file-mime "text/x-asm", 49
	file-magic /(^[ \x09]{0,50}\.(asciiz|asciz|section|globl|align|even|byte|file|type))/
}

# >0  regex,=^[ \t]{0,50}\.globl (len=18), ["assembler source text"], swap_endian=0
#signature file-magic-auto517 {
#	file-mime "text/x-asm", 48
#	file-magic /(^[ \x09]{0,50}\.globl)/
#}

# >0  regex,=^[ \t]{0,50}\.text (len=17), ["assembler source text"], swap_endian=0
#signature file-magic-auto523 {
#	file-mime "text/x-asm", 47
#	file-magic /(^[ \x09]{0,50}\.text)/
#}

# >0  regex,=^[ \t]{0,50}\.even (len=17), ["assembler source text"], swap_endian=0
#signature file-magic-auto524 {
#	file-mime "text/x-asm", 47
#	file-magic /(^[ \x09]{0,50}\.even)/
#}

# >0  regex,=^[ \t]{0,50}\.byte (len=17), ["assembler source text"], swap_endian=0
#signature file-magic-auto525 {
#	file-mime "text/x-asm", 47
#	file-magic /(^[ \x09]{0,50}\.byte)/
#}

# >0  regex,=^[ \t]{0,50}\.file (len=17), ["assembler source text"], swap_endian=0
#signature file-magic-auto526 {
#	file-mime "text/x-asm", 47
#	file-magic /(^[ \x09]{0,50}\.file)/
#}

# >0  regex,=^[ \t]{0,50}\.type (len=17), ["assembler source text"], swap_endian=0
#signature file-magic-auto527 {
#	file-mime "text/x-asm", 47
#	file-magic /(^[ \x09]{0,50}\.type)/
#}


# >0  search/1,=#!/usr/bin/env perl (len=19), ["Perl script text executable"], swap_endian=0
signature file-magic-auto511 {
	file-mime "text/x-perl", 49
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fenv perl)/
}

# >0  search/Wct/4096,=<!doctype html (len=14), ["HTML document text"], swap_endian=0
signature file-magic-auto512 {
	file-mime "text/html", 49
	file-magic /(.*)(\x3c\x21[dD][oO][cC][tT][yY][pP][eE] {1,}[hH][tT][mM][lL])/
}

# This doesn't seem specific enough.
# >0  regex,=^virtual[ \t\n]+ (len=14), ["C++ source text"], swap_endian=0
#signature file-magic-auto513 {
#	file-mime "text/x-c++", 49
#	file-magic /(.*)(virtual[ \x09\x0a]+)/
#}

# >0  search/1,=#! /usr/bin/env lua (len=19), ["Lua script text executable"], swap_endian=0
signature file-magic-auto514 {
	file-mime "text/x-lua", 49
	file-magic /(.*)(\x23\x21 \x2fusr\x2fbin\x2fenv lua)/
}

# >0  search/1,=#!/usr/bin/env ruby (len=19), ["Ruby script text executable"], swap_endian=0
signature file-magic-auto515 {
	file-mime "text/x-ruby", 49
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fenv ruby)/
}

# >0  search/1,=#! /usr/bin/env tcl (len=19), ["Tcl script text executable"], swap_endian=0
signature file-magic-auto516 {
	file-mime "text/x-tcl", 49
	file-magic /(.*)(\x23\x21 \x2fusr\x2fbin\x2fenv tcl)/
}
# >0  search/1,=#!/usr/bin/env tcl (len=18), ["Tcl script text executable"], swap_endian=0
signature file-magic-auto518 {
	file-mime "text/x-tcl", 48
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fenv tcl)/
}

# >0  search/1,=#!/usr/bin/env lua (len=18), ["Lua script text executable"], swap_endian=0
signature file-magic-auto519 {
	file-mime "text/x-lua", 48
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fenv lua)/
}

# >0  search/w/1,=#! /usr/bin/python (len=18), ["Python script text executable"], swap_endian=0
signature file-magic-auto520 {
	file-mime "text/x-python", 48
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2fbin\x2fpython)/
}

# >0  search/w/1,=#!/usr/bin/nodejs (len=17), ["Node.js script text executable"], swap_endian=0
signature file-magic-auto521 {
	file-mime "application/javascript", 47
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fnodejs)/
}

# >0  regex,=^class[ \t\n]+ (len=12), ["C++ source text"], swap_endian=0
signature file-magic-auto522 {
	file-mime "text/x-c++", 47
	file-magic /(.*)(class[ \x09\x0a]+[[:alnum:]_]+)(.*)(\x7b)(.*)(public:)/
}

# >0  search/1,=This is Info file (len=17), ["GNU Info text"], swap_endian=0
signature file-magic-auto528 {
	file-mime "text/x-info", 47
	file-magic /(.*)(This is Info file)/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(autorun)]\r\n (len=13), [""], swap_endian=0
# >>>>&0  ubyte&,=0x5b, ["INItialization configuration"], swap_endian=0
signature file-magic-auto529 {
	file-mime "application/x-wine-extension-ini", 40
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([aA][uU][tT][oO][rR][uU][nN])]\x0d\x0a)([\x5b])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(autorun)]\r\n (len=13), [""], swap_endian=0
# >>>>&0  ubyte&,!0x5b, ["Microsoft Windows Autorun file"], swap_endian=0
signature file-magic-auto530 {
	file-mime "application/x-setupscript", 1
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([aA][uU][tT][oO][rR][uU][nN])]\x0d\x0a)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(version|strings)] (len=19), ["Windows setup INFormation"], swap_endian=0
signature file-magic-auto531 {
	file-mime "application/x-setupscript", 49
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([vV][eE][rR][sS][iI][oO][nN]|[sS][tT][rR][iI][nN][gG][sS])])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(WinsockCRCList|OEMCPL)] (len=25), ["Windows setup INFormation"], swap_endian=0
signature file-magic-auto532 {
	file-mime "text/inf", 55
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([Ww][iI][nN][sS][oO][cC][kK][Cc][Rr][Cc][Ll][iI][sS][tT]|[Oo][Ee][Mm][Cc][Pp][Ll])])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(.ShellClassInfo|DeleteOnCopy|LocalizedFileNames)] (len=51), ["Windows desktop.ini"], swap_endian=0
signature file-magic-auto533 {
	file-mime "application/x-wine-extension-ini", 81
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^(.[Ss][hH][eE][lL][lL][Cc][lL][aA][sS][sS][Ii][nN][fF][oO]|[Dd][eE][lL][eE][tT][eE][Oo][nN][Cc][oO][pP][yY]|[Ll][oO][cC][aA][lL][iI][zZ][eE][dD][Ff][iI][lL][eE][Nn][aA][mM][eE][sS])])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(don't load)] (len=14), ["Windows CONTROL.INI"], swap_endian=0
signature file-magic-auto534 {
	file-mime "application/x-wine-extension-ini", 44
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([dD][oO][nN]'[tT] [lL][oO][aA][dD])])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(ndishlp\$|protman\$|NETBEUI\$)] (len=33), ["Windows PROTOCOL.INI"], swap_endian=0
signature file-magic-auto535 {
	file-mime "application/x-wine-extension-ini", 63
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([nN][dD][iI][sS][hH][lL][pP]\$|[pP][rR][oO][tT][mM][aA][nN]\$|[Nn][Ee][Tt][Bb][Ee][Uu][Ii]\$)])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(windows|Compatibility|embedding)] (len=35), ["Windows WIN.INI"], swap_endian=0
signature file-magic-auto536 {
	file-mime "application/x-wine-extension-ini", 65
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([wW][iI][nN][dD][oO][wW][sS]|[Cc][oO][mM][pP][aA][tT][iI][bB][iI][lL][iI][tT][yY]|[eE][mM][bB][eE][dD][dD][iI][nN][gG])])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(boot|386enh|drivers)] (len=23), ["Windows SYSTEM.INI"], swap_endian=0
signature file-magic-auto537 {
	file-mime "application/x-wine-extension-ini", 53
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([bB][oO][oO][tT]|386[eE][nN][hH]|[dD][rR][iI][vV][eE][rR][sS])])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(SafeList)] (len=12), ["Windows IOS.INI"], swap_endian=0
signature file-magic-auto538 {
	file-mime "application/x-wine-extension-ini", 42
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([Ss][aA][fF][eE][Ll][iI][sS][tT])])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(boot loader)] (len=15), ["Windows boot.ini"], swap_endian=0
signature file-magic-auto539 {
	file-mime "application/x-wine-extension-ini", 45
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([bB][oO][oO][tT] [lL][oO][aA][dD][eE][rR])])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  ubequad&ffdfffdfffdfffdf,=24207144355233875 (0x0056004500520053), [""], swap_endian=0
# >>>>&0  ubequad&ffdfffdfffdfffff,=20548012607406173 (0x0049004f004e005d), ["Windows setup INFormation "], swap_endian=0
signature file-magic-auto540 {
	file-mime "application/x-setupscript", 110
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(\x00[\x56\x76]\x00[\x45\x65]\x00[\x52\x72]\x00[\x53\x73])(\x00[\x49\x69]\x00[\x4f\x6f]\x00[\x4e\x6e]\x00\x5d)/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  ubequad&ffdfffdfffdfffdf,=23362783849611337 (0x0053005400520049), [""], swap_endian=0
# >>>>&0  ubequad&ffdfffdfffdfffff,=21955353131548765 (0x004e00470053005d), ["Windows setup INFormation "], swap_endian=0
signature file-magic-auto541 {
	file-mime "application/x-setupscript", 110
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(\x00[\x53\x73]\x00[\x54\x74]\x00[\x52\x72]\x00[\x49\x69)(\x00[\x4e\x6e]\x00[\x47\x67]\x00[\x53\x73]\x00\x5d)/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  default&,x, [""], swap_endian=0
# >>>>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>>>&0  string/c,=version (len=7), ["Windows setup INFormation "], swap_endian=0
signature file-magic-auto542 {
	file-mime "application/x-setupscript", 100
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(.*)(\x5b)([vV][eE][rR][sS][iI][oO][nN])/
}

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  default&,x, [""], swap_endian=0
# >>>>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>>>&0  ubequad&ffdfffdfffdfffdf,=24207144355233875 (0x0056004500520053), [""], swap_endian=0
# >>>>>>&0  ubequad&ffdfffdfffdfffff,=20548012607406173 (0x0049004f004e005d), ["Windows setup INFormation "], swap_endian=0
signature file-magic-auto543 {
	file-mime "application/x-setupscript", 110
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(.*)(\x5b)(\x00[\x56\x76]\x00[\x45\x65]\x00[\x52\x72]\x00[\x53\x73])(\x00[\x49\x69]\x00[\x4f\x6f]\x00[\x4e\x6e]\x00\x5d)/
}

# >0  search/1,=<MakerDictionary (len=16), ["FrameMaker Dictionary text"], swap_endian=0
signature file-magic-auto544 {
	file-mime "application/x-mif", 46
	file-magic /(.*)(\x3cMakerDictionary)/
}

# >0  search/w/1,=#! /usr/bin/wish (len=16), ["Tcl/Tk script text executable"], swap_endian=0
signature file-magic-auto545 {
	file-mime "text/x-tcl", 46
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2fbin\x2fwish)/
}

# >0  search/w/1,=#! /usr/bin/ruby (len=16), ["Ruby script text executable"], swap_endian=0
signature file-magic-auto546 {
	file-mime "text/x-ruby", 46
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2fbin\x2fruby)/
}

# >0  search/w/1,=#! /usr/bin/lua (len=15), ["Lua script text executable"], swap_endian=0
signature file-magic-auto547 {
	file-mime "text/x-lua", 45
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2fbin\x2flua)/
}

# >0  search/w/1,=#! /usr/bin/tcl (len=15), ["Tcl script text executable"], swap_endian=0
signature file-magic-auto548 {
	file-mime "text/x-tcl", 45
	file-magic /(.*)(\x23\x21 ?\x2fusr\x2fbin\x2ftcl)/
}

# >0  search/wct/4096,=<head (len=5), ["HTML document text"], swap_endian=0
signature file-magic-auto549 {
	file-mime "text/html", 45
	file-magic /(.*)(\x3c[hH][eE][aA][dD])/
}

# >0  search/wct/4096,=<html (len=5), ["HTML document text"], swap_endian=0
signature file-magic-auto550 {
	file-mime "text/html", 45
	file-magic /(.*)(\x3c[hH][tT][mM][lL])/
}

# >0  search/w/1,=#!/usr/bin/node (len=15), ["Node.js script text executable"], swap_endian=0
signature file-magic-auto551 {
	file-mime "application/javascript", 45
	file-magic /(.*)(\x23\x21\x2fusr\x2fbin\x2fnode)/
}

# >0  search/wct/1,=<?xml (len=5), ["XML document text"], swap_endian=0
signature file-magic-auto552 {
	file-mime "application/xml", 45
	file-magic /(.*)(\x3c\x3f[xX][mM][lL])/
}

# >0  search/1,=\input texinfo (len=14), ["Texinfo source text"], swap_endian=0
signature file-magic-auto553 {
	file-mime "text/x-texinfo", 44
	file-magic /(.*)(\x5cinput texinfo)/
}

# Not specific enough.
# >0  regex,=^private: (len=9), ["C++ source text"], swap_endian=0
#signature file-magic-auto554 {
#	file-mime "text/x-c++", 44
#	file-magic /(.*)(private:)/
#}

# >0  search/4096,=def __init__ (len=12), [""], swap_endian=0
# >>&0  search/64,=self (len=4), ["Python script text executable"], swap_endian=0
signature file-magic-auto555 {
	file-mime "text/x-python", 38
	file-magic /(.*)(def \x5f\x5finit\x5f\x5f)(.*)(self)/
}

# >0  search/wct/4096,=<a href= (len=8), ["HTML document text"], swap_endian=0
signature file-magic-auto556 {
	file-mime "text/html", 43
	file-magic /(.*)(\x3c[aA] ?[hH][rR][eE][fF]\x3d)/
}

# >0  regex,=^extern[ \t\n]+ (len=13), ["C source text"], swap_endian=0
signature file-magic-auto557 {
	file-mime "text/x-c", 43
	file-magic /(.*)(extern[ \x09\x0a]+)/
}

# >0  search/4096,=% -*-latex-*- (len=13), ["LaTeX document text"], swap_endian=0
signature file-magic-auto558 {
	file-mime "text/x-tex", 43
	file-magic /(.*)(\x25 \x2d\x2a\x2dlatex\x2d\x2a\x2d)/
}

# Doesn't seem specific enough.
# >0  regex,=^double[ \t\n]+ (len=13), ["C source text"], swap_endian=0
#signature file-magic-auto559 {
#	file-mime "text/x-c", 43
#	file-magic /(^double[ \x09\x0a]+)/
#}

# >0  regex,=^struct[ \t\n]+ (len=13), ["C source text"], swap_endian=0
signature file-magic-auto560 {
	file-mime "text/x-c", 43
	file-magic /(.*)(struct[ \x09\x0a]+)/
}

# >0  search/w/1,=#!/bin/nodejs (len=13), ["Node.js script text executable"], swap_endian=0
signature file-magic-auto561 {
	file-mime "application/javascript", 43
	file-magic /(.*)(\x23\x21\x2fbin\x2fnodejs)/
}

# Not specific enough.
# >0  regex,=^public: (len=8), ["C++ source text"], swap_endian=0
#signature file-magic-auto562 {
#	file-mime "text/x-c++", 43
#	file-magic /(.*)(public:)/
#}

# >0  search/wct/4096,=<script (len=7), ["HTML document text"], swap_endian=0
signature file-magic-auto563 {
	file-mime "text/html", 42
	file-magic /(.*)(\x3c[sS][cC][rR][iI][pP][tT])/
}

# Doesn't seem specific enough.
# >0  regex,=^float[ \t\n]+ (len=12), ["C source text"], swap_endian=0
#signature file-magic-auto564 {
#	file-mime "text/x-c", 42
#	file-magic /(^float[ \x09\x0a]+)/
#}

# Doesn't seem specific enough.
# >0  regex,=^union[ \t\n]+ (len=12), ["C source text"], swap_endian=0
#signature file-magic-auto565 {
#	file-mime "text/x-c", 42
#	file-magic /(^union[ \x09\x0a]+)/
#}

# The use of non-sequential offsets and relational operations made the
# autogenerated signature incorrrect.
# >0  belong&,>100 (0x00000064), [""], swap_endian=0
# >>8  belong&,<3 (0x00000003), [""], swap_endian=0
# >>>12  belong&,<33 (0x00000021), [""], swap_endian=0
# >>>>4  belong&,=7 (0x00000007), ["XWD X Window Dump image data"], swap_endian=0
#signature file-magic-auto566 {
#	file-mime "image/x-xwindowdump", 70
#	file-magic /(.{4})(.{4})(.{4})(.{4})(.*)(\x00\x00\x00\x07)/
#}

# >0  search/wct/4096,=<title (len=6), ["HTML document text"], swap_endian=0
signature file-magic-auto567 {
	file-mime "text/html", 41
	file-magic /(.*)(\x3c[tT][iI][tT][lL][eE])/
}

# >0  regex,=^char[ \t\n]+ (len=11), ["C source text"], swap_endian=0
signature file-magic-auto568 {
	file-mime "text/x-c", 41
	file-magic /(.*)(char[ \x09\x0a]+)/
}

# >0  search/1,=#! (len=2), [""], swap_endian=0
# >>0  regex,=^#!.*/bin/perl$ (len=15), ["Perl script text executable"], swap_endian=0
signature file-magic-auto569 {
	file-mime "text/x-perl", 45
	file-magic /(^#!.*\x2fbin\x2fperl$)/
}

# >0  search/w/1,=#!/bin/node (len=11), ["Node.js script text executable"], swap_endian=0
signature file-magic-auto570 {
	file-mime "application/javascript", 41
	file-magic /(.*)(\x23\x21\x2fbin\x2fnode)/
}

# Too much use of bitmasking and relational comparisons and non-sequential
# offsets for this to be autogenerated.  (Also, the depth isn't displayed
# correctly in the debug output below: it reached a depth that exceeded
# the code's ability to display the full amount of '>'s).
# >0  ubelong&0000ffff,<3104 (0x00000c20), [""], swap_endian=0
# >>2  ubyte&,>0x00, [""], swap_endian=0
# >>>3  ubyte&,>0x00, [""], swap_endian=0
# >>>>3  ubyte&,<0x20, [""], swap_endian=0
# >>>>>0  ubyte&,>0x01, [""], swap_endian=0
# >>>>>>27  ubyte&,=0x00, [""], swap_endian=0
# >>>>>>>24  ubelong&ffffffff,<19931137 (0x01302001), [""], swap_endian=0
# >>>>>>>>24  ubelong&ffffffff,=0 (0x00000000), [""], swap_endian=0
# >12  ubelong&fffffefe,=0 (0x00000000), [""], swap_endian=0
# >>28  ubyte&000000f8,=0x00, [""], swap_endian=0
# >>>8  uleshort&,>31 (0x001f), [""], swap_endian=0
# >>>>32  ubyte&,>0x00, [""], swap_endian=0
#signature file-magic-auto571 {
#	file-mime "application/x-dbf", 11
#	file-magic /(.{4})(.*)([\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])([\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])(.*)([\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f])(.*)([\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])(.{26})([\x00])(.*)(.{4})(.*)(.{4})(.*)(.{4})(.{12})([\x00\x01\x02\x03\x04\x05\x06\x07])(.*)(.{2})(.{22})([\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff])/
#}

# >0  search/wct/4096,=<table (len=6), ["HTML document text"], swap_endian=0
signature file-magic-auto572 {
	file-mime "text/html", 41
	file-magic /(.*)(\x3c[tT][aA][bB][lL][eE])/
}

# >0  string/t,=@ (len=1), [""], swap_endian=0
# >>1  string/Wc,= echo off (len=9), ["DOS batch file text"], swap_endian=0
signature file-magic-auto573 {
	file-mime "text/x-msdos-batch", 120
	file-magic /(\x40)( {1,}[eE][cC][hH][oO] {1,}[oO][fF][fF])/
}

# >0  string/t,=@ (len=1), [""], swap_endian=0
# >>1  string/Wc,=echo off (len=8), ["DOS batch file text"], swap_endian=0
signature file-magic-auto574 {
	file-mime "text/x-msdos-batch", 110
	file-magic /(\x40)([eE][cC][hH][oO] {1,}[oO][fF][fF])/
}

# >0  string/t,=@ (len=1), [""], swap_endian=0
# >>1  string/Wc,=rem (len=3), ["DOS batch file text"], swap_endian=0
signature file-magic-auto575 {
	file-mime "text/x-msdos-batch", 60
	file-magic /(\x40)([rR][eE][mM])/
}

# >0  string/t,=@ (len=1), [""], swap_endian=0
# >>1  string/Wc,=set  (len=4), ["DOS batch file text"], swap_endian=0
signature file-magic-auto576 {
	file-mime "text/x-msdos-batch", 70
	file-magic /(\x40)([sS][eE][tT] {1,})/
}

# >0  search/wct/4096,=<style (len=6), ["HTML document text"], swap_endian=0
signature file-magic-auto577 {
	file-mime "text/html", 41
	file-magic /(.*)(\x3c[sS][tT][yY][lL][eE])/
}

# >0  regex,=^dnl  (len=5), ["M4 macro processor script text"], swap_endian=0
signature file-magic-auto578 {
	file-mime "text/x-m4", 40
	file-magic /(^dnl )/
}

# >0  regex,=^all: (len=5), ["makefile script text"], swap_endian=0
signature file-magic-auto579 {
	file-mime "text/x-makefile", 40
	file-magic /(^all:)/
}

# >0  regex,=^.PRECIOUS (len=10), ["makefile script text"], swap_endian=0
signature file-magic-auto580 {
	file-mime "text/x-makefile", 40
	file-magic /(^.PRECIOUS)/
}

# >0  search/8192,=main( (len=5), ["C source text"], swap_endian=0
signature file-magic-auto581 {
	file-mime "text/x-c", 40
	file-magic /(.*)(main\x28)/
}

# Not specific enough.
# >0  search/1,=\" (len=2), ["troff or preprocessor input text"], swap_endian=0
#signature file-magic-auto582 {
#	file-mime "text/troff", 40
#	file-magic /(.*)(\x5c\x22)/
#}

# >0  search/4096,=(defparam  (len=10), ["Lisp/Scheme program text"], swap_endian=0
signature file-magic-auto583 {
	file-mime "text/x-lisp", 40
	file-magic /(.*)(\x28defparam )/
}

# >0  search/4096,=(autoload  (len=10), ["Lisp/Scheme program text"], swap_endian=0
signature file-magic-auto584 {
	file-mime "text/x-lisp", 40
	file-magic /(.*)(\x28autoload )/
}

#This signature seems too generic.
# >0  search/1,=diff  (len=5), ["diff output text"], swap_endian=0
#signature file-magic-auto585 {
#	file-mime "text/x-diff", 40
#	file-magic /(.*)(diff )/
#}

# >0  regex,=^#include (len=9), ["C source text"], swap_endian=0
signature file-magic-auto586 {
	file-mime "text/x-c", 39
	file-magic /(.*)(#include)/
}

# >0  search/1,=.\" (len=3), ["troff or preprocessor input text"], swap_endian=0
signature file-magic-auto587 {
	file-mime "text/troff", 39
	file-magic /(.*)(\x2e\x5c\x22)/
}

# >0  search/1,='\" (len=3), ["troff or preprocessor input text"], swap_endian=0
signature file-magic-auto588 {
	file-mime "text/troff", 39
	file-magic /(.*)(\x27\x5c\x22)/
}

# >0  search/1,=<TeXmacs| (len=9), ["TeXmacs document text"], swap_endian=0
signature file-magic-auto589 {
	file-mime "text/texmacs", 39
	file-magic /(.*)(\x3cTeXmacs\x7c)/
}

# >0  search/1,=/* XPM */ (len=9), ["X pixmap image text"], swap_endian=0
signature file-magic-auto590 {
	file-mime "image/x-xpmi", 39
	file-magic /(.*)(\x2f\x2a XPM \x2a\x2f)/
}

# >0  search/1,=<?\n (len=3), ["PHP script text"], swap_endian=0
signature file-magic-auto591 {
	file-mime "text/x-php", 39
	file-magic /(.*)(\x3c\x3f\x0a)/
}

# >0  search/1,=<?\r (len=3), ["PHP script text"], swap_endian=0
signature file-magic-auto592 {
	file-mime "text/x-php", 39
	file-magic /(.*)(\x3c\x3f\x0d)/
}

# >0  search/1,=''' (len=3), ["troff or preprocessor input text"], swap_endian=0
signature file-magic-auto593 {
	file-mime "text/troff", 39
	file-magic /(.*)(\x27\x27\x27)/
}

# >0  search/4096,=try: (len=4), [""], swap_endian=0
# >>&0  regex,=^\s*except.*: (len=13), ["Python script text executable"], swap_endian=0
signature file-magic-auto594 {
	file-mime "text/x-python", 43
	file-magic /(.*)(try\x3a)(^\s*except.*:)/
}

# >0  search/4096,=try: (len=4), [""], swap_endian=0
# >>&0  search/4096,=finally: (len=8), ["Python script text executable"], swap_endian=0
signature file-magic-auto595 {
	file-mime "text/x-python", 38
	file-magic /(.*)(try\x3a)(.*)(finally\x3a)/
}

# >0  search/8192,="LIBHDR" (len=8), ["BCPL source text"], swap_endian=0
signature file-magic-auto596 {
	file-mime "text/x-bcpl", 38
	file-magic /(.*)(\x22LIBHDR\x22)/
}

# >0  regex,=^SUBDIRS (len=8), ["automake makefile script text"], swap_endian=0
signature file-magic-auto597 {
	file-mime "text/x-makefile", 38
	file-magic /(.*)(SUBDIRS)/
}

# >0  search/4096,=(defvar  (len=8), ["Lisp/Scheme program text"], swap_endian=0
signature file-magic-auto598 {
	file-mime "text/x-lisp", 38
	file-magic /(.*)(\x28defvar )/
}

# Not specific enough.
# >0  regex,=^program (len=8), ["Pascal source text"], swap_endian=0
#signature file-magic-auto599 {
#	file-mime "text/x-pascal", 38
#	file-magic /(^program)/
#}

# >0  search/1,=Only in  (len=8), ["diff output text"], swap_endian=0
signature file-magic-auto600 {
	file-mime "text/x-diff", 38
	file-magic /(.*)(Only in )/
}

# This signature doesn't seem specific enough.
# >0  search/1,=***  (len=4), ["diff output text"], swap_endian=0
#signature file-magic-auto601 {
#	file-mime "text/x-diff", 38
#	file-magic /(.*)(\x2a\x2a\x2a )/
#}

# >0  search/1,='.\" (len=4), ["troff or preprocessor input text"], swap_endian=0
signature file-magic-auto602 {
	file-mime "text/troff", 38
	file-magic /(.*)(\x27\x2e\x5c\x22)/
}

# LDFLAGS appears in other contexts, e.g. shell script.
# >0  regex,=^LDFLAGS (len=8), ["makefile script text"], swap_endian=0
#signature file-magic-auto603 {
#	file-mime "text/x-makefile", 38
#	file-magic /(.*)(LDFLAGS)/
#}

# >0  search/8192,="libhdr" (len=8), ["BCPL source text"], swap_endian=0
signature file-magic-auto604 {
	file-mime "text/x-bcpl", 38
	file-magic /(.*)(\x22libhdr\x22)/
}

# Not specific enough.
# >0  regex,=^record (len=7), ["Pascal source text"], swap_endian=0
#signature file-magic-auto605 {
#	file-mime "text/x-pascal", 37
#	file-magic /(^record)/
#}

# >0  regex,=^CFLAGS (len=7), ["makefile script text"], swap_endian=0
signature file-magic-auto606 {
	file-mime "text/x-makefile", 37
	file-magic /(.*)(CFLAGS)/
}

# >0  search/4096,=(defun  (len=7), ["Lisp/Scheme program text"], swap_endian=0
signature file-magic-auto607 {
	file-mime "text/x-lisp", 37
	file-magic /(.*)(\x28defun )/
}

# >0  regex,=^msgid  (len=7), ["GNU gettext message catalogue text"], swap_endian=0
signature file-magic-auto608 {
	file-mime "text/x-po", 37
	file-magic /(^msgid )/
}

# >0  search/8192,=(input, (len=7), ["Pascal source text"], swap_endian=0
signature file-magic-auto609 {
	file-mime "text/x-pascal", 37
	file-magic /(.*)(\x28input\x2c)/
}

# Not specific enough.
# >0  search/1,=Index: (len=6), ["RCS/CVS diff output text"], swap_endian=0
#signature file-magic-auto610 {
#	file-mime "text/x-diff", 44
#	file-magic /(.*)(Index\x3a)/
#}

# >0  search/4096,=(setq  (len=6), ["Lisp/Scheme program text"], swap_endian=0
signature file-magic-auto611 {
	file-mime "text/x-lisp", 36
	file-magic /(.*)(\x28setq )/
}

# >0  regex/100,=^[Cc][ \t] (len=9), ["FORTRAN program"], swap_endian=0
signature file-magic-auto612 {
	file-mime "text/x-fortran", 34
	file-magic /(^[Cc][ \x09])/
}

# >0  search/wt/1,=<?XML (len=5), ["broken XML document text"], swap_endian=0
signature file-magic-auto613 {
	file-mime "application/xml", 30
	file-magic /(.*)(\x3c\x3fXML)/
}

# >0  search/wtb/1,=<?xml (len=5), ["XML document text"], swap_endian=0
signature file-magic-auto614 {
	file-mime "application/xml", 30
	file-magic /(.*)(\x3c\x3fxml)/
}

# >0  regex,^import.*;$ (len=10), ["Java source"], swap_endian=0
signature file-magic-auto615 {
	file-mime "text/x-java", 20
	file-magic /(import.*;$)/
}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x01, ["LSB"], swap_endian=0
# >>>16  leshort&,=0 (0x0000), ["no file type,"], swap_endian=0
#signature file-magic-auto616 {
#	file-mime "application/octet-stream", 50
#	file-magic /(\x7fELF)(.{1})([\x01])(.{10})(\x00\x00)/
#}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x02, ["MSB"], swap_endian=0
# >>>16  leshort&,=0 (0x0000), ["no file type,"], swap_endian=1
#signature file-magic-auto617 {
#	file-mime "application/octet-stream", 50
#	file-magic /(\x7fELF)(.{1})([\x02])(.{10})(\x00\x00)/
#}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x01, ["LSB"], swap_endian=0
# >>>16  leshort&,=1 (0x0001), ["relocatable,"], swap_endian=0
signature file-magic-auto618 {
	file-mime "application/x-object", 50
	file-magic /(\x7fELF)([\x01\x02])([\x01])(.{10})(\x01\x00)/
}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x02, ["MSB"], swap_endian=0
# >>>16  leshort&,=1 (0x0001), ["relocatable,"], swap_endian=1
signature file-magic-auto619 {
	file-mime "application/x-object", 50
	file-magic /(\x7fELF)([\x01\x02])([\x02])(.{10})(\x00\x01)/
}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x01, ["LSB"], swap_endian=0
# >>>16  leshort&,=2 (0x0002), ["executable,"], swap_endian=0
signature file-magic-auto620 {
	file-mime "application/x-executable", 50
	file-magic /(\x7fELF)([\x01\x02])([\x01])(.{10})(\x02\x00)/
}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x02, ["MSB"], swap_endian=0
# >>>16  leshort&,=2 (0x0002), ["executable,"], swap_endian=1
signature file-magic-auto621 {
	file-mime "application/x-executable", 50
	file-magic /(\x7fELF)([\x01\x02])([\x02])(.{10})(\x00\x02)/
}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x01, ["LSB"], swap_endian=0
# >>>16  leshort&,=3 (0x0003), ["shared object,"], swap_endian=0
signature file-magic-auto622 {
	file-mime "application/x-sharedlib", 50
	file-magic /(\x7fELF)([\x01\x02])([\x01])(.{10})(\x03\x00)/
}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x02, ["MSB"], swap_endian=0
# >>>16  leshort&,=3 (0x0003), ["shared object,"], swap_endian=1
signature file-magic-auto623 {
	file-mime "application/x-sharedlib", 50
	file-magic /(\x7fELF)([\x01\x02])([\x02])(.{10})(\x00\x03)/
}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x01, ["LSB"], swap_endian=0
# >>>16  leshort&,=4 (0x0004), ["core file"], swap_endian=0
signature file-magic-auto624 {
	file-mime "application/x-coredump", 50
	file-magic /(\x7fELF)([\x01\x02])([\x01])(.{10})(\x04\x00)/
}

# >0  string,=\177ELF (len=4), ["ELF"], swap_endian=0
# >>5  byte&,=0x02, ["MSB"], swap_endian=0
# >>>16  leshort&,=4 (0x0004), ["core file"], swap_endian=1
signature file-magic-auto625 {
	file-mime "application/x-coredump", 50
	file-magic /(\x7fELF)([\x01\x02])([\x02])(.{10})(\x00\x04)/
}

