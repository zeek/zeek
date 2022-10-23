# These signatures were semi-automatically generated from libmagic's
# (~ v5.17) magic database rules that have an associated mime type.
# After generating, they were all manually reviewed and occassionally
# needed minor modifications by hand or were just ommited depending on
# the complexity of the original magic rules.
#
# The instrumented version of the `file` command used to generate these
# is located at: https://github.com/jsiwek/file/tree/bro-signatures.

# >2  string,=---BEGIN PGP PUBLIC KEY BLOCK- (len=30), ["PGP public key block"], swap_endian=0
signature file-magic-auto1 {
	file-mime "application/pgp-keys", 330
	file-magic /(.{2})(\x2d\x2d\x2dBEGIN PGP PUBLIC KEY BLOCK\x2d)/
}

# >11  string,=must be converted with BinHex (len=29), ["BinHex binary text"], swap_endian=0
signature file-magic-auto3 {
	file-mime "application/mac-binhex40", 320
	file-magic /(.{11})(must be converted with BinHex)/
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

# >0  string,=# PaCkAgE DaTaStReAm (len=20), ["pkg Datastream (SVR4)"], swap_endian=0
signature file-magic-auto19 {
	file-mime "application/x-svr4-package", 230
	file-magic /(\x23 PaCkAgE DaTaStReAm)/
}

# >0  string/t,=[KDE Desktop Entry] (len=19), ["KDE desktop entry"], swap_endian=0
signature file-magic-auto21 {
	file-mime "application/x-kdelnk", 220
	file-magic /(\x5bKDE Desktop Entry\x5d)/
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

# >369  string,=MICROSOFT PIFEX\000 (len=16), ["Windows Program Information File"], swap_endian=0
signature file-magic-auto32 {
	file-mime "application/x-dosexec", 190
	file-magic /(.{369})(MICROSOFT PIFEX\x00)/
}

# >0  string/w,=#VRML V1.0 ascii (len=16), ["VRML 1 file"], swap_endian=0
signature file-magic-auto34 {
	file-mime "model/vrml", 190
	file-magic /(\x23VRML ?V1\x2e0 ?ascii)/
}

# >0  string,=Extended Module: (len=16), ["Fasttracker II module sound data"], swap_endian=0
signature file-magic-auto36 {
	file-mime "audio/x-mod", 190
	file-magic /(Extended Module\x3a)/
}

# >0  string/t,=<?xml version=" (len=15), [""], swap_endian=0
# >>20  search/wc/1000,=<!DOCTYPE X3D (len=13), ["X3D (Extensible 3D) model xml text"], swap_endian=0
signature file-magic-auto40 {
	file-mime "model/x3d", 43
	file-magic /(\x3c\x3fxml version\x3d\x22)(.{5})(.*)(\x3c\x21DOCTYPE ?X3D)/
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

# >0  string/c,=BEGIN:VCALENDAR (len=15), ["vCalendar calendar file"], swap_endian=0
signature file-magic-auto47 {
	file-mime "text/calendar", 180
	file-magic /(BEGIN\x3aVCALENDAR)/
}

# >0  string/w,=#VRML V2.0 utf8 (len=15), ["ISO/IEC 14772 VRML 97 file"], swap_endian=0
signature file-magic-auto50 {
	file-mime "model/vrml", 180
	file-magic /(\x23VRML ?V2\x2e0 ?utf8)/
}

# >0  string,=MAS_UTrack_V00 (len=14), [""], swap_endian=0
# >>14  string,>/0 (len=2), ["ultratracker V1.%.1s module sound data"], swap_endian=0
signature file-magic-auto53 {
	file-mime "audio/x-mod", 20
	file-magic /(MAS\x5fUTrack\x5fV00)(\x2f0)/
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


# >0  string/w,=<map version (len=12), ["Freemind document"], swap_endian=0
signature file-magic-auto70 {
	file-mime "application/x-freemind", 150
	file-magic /(\x3cmap ?version)/
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

# >0  string,=<BookFile (len=9), ["FrameMaker Book file"], swap_endian=0
signature file-magic-auto90 {
	file-mime "application/x-mif", 120
	file-magic /(\x3cBookFile)/
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

# >0  string/t,=#! rnews (len=8), ["batched news text"], swap_endian=0
signature file-magic-auto99 {
	file-mime "message/rfc822", 110
	file-magic /(\x23\x21 rnews)/
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

# >0  string,=\211HDF\r\n\032\n (len=8), ["Hierarchical Data Format (version 5) data"], swap_endian=0
signature file-magic-auto109 {
	file-mime "application/x-hdf", 110
	file-magic /(\x89HDF\x0d\x0a\x1a\x0a)/
}

# Find a way to do the following to generically detect ICC profiles.
# An ICC parser should deal with the difference in these formats.
## >36  string,=acspSUNW (len=8), ["Sun KCMS ICC Profile"], swap_endian=0
#signature file-magic-auto111 {
#	file-mime "application/vnd.iccprofile", 110
#	file-magic /(.{36})(acspSUNW)/
#}
#
## >36  string,=acspSGI  (len=8), ["SGI ICC Profile"], swap_endian=0
#signature file-magic-auto112 {
#	file-mime "application/vnd.iccprofile", 110
#	file-magic /(.{36})(acspSGI )/
#}
#
## >36  string,=acspMSFT (len=8), ["Microsoft ICM Color Profile"], swap_endian=0
#signature file-magic-auto113 {
#	file-mime "application/vnd.iccprofile", 110
#	file-magic /(.{36})(acspMSFT)/
#}
#
## >36  string,=acspAPPL (len=8), ["ColorSync ICC Profile"], swap_endian=0
#signature file-magic-auto114 {
#	file-mime "application/vnd.iccprofile", 110
#	file-magic /(.{36})(acspAPPL)/
#}
#
## >36  string,=acsp (len=4), ["ICC Profile"], swap_endian=0
#signature file-magic-auto277 {
#	file-mime "application/vnd.iccprofile", 70
#	file-magic /(.{36})(acsp)/
#}


# >512  string,=R\000o\000o\000t\000 (len=8), ["Hangul (Korean) Word Processor File 2000"], swap_endian=0
#signature file-magic-auto116 {
#	file-mime "application/x-hwp", 110
#	file-magic /(.{512})(R\x00o\x00o\x00t\x00)/
#}

# >0  string,=<MIFFile (len=8), ["FrameMaker MIF (ASCII) file"], swap_endian=0
signature file-magic-auto118 {
	file-mime "application/x-mif", 110
	file-magic /(\x3cMIFFile)/
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

# >0  string,=<Maker (len=6), ["Intermediate Print File	FrameMaker IPL file"], swap_endian=0
signature file-magic-auto152 {
	file-mime "application/x-mif", 90
	file-magic /(\x3cMaker)/
}

# >0  string/t,=# xmcd (len=6), ["xmcd database file for kscd"], swap_endian=0
signature file-magic-auto155 {
	file-mime "text/x-xmcd", 90
	file-magic /(\x23 xmcd)/
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

# >0  string,=%PDF- (len=5), ["PDF document"], swap_endian=0
signature file-magic-auto189 {
	file-mime "application/pdf", 80
	file-magic /(\x25PDF\x2d)/
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

# >0  string,={\rtf (len=5), ["Rich Text Format data,"], swap_endian=0
signature file-magic-auto196 {
	file-mime "text/rtf", 80
	file-magic /(\x7b\x5crtf)/
}

# >0  string,=%FDF- (len=5), ["FDF document"], swap_endian=0
signature file-magic-auto203 {
	file-mime "application/vnd.fdf", 80
	file-magic /(\x25FDF\x2d)/
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

# Converting bitmask to character class might make the regex
# unfriendly to humans.
# >0  belong&ffffffffff5fff10,=1195376656 (0x47400010), [""], swap_endian=0
#signature file-magic-auto210 {
#	file-mime "video/mp2t", 71
#	file-magic /(.{4})/
#}

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
# >>>50  string,=epub+zip (len=8), ["EPUB document"], swap_endian=0
signature file-magic-auto245 {
	file-mime "application/epub+zip", 110
	file-magic /(PK\x03\x04)(.{22})(\x08\x00\x00\x00mimetypeapplication\x2f)(epub\x2bzip)/
}


# >4  string,=idsc (len=4), ["Apple QuickTime image (fast start)"], swap_endian=0
signature file-magic-auto255 {
	file-mime "image/x-quicktime", 70
	file-magic /....(idsc)/
}

# >4  string,=pckg (len=4), ["Apple QuickTime compressed archive"], swap_endian=0
signature file-magic-auto256 {
	file-mime "application/x-quicktime-player", 70
	file-magic /....(pckg)/
}


# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string/W,=M4A (len=3), [", MPEG v4 system, iTunes AAC-LC"], swap_endian=0
signature file-magic-auto268 {
	file-mime "audio/mp4", 60
	file-magic /....(ftyp)(M4A)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string/W,=M4V (len=3), [", MPEG v4 system, iTunes AVC-LC"], swap_endian=0
signature file-magic-auto269 {
	file-mime "video/mp4", 60
	file-magic /....(ftyp)(M4V)/
}

# >4  string,=ftyp (len=4), ["ISO Media"], swap_endian=0
# >>8  string/W,=qt (len=2), [", Apple QuickTime movie"], swap_endian=0
signature file-magic-auto270 {
	file-mime "video/quicktime", 50
	file-magic /....(ftyp)(qt)/
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


# >0  string,=MAC  (len=4), ["Monkey's Audio compressed format"], swap_endian=0
signature file-magic-auto276 {
	file-mime "audio/x-ape", 70
	file-magic /(MAC )/
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

# >128  string,=DICM (len=4), ["DICOM medical imaging data"], swap_endian=0
signature file-magic-auto288 {
	file-mime "application/dicom", 70
	file-magic /(.{128})(DICM)/
}

# >0  string,=IMPM (len=4), ["Impulse Tracker module sound data -"], swap_endian=0
signature file-magic-auto290 {
	file-mime "audio/x-mod", 70
	file-magic /(IMPM)/
}

# >0  belong&,=235082497 (0x0e031301), ["Hierarchical Data Format (version 4) data"], swap_endian=0
signature file-magic-auto293 {
	file-mime "application/x-hdf", 70
	file-magic /(\x0e\x03\x13\x01)/
}

## >1080  string,=32CN (len=4), ["32-channel Taketracker module sound data"], swap_endian=0
#signature file-magic-auto304 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(32CN)/
#}
#
## >1080  string,=16CN (len=4), ["16-channel Taketracker module sound data"], swap_endian=0
#signature file-magic-auto305 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(16CN)/
#}
#
## >1080  string,=OKTA (len=4), ["8-channel Octalyzer module sound data"], swap_endian=0
#signature file-magic-auto306 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(OKTA)/
#}
#
## >1080  string,=CD81 (len=4), ["8-channel Octalyser module sound data"], swap_endian=0
#signature file-magic-auto307 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(CD81)/
#}
#
## >1080  string,=8CHN (len=4), ["8-channel Fasttracker module sound data"], swap_endian=0
#signature file-magic-auto308 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(8CHN)/
#}
#
## >1080  string,=6CHN (len=4), ["6-channel Fasttracker module sound data"], swap_endian=0
#signature file-magic-auto309 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(6CHN)/
#}
#
## >1080  string,=4CHN (len=4), ["4-channel Fasttracker module sound data"], swap_endian=0
#signature file-magic-auto310 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(4CHN)/
#}
#
## >1080  string,=FLT8 (len=4), ["8-channel Startracker module sound data"], swap_endian=0
#signature file-magic-auto311 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(FLT8)/
#}
#
## >1080  string,=FLT4 (len=4), ["4-channel Startracker module sound data"], swap_endian=0
#signature file-magic-auto312 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(FLT4)/
#}
#
## >1080  string,=M!K! (len=4), ["4-channel Protracker module sound data"], swap_endian=0
#signature file-magic-auto313 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(M\x21K\x21)/
#}
#
## >1080  string,=M.K. (len=4), ["4-channel Protracker module sound data"], swap_endian=0
#signature file-magic-auto314 {
#	file-mime "audio/x-mod", 70
#	file-magic /(.{1080})(M\x2eK\x2e)/
#}

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

# >0  string,=RIFF (len=4), ["RIFF (little-endian) data"], swap_endian=0
# >>8  string,=WAVE (len=4), [", WAVE audio"], swap_endian=0
signature file-magic-auto354 {
	file-mime "audio/x-wav", 70
	file-magic /(RIFF)(.{4})(WAVE)/
}

# >0  string,=RIFF (len=4), ["RIFF (little-endian) data"], swap_endian=0
# >>8  string,=AVI  (len=4), [", AVI"], swap_endian=0
signature file-magic-auto357 {
	file-mime "video/x-msvideo", 70
	file-magic /(RIFF)(.{4})(AVI )/
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

# >0  string,=<MML (len=4), ["FrameMaker MML file"], swap_endian=0
signature file-magic-auto381 {
	file-mime "application/x-mif", 70
	file-magic /(\x3cMML)/
}

# >0  string,=OggS (len=4), ["Ogg data"], swap_endian=0
signature file-magic-auto385 {
	file-mime "application/ogg", 70
	file-magic /(OggS)/
}

## >0  search/4096,=\documentstyle (len=14), ["LaTeX document text"], swap_endian=0
#signature file-magic-auto390 {
#	file-mime "text/x-tex", 62
#	file-magic /(.*)(\x5cdocumentstyle)/
#}

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

# >0  string,=MP+ (len=3), ["Musepack audio"], swap_endian=0
signature file-magic-auto401 {
	file-mime "audio/x-musepack", 60
	file-magic /(MP\x2b)/
}

# >0  string,=\004%! (len=3), ["PostScript document text"], swap_endian=0
signature file-magic-auto405 {
	file-mime "application/postscript", 60
	file-magic /(\x04\x25\x21)/
}

## >0  search/4096,=\documentclass (len=14), ["LaTeX 2e document text"], swap_endian=0
#signature file-magic-auto412 {
#	file-mime "text/x-tex", 59
#	file-magic /(.*)(\x5cdocumentclass)/
#}
#
## >0  search/4096,=\contentsline (len=13), ["LaTeX table of contents"], swap_endian=0
#signature file-magic-auto414 {
#	file-mime "text/x-tex", 58
#	file-magic /(.*)(\x5ccontentsline)/
#}
#
## >0  search/4096,=\chapter (len=8), ["LaTeX document text"], swap_endian=0
#signature file-magic-auto415 {
#	file-mime "text/x-tex", 56
#	file-magic /(.*)(\x5cchapter)/
#}
#
## >0  search/4096,=\section (len=8), ["LaTeX document text"], swap_endian=0
#signature file-magic-auto416 {
#	file-mime "text/x-tex", 56
#	file-magic /(.*)(\x5csection)/
#}
#
## >0  search/4096,=\setlength (len=10), ["LaTeX document text"], swap_endian=0
#signature file-magic-auto419 {
#	file-mime "text/x-tex", 55
#	file-magic /(.*)(\x5csetlength)/
#}
#
## >0  search/1,=Common subdirectories:  (len=23), ["diff output text"], swap_endian=0
#signature file-magic-auto422 {
#	file-mime "text/x-diff", 53
#	file-magic /(.*)(Common subdirectories\x3a )/
#}
#
## >0  search/4096,=(custom-set-variables  (len=22), ["Lisp/Scheme program text"], swap_endian=0
#signature file-magic-auto426 {
#	file-mime "text/x-lisp", 52
#	file-magic /(.*)(\x28custom\x2dset\x2dvariables )/
#}

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

## >0  search/4096,=\relax (len=6), ["LaTeX auxiliary file"], swap_endian=0
#signature file-magic-auto463 {
#	file-mime "text/x-tex", 51
#	file-magic /(.*)(\x5crelax)/
#}
#
## >0  search/4096,=\begin (len=6), ["LaTeX document text"], swap_endian=0
#signature file-magic-auto464 {
#	file-mime "text/x-tex", 51
#	file-magic /.*\x5c(input|begin)/
#}

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

# >0  beshort&,=-31486 (0x8502), ["GPG encrypted data"], swap_endian=0
signature file-magic-auto496 {
	file-mime "text/PGP", 50
	file-magic /(\x85\x02)/
}

# >0  beshort&,=2935 (0x0b77), ["ATSC A/52 aka AC-3 aka Dolby Digital stream,"], swap_endian=0
signature file-magic-auto507 {
	file-mime "audio/vnd.dolby.dd-raw", 50
	file-magic /(\x0b\x77)/
}

## >0  search/1,=This is Info file (len=17), ["GNU Info text"], swap_endian=0
#signature file-magic-auto528 {
#	file-mime "text/x-info", 47
#	file-magic /(.*)(This is Info file)/
#}

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

# >0  regex/s,=\`(\r\n|;|[[]|\377\376) (len=15), [""], swap_endian=0
# >>&0  search/8192,=[ (len=1), [""], swap_endian=0
# >>>&0  regex/c,=^(WinsockCRCList|OEMCPL)] (len=25), ["Windows setup INFormation"], swap_endian=0
signature file-magic-auto532 {
	file-mime "text/inf", 55
	file-magic /(\`(\x0d\x0a|;|[[]|\xff\xfe))(.*)(\x5b)(^([Ww][iI][nN][sS][oO][cC][kK][Cc][Rr][Cc][Ll][iI][sS][tT]|[Oo][Ee][Mm][Cc][Pp][Ll])])/
}

## >0  search/1,=<MakerDictionary (len=16), ["FrameMaker Dictionary text"], swap_endian=0
#signature file-magic-auto544 {
#	file-mime "application/x-mif", 46
#	file-magic /(.*)(\x3cMakerDictionary)/
#}

## >0  search/4096,=% -*-latex-*- (len=13), ["LaTeX document text"], swap_endian=0
#signature file-magic-auto558 {
#	file-mime "text/x-tex", 43
#	file-magic /(.*)(\x25 \x2d\x2a\x2dlatex\x2d\x2a\x2d)/
#}

# The use of non-sequential offsets and relational operations made the
# autogenerated signature incorrect.
# >0  belong&,>100 (0x00000064), [""], swap_endian=0
# >>8  belong&,<3 (0x00000003), [""], swap_endian=0
# >>>12  belong&,<33 (0x00000021), [""], swap_endian=0
# >>>>4  belong&,=7 (0x00000007), ["XWD X Window Dump image data"], swap_endian=0
#signature file-magic-auto566 {
#	file-mime "image/x-xwindowdump", 70
#	file-magic /(.{4})(.{4})(.{4})(.{4})(.*)(\x00\x00\x00\x07)/
#}

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


## >0  search/4096,=(defparam  (len=10), ["Lisp/Scheme program text"], swap_endian=0
#signature file-magic-auto583 {
#	file-mime "text/x-lisp", 40
#	file-magic /(.*)(\x28defparam )/
#}
#
## >0  search/4096,=(autoload  (len=10), ["Lisp/Scheme program text"], swap_endian=0
#signature file-magic-auto584 {
#	file-mime "text/x-lisp", 40
#	file-magic /(.*)(\x28autoload )/
#}
#
## >0  search/1,=<TeXmacs| (len=9), ["TeXmacs document text"], swap_endian=0
#signature file-magic-auto589 {
#	file-mime "text/texmacs", 39
#	file-magic /(.*)(\x3cTeXmacs\x7c)/
#}
#
## >0  search/1,=/* XPM */ (len=9), ["X pixmap image text"], swap_endian=0
#signature file-magic-auto590 {
#	file-mime "image/x-xpmi", 39
#	file-magic /(.*)(\x2f\x2a XPM \x2a\x2f)/
#}
#
## >0  search/8192,="LIBHDR" (len=8), ["BCPL source text"], swap_endian=0
#signature file-magic-auto596 {
#	file-mime "text/x-bcpl", 38
#	file-magic /(.*)(\x22LIBHDR\x22)/
#}
#
## >0  search/4096,=(defvar  (len=8), ["Lisp/Scheme program text"], swap_endian=0
#signature file-magic-auto598 {
#	file-mime "text/x-lisp", 38
#	file-magic /(.*)(\x28defvar )/
#}
#
## >0  search/1,=Only in  (len=8), ["diff output text"], swap_endian=0
#signature file-magic-auto600 {
#	file-mime "text/x-diff", 38
#	file-magic /(.*)(Only in )/
#}
#
## >0  search/8192,="libhdr" (len=8), ["BCPL source text"], swap_endian=0
#signature file-magic-auto604 {
#	file-mime "text/x-bcpl", 38
#	file-magic /(.*)(\x22libhdr\x22)/
#}
#
## >0  search/4096,=(defun  (len=7), ["Lisp/Scheme program text"], swap_endian=0
#signature file-magic-auto607 {
#	file-mime "text/x-lisp", 37
#	file-magic /(.*)(\x28defun )/
#}

# >0  regex,=^msgid  (len=7), ["GNU gettext message catalogue text"], swap_endian=0
signature file-magic-auto608 {
	file-mime "text/x-po", 37
	file-magic /(^msgid )/
}

# >0  search/4096,=(setq  (len=6), ["Lisp/Scheme program text"], swap_endian=0
#signature file-magic-auto611 {
#	file-mime "text/x-lisp", 36
#	file-magic /(.*)(\x28setq )/
#}
