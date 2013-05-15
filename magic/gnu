# See COPYING file in this directory for original libmagic copyright.
#------------------------------------------------------------------------------
# $File: gnu,v 1.13 2012/01/03 17:16:54 christos Exp $
# gnu:  file(1) magic for various GNU tools
#
# GNU nlsutils message catalog file format
#
# GNU message catalog (.mo and .gmo files)

# GnuPG
# The format is very similar to pgp
# Note: magic.mime had 0x8501 for the next line instead of 0x8502
0	beshort		0x8502			GPG encrypted data
!:mime	text/PGP # encoding: data

# This magic is not particularly good, as the keyrings don't have true
# magic. Nevertheless, it covers many keyrings.
0       beshort         0x9901                  GPG key public ring
!:mime	application/x-gnupg-keyring

# gettext message catalogue
0	regex	\^msgid\ 		GNU gettext message catalogue text
!:mime text/x-po
