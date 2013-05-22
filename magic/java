# See COPYING file in this directory for original libmagic copyright.
#------------------------------------------------------------
# $File: java,v 1.13 2011/12/08 12:12:46 rrt Exp $
# Java ByteCode and Mach-O binaries (e.g., Mac OS X) use the
# same magic number, 0xcafebabe, so they are both handled
# in the entry called "cafebabe".
#------------------------------------------------------------

0	belong		0xfeedfeed	Java KeyStore
!:mime	application/x-java-keystore
0	belong		0xcececece	Java JCE KeyStore
!:mime	application/x-java-jce-keystore

# Java source
0	regex	^import.*;$	Java source
!:mime	text/x-java
