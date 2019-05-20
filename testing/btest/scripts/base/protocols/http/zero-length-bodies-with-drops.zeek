# This tests an issue with interaction between zero length
# http bodies and the file analysis code.  It is creating
# files when there isn't actually any body there and shouldn't
# create a file.
#
# @TEST-EXEC: zeek -r $TRACES/http/zero-length-bodies-with-drops.pcap %INPUT

# There shouldn't be a files log (no files!)
# @TEST-EXEC: test ! -f files.log

