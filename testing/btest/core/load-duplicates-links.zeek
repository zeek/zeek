# This tests Zeek's mechanism to prevent duplicate script loading on links.
#
# @TEST-EXEC: mkdir foo
# @TEST-EXEC: mkdir bar
# @TEST-EXEC: mkdir baz

# @TEST-EXEC: echo 'event zeek_init() &priority=3 { print "foo"; }' >foo/main.zeek
# @TEST-EXEC: echo 'event zeek_init() &priority=2 { print "bar"; }' >bar/main.zeek
# @TEST-EXEC: echo 'event zeek_init() &priority=1 { print "baz"; }' >baz/main.zeek

# @TEST-EXEC: echo "@load ./main" >common-load.zeek
# @TEST-EXEC: ln common-load.zeek foo/__load__.zeek
# @TEST-EXEC: ln common-load.zeek bar/__load__.zeek

# @TEST-EXEC: echo "@load ./main" >baz/__load__.zeek
# @TEST-EXEC: echo "@load ./main-sym" >>baz/__load__.zeek
# @TEST-EXEC: (cd baz && ln -s main.zeek main-sym.zeek)

# @TEST-EXEC: zeek -b foo bar baz foo/../foo bar/../bar baz/../baz $(pwd)/foo $(pwd)/bar $(pwd)/baz >out
# @TEST-EXEC: btest-diff out
