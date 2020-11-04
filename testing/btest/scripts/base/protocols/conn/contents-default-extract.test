# @TEST-EXEC: zeek -b -f "tcp port 21" -r $TRACES/ftp/ipv6.trace base/protocols/conn "Conn::default_extract=T"

# Note: files renamed to remove colons due to Windows filesystem limitations.
# Allows one to clone the source tree on Windows for now.  For real Windows
# runtime compatibility, the original filenames will need a different format.

# @TEST-EXEC: mv contents_[2001:470:1f11:81f:c999:d94:aa7c:2e3e]:49185-[2001:470:4867:99::21]:21_orig.dat contents_[2001-470-1f11-81f-c999-d94-aa7c-2e3e]-49185-[2001-470-4867-99--21]-21_orig.dat
# @TEST-EXEC: mv contents_[2001:470:1f11:81f:c999:d94:aa7c:2e3e]:49185-[2001:470:4867:99::21]:21_resp.dat contents_[2001-470-1f11-81f-c999-d94-aa7c-2e3e]-49185-[2001-470-4867-99--21]-21_resp.dat

# @TEST-EXEC: btest-diff contents_[2001-470-1f11-81f-c999-d94-aa7c-2e3e]-49185-[2001-470-4867-99--21]-21_orig.dat
# @TEST-EXEC: btest-diff contents_[2001-470-1f11-81f-c999-d94-aa7c-2e3e]-49185-[2001-470-4867-99--21]-21_resp.dat
