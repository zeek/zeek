# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/utils/urls

print decompose_uri("https://www.example.com/");
print decompose_uri("http://example.com:99/test//?foo=bar");
print decompose_uri("ftp://1.2.3.4/pub/files/something.exe");
print decompose_uri("http://hyphen-example.com/index.asp?q=123");
print decompose_uri("git://git.kernel.org:/pub/scm/linux/");

# This is mostly undefined behavior but it doesn't give any
# reporter messages at least.
print decompose_uri("dfasjdfasdfasdf?asd");

# These aren't supported yet.
#print decompose_uri("mailto:foo@bar.com?subject=test!");
#print decompose_uri("http://example.com/?test=ampersand&amp;test");
#print decompose_uri("http://user:password@example.com/");

local s = "https://example1.com testing https://example2.com";
print find_all_urls(s);
local t = "https://example1.com/?test=1 testing https://example2.com/?test=2";
print find_all_urls(t);
