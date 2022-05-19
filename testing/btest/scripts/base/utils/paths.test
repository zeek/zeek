# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/utils/paths

function test_extract(str: string, expect: string)
	{
	local result = extract_path(str);
	print fmt("Given : %s", str);
	print fmt("Expect: %s", expect);
	print fmt("Result: %s", result);
	print fmt("Result: %s", result == expect ? "SUCCESS" : "FAIL");
	print "===============================";
	}

function test_compress(str: string, expect: string)
	{
	local result = compress_path(str);
	print fmt("Given : %s", str);
	print fmt("Expect: %s", expect);
	print fmt("Result: %s", result);
	print fmt("Result: %s", result == expect ? "SUCCESS" : "FAIL");
	print "===============================";
	}

print "test compress_path()";
print "===============================";
test_compress("foo//bar", "foo/bar");
test_compress("foo//bar/..", "foo");
test_compress("foo/bar/../..", "");
test_compress("foo//bar/../..", "");
test_compress("/foo/../bar", "/bar");
test_compress("/foo/../bar/..", "/");
test_compress("/foo/baz/../..", "/");
test_compress("../..", "../..");
test_compress("foo/../../..", "../..");

print "test extract_path()";
print "===============================";
test_extract("\"/this/is/a/dir\" is current directory", "/this/is/a/dir");
test_extract("/this/is/a/dir is current directory", "/this/is/a/dir");
test_extract("/this/is/a/dir\\ is\\ current\\ directory", "/this/is/a/dir\\ is\\ current\\ directory");
test_extract("hey, /foo/bar/baz.zeek is a cool script", "/foo/bar/baz.zeek");
test_extract("here's two dirs: /foo/bar and /foo/baz", "/foo/bar");

print "test build_path_compressed()";
print "===============================";
print build_path_compressed("/home/zeek/", "policy/somefile.zeek");
print build_path_compressed("/home/zeek/", "/usr/local/zeek/share/zeek/somefile.zeek");
print build_path_compressed("/home/zeek/", "/usr/local/zeek/share/../../zeek/somefile.zeek");

print "===============================";
print "test build_path()";
print "===============================";
print build_path("/home/zeek/", "policy/somefile.zeek");
print build_path("/home/zeek/", "/usr/local/zeek/share/zeek/somefile.zeek");
print build_path("", "policy/somefile.zeek");
print build_path("", "/usr/local/zeek/share/zeek/somefile.zeek");
print build_path("/", "policy/somefile.zeek");
