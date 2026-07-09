# @TEST-DOC: Check that every Python bytecode signature in magic/python.sig identifies application/x-python-bytecode via file_magic().
# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@load base/frameworks/files

type Case: record {
	note:  string;
	input: string;
};

global cases: vector of Case = {
	[$note="file-pyc-1",    $input="\xfc\xc4\x0d\x0a"],
	[$note="file-pyc-2",    $input="\x03\xf3\x0d\x0a"],
	[$note="file-pyc-3-0",  $input="\xff\x0b\x0d\x0a"],
	[$note="file-pyc-3-1",  $input="\x45\x0c\x0d\x0a"],
	[$note="file-pyc-3-2",  $input="\x58\x0c\x0d\x0a"],
	[$note="file-pyc-3-3",  $input="\x76\x0c\x0d\x0a"],
	[$note="file-pyc-3-4",  $input="\xb2\x0c\x0d\x0a"],
	[$note="file-pyc-3-5",  $input="\xf8\x0c\x0d\x0a"],
	[$note="file-pyc-3-6",  $input="\x20\x0d\x0d\x0a"],
	[$note="file-pyc-3-7",  $input="\x3e\x0d\x0d\x0a"],
	[$note="file-pyc-3-8",  $input="\x48\x0d\x0d\x0a"],
	[$note="file-pyc-3-9",  $input="\x5c\x0d\x0d\x0a"],
	[$note="file-pyc-3-10", $input="\x66\x0d\x0d\x0a"],
	[$note="file-pyc-3-11", $input="\x7a\x0d\x0d\x0a"],
	[$note="file-pyc-3-12", $input="\xac\x0d\x0d\x0a"],
	[$note="file-pyc-3-13", $input="\xde\x0d\x0d\x0a"],
	[$note="file-pyc-3-14", $input="\x10\x0e\x0d\x0a"],
};

event zeek_init()
	{
	for ( i in cases )
		print cases[i]$note, file_magic(cases[i]$input);
	}
