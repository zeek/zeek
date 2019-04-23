# @TEST-EXEC: unset BRO_DISABLE_BROXYGEN; zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

##! This is a test script.
##! With some summary comments.

## Hello world.  This is an option.
## With some more description here.
## And here.
const myvar = 7 &redef;  ##< Maybe just one more.

## This function prints a string line by line.
##
## lines: A string to print line by line, w/ lines delimited by newline chars.
global print_lines: function(lines: string, prefix: string &default="");

## And some more comments on the function implementation.
function print_lines(lines: string, prefix: string)
	{
	local v: vector of string;
	local line_table = split(lines, /\n/);

	for ( i in line_table )
		v[i] = line_table[i];

	for ( i in v )
		print fmt("%s%s", prefix, v[i]);
	}

function print_comments(name: string, func: function(name: string): string)
	{
	print fmt("%s:", name);
	print_lines(func(name), "    ");
	}

## This is an alias for count.
type mytype: count;

## My record type.
type myrecord: record {
	## The first field.
	## Does something...
	aaa: count;    ##< Done w/ aaa.
	## The second field.
	bbb: string;   ##< Done w/ bbb.
	               ##< No really, done w/ bbb.
	## Third field.
	ccc: int;      ##< Done w/ ccc.
	## Fourth field.
	ddd: interval; ##< Done w/ ddd.
};


## My enum type;
type myenum: enum {
	## First enum value.
	## I know, the name isn't clever.
	FIRST,  ##< Done w/ first.
	## Second enum value.
	SECOND, ##< Done w/ second.
	## Third enum value.
	THIRD,  ##< Done w/ third.
	        ##< Done w/ third again.
	## SIC.
	## It's a programming language.
	FORTH  ##< Using Reverse Polish Notation.
	       ##< Done w/ forth.
};

redef record myrecord += {
	## First redef'd field.
	## With two lines of comments.
	eee: count &optional; ##< And two post-notation comments.
	                      ##< Done w/ eee.
	## Second redef'd field.
	fff: count &optional; ##< Done w/ fff.
	## Third redef'd field.
	ggg: count &optional; ##< Done w/ ggg.
};

redef enum myenum += {
	## First redef'd enum val.
	FIFTH, ##< Done w/ fifth.
	## Second redef'd enum val.
	SIXTH, ##< Done w/ sixth.
	## Third redef'd enum val.
	## Lucky number seven.
	SEVENTH, ##< Still works with comma.
	         ##< Done w/ seventh.
};

print_lines(get_script_comments(@DIR + "/" + @FILENAME));
print_comments("myvar", get_identifier_comments);
print_comments("print_lines", get_identifier_comments);
print_comments("mytype", get_identifier_comments);
print_comments("myrecord", get_identifier_comments);
print_comments("myrecord$aaa", get_record_field_comments);
print_comments("myrecord$bbb", get_record_field_comments);
print_comments("myrecord$ccc", get_record_field_comments);
print_comments("myrecord$ddd", get_record_field_comments);
print_comments("myrecord$eee", get_record_field_comments);
print_comments("myrecord$fff", get_record_field_comments);
print_comments("myrecord$ggg", get_record_field_comments);
print_comments("myenum", get_identifier_comments);
print_comments("FIRST", get_identifier_comments);
print_comments("SECOND", get_identifier_comments);
print_comments("THIRD", get_identifier_comments);
print_comments("FORTH", get_identifier_comments);
print_comments("FIFTH", get_identifier_comments);
print_comments("SIXTH", get_identifier_comments);
print_comments("SEVENTH", get_identifier_comments);
