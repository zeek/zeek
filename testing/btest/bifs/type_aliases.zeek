# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type MyRec: record {
	a: bool &optional;
};

type Color: enum { RED, GREEN, BLUE };
type ColorAlias: Color;

type MyRecAlias: MyRec;
type MyString: string;
type MyOtherString: string;
type AnotherString: MyString;
type MyTable: table[count] of string;
type MyTable2: MyTable;
type MyTable3: MyTable2;
type MyTable4: MyTable3;

function type_alias_list(label: string, x: any): string
	{
	local rval = fmt("type aliases for '%s':", label);
	local aliases = type_aliases(x);

	if ( |aliases| == 0 )
		rval += fmt(" it's just a '%s'", type_name(x));
	else
		for ( a in aliases )
			rval += fmt(" %s", a);

	return rval;
	}

print type_alias_list("RED enum val", RED);
print type_alias_list("Color enum type", Color);

print type_alias_list("MyRec val", MyRec());
print type_alias_list("MyRecAlias val", MyRecAlias());

print type_alias_list("MyRec type", MyRec);
print type_alias_list("MyRecalias type", MyRecAlias);

local mys: MyString = "hi";
print type_alias_list("MyString val", mys);
print type_alias_list("MyString type", MyString);
print type_alias_list("MyOtherString type", MyOtherString);
print type_alias_list("AnotherString type", AnotherString);

print type_alias_list("string literal value", "test");
print type_alias_list("count literal value", 7);

print type_alias_list("MyTable value", MyTable([1] = "one", [2] = "two"));
print type_alias_list("MyTable2 value", MyTable2([1] = "one", [2] = "two"));
print type_alias_list("MyTable3 value", MyTable3([1] = "one", [2] = "two"));
print type_alias_list("MyTable4 value", MyTable4([1] = "one", [2] = "two"));
print type_alias_list("MyTable type", MyTable);
print type_alias_list("MyTable2 type", MyTable2);
print type_alias_list("MyTable3 type", MyTable3);
print type_alias_list("MyTable4 type", MyTable4);
print type_alias_list("table value", table([1] = "one", [2] = "two"));
