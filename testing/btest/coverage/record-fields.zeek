# @TEST-DOC: Output interesting record types in bare and default mode recursively. Currently just the connection record type.
#
# @TEST-REQUIRES: ${SCRIPTS}/have-spicy
# @TEST-EXEC: zeek -b %INPUT >out.bare
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out.bare
# @TEST-EXEC: zeek %INPUT >out.default
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out.default

global record_types_seen: set[string];


# Given a type_name string from a field, extract all record type names.
#
# For example, `table[record conn_id] of record Conn::Info` yields `[conn_id, Conn::Info]`.
#
function extract_record_type_names(tn: string): vector of string
	{
	local names: vector of string;
	while ( /.*record [^ ] ?/ in tn )
		{
		tn = gsub(tn, /.*record /, "");  # strip leading 'record '
		local parts = split_string1(tn, / ?/);
		names += parts[0];
		if ( |parts| == 1 )
			break;

		tn = parts[1];
		}

	return names;
	}

function render_field(name: string, fr: record_field): string
	{
	return fmt("%s: %s, log=%s, optional=%s", name, fr$type_name, fr$log, fr$optional);
	}

function print_record_type(indent: string, rt: any)
	{
	local field_names: vector of string;
	local fields = record_fields(rt);
	for ( fn, _ in fields )
		field_names += fn;

	sort(field_names, strcmp);

	print fmt("%s%s {", indent, rt);
	for ( _, fn in field_names )
		{
		local fr = fields[fn];
		print fmt("%s  * %s", indent, render_field(fn, fr));
		# Recurse into record types of the field and print those as well.
		for ( _, frt in extract_record_type_names(fr$type_name) )
			{
			if ( frt in record_types_seen )
				print fmt("%s      %s { ... }", indent, frt);
			else
				{
				add record_types_seen[frt];
				print_record_type(indent + "      ", frt);
				}
			}
		}

	print fmt("%s }", indent);
	}

event zeek_init()
	{
	print zeek_args();
	print_record_type("", "connection");
	}
