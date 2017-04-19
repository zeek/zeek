##! Functions to assist with generating JSON data from Bro data scructures.
# We might want to implement this in core somtime, this looks... hacky at best.

@load base/utils/strings

## A function to convert arbitrary Bro data into a JSON string.
##
## v: The value to convert to JSON.  Typically a record.
##
## only_loggable: If the v value is a record this will only cause
##                fields with the &log attribute to be included in the JSON.
##
## returns: a JSON formatted string.
function to_json(v: any, only_loggable: bool &default=F, field_escape_pattern: pattern &default=/^_/): string
	{
	local tn = type_name(v);
	switch ( tn )
		{
		case "type":
		return "";

		case "string":
		return cat("\"", gsub(gsub(clean(v), /\\/, "\\\\"), /\"/, "\\\""), "\"");

		case "port":
		return cat(port_to_count(to_port(cat(v))));

		case "enum":
		fallthrough;
		case "interval":
		fallthrough;
		case "addr":
		fallthrough;
		case "subnet":
		return cat("\"", v, "\"");

		case "int":
		fallthrough;
		case "count":
		fallthrough;
		case "time":
		return cat(v);

		case "double":
		return fmt("%.16g", v);

		case "bool":
		local bval: bool = v;
		return bval ? "true" : "false";

		default:
		break;
		}

	if ( /^record/ in tn )
		{
		local rec_parts: string_vec = vector();

		local ft = record_fields(v);
		for ( field in ft )
			{
			local field_desc = ft[field];
			# replace the escape pattern in the field.
			if( field_escape_pattern in field )
				field = cat(sub(field, field_escape_pattern, ""));
			if ( field_desc?$value && (!only_loggable || field_desc$log) )
				{
				local onepart = cat("\"", field, "\": ", to_json(field_desc$value, only_loggable));
				rec_parts[|rec_parts|] = onepart;
				}
			}
			return cat("{", join_string_vec(rec_parts, ", "), "}");
		}

	# None of the following are supported.
	else if ( /^set/ in tn )
		{
		local set_parts: string_vec = vector();
		local sa: set[bool] = v;
		for ( sv in sa )
			{
			set_parts[|set_parts|] = to_json(sv, only_loggable);
			}
		return cat("[", join_string_vec(set_parts, ", "), "]");
		}
	else if ( /^table/ in tn )
		{
		local tab_parts: vector of string = vector();
		local ta: table[bool] of any = v;
		for ( ti in ta )
			{
			local ts = to_json(ti);
			local if_quotes = (ts[0] == "\"") ? "" : "\"";
			tab_parts[|tab_parts|] = cat(if_quotes, ts, if_quotes, ": ", to_json(ta[ti], only_loggable));
			}
		return cat("{", join_string_vec(tab_parts, ", "), "}");
		}
	else if ( /^vector/ in tn )
		{
		local vec_parts: string_vec = vector();
		local va: vector of any = v;
		for ( vi in va )
			{
			vec_parts[|vec_parts|] = to_json(va[vi], only_loggable);
			}
		return cat("[", join_string_vec(vec_parts, ", "), "]");
		}

	return "\"\"";
	}
