// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <sstream>
#include <errno.h>

#include "./Ascii.h"

using namespace threading::formatter;

Ascii::SeparatorInfo::SeparatorInfo()
	{
	separator = "SHOULD_NOT_BE_USED";
	set_separator = "SHOULD_NOT_BE_USED";
	unset_field = "SHOULD_NOT_BE_USED";
	empty_field = "SHOULD_NOT_BE_USED";
	}

Ascii::SeparatorInfo::SeparatorInfo(const string& arg_separator,
				    const string& arg_set_separator,
				    const string& arg_unset_field,
				    const string& arg_empty_field)
	{
	separator = arg_separator;
	set_separator = arg_set_separator;
	unset_field = arg_unset_field;
	empty_field = arg_empty_field;
	}

Ascii::Ascii(threading::MsgThread* t, const SeparatorInfo& info) : Formatter(t)
	{
	separators = info;
	}

Ascii::~Ascii()
	{
	}

bool Ascii::Describe(ODesc* desc, int num_fields, const threading::Field* const * fields,
                     threading::Value** vals) const
	{
	for ( int i = 0; i < num_fields; i++ )
		{
		if ( i > 0 )
			desc->AddRaw(separators.separator);

		if ( ! Describe(desc, vals[i], fields[i]->name) )
			return false;
		}

	return true;
	}

bool Ascii::Describe(ODesc* desc, threading::Value* val, const string& name) const
	{
	if ( ! val->present )
		{
		desc->Add(separators.unset_field);
		return true;
		}

	switch ( val->type ) {

	case TYPE_BOOL:
		desc->Add(val->val.int_val ? "T" : "F");
		break;

	case TYPE_INT:
		desc->Add(val->val.int_val);
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		desc->Add(val->val.uint_val);
		break;

	case TYPE_PORT:
		desc->Add(val->val.port_val.port);
		break;

	case TYPE_SUBNET:
		desc->Add(Render(val->val.subnet_val));
		break;

	case TYPE_ADDR:
		desc->Add(Render(val->val.addr_val));
		break;

	case TYPE_DOUBLE:
		// Rendering via Add() truncates trailing 0s after the
		// decimal point. The difference with TIME/INTERVAL is mainly
		// to keep the log format consistent.
		desc->Add(val->val.double_val);
		break;

	case TYPE_INTERVAL:
	case TYPE_TIME:
		// Rendering via Render() keeps trailing 0s after the decimal
		// point. The difference with DOUBLE is mainly to keep the
		// log format consistent.
		desc->Add(Render(val->val.double_val));
		break;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		int size = val->val.string_val.length;
		const char* data = val->val.string_val.data;

		if ( ! size )
			{
			desc->Add(separators.empty_field);
			break;
			}

		if ( size == (int)separators.unset_field.size() && memcmp(data, separators.unset_field.data(), size) == 0 )
			{
			// The value we'd write out would match exactly the
			// place-holder we use for unset optional fields. We
			// escape the first character so that the output
			// won't be ambigious.
			char hex[4] = {'\\', 'x', '0', '0'};
			bytetohex(*data, hex + 2);
			desc->AddRaw(hex, 4);

			++data;
			--size;
			}

		if ( size )
			desc->AddN(data, size);

		break;
		}

	case TYPE_TABLE:
		{
		if ( ! val->val.set_val.size )
			{
			desc->Add(separators.empty_field);
			break;
			}

		desc->AddEscapeSequence(separators.set_separator);

		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddRaw(separators.set_separator);

			if ( ! Describe(desc, val->val.set_val.vals[j]) )
				{
				desc->RemoveEscapeSequence(separators.set_separator);
				return false;
				}
			}

		desc->RemoveEscapeSequence(separators.set_separator);

		break;
		}

	case TYPE_VECTOR:
		{
		if ( ! val->val.vector_val.size )
			{
			desc->Add(separators.empty_field);
			break;
			}

		desc->AddEscapeSequence(separators.set_separator);

		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddRaw(separators.set_separator);

			if ( ! Describe(desc, val->val.vector_val.vals[j]) )
				{
				desc->RemoveEscapeSequence(separators.set_separator);
				return false;
				}
			}

		desc->RemoveEscapeSequence(separators.set_separator);

		break;
		}

	default:
		GetThread()->Error(GetThread()->Fmt("Ascii writer unsupported field format %d", val->type));
		return false;
	}

	return true;
	}


threading::Value* Ascii::ParseValue(const string& s, const string& name, TypeTag type, TypeTag subtype) const
	{
	if ( s.compare(separators.unset_field) == 0 )  // field is not set...
		return new threading::Value(type, false);

	threading::Value* val = new threading::Value(type, true);
	const char* start = s.c_str();
	char* end = 0;
	errno = 0;

	switch ( type ) {
	case TYPE_ENUM:
	case TYPE_STRING:
		{
		string unescaped = get_unescaped_string(s);
		val->val.string_val.length = unescaped.size();
		val->val.string_val.data = copy_string(unescaped.c_str());
		break;
		}

	case TYPE_BOOL:
		if ( s == "T" )
			val->val.int_val = 1;
		else if ( s == "F" )
			val->val.int_val = 0;
		else
			{
			GetThread()->Error(GetThread()->Fmt("Field: %s Invalid value for boolean: %s",
				  name.c_str(), start));
			goto parse_error;
			}
		break;

	case TYPE_INT:
		val->val.int_val = strtoll(start, &end, 10);
		if ( CheckNumberError(start, end) )
			goto parse_error;
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		val->val.double_val = strtod(start, &end);
		if ( CheckNumberError(start, end) )
			goto parse_error;
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		val->val.uint_val = strtoull(start, &end, 10);
		if ( CheckNumberError(start, end) )
			goto parse_error;
		break;

	case TYPE_PORT:
		val->val.port_val.port = strtoull(start, &end, 10);
		if ( CheckNumberError(start, end) )
			goto parse_error;

		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET:
		{
		string unescaped = get_unescaped_string(s);
		size_t pos = unescaped.find("/");
		if ( pos == unescaped.npos )
			{
			GetThread()->Error(GetThread()->Fmt("Invalid value for subnet: %s", start));
			goto parse_error;
			}

		string width_str = unescaped.substr(pos + 1);
		uint8_t width = (uint8_t) strtol(width_str.c_str(), &end, 10);

		if ( CheckNumberError(start, end) )
			goto parse_error;

		string addr = unescaped.substr(0, pos);

		val->val.subnet_val.prefix = ParseAddr(addr);
		val->val.subnet_val.length = width;
		break;
		}

	case TYPE_ADDR:
		{
		string unescaped = get_unescaped_string(s);
		val->val.addr_val = ParseAddr(unescaped);
		break;
		}

	case TYPE_TABLE:
	case TYPE_VECTOR:
		// First - common initialization
		// Then - initialization for table.
		// Then - initialization for vector.
		// Then - common stuff
		{
		// how many entries do we have...
		unsigned int length = 1;
		for ( unsigned int i = 0; i < s.size(); i++ )
			{
			if ( s[i] == separators.set_separator[0] )
				length++;
			}

		unsigned int pos = 0;
		bool error = false;

		if ( separators.empty_field.size() > 0 && s.compare(separators.empty_field) == 0 )
			length = 0;

		threading::Value** lvals = new threading::Value* [length];

		if ( type == TYPE_TABLE )
			{
			val->val.set_val.vals = lvals;
			val->val.set_val.size = length;
			}

		else if ( type == TYPE_VECTOR )
			{
			val->val.vector_val.vals = lvals;
			val->val.vector_val.size = length;
			}

		else
			assert(false);

		if ( length == 0 )
			break; //empty

		istringstream splitstream(s);
		while ( splitstream )
			{
			string element;

			if ( ! getline(splitstream, element, separators.set_separator[0]) )
				break;

			if ( pos >= length )
				{
				GetThread()->Error(GetThread()->Fmt("Internal error while parsing set. pos %d >= length %d."
				          " Element: %s", pos, length, element.c_str()));
				error = true;
				break;
				}

			threading::Value* newval = ParseValue(element, name, subtype);
			if ( newval == 0 )
				{
				GetThread()->Error("Error while reading set or vector");
				error = true;
				break;
				}

			lvals[pos] = newval;

			pos++;
			}

		// Test if the string ends with a set_separator... or if the
		// complete string is empty. In either of these cases we have
		// to push an empty val on top of it.
		if ( ! error && (s.empty() || *s.rbegin() == separators.set_separator[0]) )
			{
			lvals[pos] = ParseValue("", name, subtype);
			if ( lvals[pos] == 0 )
				{
				GetThread()->Error("Error while trying to add empty set element");
				goto parse_error;
				}

			pos++;
			}

		if ( error ) {
			// We had an error while reading a set or a vector.
			// Hence we have to clean up the values that have
			// been read so far
			for ( unsigned int i = 0; i < pos; i++ )
				delete lvals[i];

			goto parse_error;
		}

		if ( pos != length )
			{
			GetThread()->Error(GetThread()->Fmt("Internal error while parsing set: did not find all elements: %s", start));
			goto parse_error;
			}

		break;
		}

	default:
		GetThread()->Error(GetThread()->Fmt("unsupported field format %d for %s", type,
						    name.c_str()));
		goto parse_error;
	}

	return val;

parse_error:
	delete val;
	return 0;
	}

bool Ascii::CheckNumberError(const char* start, const char* end) const
	{
	threading::MsgThread* thread = GetThread();

	if ( end == start && *end != '\0'  ) {
		thread->Error(thread->Fmt("String '%s' contained no parseable number", start));
		return true;
	}

	if ( end - start == 0 && *end == '\0' )
		{
		thread->Error("Got empty string for number field");
		return true;
		}

	if ( (*end != '\0') )
		thread->Warning(thread->Fmt("Number '%s' contained non-numeric trailing characters. Ignored trailing characters '%s'", start, end));

	if ( errno == EINVAL )
		{
		thread->Error(thread->Fmt("String '%s' could not be converted to a number", start));
		return true;
		}

	else if ( errno == ERANGE )
		{
		thread->Error(thread->Fmt("Number '%s' out of supported range.", start));
		return true;
		}

	return false;
	}
