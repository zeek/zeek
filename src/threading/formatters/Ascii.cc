// See the file "COPYING" in the main distribution directory for copyright.

#include "threading/formatters/Ascii.h"

#include "zeek/zeek-config.h"

#include <cerrno>
#include <sstream>

#include "zeek/Desc.h"
#include "zeek/threading/MsgThread.h"

using namespace std;

namespace zeek::threading::formatter
	{

// If the value we'd write out would match exactly the a reserved string, we
// escape the first character so that the output won't be ambiguous. If this
// function returns true, it has added an escaped version of data to desc.
static inline bool escapeReservedContent(ODesc* desc, const string& reserved, const char* data,
                                         int size)
	{
	if ( size != (int)reserved.size() || memcmp(data, reserved.data(), size) != 0 )
		return false;

	char hex[4] = {'\\', 'x', '0', '0'};
	util::bytetohex(*data, hex + 2);
	desc->AddRaw(hex, 4);
	desc->AddN(data + 1, size - 1);
	return true;
	}

Ascii::SeparatorInfo::SeparatorInfo()
	{
	separator = "SHOULD_NOT_BE_USED";
	set_separator = "SHOULD_NOT_BE_USED";
	unset_field = "SHOULD_NOT_BE_USED";
	empty_field = "SHOULD_NOT_BE_USED";
	}

Ascii::SeparatorInfo::SeparatorInfo(const string& arg_separator, const string& arg_set_separator,
                                    const string& arg_unset_field, const string& arg_empty_field)
	{
	separator = arg_separator;
	set_separator = arg_set_separator;
	unset_field = arg_unset_field;
	empty_field = arg_empty_field;
	}

Ascii::Ascii(MsgThread* t, const SeparatorInfo& info) : Formatter(t)
	{
	separators = info;
	}

Ascii::~Ascii() { }

bool Ascii::Describe(ODesc* desc, int num_fields, const Field* const* fields, Value** vals) const
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

bool Ascii::Describe(ODesc* desc, Value* val, const string& name) const
	{
	if ( ! val->present )
		{
		desc->Add(separators.unset_field);
		return true;
		}

	switch ( val->type )
		{

		case TYPE_BOOL:
			desc->Add(val->val.int_val ? "T" : "F");
			break;

		case TYPE_INT:
			desc->Add(val->val.int_val);
			break;

		case TYPE_COUNT:
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
			desc->Add(val->val.double_val, true);
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

			if ( escapeReservedContent(desc, separators.unset_field, data, size) )
				break;

			if ( escapeReservedContent(desc, separators.empty_field, data, size) )
				break;

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

			for ( zeek_int_t j = 0; j < val->val.set_val.size; j++ )
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

			for ( zeek_int_t j = 0; j < val->val.vector_val.size; j++ )
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
			GetThread()->Warning(
				GetThread()->Fmt("Ascii writer unsupported field format %d", val->type));
			return false;
		}

	return true;
	}

Value* Ascii::ParseValue(const string& s, const string& name, TypeTag type, TypeTag subtype) const
	{
	if ( ! separators.unset_field.empty() &&
	     s.compare(separators.unset_field) == 0 ) // field is not set...
		return new Value(type, false);

	Value* val = new Value(type, subtype, true);
	const char* start = s.c_str();
	char* end = nullptr;
	errno = 0;
	size_t pos;

	switch ( type )
		{
		case TYPE_ENUM:
		case TYPE_STRING:
			{
			string unescaped = util::get_unescaped_string(s);
			val->val.string_val.length = unescaped.size();
			val->val.string_val.data = new char[val->val.string_val.length];
			// we do not need a zero-byte at the end - the input manager adds that explicitly
			memcpy(val->val.string_val.data, unescaped.data(), unescaped.size());
			break;
			}

		case TYPE_BOOL:
			{
			auto stripped = util::strstrip(s);
			if ( stripped == "T" || stripped == "1" )
				val->val.int_val = 1;
			else if ( stripped == "F" || stripped == "0" )
				val->val.int_val = 0;
			else
				{
				GetThread()->Warning(GetThread()->Fmt("Field: %s Invalid value for boolean: %s",
				                                      name.c_str(), start));
				goto parse_error;
				}
			break;
			}

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
			val->val.uint_val = strtoull(start, &end, 10);
			if ( CheckNumberError(start, end, true) )
				goto parse_error;
			break;

		case TYPE_PORT:
			{
			auto stripped = util::strstrip(s);
			val->val.port_val.proto = TRANSPORT_UNKNOWN;
			pos = stripped.find('/');
			string numberpart;
			if ( pos != std::string::npos && stripped.length() > pos + 1 )
				{
				auto proto = stripped.substr(pos + 1);
				if ( util::strtolower(proto) == "tcp" )
					val->val.port_val.proto = TRANSPORT_TCP;
				else if ( util::strtolower(proto) == "udp" )
					val->val.port_val.proto = TRANSPORT_UDP;
				else if ( util::strtolower(proto) == "icmp" )
					val->val.port_val.proto = TRANSPORT_ICMP;
				else if ( util::strtolower(proto) == "unknown" )
					val->val.port_val.proto = TRANSPORT_UNKNOWN;
				else
					GetThread()->Warning(GetThread()->Fmt(
						"Port '%s' contained unknown protocol '%s'", s.c_str(), proto.c_str()));
				}

			if ( pos != std::string::npos && pos > 0 )
				{
				numberpart = stripped.substr(0, pos);
				start = numberpart.c_str();
				}
			val->val.port_val.port = strtoull(start, &end, 10);
			if ( CheckNumberError(start, end, true) )
				goto parse_error;
			}
			break;

		case TYPE_SUBNET:
			{
			string unescaped = util::strstrip(util::get_unescaped_string(s));
			size_t pos = unescaped.find('/');
			if ( pos == unescaped.npos )
				{
				GetThread()->Warning(GetThread()->Fmt("Invalid value for subnet: %s", start));
				goto parse_error;
				}

			string width_str = unescaped.substr(pos + 1);
			uint8_t width = (uint8_t)strtol(width_str.c_str(), &end, 10);

			if ( CheckNumberError(start, end) )
				goto parse_error;

			string addr = unescaped.substr(0, pos);

			val->val.subnet_val.prefix = ParseAddr(addr);
			val->val.subnet_val.length = width;
			break;
			}

		case TYPE_ADDR:
			{
			string unescaped = util::strstrip(util::get_unescaped_string(s));
			val->val.addr_val = ParseAddr(unescaped);
			break;
			}

		case TYPE_PATTERN:
			{
			string candidate = util::get_unescaped_string(s);
			// A string is a candidate pattern iff it begins and ends with
			// a '/'. Rather or not the rest of the string is legal will
			// be determined later when it is given to the RE engine.
			if ( candidate.size() >= 2 )
				{
				if ( candidate.front() == candidate.back() && candidate.back() == '/' )
					{
					// Remove the '/'s
					candidate.erase(0, 1);
					candidate.erase(candidate.size() - 1);
					val->val.pattern_text_val = util::copy_string(candidate.c_str());
					break;
					}
				}

			GetThread()->Warning(
				GetThread()->Fmt("String '%s' contained no parseable pattern.", candidate.c_str()));
			goto parse_error;
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
				for ( const auto& c : s )
					{
					if ( c == separators.set_separator[0] )
						length++;
					}

				unsigned int pos = 0;
				bool error = false;

				if ( separators.empty_field.size() > 0 && s.compare(separators.empty_field) == 0 )
					length = 0;

				if ( separators.empty_field.empty() && s.empty() )
					length = 0;

				Value** lvals = new Value*[length];

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
					break; // empty

				istringstream splitstream(s);
				while ( splitstream )
					{
					string element;

					if ( ! getline(splitstream, element, separators.set_separator[0]) )
						break;

					if ( pos >= length )
						{
						GetThread()->Warning(GetThread()->Fmt(
							"Internal error while parsing set. pos %d >= length %d."
							" Element: %s",
							pos, length, element.c_str()));
						error = true;
						break;
						}

					Value* newval = ParseValue(element, name, subtype);
					if ( newval == nullptr )
						{
						GetThread()->Warning("Error while reading set or vector");
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
					if ( lvals[pos] == nullptr )
						{
						GetThread()->Warning("Error while trying to add empty set element");
						goto parse_error;
						}

					pos++;
					}

				if ( error )
					{
					// We had an error while reading a set or a vector.
					// Hence we have to clean up the values that have
					// been read so far
					for ( unsigned int i = 0; i < pos; i++ )
						delete lvals[i];

					// and set the length of the set to 0, otherwhise the destructor will crash.
					val->val.vector_val.size = 0;

					goto parse_error;
					}

				if ( pos != length )
					{
					GetThread()->Warning(GetThread()->Fmt(
						"Internal error while parsing set: did not find all elements: %s", start));
					goto parse_error;
					}

				break;
				}

		default:
			GetThread()->Warning(
				GetThread()->Fmt("unsupported field format %d for %s", type, name.c_str()));
			goto parse_error;
		}

	return val;

parse_error:
	delete val;
	return nullptr;
	}

bool Ascii::CheckNumberError(const char* start, const char* end, bool nonneg_only) const
	{
	MsgThread* thread = GetThread();

	if ( end == start && *end != '\0' )
		{
		thread->Warning(thread->Fmt("String '%s' contained no parseable number", start));
		return true;
		}

	if ( end - start == 0 && *end == '\0' )
		{
		thread->Warning("Got empty string for number field");
		return true;
		}

	if ( (*end != '\0') )
		thread->Warning(thread->Fmt("Number '%s' contained non-numeric trailing characters. "
		                            "Ignored trailing characters '%s'",
		                            start, end));

	if ( nonneg_only )
		{
		// String may legitimately start with whitespace, so
		// we skip this before checking for a minus sign.
		const char* s = start;
		while ( s < end && isspace(*s) )
			s++;
		if ( *s == '-' )
			{
			thread->Warning(thread->Fmt("Number '%s' cannot be negative", start));
			return true;
			}
		}

	if ( errno == EINVAL )
		{
		thread->Warning(thread->Fmt("String '%s' could not be converted to a number", start));
		return true;
		}

	else if ( errno == ERANGE )
		{
		thread->Warning(thread->Fmt("Number '%s' out of supported range.", start));
		return true;
		}

	return false;
	}

	} // namespace zeek::threading::formatter
