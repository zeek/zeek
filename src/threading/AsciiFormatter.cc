// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <sstream>
#include <errno.h>

#include "AsciiFormatter.h"
#include "bro_inet_ntop.h"

AsciiFormatter::SeparatorInfo::SeparatorInfo()
	{
	this->set_separator = "SHOULD_NOT_BE_USED";
	this->unset_field = "SHOULD_NOT_BE_USED";
	this->empty_field = "SHOULD_NOT_BE_USED";
	}

AsciiFormatter::SeparatorInfo::SeparatorInfo(const string & set_separator,
				 const string & unset_field, const string & empty_field)
	{
	this->set_separator = set_separator;
	this->unset_field = unset_field;
	this->empty_field = empty_field;
	}

AsciiFormatter::AsciiFormatter(threading::MsgThread* t, const SeparatorInfo info)
	{
	thread = t;
	this->separators = info;
	}

AsciiFormatter::~AsciiFormatter()
	{
	}

bool AsciiFormatter::Describe(ODesc* desc, threading::Value* val, const string& name) const
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
			static const char hex_chars[] = "0123456789abcdef";
			char hex[6] = "\\x00";
			hex[2] = hex_chars[((*data) & 0xf0) >> 4];
			hex[3] = hex_chars[(*data) & 0x0f];
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

			if ( ! Describe(desc, val->val.set_val.vals[j], name) )
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

			if ( ! Describe(desc, val->val.vector_val.vals[j], name) )
				{
				desc->RemoveEscapeSequence(separators.set_separator);
				return false;
				}
			}
		desc->RemoveEscapeSequence(separators.set_separator);

		break;
		}

	default:
		thread->Error(thread->Fmt("unsupported field format %d for %s", val->type, name.c_str()));
		return false;
	}

	return true;
	}


threading::Value* AsciiFormatter::ParseValue(string s, string name, TypeTag type, TypeTag subtype) const
	{
	if ( s.compare(separators.unset_field) == 0 )  // field is not set...
		return new threading::Value(type, false);

	threading::Value* val = new threading::Value(type, true);
	char* end = 0;
	errno = 0;

	switch ( type ) {
	case TYPE_ENUM:
	case TYPE_STRING:
		s = get_unescaped_string(s);
		val->val.string_val.length = s.size();
		val->val.string_val.data = copy_string(s.c_str());
		break;

	case TYPE_BOOL:
		if ( s == "T" )
			val->val.int_val = 1;
		else if ( s == "F" )
			val->val.int_val = 0;
		else
			{
			thread->Error(thread->Fmt("Field: %s Invalid value for boolean: %s",
				  name.c_str(), s.c_str()));
			goto parse_error;
			}
		break;

	case TYPE_INT:
		val->val.int_val = strtoll(s.c_str(), &end, 10);
		if ( CheckNumberError(s, end) )
			goto parse_error;
		break;

	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
		val->val.double_val = strtod(s.c_str(), &end);
		if ( CheckNumberError(s, end) )
			goto parse_error;
		break;

	case TYPE_COUNT:
	case TYPE_COUNTER:
		val->val.uint_val = strtoull(s.c_str(), &end, 10);
		if ( CheckNumberError(s, end) )
			goto parse_error;
		break;

	case TYPE_PORT:
		val->val.port_val.port = strtoull(s.c_str(), &end, 10);
		if ( CheckNumberError(s, end) )
			goto parse_error;

		val->val.port_val.proto = TRANSPORT_UNKNOWN;
		break;

	case TYPE_SUBNET:
		{
		s = get_unescaped_string(s);
		size_t pos = s.find("/");
		if ( pos == s.npos )
			{
			thread->Error(thread->Fmt("Invalid value for subnet: %s", s.c_str()));
			goto parse_error;
			}

		string width_str = s.substr(pos + 1);
		uint8_t width = (uint8_t) strtol(width_str.c_str(), &end, 10);

		if ( CheckNumberError(s, end) )
			goto parse_error;

		string addr = s.substr(0, pos);

		val->val.subnet_val.prefix = ParseAddr(addr);
		val->val.subnet_val.length = width;
		break;
		}

	case TYPE_ADDR:
		s = get_unescaped_string(s);
		val->val.addr_val = ParseAddr(s);
		break;

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
				thread->Error(thread->Fmt("Internal error while parsing set. pos %d >= length %d."
				          " Element: %s", pos, length, element.c_str()));
				error = true;
				break;
				}

			threading::Value* newval = ParseValue(element, name, subtype);
			if ( newval == 0 )
				{
				thread->Error("Error while reading set or vector");
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
				thread->Error("Error while trying to add empty set element");
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
			thread->Error(thread->Fmt("Internal error while parsing set: did not find all elements: %s", s.c_str()));
			goto parse_error;
			}

		break;
		}

	default:
		thread->Error(thread->Fmt("unsupported field format %d for %s", type,
		name.c_str()));
		goto parse_error;
	}

	return val;

parse_error:
	delete val;
	return 0;
	}

bool AsciiFormatter::CheckNumberError(const string& s, const char* end) const
	{
	// Do this check first, before executing s.c_str() or similar.
	// otherwise the value to which *end is pointing at the moment might
	// be gone ...
	bool endnotnull =  (*end != '\0');

	if ( s.length() == 0 )
		{
		thread->Error("Got empty string for number field");
		return true;
		}

	if ( end == s.c_str() ) {
		thread->Error(thread->Fmt("String '%s' contained no parseable number", s.c_str()));
		return true;
	}

	if ( endnotnull )
		thread->Warning(thread->Fmt("Number '%s' contained non-numeric trailing characters. Ignored trailing characters '%s'", s.c_str(), end));

	if ( errno == EINVAL )
		{
		thread->Error(thread->Fmt("String '%s' could not be converted to a number", s.c_str()));
		return true;
		}

	else if ( errno == ERANGE )
		{
		thread->Error(thread->Fmt("Number '%s' out of supported range.", s.c_str()));
		return true;
		}

	return false;
	}

string AsciiFormatter::Render(const threading::Value::addr_t& addr) const
	{
	if ( addr.family == IPv4 )
		{
		char s[INET_ADDRSTRLEN];

		if ( ! bro_inet_ntop(AF_INET, &addr.in.in4, s, INET_ADDRSTRLEN) )
			return "<bad IPv4 address conversion>";
		else
			return s;
		}
	else
		{
		char s[INET6_ADDRSTRLEN];

		if ( ! bro_inet_ntop(AF_INET6, &addr.in.in6, s, INET6_ADDRSTRLEN) )
			return "<bad IPv6 address conversion>";
		else
			return s;
		}
	}

TransportProto AsciiFormatter::ParseProto(const string &proto) const
	{
	if ( proto == "unknown" )
		return TRANSPORT_UNKNOWN;
	else if ( proto == "tcp" )
		return TRANSPORT_TCP;
	else if ( proto == "udp" )
		return TRANSPORT_UDP;
	else if ( proto == "icmp" )
		return TRANSPORT_ICMP;

	thread->Error(thread->Fmt("Tried to parse invalid/unknown protocol: %s", proto.c_str()));

	return TRANSPORT_UNKNOWN;
	}


// More or less verbose copy from IPAddr.cc -- which uses reporter.
threading::Value::addr_t AsciiFormatter::ParseAddr(const string &s) const
	{
		threading::Value::addr_t val;

	if ( s.find(':') == std::string::npos ) // IPv4.
		{
		val.family = IPv4;

		if ( inet_aton(s.c_str(), &(val.in.in4)) <= 0 )
			{
			thread->Error(thread->Fmt("Bad address: %s", s.c_str()));
			memset(&val.in.in4.s_addr, 0, sizeof(val.in.in4.s_addr));
			}
		}

	else
		{
		val.family = IPv6;
		if ( inet_pton(AF_INET6, s.c_str(), val.in.in6.s6_addr) <=0 )
			{
			thread->Error(thread->Fmt("Bad address: %s", s.c_str()));
			memset(val.in.in6.s6_addr, 0, sizeof(val.in.in6.s6_addr));
			}
		}

	return val;
	}

string AsciiFormatter::Render(const threading::Value::subnet_t& subnet) const
	{
	char l[16];

	if ( subnet.prefix.family == IPv4 )
		modp_uitoa10(subnet.length - 96, l);
	else
		modp_uitoa10(subnet.length, l);

	string s = Render(subnet.prefix) + "/" + l;

	return s;
	}

string AsciiFormatter::Render(double d) const
	{
	char buf[256];
	modp_dtoa(d, buf, 6);
	return buf;
	}

