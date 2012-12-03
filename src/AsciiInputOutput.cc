// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "AsciiInputOutput.h"
#include "bro_inet_ntop.h"

AsciiInputOutput::AsciiInputOutput(threading::MsgThread* t, const string & separator, const string & set_separator, 
				const string & empty_field, const string & unset_field) 
	{
	thread = t;
	this->separator = separator;
	this->set_separator = set_separator;
	this->empty_field = empty_field;
	this->unset_field = unset_field;
	}


AsciiInputOutput::~AsciiInputOutput()
	{
	}

bool AsciiInputOutput::ValToODesc(ODesc* desc, threading::Value* val, const threading::Field* field) const
	{
	if ( ! val->present )
		{
		desc->Add(unset_field);
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
		// point. The difference with DOUBLEis mainly to keep the log
		// format consistent.
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
			desc->Add(empty_field);
			break;
			}

		if ( size == unset_field.size() && memcmp(data, unset_field.data(), size) == 0 )
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
			desc->Add(empty_field);
			break;
			}

		desc->AddEscapeSequence(set_separator);
		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddRaw(set_separator);

			if ( ! ValToODesc(desc, val->val.set_val.vals[j], field) )
				{
				desc->RemoveEscapeSequence(set_separator);
				return false;
				}
			}
		desc->RemoveEscapeSequence(set_separator);

		break;
		}

	case TYPE_VECTOR:
		{
		if ( ! val->val.vector_val.size )
			{
			desc->Add(empty_field);
			break;
			}

		desc->AddEscapeSequence(set_separator);
		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				desc->AddRaw(set_separator);

			if ( ! ValToODesc(desc, val->val.vector_val.vals[j], field) )
				{
				desc->RemoveEscapeSequence(set_separator);
				return false;
				}
			}
		desc->RemoveEscapeSequence(set_separator);

		break;
		}

	default:
		thread->Error(thread->Fmt("unsupported field format %d for %s", val->type, field->name));
		return false;
	}

	return true;
	}


string AsciiInputOutput::Render(const threading::Value::addr_t& addr) 
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

string AsciiInputOutput::Render(const threading::Value::subnet_t& subnet) 
	{
	char l[16];

	if ( subnet.prefix.family == IPv4 )
		modp_uitoa10(subnet.length - 96, l);
	else
		modp_uitoa10(subnet.length, l);

	string s = Render(subnet.prefix) + "/" + l;

	return s;
	}

string AsciiInputOutput::Render(double d) 
	{
	char buf[256];
	modp_dtoa(d, buf, 6);
	return buf;
	}

