// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <sstream>
#include <errno.h>
#include <math.h>

#include "./JSON.h"

using namespace threading::formatter;

JSON::JSON(MsgThread* t, bool json_iso_timestamps) : Formatter(t)
	{
	iso_timestamps = json_iso_timestamps;
	}

JSON::~JSON()
	{
	}

bool JSON::Describe(ODesc* desc, int num_fields, const Field* const * fields,
                    Value** vals) const
	{
	desc->AddRaw("{");
	for ( int i = 0; i < num_fields; i++ )
		{
		if ( i > 0 &&
		     desc->Bytes()[desc->Len()] != ',' && vals[i]->present )
			{
			desc->AddRaw(",");
			}

		if ( ! Describe(desc, vals[i], fields[i]->name) )
			return false;
		}
	desc->AddRaw("}");
	return true;
	}

bool JSON::Describe(ODesc* desc, Value* val, const string& name) const
	{
	if ( ! val->present )
		return true;

	desc->AddRaw("\"", 1);
	desc->Add(name);
	desc->AddRaw("\":", 2);

	return Describe(desc, val);
	}

bool JSON::Describe(ODesc* desc, Value* val) const
	{
	if ( ! val->present )
		return true;

	switch ( val->type )
		{
		case TYPE_BOOL:
			desc->AddRaw(val->val.int_val == 0 ? "false" : "true");
			break;

		case TYPE_INT:
			desc->Add(val->val.int_val);
			break;

		case TYPE_COUNT:
		case TYPE_COUNTER:
			{
			// JSON doesn't support unsigned 64bit ints.
			if ( val->val.uint_val >= INT64_MAX )
				{
				thread->Error(thread->Fmt("count value too large for JSON: %" PRIu64, val->val.uint_val));
				desc->AddRaw("null", 4);
				}
			else
				desc->Add(val->val.uint_val);
			break;
			}

		case TYPE_PORT:
			desc->Add(val->val.port_val.port);
			break;

		case TYPE_SUBNET:
			desc->AddRaw("\"", 1);
			desc->Add(Render(val->val.subnet_val));
			desc->AddRaw("\"", 1);
			break;

		case TYPE_ADDR:
			desc->AddRaw("\"", 1);
			desc->Add(Render(val->val.addr_val));
			desc->AddRaw("\"", 1);
			break;

		case TYPE_DOUBLE:
		case TYPE_INTERVAL:
			desc->Add(val->val.double_val);
			break;

		case TYPE_TIME:
			{
			if ( iso_timestamps )
				{
				char buffer[40];
				time_t t = time_t(val->val.double_val);
				if ( strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", gmtime(&t)) == 0 )
					thread->Error(thread->Fmt("strftime error for JSON: %" PRIu64));
				else
					{
					double integ;
					double frac = modf(val->val.double_val, &integ);
					snprintf(buffer, sizeof(buffer), "%s.%06.0fZ", buffer, frac*1000000);
					desc->AddRaw("\"", 1);
					desc->Add(buffer);
					desc->AddRaw("\"", 1);
					}
				}
			else
				{
				// ElasticSearch uses milliseconds for timestamps and json only
				// supports signed ints (uints can be too large).
				uint64_t ts = (uint64_t) (val->val.double_val * 1000);
				if ( ts >= INT64_MAX )
					{
					thread->Error(thread->Fmt("time value too large for JSON: %" PRIu64, ts));
					desc->AddRaw("null", 4);
					}
				else
					desc->Add(ts);
				}
			break;
			}

		case TYPE_ENUM:
		case TYPE_STRING:
		case TYPE_FILE:
		case TYPE_FUNC:
			{
			desc->AddRaw("\"", 1);
			for ( int i = 0; i < val->val.string_val.length; ++i )
				{
				char c = val->val.string_val.data[i];
				// 2byte Unicode escape special characters.
				if ( c < 32 || c > 126 || c == '\n' || c == '"' || c == '\'' || c == '\\' || c == '&' )
					{
					static const char hex_chars[] = "0123456789abcdef";
					desc->AddRaw("\\u00", 4);
					desc->AddRaw(&hex_chars[(c & 0xf0) >> 4], 1);
					desc->AddRaw(&hex_chars[c & 0x0f], 1);
					}
				else
					desc->AddRaw(&c, 1);
				}
			desc->AddRaw("\"", 1);
			break;
			}

		case TYPE_TABLE:
			{
			desc->AddRaw("[", 1);
			for ( int j = 0; j < val->val.set_val.size; j++ )
				{
				if ( j > 0 )
					desc->AddRaw(",", 1);
				Describe(desc, val->val.set_val.vals[j]);
				}
			desc->AddRaw("]", 1);
			break;
			}

		case TYPE_VECTOR:
			{
			desc->AddRaw("[", 1);
			for ( int j = 0; j < val->val.vector_val.size; j++ )
				{
				if ( j > 0 )
					desc->AddRaw(",", 1);
				Describe(desc, val->val.vector_val.vals[j]);
				}
			desc->AddRaw("]", 1);
			break;
			}

		default:
			return false;
		}

	return true;
	}

threading::Value* JSON::ParseValue(string s, string name, TypeTag type, TypeTag subtype) const
	{
	thread->Error("JSON formatter does not support parsing yet.");
	return NULL;
	}
