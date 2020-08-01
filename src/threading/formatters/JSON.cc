// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "JSON.h"
#include "rapidjson/internal/ieee754.h"
#include "Desc.h"
#include "threading/MsgThread.h"

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

#include <sstream>
#include <errno.h>
#include <math.h>
#include <stdint.h>

namespace zeek::threading::formatter {

bool JSON::NullDoubleWriter::Double(double d)
	{
	if ( rapidjson::internal::Double(d).IsNanOrInf() )
		return rapidjson::Writer<rapidjson::StringBuffer>::Null();

	return rapidjson::Writer<rapidjson::StringBuffer>::Double(d);
	}

JSON::JSON(zeek::threading::MsgThread* t, TimeFormat tf) : zeek::threading::Formatter(t), surrounding_braces(true)
	{
	timestamps = tf;
	}

JSON::~JSON()
	{
	}

bool JSON::Describe(zeek::ODesc* desc, int num_fields, const zeek::threading::Field* const * fields,
                    zeek::threading::Value** vals) const
	{
	rapidjson::StringBuffer buffer;
	NullDoubleWriter writer(buffer);

	writer.StartObject();

	for ( int i = 0; i < num_fields; i++ )
		{
		if ( vals[i]->present )
			BuildJSON(writer, vals[i], fields[i]->name);
		}

	writer.EndObject();
	desc->Add(buffer.GetString());

	return true;
	}

bool JSON::Describe(zeek::ODesc* desc, zeek::threading::Value* val, const std::string& name) const
	{
	if ( desc->IsBinary() )
		{
		GetThread()->Error("json formatter: binary format not supported");
		return false;
		}

	if ( ! val->present || name.empty() )
		return true;

	rapidjson::Document doc;
	rapidjson::StringBuffer buffer;
	NullDoubleWriter writer(buffer);

	writer.StartObject();
	BuildJSON(writer, val, name);
	writer.EndObject();

	desc->Add(buffer.GetString());
	return true;
	}

zeek::threading::Value* JSON::ParseValue(const std::string& s, const std::string& name,
                                         zeek::TypeTag type, zeek::TypeTag subtype) const
	{
	GetThread()->Error("JSON formatter does not support parsing yet.");
	return nullptr;
	}

void JSON::BuildJSON(NullDoubleWriter& writer, zeek::threading::Value* val, const std::string& name) const
	{
	if ( ! val->present )
		{
		writer.Null();
		return;
		}

	if ( ! name.empty() )
		writer.Key(name);

	switch ( val->type )
		{
		case zeek::TYPE_BOOL:
			writer.Bool(val->val.int_val != 0);
			break;

		case zeek::TYPE_INT:
			writer.Int64(val->val.int_val);
			break;

		case zeek::TYPE_COUNT:
			writer.Uint64(val->val.uint_val);
			break;

		case zeek::TYPE_PORT:
			writer.Uint64(val->val.port_val.port);
			break;

		case zeek::TYPE_SUBNET:
			writer.String(Formatter::Render(val->val.subnet_val));
			break;

		case zeek::TYPE_ADDR:
			writer.String(Formatter::Render(val->val.addr_val));
			break;

		case zeek::TYPE_DOUBLE:
		case zeek::TYPE_INTERVAL:
			writer.Double(val->val.double_val);
			break;

		case zeek::TYPE_TIME:
			{
			if ( timestamps == TS_ISO8601 )
				{
				char buffer[40];
				char buffer2[48];
				time_t the_time = time_t(floor(val->val.double_val));
				struct tm t;

				if ( ! gmtime_r(&the_time, &t) ||
				     ! strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &t) )
					{
					GetThread()->Error(GetThread()->Fmt("json formatter: failure getting time: (%lf)", val->val.double_val));
					// This was a failure, doesn't really matter what gets put here
					// but it should probably stand out...
					writer.String("2000-01-01T00:00:00.000000");
					}
				else
					{
					double integ;
					double frac = modf(val->val.double_val, &integ);

					if ( frac < 0 )
						frac += 1;

					snprintf(buffer2, sizeof(buffer2), "%s.%06.0fZ", buffer, fabs(frac) * 1000000);
					writer.String(buffer2, strlen(buffer2));
					}
				}

			else if ( timestamps == TS_EPOCH )
				writer.Double(val->val.double_val);

			else if ( timestamps == TS_MILLIS )
				{
				// ElasticSearch uses milliseconds for timestamps
				writer.Uint64((uint64_t) (val->val.double_val * 1000));
				}

			break;
			}

		case zeek::TYPE_ENUM:
		case zeek::TYPE_STRING:
		case zeek::TYPE_FILE:
		case zeek::TYPE_FUNC:
			{
			writer.String(json_escape_utf8(std::string(val->val.string_val.data, val->val.string_val.length)));
			break;
			}

		case zeek::TYPE_TABLE:
			{
			writer.StartArray();

			for ( bro_int_t idx = 0; idx < val->val.set_val.size; idx++ )
				BuildJSON(writer, val->val.set_val.vals[idx]);

			writer.EndArray();
			break;
			}

		case zeek::TYPE_VECTOR:
			{
			writer.StartArray();

			for ( bro_int_t idx = 0; idx < val->val.vector_val.size; idx++ )
				BuildJSON(writer, val->val.vector_val.vals[idx]);

			writer.EndArray();
			break;
			}

		default:
			zeek::reporter->Warning("Unhandled type in JSON::BuildJSON");
			break;
		}
	}

} // namespace zeek::threading::formatter
