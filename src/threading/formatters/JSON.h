// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#define RAPIDJSON_HAS_STDSTRING 1
#include "3rdparty/rapidjson/include/rapidjson/document.h"
#include "3rdparty/rapidjson/include/rapidjson/writer.h"

#include "../Formatter.h"

namespace threading { namespace formatter {

/**
  * A thread-safe class for converting values into a JSON representation
  * and vice versa.
  */
class JSON : public Formatter {
public:
	enum TimeFormat {
		TS_EPOCH,	// Doubles that represents seconds from the UNIX epoch.
		TS_ISO8601,	// ISO 8601 defined human readable timestamp format.
		TS_MILLIS	// Milliseconds from the UNIX epoch.  Some consumers need this (e.g., elasticsearch).
		};

	JSON(threading::MsgThread* t, TimeFormat tf);
	~JSON() override;

	bool Describe(ODesc* desc, threading::Value* val, const string& name = "") const override;
	bool Describe(ODesc* desc, int num_fields, const threading::Field* const * fields,
	                      threading::Value** vals) const override;
	threading::Value* ParseValue(const string& s, const string& name, TypeTag type, TypeTag subtype = TYPE_ERROR) const override;

	class NullDoubleWriter : public rapidjson::Writer<rapidjson::StringBuffer> {
	public:
		NullDoubleWriter(rapidjson::StringBuffer& stream) : rapidjson::Writer<rapidjson::StringBuffer>(stream) {}
		bool Double(double d);
	};

private:
	void BuildJSON(NullDoubleWriter& writer, Value* val, const string& name = "") const;

	TimeFormat timestamps;
	bool surrounding_braces;
};

}}
