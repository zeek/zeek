// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#define RAPIDJSON_HAS_STDSTRING 1
#include "rapidjson/document.h"
#include "rapidjson/writer.h"

#include "../Formatter.h"

namespace zeek::threading::formatter {

/**
  * A thread-safe class for converting values into a JSON representation
  * and vice versa.
  */
class JSON : public zeek::threading::Formatter {
public:
	enum TimeFormat {
		TS_EPOCH,	// Doubles that represents seconds from the UNIX epoch.
		TS_ISO8601,	// ISO 8601 defined human readable timestamp format.
		TS_MILLIS	// Milliseconds from the UNIX epoch.  Some consumers need this (e.g., elasticsearch).
		};

	JSON(zeek::threading::MsgThread* t, TimeFormat tf);
	~JSON() override;

	bool Describe(zeek::ODesc* desc, zeek::threading::Value* val, const std::string& name = "") const override;
	bool Describe(zeek::ODesc* desc, int num_fields, const zeek::threading::Field* const * fields,
	              zeek::threading::Value** vals) const override;
	zeek::threading::Value* ParseValue(const std::string& s, const std::string& name, zeek::TypeTag type,
	                                   zeek::TypeTag subtype = zeek::TYPE_ERROR) const override;

	class NullDoubleWriter : public rapidjson::Writer<rapidjson::StringBuffer> {
	public:
		NullDoubleWriter(rapidjson::StringBuffer& stream) : rapidjson::Writer<rapidjson::StringBuffer>(stream) {}
		bool Double(double d);
	};

private:
	void BuildJSON(NullDoubleWriter& writer, zeek::threading::Value* val, const std::string& name = "") const;

	TimeFormat timestamps;
	bool surrounding_braces;
};

} // namespace zeek::threading::formatter

namespace threading::formatter {
	using JSON [[deprecated("Remove in v4.1. Use zeek::threading::formatter::JSON.")]] = zeek::threading::formatter::JSON;
}
