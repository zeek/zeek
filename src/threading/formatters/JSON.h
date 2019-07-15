// See the file "COPYING" in the main distribution directory for copyright.

#ifndef THREADING_FORMATTERS_JSON_H
#define THREADING_FORMATTERS_JSON_H

#include "../Formatter.h"
#include "3rdparty/json.hpp"
#include "3rdparty/fifo_map.hpp"


namespace threading { namespace formatter {

// Define a class for use with the json library that orders the keys in the same order that
// they were inserted. By default, the json library orders them alphabetically and we don't
// want it like that.
template<class K, class V, class compare, class A>
using json_fifo_map = nlohmann::fifo_map<K, V, nlohmann::fifo_map_compare<K>, A>;
using ZeekJson = nlohmann::basic_json<json_fifo_map>;

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

private:

	ZeekJson BuildJSON(Value* val, const string& name = "") const;

	TimeFormat timestamps;
	bool surrounding_braces;
};

}}

#endif /* THREADING_FORMATTERS_JSON_H */
