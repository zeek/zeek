// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "../Formatter.h"
#include "3rdparty/json.hpp"
#include "3rdparty/tsl-ordered-map/ordered_map.h"


namespace threading { namespace formatter {

// Define a class for use with the json library that orders the keys in the same order that
// they were inserted. By default, the json library orders them alphabetically and we don't
// want it like that.
template<class Key, class T, class Ignore, class Allocator,
         class Hash = std::hash<Key>, class KeyEqual = std::equal_to<Key>,
         class AllocatorPair = typename std::allocator_traits<Allocator>::template rebind_alloc<std::pair<Key, T>>,
         class ValueTypeContainer = std::vector<std::pair<Key, T>, AllocatorPair>>
using ordered_map = tsl::ordered_map<Key, T, Hash, KeyEqual, AllocatorPair, ValueTypeContainer>;

using ZeekJson = nlohmann::basic_json<ordered_map>;

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
