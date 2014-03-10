// See the file "COPYING" in the main distribution directory for copyright.

#ifndef THREADING_FORMATTERS_JSON_H
#define THREADING_FORMATTERS_JSON_H

#include "../Formatter.h"

namespace threading { namespace formatter {

/**
  * A thread-safe class for converting values into a JSON representation
  * and vice versa.
  */
class JSON : public Formatter {
public:
	JSON(threading::MsgThread* t, bool json_iso_timestamps);
	virtual ~JSON();

	virtual bool Describe(ODesc* desc, threading::Value* val) const;
	virtual bool Describe(ODesc* desc, threading::Value* val, const string& name) const;
	virtual bool Describe(ODesc* desc, int num_fields, const threading::Field* const * fields,
	                      threading::Value** vals) const;
	virtual threading::Value* ParseValue(string s, string name, TypeTag type, TypeTag subtype = TYPE_ERROR) const;

private:
	bool iso_timestamps;
};

}}

#endif /* THREADING_FORMATTERS_JSON_H */
