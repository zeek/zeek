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
	enum TimeFormat {
		TS_EPOCH,	// Doubles that represents seconds from the UNIX epoch.
		TS_ISO8601,	// ISO 8601 defined human readable timestamp format.
		TS_MILLIS	// Milliseconds from the UNIX epoch.  Some consumers need this (e.g., elasticsearch).
		};

	/**
	 * Constructor.
	 *
	 * @param t The thread that uses this class instance. The class uses
	 * some of the thread's methods, e.g., for error reporting and
	 * internal formatting.
	 *
	 * @param tf TimeFormat The format to use for time fields.
	 *
	 * #@param size_limit_hint Specifies a maximum size that shouldn't be
	 * significantly exceeded for the final JSON representation of a log
	 * entry. If necessary the formatter will truncate the data. It's not
	 * a hard limit though, the result might still be slightly larger
	 * than the limit. It will remain a syntactically valid log entry,
	 * even if truncated. Set to zero to disable any truncation.
	 */
	JSON(threading::MsgThread* t, TimeFormat tf, unsigned int size_limit_hint = 0);
	virtual ~JSON();

	virtual bool Describe(ODesc* desc, threading::Value* val, const string& name = "") const;
	virtual bool Describe(ODesc* desc, int num_fields, const threading::Field* const * fields,
	                      threading::Value** vals) const;
	virtual threading::Value* ParseValue(const string& s, const string& name, TypeTag type, TypeTag subtype = TYPE_ERROR) const;

	void SurroundingBraces(bool use_braces);

private:
	bool DescribeInternal(ODesc* desc, Value* val, const string& name, const string& last_name, std::vector<std::string>* ptruncated) const;

	TimeFormat timestamps;
	bool surrounding_braces;
	unsigned int size_limit_hint;
};

}}

#endif /* THREADING_FORMATTERS_JSON_H */
