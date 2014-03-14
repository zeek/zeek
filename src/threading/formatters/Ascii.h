// See the file "COPYING" in the main distribution directory for copyright.

#ifndef THREADING_FORMATTERS_ASCII_H
#define THREADING_FORMATTERS_ASCII_H

#include "../Formatter.h"

namespace threading { namespace formatter {

class Ascii : public Formatter {
public:
	/**
	 * A struct to pass the necessary configuration values to the
	 * Ascii module on initialization.
	 */
	struct SeparatorInfo
		{
		string separator;		// Separator between columns
		string set_separator;	// Separator between set elements.
		string unset_field;	// String marking an unset field.
		string empty_field;	// String marking an empty (but set) field.

		/**
		 * Constructor that defines all the configuration options.
		 * Use if you need either ValToODesc or EntryToVal.
		 */
		SeparatorInfo(const string& separator, const string& set_separator, const string& unset_field, const string& empty_field);

		/**
		 * Constructor that leaves separators etc unset to dummy
		 * values. Useful if you use only methods that don't need any
		 * of them, like StringToAddr, etc.
		 */
		SeparatorInfo();
		};

	/**
	 * Constructor.
	 *
	 * @param t The thread that uses this class instance. The class uses
	 * some of the thread's methods, e.g., for error reporting and
	 * internal formatting.
	 *
	 * @param info SeparatorInfo structure defining the necessary
	 * separators.
	 */
	Ascii(threading::MsgThread* t, const SeparatorInfo& info);
	virtual ~Ascii();

	virtual bool Describe(ODesc* desc, threading::Value* val, const string& name = "") const;
	virtual bool Describe(ODesc* desc, int num_fields, const threading::Field* const * fields,
	                      threading::Value** vals) const;
	virtual threading::Value* ParseValue(const string& s, const string& name, TypeTag type, TypeTag subtype = TYPE_ERROR) const;

private:
	bool CheckNumberError(const char* start, const char* end) const;

	SeparatorInfo separators;
};

}}

#endif /* THREADING_FORMATTERS_ASCII_H */
