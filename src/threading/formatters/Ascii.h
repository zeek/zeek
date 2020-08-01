// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "../Formatter.h"

namespace zeek::threading::formatter {

class Ascii final : public zeek::threading::Formatter {
public:
	/**
	 * A struct to pass the necessary configuration values to the
	 * Ascii module on initialization.
	 */
	struct SeparatorInfo
		{
		std::string separator;		// Separator between columns
		std::string set_separator;	// Separator between set elements.
		std::string unset_field;	// String marking an unset field.
		std::string empty_field;	// String marking an empty (but set) field.

		/**
		 * Constructor that defines all the configuration options.
		 * Use if you need either ValToODesc or EntryToVal.
		 */
		SeparatorInfo(const std::string& separator, const std::string& set_separator,
		              const std::string& unset_field, const std::string& empty_field);

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
	Ascii(zeek::threading::MsgThread* t, const SeparatorInfo& info);
	virtual ~Ascii();

	virtual bool Describe(zeek::ODesc* desc, zeek::threading::Value* val, const std::string& name = "") const;
	virtual bool Describe(zeek::ODesc* desc, int num_fields, const zeek::threading::Field* const * fields,
	                      zeek::threading::Value** vals) const;
	virtual zeek::threading::Value* ParseValue(const std::string& s, const std::string& name,
	                                           zeek::TypeTag type, zeek::TypeTag subtype = zeek::TYPE_ERROR) const;

private:
	bool CheckNumberError(const char* start, const char* end) const;

	SeparatorInfo separators;
};

} // namespace zeek::threading::formatter

namespace threading::formatter {
	using Ascii [[deprecated("Remove in v4.1. Use zeek::threading::formatter::Ascii.")]] = zeek::threading::formatter::Ascii;
}
