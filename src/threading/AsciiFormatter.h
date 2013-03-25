// See the file "COPYING" in the main distribution directory for copyright.

#ifndef THREADING_ASCII_FORMATTER_H
#define THREADING_ASCII_FORMATTER_H

#include "../Desc.h"
#include "MsgThread.h"

/**
  * A thread-safe class for converting values into a readable ASCII
  * representation, and vice versa. This is a utility class that factors out
  * common rendering/parsing code needed by a number of input/output threads.
  */
class AsciiFormatter {
public:
	/**
	 * A struct to pass the necessary configuration values to the
	 * AsciiFormatter module on initialization.
	 */
	struct SeparatorInfo
		{
		string set_separator;	// Separator between set elements.
		string unset_field;	// String marking an unset field.
		string empty_field;	// String marking an empty (but set) field.

		/**
		 * Constructor that leaves separators etc unset to dummy
		 * values. Useful if you use only methods that don't need any
		 * of them, like StringToAddr, etc.
		 */
		SeparatorInfo();

		/**
		 * Constructor that defines all the configuration options.
		 * Use if you need either ValToODesc or EntryToVal.
		 */
		SeparatorInfo(const string& set_separator, const string& unset_field, const string& empty_field);
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
	AsciiFormatter(threading::MsgThread* t, const SeparatorInfo info);

	/**
	 * Destructor.
	 */
	~AsciiFormatter();

	/**
	 * Convert a threading value into a corresponding ASCII.
	 * representation.
	 *
	 * @param desc The ODesc object to write to.
	 *
	 * @param val the Value to render to the ODesc object.
	 *
	 * @param The name of a field associated with the value. Used only
	 * for error reporting.
	 *
	 * @return Returns true on success, false on error. Errors are also
	 * flagged via the reporter.
	 */
	bool Describe(ODesc* desc, threading::Value* val, const string& name) const;

	/**
	 * Convert an IP address into a string.
	 *
	 * @param addr The address.
	 *
	 * @return An ASCII representation of the address.
	 */
	string Render(const threading::Value::addr_t& addr) const;

	/**
	 * Convert an subnet value into a string.
	 *
	 * @param addr The address.
	 *
	 * @return An ASCII representation of the subnet.
	 */
	string Render(const threading::Value::subnet_t& subnet) const;

	/**
	 * Convert a double into a string. This renders the double with Bro's
	 * standard precision.
	 *
	 * @param d The double.
	 *
	 * @return An ASCII representation of the double.
	 */
	string Render(double d) const;

	/**
	 * Convert the ASCII representation of a field into a value.
	 *
	 * @param s The string to parse.
	 *
	 * @param The name of a field associated with the value. Used only
	 * for error reporting.
	 *
	 * @return The new value, or null on error. Errors are also flagged
	 * via the reporter.
	 */
	threading::Value* ParseValue(string s, string name, TypeTag type, TypeTag subtype = TYPE_ERROR) const;

	/**
	 * Convert a string into a TransportProto. The string must be one of
	 * \c tcp, \c udp, \c icmp, or \c unknown.
	 *
	 * @param proto The transport protocol
	 *
	 * @return The transport protocol, which will be \c TRANSPORT_UNKNOWN
	 * on error. Errors are also flagged via the reporter.
	 */
	TransportProto ParseProto(const string &proto) const;

	/**
	 * Convert a string into a Value::addr_t.
	 *
	 * @param addr String containing an IPv4 or IPv6 address.
	 *
	 * @return The address, which will be all-zero on error. Errors are
	 * also flagged via the reporter.
	 */
	threading::Value::addr_t ParseAddr(const string &addr) const;

private:
	bool CheckNumberError(const string& s, const char * end) const;

	SeparatorInfo separators;
	threading::MsgThread* thread;
};

#endif /* THREADING_ASCII_FORMATTER_H */
