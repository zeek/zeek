// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/Type.h"
#include "zeek/threading/SerialTypes.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(MsgThread, zeek, threading);

namespace zeek::threading {

/**
  * A thread-safe class for converting values into some textual format. This
  * is a base class that implements the interface for common
  * rendering/parsing code needed by a number of input/output threads.
  */
class Formatter {
public:
	/**
	 * Constructor.
	 *
	 * @param t The thread that uses this class instance. The class uses
	 * some of the thread's methods, e.g., for error reporting and
	 * internal formatting.
	 *
	 */
	explicit Formatter(MsgThread* t);

	/**
	 * Destructor.
	 */
	virtual ~Formatter();

	/**
	 * Convert a list of threading values into an implementation specific
	 * textual representation.
	 *
	 * @param desc The ODesc object to write to.
	 *
	 * @param num_fields The number of fields in the logging record.
	 *
	 * @param fields Information about the fields for each of the given
	 * log values.
	 *
	 * @param vals The field values.
	 *
	 * @return Returns true on success, false on error. Errors must also
	 * be flagged via the thread.
	 */
	virtual bool Describe(ODesc* desc, int num_fields, const Field* const * fields,
	                      Value** vals) const = 0;

	/**
	 * Convert a single threading value into an implementation-specific
	 * representation.
	 *
	 * @param desc The ODesc object to write to.
	 *
	 * @param val the Value to render to the ODesc object.
	 *
	 * @param The name of a field associated with the value.
	 *
	 * @return Returns true on success, false on error. Errors are also
	 * flagged via the thread.
	 */
	virtual bool Describe(ODesc* desc, Value* val, const std::string& name = "") const = 0;

	/**
	 * Convert an implementation-specific textual representation of a
	 * field into a value.
	 *
	 * @param s The string to parse.
	 *
	 * @param The name of a field associated with the value. Used only
	 * for error reporting.
	 *
	 * @return The new value, or null on error. Errors must also be
	 * flagged via the thread.
	 */
	virtual Value* ParseValue(const std::string& s, const std::string& name, TypeTag type,
	                          TypeTag subtype = TYPE_ERROR) const = 0;

	/**
	 * Convert an IP address into a string.
	 *
	 * This is a helper function that formatter implementations may use.
	 *
	 * @param addr The address.
	 *
	 * @return An ASCII representation of the address.
	 */
	static std::string Render(const Value::addr_t& addr);

	/**
	 * Convert an subnet value into a string.
	 *
	 * This is a helper function that formatter implementations may use.
	 *
	 * @param addr The address.
	 *
	 * @return An ASCII representation of the subnet.
	 */
	static std::string Render(const Value::subnet_t& subnet);

	/**
	 * Convert a double into a string. This renders the double with Bro's
	 * standard precision.
	 *
	 * This is a helper function that formatter implementations may use.
	 *
	 * @param d The double.
	 *
	 * @return An ASCII representation of the double.
	 */
	static std::string Render(double d);

	/**
	 * Convert a transport protocol into a string.
	 *
	 * This is a helper function that formatter implementations may use.
	 *
	 * @param proto The transport protocol.
	 *
	 * @return An ASCII representation of the protocol.
	 */
	static std::string Render(TransportProto proto);

	/**
	 * Convert a string into a TransportProto. The string must be one of
	 * \c tcp, \c udp, \c icmp, or \c unknown.
	 *
	 * This is a helper function that formatter implementations may use.
	 *
	 * @param proto The transport protocol
	 *
	 * @return The transport protocol, which will be \c TRANSPORT_UNKNOWN
	 * on error. Errors are also flagged via the thread.
	 */
	TransportProto ParseProto(const std::string &proto) const;

	/**
	 * Convert a string into a Value::addr_t.
	 *
	 * This is a helper function that formatter implementations may use.
	 *
	 * @param addr String containing an IPv4 or IPv6 address.
	 *
	 * @return The address, which will be all-zero on error. Errors are
	 * also flagged via the thread.
	 */
	Value::addr_t ParseAddr(const std::string &addr) const;

protected:
	/**
	 * Returns the thread associated with the formatter via the
	 * constructor.
	 */
	MsgThread* GetThread() const	{ return thread; }

private:
	MsgThread* thread;
};

} // namespace zeek::threading
