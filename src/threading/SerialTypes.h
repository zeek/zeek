
#ifndef THREADING_SERIALIZATIONTYPES_H
#define THREADING_SERIALIZATIONTYPES_H

using namespace std;

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "Type.h"
#include "net_util.h"

class SerializationFormat;

namespace threading {

/**
 * Definition of a log file, i.e., one column of a log stream.
 */
struct Field {
	string name;	//! Name of the field.
	TypeTag type;	//! Type of the field.
	TypeTag subtype;	//! Inner type for sets.

	/**
	 * Constructor.
	 */
	Field() 	{ subtype = TYPE_VOID; }

	/**
	 * Copy constructor.
	 */
	Field(const Field& other)
		: name(other.name), type(other.type), subtype(other.subtype) {  }

	/**
	 * Unserializes a field.
	 *
	 * @param fmt The serialization format to use. The format handles
	 * low-level I/O.
	 *
	 * @return False if an error occured.
	 */
	bool Read(SerializationFormat* fmt);

	/**
	 * Serializes a field.
	 *
	 * @param fmt The serialization format to use. The format handles
	 * low-level I/O.
	 *
	 * @return False if an error occured.
	 */
	bool Write(SerializationFormat* fmt) const;
};

/**
 * Definition of a log value, i.e., a entry logged by a stream.
 *
 * This struct essentialy represents a serialization of a Val instance (for
 * those Vals supported).
 */
struct Value {
	TypeTag type;	//! The type of the value.
	bool present;	//! False for optional record fields that are not set.

	struct set_t { bro_int_t size; Value** vals; };
	typedef set_t vec_t;
	struct port_t { bro_uint_t port; TransportProto proto; };

        struct addr_t {
		IPFamily family;
		union {
			struct in_addr in4;
			struct in6_addr in6;
		} in;
	};

	struct subnet_t { addr_t prefix; uint8_t length; };

	/**
	 * This union is a subset of BroValUnion, including only the types we
	 * can log directly. See IsCompatibleType().
	 */
	union _val {
		bro_int_t int_val;
		bro_uint_t uint_val;
		port_t port_val;
		double double_val;
		set_t set_val;
		vec_t vector_val;
		addr_t addr_val;
		subnet_t subnet_val;
		string* string_val;
	} val;

	/**
	* Constructor.
	*
	* arg_type: The type of the value.
	*
	* arg_present: False if the value represents an optional record field
	* that is not set.
	 */
	Value(TypeTag arg_type = TYPE_ERROR, bool arg_present = true)
		: type(arg_type), present(arg_present)	{}

	/**
	 * Destructor.
	 */
	~Value();

	/**
	 * Unserializes a value.
	 *
	 * @param fmt The serialization format to use. The format handles low-level I/O.
	 *
	 * @return False if an error occured.
	 */
	bool Read(SerializationFormat* fmt);

	/**
	 * Serializes a value.
	 *
	 * @param fmt The serialization format to use. The format handles
	 * low-level I/O.
	 *
	 * @return False if an error occured.
	 */
	bool Write(SerializationFormat* fmt) const;

	/**
	 * Returns true if the type can be represented by a Value. If
	 * `atomic_only` is true, will not permit composite types.
	 */
	static bool IsCompatibleType(BroType* t, bool atomic_only=false);

private:
friend class ::IPAddr;
	Value(const Value& other)	{ } // Disabled.
};

}

#endif /* THREADING_SERIALIZATIONTZPES_H */
