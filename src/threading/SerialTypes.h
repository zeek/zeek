
#ifndef THREADING_SERIALIZATIONTYPES_H
#define THREADING_SERIALIZATIONTYPES_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "Type.h"
#include "net_util.h"

using namespace std;

class SerializationFormat;
class RemoteSerializer;

namespace threading {

/**
 * Definition of a log file, i.e., one column of a log stream.
 */
struct Field {
	const char* name;	//! Name of the field.
	//! Needed by input framework. Port fields have two names (one for the
	//! port, one for the type), and this specifies the secondary name.
	const char* secondary_name;
	TypeTag type;	//! Type of the field.
	TypeTag subtype;	//! Inner type for sets.
	bool optional;	//! True if field is optional.

	/**
	 * Constructor.
	 */
	Field(const char* name, const char* secondary_name, TypeTag type, TypeTag subtype, bool optional)
		: name(name ? copy_string(name) : 0),
		  secondary_name(secondary_name ? copy_string(secondary_name) : 0),
		  type(type), subtype(subtype), optional(optional)	{ }

	/**
	 * Copy constructor.
	 */
	Field(const Field& other)
		: name(other.name ? copy_string(other.name) : 0),
		  secondary_name(other.secondary_name ? copy_string(other.secondary_name) : 0),
		  type(other.type), subtype(other.subtype), optional(other.optional)	{ }

	~Field()
		{
		delete [] name;
		delete [] secondary_name;
		}

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

	/**
	 * Returns a textual description of the field's type. This method is
	 * thread-safe.
	 */
	string TypeName() const;

private:
	friend class ::RemoteSerializer;

	// Force usage of constructor above.
	Field()	{}
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

		struct {
			char* data;
			int length;
		} string_val;

		_val() { memset(this, 0, sizeof(_val)); }
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
	 * `atomic_only` is true, will not permit composite types. This
	 * method is thread-safe. */
	static bool IsCompatibleType(BroType* t, bool atomic_only=false);

private:
	friend class ::IPAddr;
	Value(const Value& other)	{ } // Disabled.
};

}

#endif /* THREADING_SERIALIZATIONTZPES_H */
