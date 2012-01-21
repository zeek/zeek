#ifndef LOGBASE_H
#define LOGBASE_H

#include "Val.h"
#include "Type.h"

class SerializationFormat;

// Description of a log field.
struct LogField {
	string name;
	TypeTag type;
	// inner type of sets
	TypeTag subtype;

	LogField() 	{ subtype = TYPE_VOID; }
	LogField(const LogField& other)
		: name(other.name), type(other.type), subtype(other.subtype) {  }

	// (Un-)serialize.
	bool Read(SerializationFormat* fmt);
	bool Write(SerializationFormat* fmt) const;
};

// Values as logged by a writer.
struct LogVal {
	TypeTag type;
	bool present; // False for unset fields.

	// The following union is a subset of BroValUnion, including only the
	// types we can log directly.
	struct set_t { bro_int_t size; LogVal** vals; };
	typedef set_t vec_t;

	union _val {
		bro_int_t int_val;
		bro_uint_t uint_val;
		uint32 addr_val[NUM_ADDR_WORDS];
		subnet_type subnet_val;
		double double_val;
		string* string_val;
		set_t set_val;
		vec_t vector_val;
	} val;

	LogVal(TypeTag arg_type = TYPE_ERROR, bool arg_present = true)
		: type(arg_type), present(arg_present)	{}
	~LogVal();

	// (Un-)serialize.
	bool Read(SerializationFormat* fmt);
	bool Write(SerializationFormat* fmt) const;

	// Returns true if the type can be logged the framework. If
	// `atomic_only` is true, will not permit composite types.
	static bool IsCompatibleType(BroType* t, bool atomic_only=false);

private:
	LogVal(const LogVal& other)	{ }
};

#endif
