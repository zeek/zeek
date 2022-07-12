// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/threading/SerialTypes.h"

#include "zeek/Reporter.h"
#include "zeek/SerializationFormat.h"
// The following are required for ValueToVal.
#include "zeek/Expr.h"
#include "zeek/ID.h"
#include "zeek/IPAddr.h"
#include "zeek/RE.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/module_util.h"

namespace zeek::threading
	{

bool Field::Read(detail::SerializationFormat* fmt)
	{
	int t;
	int st;
	std::string tmp_name;
	bool have_2nd;

	if ( ! fmt->Read(&have_2nd, "have_2nd") )
		return false;

	if ( have_2nd )
		{
		std::string tmp_secondary_name;
		if ( ! fmt->Read(&tmp_secondary_name, "secondary_name") )
			return false;

		secondary_name = util::copy_string(tmp_secondary_name.c_str());
		}
	else
		secondary_name = nullptr;

	bool success = (fmt->Read(&tmp_name, "name") && fmt->Read(&t, "type") &&
	                fmt->Read(&st, "subtype") && fmt->Read(&optional, "optional"));

	if ( ! success )
		return false;

	name = util::copy_string(tmp_name.c_str());

	type = static_cast<TypeTag>(t);
	subtype = static_cast<TypeTag>(st);

	return true;
	}

bool Field::Write(detail::SerializationFormat* fmt) const
	{
	assert(name);

	if ( secondary_name )
		{
		if ( ! (fmt->Write(true, "have_2nd") && fmt->Write(secondary_name, "secondary_name")) )
			return false;
		}
	else if ( ! fmt->Write(false, "have_2nd") )
		return false;

	return (fmt->Write(name, "name") && fmt->Write((int)type, "type") &&
	            fmt->Write((int)subtype, "subtype"),
	        fmt->Write(optional, "optional"));
	}

std::string Field::TypeName() const
	{
	std::string n;

	// We do not support tables, if the internal Zeek type is table it
	// always is a set.
	if ( type == TYPE_TABLE )
		n = "set";
	else
		n = type_name(type);

	if ( (type == TYPE_TABLE) || (type == TYPE_VECTOR) )
		{
		n += "[";
		n += type_name(subtype);
		n += "]";
		}

	return n;
	}

Value::~Value()
	{
	if ( ! present )
		return;

	if ( type == TYPE_ENUM || type == TYPE_STRING || type == TYPE_FILE || type == TYPE_FUNC )
		delete[] val.string_val.data;

	else if ( type == TYPE_PATTERN )
		delete[] val.pattern_text_val;

	else if ( type == TYPE_TABLE )
		{
		for ( zeek_int_t i = 0; i < val.set_val.size; i++ )
			delete val.set_val.vals[i];

		delete[] val.set_val.vals;
		}

	else if ( type == TYPE_VECTOR )
		{
		for ( zeek_int_t i = 0; i < val.vector_val.size; i++ )
			delete val.vector_val.vals[i];

		delete[] val.vector_val.vals;
		}
	}

bool Value::IsCompatibleType(Type* t, bool atomic_only)
	{
	if ( ! t )
		return false;

	switch ( t->Tag() )
		{
		case TYPE_BOOL:
		case TYPE_INT:
		case TYPE_COUNT:
		case TYPE_PORT:
		case TYPE_SUBNET:
		case TYPE_ADDR:
		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
		case TYPE_ENUM:
		case TYPE_STRING:
		case TYPE_FILE:
		case TYPE_FUNC:
			return true;

		case TYPE_RECORD:
			return ! atomic_only;

		case TYPE_TABLE:
			{
			if ( atomic_only )
				return false;

			if ( ! t->IsSet() )
				return false;

			return IsCompatibleType(t->AsSetType()->GetIndices()->GetPureType().get(), true);
			}

		case TYPE_VECTOR:
			{
			if ( atomic_only )
				return false;

			return IsCompatibleType(t->AsVectorType()->Yield().get(), true);
			}

		default:
			return false;
		}

	return false;
	}

bool Value::Read(detail::SerializationFormat* fmt)
	{
	int ty, sty;

	if ( ! (fmt->Read(&ty, "type") && fmt->Read(&sty, "subtype") &&
	        fmt->Read(&present, "present")) )
		return false;

	type = static_cast<TypeTag>(ty);
	subtype = static_cast<TypeTag>(sty);

	if ( ! present )
		return true;

	switch ( type )
		{
		case TYPE_BOOL:
		case TYPE_INT:
			return fmt->Read(&val.int_val, "int");

		case TYPE_COUNT:
			return fmt->Read(&val.uint_val, "uint");

		case TYPE_PORT:
			{
			int proto;
			if ( ! (fmt->Read(&val.port_val.port, "port") && fmt->Read(&proto, "proto")) )
				{
				return false;
				}

			switch ( proto )
				{
				case 0:
					val.port_val.proto = TRANSPORT_UNKNOWN;
					break;
				case 1:
					val.port_val.proto = TRANSPORT_TCP;
					break;
				case 2:
					val.port_val.proto = TRANSPORT_UDP;
					break;
				case 3:
					val.port_val.proto = TRANSPORT_ICMP;
					break;
				default:
					return false;
				}

			return true;
			}

		case TYPE_ADDR:
			{
			char family;

			if ( ! fmt->Read(&family, "addr-family") )
				return false;

			switch ( family )
				{
				case 4:
					val.addr_val.family = IPv4;
					return fmt->Read(&val.addr_val.in.in4, "addr-in4");

				case 6:
					val.addr_val.family = IPv6;
					return fmt->Read(&val.addr_val.in.in6, "addr-in6");
				}

			// Can't be reached.
			abort();
			}

		case TYPE_SUBNET:
			{
			char length;
			char family;

			if ( ! (fmt->Read(&length, "subnet-len") && fmt->Read(&family, "subnet-family")) )
				return false;

			switch ( family )
				{
				case 4:
					val.subnet_val.length = (uint8_t)length;
					val.subnet_val.prefix.family = IPv4;
					return fmt->Read(&val.subnet_val.prefix.in.in4, "subnet-in4");

				case 6:
					val.subnet_val.length = (uint8_t)length;
					val.subnet_val.prefix.family = IPv6;
					return fmt->Read(&val.subnet_val.prefix.in.in6, "subnet-in6");
				}

			// Can't be reached.
			abort();
			}

		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
			return fmt->Read(&val.double_val, "double");

		case TYPE_ENUM:
		case TYPE_STRING:
		case TYPE_FILE:
		case TYPE_FUNC:
			return fmt->Read(&val.string_val.data, &val.string_val.length, "string");

		case TYPE_TABLE:
			{
			if ( ! fmt->Read(&val.set_val.size, "set_size") )
				return false;

			val.set_val.vals = new Value*[val.set_val.size];

			for ( zeek_int_t i = 0; i < val.set_val.size; ++i )
				{
				val.set_val.vals[i] = new Value;

				if ( ! val.set_val.vals[i]->Read(fmt) )
					return false;
				}

			return true;
			}

		case TYPE_VECTOR:
			{
			if ( ! fmt->Read(&val.vector_val.size, "vector_size") )
				return false;

			val.vector_val.vals = new Value*[val.vector_val.size];

			for ( zeek_int_t i = 0; i < val.vector_val.size; ++i )
				{
				val.vector_val.vals[i] = new Value;

				if ( ! val.vector_val.vals[i]->Read(fmt) )
					return false;
				}

			return true;
			}

		default:
			reporter->InternalError("unsupported type %s in Value::Read", type_name(type));
		}

	return false;
	}

bool Value::Write(detail::SerializationFormat* fmt) const
	{
	if ( ! (fmt->Write((int)type, "type") && fmt->Write((int)subtype, "subtype") &&
	        fmt->Write(present, "present")) )
		return false;

	if ( ! present )
		return true;

	switch ( type )
		{
		case TYPE_BOOL:
		case TYPE_INT:
			return fmt->Write(val.int_val, "int");

		case TYPE_COUNT:
			return fmt->Write(val.uint_val, "uint");

		case TYPE_PORT:
			return fmt->Write(val.port_val.port, "port") && fmt->Write(val.port_val.proto, "proto");

		case TYPE_ADDR:
			{
			switch ( val.addr_val.family )
				{
				case IPv4:
					return fmt->Write((char)4, "addr-family") &&
					       fmt->Write(val.addr_val.in.in4, "addr-in4");

				case IPv6:
					return fmt->Write((char)6, "addr-family") &&
					       fmt->Write(val.addr_val.in.in6, "addr-in6");
				}

			// Can't be reached.
			abort();
			}

		case TYPE_SUBNET:
			{
			if ( ! fmt->Write((char)val.subnet_val.length, "subnet-length") )
				return false;

			switch ( val.subnet_val.prefix.family )
				{
				case IPv4:
					return fmt->Write((char)4, "subnet-family") &&
					       fmt->Write(val.subnet_val.prefix.in.in4, "subnet-in4");

				case IPv6:
					return fmt->Write((char)6, "subnet-family") &&
					       fmt->Write(val.subnet_val.prefix.in.in6, "subnet-in6");
				}

			// Can't be reached.
			abort();
			}

		case TYPE_DOUBLE:
		case TYPE_TIME:
		case TYPE_INTERVAL:
			return fmt->Write(val.double_val, "double");

		case TYPE_ENUM:
		case TYPE_STRING:
		case TYPE_FILE:
		case TYPE_FUNC:
			return fmt->Write(val.string_val.data, val.string_val.length, "string");

		case TYPE_TABLE:
			{
			if ( ! fmt->Write(val.set_val.size, "set_size") )
				return false;

			for ( int i = 0; i < val.set_val.size; ++i )
				{
				if ( ! val.set_val.vals[i]->Write(fmt) )
					return false;
				}

			return true;
			}

		case TYPE_VECTOR:
			{
			if ( ! fmt->Write(val.vector_val.size, "vector_size") )
				return false;

			for ( int i = 0; i < val.vector_val.size; ++i )
				{
				if ( ! val.vector_val.vals[i]->Write(fmt) )
					return false;
				}

			return true;
			}

		default:
			reporter->InternalError("unsupported type %s in Value::Write", type_name(type));
		}

	// unreachable
	return false;
	}

void Value::delete_value_ptr_array(Value** vals, int num_fields)
	{
	for ( int i = 0; i < num_fields; ++i )
		delete vals[i];

	delete[] vals;
	}

Val* Value::ValueToVal(const std::string& source, const Value* val, bool& have_error)
	{
	if ( have_error )
		return nullptr;

	if ( ! val->present )
		return nullptr; // unset field

	switch ( val->type )
		{
		case TYPE_BOOL:
			return val_mgr->Bool(val->val.int_val)->Ref();

		case TYPE_INT:
			return val_mgr->Int(val->val.int_val).release();

		case TYPE_COUNT:
			return val_mgr->Count(val->val.int_val).release();

		case TYPE_DOUBLE:
			return new DoubleVal(val->val.double_val);

		case TYPE_TIME:
			return new TimeVal(val->val.double_val);

		case TYPE_INTERVAL:
			return new IntervalVal(val->val.double_val);

		case TYPE_STRING:
			{
			auto* s = new String((const u_char*)val->val.string_val.data,
			                     val->val.string_val.length, true);
			return new StringVal(s);
			}

		case TYPE_PORT:
			return val_mgr->Port(val->val.port_val.port, val->val.port_val.proto)->Ref();

		case TYPE_ADDR:
			{
			IPAddr* addr = nullptr;
			switch ( val->val.addr_val.family )
				{
				case IPv4:
					addr = new IPAddr(val->val.addr_val.in.in4);
					break;

				case IPv6:
					addr = new IPAddr(val->val.addr_val.in.in6);
					break;

				default:
					assert(false);
				}

			auto* addrval = new AddrVal(*addr);
			delete addr;
			return addrval;
			}

		case TYPE_SUBNET:
			{
			IPAddr* addr = nullptr;
			switch ( val->val.subnet_val.prefix.family )
				{
				case IPv4:
					addr = new IPAddr(val->val.subnet_val.prefix.in.in4);
					break;

				case IPv6:
					addr = new IPAddr(val->val.subnet_val.prefix.in.in6);
					break;

				default:
					assert(false);
				}

			auto* subnetval = new SubNetVal(*addr, val->val.subnet_val.length);
			delete addr;
			return subnetval;
			}

		case TYPE_PATTERN:
			{
			auto* re = new RE_Matcher(val->val.pattern_text_val);
			re->Compile();
			return new PatternVal(re);
			}

		case TYPE_TABLE:
			{
			TypeListPtr set_index;
			if ( val->val.set_val.size == 0 &&
			     (val->subtype == TYPE_VOID || val->subtype == TYPE_ENUM) )
				// don't know type - unspecified table.
				set_index = make_intrusive<TypeList>();
			else
				{
				// all entries have to have the same type...
				TypeTag stag = val->subtype;
				if ( stag == TYPE_VOID )
					stag = val->val.set_val.vals[0]->type;

				TypePtr index_type;

				if ( stag == TYPE_ENUM )
					{
					// Enums are not a base-type, so need to look it up.
					const auto& sv = val->val.set_val.vals[0]->val.string_val;
					std::string enum_name(sv.data, sv.length);
					const auto& enum_id = detail::global_scope()->Find(enum_name);

					if ( ! enum_id )
						{
						reporter->Warning("Value '%s' of source '%s' is not a valid enum.",
						                  enum_name.data(), source.c_str());

						have_error = true;
						return nullptr;
						}

					index_type = enum_id->GetType();
					}
				else
					index_type = base_type(stag);

				set_index = make_intrusive<TypeList>(index_type);
				set_index->Append(std::move(index_type));
				}

			auto s = make_intrusive<SetType>(std::move(set_index), nullptr);
			auto t = make_intrusive<TableVal>(std::move(s));
			for ( int j = 0; j < val->val.set_val.size; j++ )
				{
				Val* assignval = ValueToVal(source, val->val.set_val.vals[j], have_error);
				if ( have_error )
					return nullptr;

				t->Assign({AdoptRef{}, assignval}, nullptr);
				}

			return t.release();
			}

		case TYPE_VECTOR:
			{
			TypePtr type;

			if ( val->val.vector_val.size == 0 &&
			     (val->subtype == TYPE_VOID || val->subtype == TYPE_ENUM) )
				// don't know type - unspecified table.
				type = base_type(TYPE_ANY);
			else
				{
				// all entries have to have the same type...
				if ( val->subtype == TYPE_VOID )
					type = base_type(val->val.vector_val.vals[0]->type);
				else if ( val->subtype == TYPE_ENUM )
					{
					// Enums are not a base-type, so need to look it up.
					const auto& sv = val->val.vector_val.vals[0]->val.string_val;
					std::string enum_name(sv.data, sv.length);
					const auto& enum_id = detail::global_scope()->Find(enum_name);

					if ( ! enum_id )
						{
						reporter->Warning("Value '%s' of source '%s' is not a valid enum.",
						                  enum_name.data(), source.c_str());

						have_error = true;
						return nullptr;
						}

					type = enum_id->GetType();
					}
				else
					type = base_type(val->subtype);
				}

			auto vt = make_intrusive<VectorType>(std::move(type));
			auto v = make_intrusive<VectorVal>(std::move(vt));

			for ( int j = 0; j < val->val.vector_val.size; j++ )
				{
				auto el = ValueToVal(source, val->val.vector_val.vals[j], have_error);
				if ( have_error )
					return nullptr;

				v->Assign(j, {AdoptRef{}, el});
				}

			return v.release();
			}

		case TYPE_ENUM:
			{
			// Convert to string first to not have to deal with missing
			// \0's...
			std::string enum_string(val->val.string_val.data, val->val.string_val.length);

			// let's try looking it up by global ID.
			const auto& id = detail::lookup_ID(enum_string.c_str(), detail::GLOBAL_MODULE_NAME);

			if ( ! id || ! id->IsEnumConst() )
				{
				reporter->Warning("Value '%s' for source '%s' is not a valid enum.",
				                  enum_string.c_str(), source.c_str());

				have_error = true;
				return nullptr;
				}

			EnumType* t = id->GetType()->AsEnumType();
			int intval = t->Lookup(id->ModuleName(), id->Name());
			if ( intval < 0 )
				{
				reporter->Warning("Enum value '%s' for source '%s' not found.", enum_string.c_str(),
				                  source.c_str());

				have_error = true;
				return nullptr;
				}

			auto rval = t->GetEnumVal(intval);
			return rval.release();
			}

		default:
			reporter->InternalError("Unsupported type in SerialTypes::ValueToVal from source %s",
			                        source.c_str());
		}

	assert(false);
	return nullptr;
	}

	} // namespace zeek::threading
