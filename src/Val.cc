// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <sys/types.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

#include "Val.h"
#include "Net.h"
#include "File.h"
#include "Func.h"
#include "RE.h"
#include "Scope.h"
#include "NetVar.h"
#include "Expr.h"
#include "Serializer.h"
#include "PrefixTable.h"
#include "Conn.h"
#include "Reporter.h"
#include "IPAddr.h"

#include "broker/Data.h"

Val::Val(Func* f)
	{
	val.func_val = f;
	::Ref(val.func_val);
	type = f->FType()->Ref();
#ifdef DEBUG
	bound_id = 0;
#endif
	}

Val::Val(BroFile* f)
	{
	static FileType* string_file_type = 0;
	if ( ! string_file_type )
		string_file_type = new FileType(base_type(TYPE_STRING));

	val.file_val = f;

	assert(f->FType()->Tag() == TYPE_STRING);
	type = string_file_type->Ref();

#ifdef DEBUG
	bound_id = 0;
#endif
	}

Val::~Val()
	{
	if ( type->InternalType() == TYPE_INTERNAL_STRING )
		delete val.string_val;

	else if ( type->Tag() == TYPE_FUNC )
		Unref(val.func_val);

	else if ( type->Tag() == TYPE_FILE )
		Unref(val.file_val);

	Unref(type);
#ifdef DEBUG
	delete [] bound_id;
#endif
	}

Val* Val::Clone()
	{
	Val::CloneState state;
	return Clone(&state);
	}

Val* Val::Clone(CloneState* state)
	{
	auto i = state->clones.find(this);

	if ( i != state->clones.end() )
		return i->second->Ref();

	auto c = DoClone(state);
	assert(c);

	state->clones.insert(std::make_pair(this, c));
	return c;
	}

Val* Val::DoClone(CloneState* state)
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:
	case TYPE_INTERNAL_UNSIGNED:
	case TYPE_INTERNAL_DOUBLE:
	 	// Immutable.
		return Ref();

	case TYPE_INTERNAL_OTHER:
		// Derived classes are responsible for this. Exception:
		// Functions and files. There aren't any derived classes.
		if ( type->Tag() == TYPE_FUNC )
			// Immutable.
			return Ref();

		if ( type->Tag() == TYPE_FILE )
			{
			// I think we can just ref the file here - it is unclear what else
			// to do.  In the case of cached files, I think this is equivalent
			// to what happened before - serialization + unserialization just
			// have you the same pointer that you already had.  In the case of
			// non-cached files, the behavior now is different; in the past,
			// serialize + unserialize gave you a new file object because the
			// old one was not in the list anymore. This object was
			// automatically opened. This does not happen anymore - instead you
			// get the non-cached pointer back which is brought back into the
			// cache when written too.
			return Ref();
			}

		// Fall-through.

	default:
		reporter->InternalError("cloning illegal base type");
	}

	reporter->InternalError("cannot be reached");
	return nullptr;
 	}

bool Val::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Val* Val::Unserialize(UnserialInfo* info, TypeTag type, const BroType* exact_type)
	{
	Val* v = (Val*) SerialObj::Unserialize(info, SER_VAL);
	if ( ! v )
		return 0;

	if ( type != TYPE_ANY && (v->Type()->Tag() != type
		|| (exact_type && ! same_type(exact_type, v->Type()))) )
		{
		info->s->Error("type mismatch for value");
		Unref(v);
		return 0;
		}

	// For MutableVals, we may get a value which, by considering the
	// globally unique ID, we already know. To keep references correct,
	// we have to bind to the local version. (FIXME: This is not the
	// nicest solution.  Ideally, DoUnserialize() should be able to pass
	// us an alternative ptr to the correct object.)
	if ( v->IsMutableVal() )
		{
		MutableVal* mv = v->AsMutableVal();
		if ( mv->HasUniqueID() )
			{
			ID* current =
				global_scope()->Lookup(mv->UniqueID()->Name());

			if ( current && current != mv->UniqueID() )
				{
				DBG_LOG(DBG_STATE, "binding to already existing ID %s\n", current->Name());
				assert(current->ID_Val());

				// Need to unset the ID here.  Otherwise,
				// when the SerializationCache destroys
				// the value, the global name will disappear.
				mv->SetID(0);
				Unref(v);
				return current->ID_Val()->Ref();
				}
			}
		}

	// An enum may be bound to a different internal number remotely than we
	// do for the same identifier. Check if this is the case, and, if yes,
	// rebind to our value.
	if ( v->Type()->Tag() == TYPE_ENUM )
		{
		int rv = v->AsEnum();
		EnumType* rt = v->Type()->AsEnumType();

		const char* name = rt->Lookup(rv);
		if ( name )
			{
			// See if we know the enum locally.
			ID* local = global_scope()->Lookup(name);
			if ( local && local->IsEnumConst() )
				{
				EnumType* lt = local->Type()->AsEnumType();
				int lv = lt->Lookup(local->ModuleName(),
							local->Name());

				// Compare.
				if ( rv != lv )
					{
					// Different, so let's bind the val
					// to the local type.
					v->val.int_val = lv;
					Unref(rt);
					v->type = lt;
					::Ref(lt);
					}
				}
			}

		}

	return v;
	}

IMPLEMENT_SERIAL(Val, SER_VAL);

bool Val::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_VAL, BroObj);

	if ( ! type->Serialize(info) )
		return false;

	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_VOID:
		info->s->Error("type is void");
		return false;

	case TYPE_INTERNAL_INT:
		return SERIALIZE(val.int_val);

	case TYPE_INTERNAL_UNSIGNED:
		return SERIALIZE(val.uint_val);

	case TYPE_INTERNAL_DOUBLE:
		return SERIALIZE(val.double_val);

	case TYPE_INTERNAL_STRING:
		return SERIALIZE_STR((const char*) val.string_val->Bytes(),
				val.string_val->Len());

	case TYPE_INTERNAL_ADDR:
		return SERIALIZE(*val.addr_val);

	case TYPE_INTERNAL_SUBNET:
		return SERIALIZE(*val.subnet_val);

	case TYPE_INTERNAL_OTHER:
		// Derived classes are responsible for this.
		// Exception: Functions and files. There aren't any derived
		// classes.
		if ( type->Tag() == TYPE_FUNC )
			if ( ! AsFunc()->Serialize(info) )
				return false;

		if ( type->Tag() == TYPE_FILE )
			if ( ! AsFile()->Serialize(info) )
				return false;
		return true;

	case TYPE_INTERNAL_ERROR:
		info->s->Error("type is error");
		return false;

	default:
		info->s->Error("type is out of range");
		return false;
	}

	return false;
	}

bool Val::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroObj);

	if ( type )
		Unref(type);

	if ( ! (type = BroType::Unserialize(info)) )
		return false;

	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_VOID:
		info->s->Error("type is void");
		return false;

	case TYPE_INTERNAL_INT:
		return UNSERIALIZE(&val.int_val);

	case TYPE_INTERNAL_UNSIGNED:
		return UNSERIALIZE(&val.uint_val);

	case TYPE_INTERNAL_DOUBLE:
		return UNSERIALIZE(&val.double_val);

	case TYPE_INTERNAL_STRING:
		const char* str;
		int len;
		if ( ! UNSERIALIZE_STR(&str, &len) )
			return false;

		val.string_val = new BroString((u_char*) str, len, 1);
		delete [] str;
		return true;

	case TYPE_INTERNAL_ADDR:
		{
		val.addr_val = new IPAddr();
		return UNSERIALIZE(val.addr_val);
		}

	case TYPE_INTERNAL_SUBNET:
		{
		val.subnet_val = new IPPrefix();
		return UNSERIALIZE(val.subnet_val);
		}

	case TYPE_INTERNAL_OTHER:
		// Derived classes are responsible for this.
		// Exception: Functions and files. There aren't any derived
		// classes.
		if ( type->Tag() == TYPE_FUNC )
			{
			val.func_val = Func::Unserialize(info);
			return val.func_val != 0;
			}
		else if ( type->Tag() == TYPE_FILE )
			{
			val.file_val = BroFile::Unserialize(info);
			return val.file_val != 0;
			}
		return true;

	case TYPE_INTERNAL_ERROR:
		info->s->Error("type is error");
		return false;

	default:
		info->s->Error("type out of range");
		return false;
	}

	return false;
	}

int Val::IsZero() const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:		return val.int_val == 0;
	case TYPE_INTERNAL_UNSIGNED:	return val.uint_val == 0;
	case TYPE_INTERNAL_DOUBLE:	return val.double_val == 0.0;

	default:			return 0;
	}
	}

int Val::IsOne() const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:		return val.int_val == 1;
	case TYPE_INTERNAL_UNSIGNED:	return val.uint_val == 1;
	case TYPE_INTERNAL_DOUBLE:	return val.double_val == 1.0;

	default:			return 0;
	}
	}

bro_int_t Val::InternalInt() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_INT )
		return val.int_val;
	else if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		// ### should check here for overflow
		return static_cast<bro_int_t>(val.uint_val);
	else
		InternalWarning("bad request for InternalInt");

	return 0;
	}

bro_uint_t Val::InternalUnsigned() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return val.uint_val;
	else
		InternalWarning("bad request for InternalUnsigned");

	return 0;
	}

double Val::InternalDouble() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return val.double_val;
	else
		InternalWarning("bad request for InternalDouble");

	return 0.0;
	}

bro_int_t Val::CoerceToInt() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_INT )
		return val.int_val;
	else if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return static_cast<bro_int_t>(val.uint_val);
	else if ( type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return static_cast<bro_int_t>(val.double_val);
	else
		InternalWarning("bad request for CoerceToInt");

	return 0;
	}

bro_uint_t Val::CoerceToUnsigned() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return val.uint_val;
	else if ( type->InternalType() == TYPE_INTERNAL_INT )
		return static_cast<bro_uint_t>(val.int_val);
	else if ( type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return static_cast<bro_uint_t>(val.double_val);
	else
		InternalWarning("bad request for CoerceToUnsigned");

	return 0;
	}

double Val::CoerceToDouble() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return val.double_val;
	else if ( type->InternalType() == TYPE_INTERNAL_INT )
		return static_cast<double>(val.int_val);
	else if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return static_cast<double>(val.uint_val);
	else
		InternalWarning("bad request for CoerceToDouble");

	return 0.0;
	}

Val* Val::SizeVal() const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:
		// Return abs value. However abs() only works on ints and llabs
		// doesn't work on Mac OS X 10.5. So we do it by hand
		if ( val.int_val < 0 )
			return val_mgr->GetCount(-val.int_val);
		else
			return val_mgr->GetCount(val.int_val);

	case TYPE_INTERNAL_UNSIGNED:
		return val_mgr->GetCount(val.uint_val);

	case TYPE_INTERNAL_DOUBLE:
		return new Val(fabs(val.double_val), TYPE_DOUBLE);

	case TYPE_INTERNAL_OTHER:
		if ( type->Tag() == TYPE_FUNC )
			return val_mgr->GetCount(val.func_val->FType()->ArgTypes()->Types()->length());

		if ( type->Tag() == TYPE_FILE )
			return new Val(val.file_val->Size(), TYPE_DOUBLE);
		break;

	default:
		break;
	}

	return val_mgr->GetCount(0);
	}

unsigned int Val::MemoryAllocation() const
	{
	return padded_sizeof(*this);
	}

int Val::AddTo(Val* v, int is_first_init) const
	{
	Error("+= initializer only applies to aggregate values");
	return 0;
	}

int Val::RemoveFrom(Val* v) const
	{
	Error("-= initializer only applies to aggregate values");
	return 0;
	}

void Val::Describe(ODesc* d) const
	{
	if ( d->IsBinary() || d->IsPortable() )
		{
		type->Describe(d);
		d->SP();
		}

	ValDescribe(d);
	}

void Val::DescribeReST(ODesc* d) const
	{
	ValDescribeReST(d);
	}

void Val::ValDescribe(ODesc* d) const
	{
	if ( d->IsReadable() && type->Tag() == TYPE_BOOL )
		{
		d->Add(CoerceToInt() ? "T" : "F");
		return;
		}

	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:		d->Add(val.int_val); break;
	case TYPE_INTERNAL_UNSIGNED:	d->Add(val.uint_val); break;
	case TYPE_INTERNAL_DOUBLE:	d->Add(val.double_val); break;
	case TYPE_INTERNAL_STRING:	d->AddBytes(val.string_val); break;
	case TYPE_INTERNAL_ADDR:	d->Add(val.addr_val->AsString().c_str()); break;

	case TYPE_INTERNAL_SUBNET:
		d->Add(val.subnet_val->AsString().c_str());
		break;

	case TYPE_INTERNAL_ERROR:	d->AddCS("error"); break;
	case TYPE_INTERNAL_OTHER:
		if ( type->Tag() == TYPE_FUNC )
			AsFunc()->Describe(d);
		else if ( type->Tag() == TYPE_FILE )
			AsFile()->Describe(d);
		else if ( type->Tag() == TYPE_TYPE )
			d->Add(type->AsTypeType()->Type()->GetName());
		else
			d->Add("<no value description>");
		break;

	case TYPE_INTERNAL_VOID:
		d->Add("<void value description>");
		break;

	default:
		reporter->InternalWarning("Val description unavailable");
		d->Add("<value description unavailable>");
		break;
	}
	}

void Val::ValDescribeReST(ODesc* d) const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_OTHER:
		Describe(d);
		break;

	default:
		d->Add("``");
		ValDescribe(d);
		d->Add("``");
	}
	}

MutableVal::~MutableVal()
	{
	for ( list<ID*>::iterator i = aliases.begin(); i != aliases.end(); ++i )
		{
		if ( global_scope() )
			global_scope()->Remove((*i)->Name());
		(*i)->ClearVal();	// just to make sure.
		Unref((*i));
		}

	if ( id )
		{
		if ( global_scope() )
			global_scope()->Remove(id->Name());
		id->ClearVal(); // just to make sure.
		Unref(id);
		}
	}

bool MutableVal::AddProperties(Properties arg_props)
	{
	if ( (props | arg_props) == props )
		// No change.
		return false;

	props |= arg_props;

	if ( ! id )
		Bind();

	return true;
	}


bool MutableVal::RemoveProperties(Properties arg_props)
	{
	if ( (props & ~arg_props) == props )
		// No change.
		return false;

	props &= ~arg_props;

	return true;
	}

ID* MutableVal::Bind() const
	{
	static bool initialized = false;

	assert(!id);

	static unsigned int id_counter = 0;
	static const int MAX_NAME_SIZE = 128;
	static char name[MAX_NAME_SIZE];
	static char* end_of_static_str = 0;

	if ( ! initialized )
		{
		// Get local IP.
		char host[MAXHOSTNAMELEN];
		strcpy(host, "localhost");
		gethostname(host, MAXHOSTNAMELEN);
		host[MAXHOSTNAMELEN-1] = '\0';
#if 0
		// We ignore errors.
		struct hostent* ent = gethostbyname(host);

		uint32 ip;
		if ( ent && ent->h_addr_list[0] )
			ip = *(uint32*) ent->h_addr_list[0];
		else
			ip = htonl(0x7f000001);	// 127.0.0.1

		safe_snprintf(name, MAX_NAME_SIZE, "#%s#%d#",
			      IPAddr(IPv4, &ip, IPAddr::Network)->AsString().c_str(),
			      getpid());
#else
		safe_snprintf(name, MAX_NAME_SIZE, "#%s#%d#", host, getpid());
#endif

		end_of_static_str = name + strlen(name);

		initialized = true;
		}

	safe_snprintf(end_of_static_str, MAX_NAME_SIZE - (end_of_static_str - name),
		      "%u", ++id_counter);
	name[MAX_NAME_SIZE-1] = '\0';

//	DBG_LOG(DBG_STATE, "new unique ID %s", name);

	id = new ID(name, SCOPE_GLOBAL, true);
	id->SetType(const_cast<MutableVal*>(this)->Type()->Ref());

	global_scope()->Insert(name, id);

	id->SetVal(const_cast<MutableVal*>(this), OP_NONE, true);

	return id;
	}

void MutableVal::TransferUniqueID(MutableVal* mv)
	{
	const char* new_name = mv->UniqueID()->Name();

	if ( ! id )
		Bind();

	DBG_LOG(DBG_STATE, "transfering ID (new %s, old/alias %s)", new_name, id->Name());

	// Keep old name as alias.
	aliases.push_back(id);

	id = new ID(new_name, SCOPE_GLOBAL, true);
	id->SetType(const_cast<MutableVal*>(this)->Type()->Ref());
	global_scope()->Insert(new_name, id);
	id->SetVal(const_cast<MutableVal*>(this), OP_NONE, true);

	Unref(mv->id);
	mv->id = 0;
	}

IMPLEMENT_SERIAL(MutableVal, SER_MUTABLE_VAL);

bool MutableVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_MUTABLE_VAL, Val);

	if ( ! SERIALIZE(props) )
		return false;

	// Don't use ID::Serialize here, that would loop.  All we
	// need is the name, anyway.
	const char* name = id ? id->Name() : "";
	if ( ! SERIALIZE(name) )
		return false;

	return true;
	}

bool MutableVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);

	if ( ! UNSERIALIZE(&props) )
		 return false;

	id = 0;

	const char* name;
	if ( ! UNSERIALIZE_STR(&name, 0) )
		return false;

	if ( *name )
		{
		id = new ID(name, SCOPE_GLOBAL, true);
		id->SetVal(this, OP_NONE, true);

		ID* current = global_scope()->Lookup(name);
		if ( ! current )
			{
			global_scope()->Insert(name, id);
			DBG_LOG(DBG_STATE, "installed formerly unknown ID %s", id->Name());
			}
		else
			{
			DBG_LOG(DBG_STATE, "got already known ID %s", current->Name());
			// This means that we already know the value and
			// that in fact we should bind to the local value.
			// Val::Unserialize() will take care of this.
			}
		}

	delete [] name;
	return true;
	}

IntervalVal::IntervalVal(double quantity, double units) :
	Val(quantity * units, TYPE_INTERVAL)
	{
	}

void IntervalVal::ValDescribe(ODesc* d) const
	{
	double v = val.double_val;

	if ( v == 0.0 )
		{
		d->Add("0 secs");
		return;
		}

	int did_one = 0;

#define DO_UNIT(unit, name) \
	if ( v >= unit || v <= -unit ) \
		{ \
		double num = double(int(v / unit)); \
		if ( num != 0.0 ) \
			{ \
			if ( did_one++ ) \
				d->SP(); \
			d->Add(num); \
			d->SP(); \
			d->Add(name); \
			if ( num != 1.0 && num != -1.0 ) \
				d->Add("s"); \
			v -= num * unit; \
			} \
		}

	DO_UNIT(Days, "day")
	DO_UNIT(Hours, "hr")
	DO_UNIT(Minutes, "min")
	DO_UNIT(Seconds, "sec")
	DO_UNIT(Milliseconds, "msec")
	DO_UNIT(Microseconds, "usec")
	}

IMPLEMENT_SERIAL(IntervalVal, SER_INTERVAL_VAL);

bool IntervalVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_INTERVAL_VAL, Val);
	return true;
	}

bool IntervalVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);
	return true;
	}

PortVal* PortManager::Get(uint32 port_num) const
	{
	return val_mgr->GetPort(port_num);
	}

PortVal* PortManager::Get(uint32 port_num, TransportProto port_type) const
	{
	return val_mgr->GetPort(port_num, port_type);
	}

uint32 PortVal::Mask(uint32 port_num, TransportProto port_type)
	{
	// Note, for ICMP one-way connections:
	// src_port = icmp_type, dst_port = icmp_code.

	if ( port_num >= 65536 )
		{
		reporter->Warning("bad port number %d", port_num);
		port_num = 0;
		}

	switch ( port_type ) {
	case TRANSPORT_TCP:
		port_num |= TCP_PORT_MASK;
		break;

	case TRANSPORT_UDP:
		port_num |= UDP_PORT_MASK;
		break;

	case TRANSPORT_ICMP:
		port_num |= ICMP_PORT_MASK;
		break;

	default:
		break;	// "unknown/other"
	}

	return port_num;
	}

PortVal::PortVal(uint32 p, TransportProto port_type) : Val(TYPE_PORT)
	{
	auto port_num = PortVal::Mask(p, port_type);
	val.uint_val = static_cast<bro_uint_t>(port_num);
	}

PortVal::PortVal(uint32 p, bool unused) : Val(TYPE_PORT)
	{
	val.uint_val = static_cast<bro_uint_t>(p);
	}

PortVal::PortVal(uint32 p) : Val(TYPE_PORT)
	{
	if ( p >= 65536 * NUM_PORT_SPACES )
		{
		InternalWarning("bad port number");
		p = 0;
		}

	val.uint_val = static_cast<bro_uint_t>(p);
	}

uint32 PortVal::Port() const
	{
	uint32 p = static_cast<uint32>(val.uint_val);
	return p & ~PORT_SPACE_MASK;
	}

int PortVal::IsTCP() const
	{
	return (val.uint_val & PORT_SPACE_MASK) == TCP_PORT_MASK;
	}

int PortVal::IsUDP() const
	{
	return (val.uint_val & PORT_SPACE_MASK) == UDP_PORT_MASK;
	}

int PortVal::IsICMP() const
	{
	return (val.uint_val & PORT_SPACE_MASK) == ICMP_PORT_MASK;
	}

void PortVal::ValDescribe(ODesc* d) const
	{
	uint32 p = static_cast<uint32>(val.uint_val);
	d->Add(p & ~PORT_SPACE_MASK);
	if ( IsUDP() )
		d->Add("/udp");
	else if ( IsTCP() )
		d->Add("/tcp");
	else if ( IsICMP() )
		d->Add("/icmp");
	else
		d->Add("/unknown");
	}

Val* PortVal::DoClone(CloneState* state)
	{
	// Immutable.
	return Ref();
	}

IMPLEMENT_SERIAL(PortVal, SER_PORT_VAL);

bool PortVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_PORT_VAL, Val);
	return true;
	}

bool PortVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);
	return true;
	}

AddrVal::AddrVal(const char* text) : Val(TYPE_ADDR)
	{
	val.addr_val = new IPAddr(text);
	}

AddrVal::AddrVal(const std::string& text) : Val(TYPE_ADDR)
	{
	val.addr_val = new IPAddr(text);
	}

AddrVal::AddrVal(uint32 addr) : Val(TYPE_ADDR)
	{
	// ### perhaps do gethostbyaddr here?
	val.addr_val = new IPAddr(IPv4, &addr, IPAddr::Network);
	}

AddrVal::AddrVal(const uint32 addr[4]) : Val(TYPE_ADDR)
	{
	val.addr_val = new IPAddr(IPv6, addr, IPAddr::Network);
	}

AddrVal::AddrVal(const IPAddr& addr) : Val(TYPE_ADDR)
	{
	val.addr_val = new IPAddr(addr);
	}

AddrVal::~AddrVal()
	{
	delete val.addr_val;
	}

unsigned int AddrVal::MemoryAllocation() const
	{
	return padded_sizeof(*this) + val.addr_val->MemoryAllocation();
	}

Val* AddrVal::SizeVal() const
	{
	if ( val.addr_val->GetFamily() == IPv4 )
		return val_mgr->GetCount(32);
	else
		return val_mgr->GetCount(128);
	}

Val* AddrVal::DoClone(CloneState* state)
	{
	// Immutable.
	return Ref();
	}

IMPLEMENT_SERIAL(AddrVal, SER_ADDR_VAL);

bool AddrVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ADDR_VAL, Val);
	return true;
	}

bool AddrVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);
	return true;
	}

SubNetVal::SubNetVal(const char* text) : Val(TYPE_SUBNET)
	{
	string s(text);
	size_t slash_loc = s.find('/');

	if ( slash_loc == string::npos )
		{
		reporter->Error("Bad string in SubNetVal ctor: %s", text);
		val.subnet_val = new IPPrefix();
		}
	else
		{
		val.subnet_val = new IPPrefix(s.substr(0, slash_loc),
		                              atoi(s.substr(slash_loc + 1).c_str()));
		}
	}

SubNetVal::SubNetVal(const char* text, int width) : Val(TYPE_SUBNET)
	{
	val.subnet_val = new IPPrefix(text, width);
	}

SubNetVal::SubNetVal(uint32 addr, int width) : Val(TYPE_SUBNET)
	{
	IPAddr a(IPv4, &addr, IPAddr::Network);
	val.subnet_val = new IPPrefix(a, width);
	}

SubNetVal::SubNetVal(const uint32* addr, int width) : Val(TYPE_SUBNET)
	{
	IPAddr a(IPv6, addr, IPAddr::Network);
	val.subnet_val = new IPPrefix(a, width);
	}

SubNetVal::SubNetVal(const IPAddr& addr, int width) : Val(TYPE_SUBNET)
	{
	val.subnet_val = new IPPrefix(addr, width);
	}

SubNetVal::SubNetVal(const IPPrefix& prefix) : Val(TYPE_SUBNET)
	{
	val.subnet_val = new IPPrefix(prefix);
	}

SubNetVal::~SubNetVal()
	{
	delete val.subnet_val;
	}

const IPAddr& SubNetVal::Prefix() const
	{
	return val.subnet_val->Prefix();
	}

int SubNetVal::Width() const
	{
	return val.subnet_val->Length();
	}

unsigned int SubNetVal::MemoryAllocation() const
	{
	return padded_sizeof(*this) + val.subnet_val->MemoryAllocation();
	}

Val* SubNetVal::SizeVal() const
	{
	int retained = 128 - val.subnet_val->LengthIPv6();
	return new Val(pow(2.0, double(retained)), TYPE_DOUBLE);
	}

void SubNetVal::ValDescribe(ODesc* d) const
	{
	d->Add(string(*val.subnet_val).c_str());
	}

IPAddr SubNetVal::Mask() const
	{
	if ( val.subnet_val->Length() == 0 )
		{
		// We need to special-case a mask width of zero, since
		// the compiler doesn't guarantee that 1 << 32 yields 0.
		uint32 m[4];
		for ( unsigned int i = 0; i < 4; ++i )
			m[i] = 0;
		IPAddr rval(IPv6, m, IPAddr::Host);
		return rval;
		}

	uint32 m[4];
	uint32* mp = m;

	uint32 w;
	for ( w = val.subnet_val->Length(); w >= 32; w -= 32 )
		   *(mp++) = 0xffffffff;

	*mp = ~((1 << (32 - w)) - 1);

	while ( ++mp < m + 4 )
		   *mp = 0;

	IPAddr rval(IPv6, m, IPAddr::Host);
	return rval;
	}

bool SubNetVal::Contains(const IPAddr& addr) const
	{
	IPAddr a(addr);
	return val.subnet_val->Contains(a);
	}

Val* SubNetVal::DoClone(CloneState* state)
	{
	// Immutable.
	return Ref();
	}

IMPLEMENT_SERIAL(SubNetVal, SER_SUBNET_VAL);

bool SubNetVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_SUBNET_VAL, Val);
	return true;
	}

bool SubNetVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);
	return true;
	}

StringVal::StringVal(BroString* s) : Val(TYPE_STRING)
	{
	val.string_val = s;
	}

StringVal::StringVal(int length, const char* s) : Val(TYPE_STRING)
	{
	// The following adds a NUL at the end.
	val.string_val = new BroString((const u_char*)  s, length, 1);
	}

StringVal::StringVal(const char* s) : Val(TYPE_STRING)
	{
	val.string_val = new BroString(s);
	}

StringVal::StringVal(const string& s) : Val(TYPE_STRING)
	{
	val.string_val = new BroString(s.c_str());
	}

StringVal* StringVal::ToUpper()
	{
	val.string_val->ToUpper();
	return this;
	}

void StringVal::ValDescribe(ODesc* d) const
	{
	// Should reintroduce escapes ? ###
	if ( d->WantQuotes() )
		d->Add("\"");
	d->AddBytes(val.string_val);
	if ( d->WantQuotes() )
		d->Add("\"");
	}

unsigned int StringVal::MemoryAllocation() const
	{
	return padded_sizeof(*this) + val.string_val->MemoryAllocation();
	}

Val* StringVal::DoClone(CloneState* state)
	{
	return new StringVal(new BroString((u_char*) val.string_val->Bytes(),
	                                   val.string_val->Len(), 1));
	}

IMPLEMENT_SERIAL(StringVal, SER_STRING_VAL);

bool StringVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_STRING_VAL, Val);
	return true;
	}

bool StringVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);
	return true;
	}

PatternVal::PatternVal(RE_Matcher* re) : Val(base_type(TYPE_PATTERN))
	{
	val.re_val = re;
	}

PatternVal::~PatternVal()
	{
	delete AsPattern();
	Unref(type);	// base_type() ref'd it, so did our base constructor
	}

int PatternVal::AddTo(Val* v, int /* is_first_init */) const
	{
	if ( v->Type()->Tag() != TYPE_PATTERN )
		{
		v->Error("not a pattern");
		return 0;
		}

	PatternVal* pv = v->AsPatternVal();

	RE_Matcher* re = new RE_Matcher(AsPattern()->PatternText());
	re->AddPat(pv->AsPattern()->PatternText());
	re->Compile();

	pv->SetMatcher(re);

	return 1;
	}

void PatternVal::SetMatcher(RE_Matcher* re)
	{
	delete AsPattern();
	val.re_val = re;
	}

void PatternVal::ValDescribe(ODesc* d) const
	{
	d->Add("/");
	d->Add(AsPattern()->PatternText());
	d->Add("/");
	}

unsigned int PatternVal::MemoryAllocation() const
	{
	return padded_sizeof(*this) + val.re_val->MemoryAllocation();
	}

Val* PatternVal::DoClone(CloneState* state)
	{
	auto re = new RE_Matcher(val.re_val->PatternText(),
	                         val.re_val->AnywherePatternText());
	re->Compile();
	return new PatternVal(re);
	}

IMPLEMENT_SERIAL(PatternVal, SER_PATTERN_VAL);

bool PatternVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_PATTERN_VAL, Val);
	return AsPattern()->Serialize(info);
	}

bool PatternVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);

	val.re_val = RE_Matcher::Unserialize(info);
	return val.re_val != 0;
	}

ListVal::ListVal(TypeTag t)
: Val(new TypeList(t == TYPE_ANY ? 0 : base_type_no_ref(t)))
	{
	tag = t;
	}

ListVal::~ListVal()
	{
	loop_over_list(vals, i)
		Unref(vals[i]);
	Unref(type);
	}

RE_Matcher* ListVal::BuildRE() const
	{
	if ( tag != TYPE_STRING )
		Internal("non-string list in ListVal::IncludedInString");

	RE_Matcher* re = new RE_Matcher();
	loop_over_list(vals, i)
		{
		const char* vs = (const char*) (vals[i]->AsString()->Bytes());
		re->AddPat(vs);
		}

	return re;
	}

void ListVal::Append(Val* v)
	{
	if ( type->AsTypeList()->IsPure() )
		{
		if ( v->Type()->Tag() != tag )
			Internal("heterogeneous list in ListVal::Append");
		}

	vals.append(v);
	type->AsTypeList()->Append(v->Type()->Ref());
	}

TableVal* ListVal::ConvertToSet() const
	{
	if ( tag == TYPE_ANY )
		Internal("conversion of heterogeneous list to set");

	TypeList* set_index = new TypeList(type->AsTypeList()->PureType());
	set_index->Append(base_type(tag));
	SetType* s = new SetType(set_index, 0);
	TableVal* t = new TableVal(s);

	loop_over_list(vals, i)
		t->Assign(vals[i], 0);

	Unref(s);
	return t;
	}

void ListVal::Describe(ODesc* d) const
	{
	if ( d->IsBinary() || d->IsPortable() )
		{
		type->Describe(d);
		d->SP();
		d->Add(vals.length());
		d->SP();
		}

	loop_over_list(vals, i)
		{
		if ( i > 0 )
			{
			if ( d->IsReadable() || d->IsPortable() )
				{
				d->Add(",");
				d->SP();
				}
			}

		vals[i]->Describe(d);
		}
	}

Val* ListVal::DoClone(CloneState* state)
	{
	auto lv = new ListVal(tag);
	lv->vals.resize(vals.length());

	loop_over_list(vals, i)
		lv->Append(vals[i]->Clone(state));

	return lv;
	}

IMPLEMENT_SERIAL(ListVal, SER_LIST_VAL);

bool ListVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_LIST_VAL, Val);

	if ( ! (SERIALIZE(char(tag)) && SERIALIZE(vals.length())) )
		return false;

	loop_over_list(vals, i)
		{
		if ( ! vals[i]->Serialize(info) )
			return false;
		}

	return true;
	}

bool ListVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);

	char t;
	int len;

	if ( ! (UNSERIALIZE(&t) && UNSERIALIZE(&len)) )
		return false;

	tag = TypeTag(t);

	while ( len-- )
		{
		Val* v = Val::Unserialize(info, TYPE_ANY);
		if ( ! v )
			return false;

		vals.append(v);
		}

	// Our dtor will do Unref(type) in addition to Val's dtor.
	if ( type )
		type->Ref();

	return true;
	}

unsigned int ListVal::MemoryAllocation() const
	{
	unsigned int size = 0;
	loop_over_list(vals, i)
		size += vals[i]->MemoryAllocation();

	return size + padded_sizeof(*this) + vals.MemoryAllocation() - padded_sizeof(vals)
		+ type->MemoryAllocation();
	}


TableValTimer::TableValTimer(TableVal* val, double t) : Timer(t, TIMER_TABLE_VAL)
	{
	table = val;
	}

TableValTimer::~TableValTimer()
	{
	table->ClearTimer(this);
	}

void TableValTimer::Dispatch(double t, int is_expire)
	{
	if ( ! is_expire )
		{
		table->ClearTimer(this);
		table->DoExpire(t);
		}
	}

static void table_entry_val_delete_func(void* val)
	{
	TableEntryVal* tv = (TableEntryVal*) val;
	tv->Unref();
	delete tv;
	}

TableVal::TableVal(TableType* t, Attributes* a) : MutableVal(t)
	{
	Init(t);
	SetAttrs(a);
	}

void TableVal::Init(TableType* t)
	{
	::Ref(t);
	table_type = t;
	expire_func = 0;
	expire_time = 0;
	expire_cookie = 0;
	timer = 0;
	def_val = 0;

	if ( t->IsSubNetIndex() )
		subnets = new PrefixTable;
	else
		subnets = 0;

	table_hash = new CompositeHash(table_type->Indices());
	val.table_val = new PDict(TableEntryVal);
	val.table_val->SetDeleteFunc(table_entry_val_delete_func);
	}

TableVal::~TableVal()
	{
	if ( timer )
		timer_mgr->Cancel(timer);

	Unref(table_type);
	delete table_hash;
	delete AsTable();
	delete subnets;
	Unref(attrs);
	Unref(def_val);
	Unref(expire_func);
	Unref(expire_time);
	}

void TableVal::RemoveAll()
	{
	// Here we take the brute force approach.
	delete AsTable();
	val.table_val = new PDict(TableEntryVal);
	val.table_val->SetDeleteFunc(table_entry_val_delete_func);
	}

int TableVal::RecursiveSize() const
	{
	int n = AsTable()->Length();

	if ( Type()->IsSet() ||
	     const_cast<TableType*>(Type()->AsTableType())->YieldType()->Tag()
			!= TYPE_TABLE )
		return n;

	PDict(TableEntryVal)* v = val.table_val;
	IterCookie* c = v->InitForIteration();

	TableEntryVal* tv;
	while ( (tv = v->NextEntry(c)) )
		{
		if ( tv->Value() )
			n += tv->Value()->AsTableVal()->RecursiveSize();
		}

	return n;
	}

void TableVal::SetAttrs(Attributes* a)
	{
	attrs = a;

	if ( ! a )
		return;

	::Ref(attrs);

	CheckExpireAttr(ATTR_EXPIRE_READ);
	CheckExpireAttr(ATTR_EXPIRE_WRITE);
	CheckExpireAttr(ATTR_EXPIRE_CREATE);

	Attr* ef = attrs->FindAttr(ATTR_EXPIRE_FUNC);
	if ( ef )
		{
		expire_func = ef->AttrExpr();
		expire_func->Ref();
		}
	}

void TableVal::CheckExpireAttr(attr_tag at)
	{
	Attr* a = attrs->FindAttr(at);

	if ( a )
		{
		expire_time = a->AttrExpr();
		expire_time->Ref();

		if ( expire_time->Type()->Tag() != TYPE_INTERVAL )
			{
			if ( ! expire_time->IsError() )
				expire_time->SetError("expiration interval has wrong type");

			return;
			}

		if ( timer )
			timer_mgr->Cancel(timer);

		// As network_time is not necessarily initialized yet,
		// we set a timer which fires immediately.
		timer = new TableValTimer(this, 1);
		timer_mgr->Add(timer);
		}
	}

int TableVal::Assign(Val* index, Val* new_val, Opcode op)
	{
	HashKey* k = ComputeHash(index);
	if ( ! k )
		{
		Unref(new_val);
		index->Error("index type doesn't match table", table_type->Indices());
		return 0;
		}

	return Assign(index, k, new_val, op);
	}

int TableVal::Assign(Val* index, HashKey* k, Val* new_val, Opcode op)
	{
	int is_set = table_type->IsSet();

	if ( (is_set && new_val) || (! is_set && ! new_val) )
		InternalWarning("bad set/table in TableVal::Assign");

	TableEntryVal* new_entry_val = new TableEntryVal(new_val);
	HashKey k_copy(k->Key(), k->Size(), k->Hash());
	TableEntryVal* old_entry_val = AsNonConstTable()->Insert(k, new_entry_val);

	// If the dictionary index already existed, the insert may free up the
	// memory allocated to the key bytes, so have to assume k is invalid
	// from here on out.
	delete k;
	k = 0;

	if ( subnets )
		{
		if ( ! index )
			{
			Val* v = RecoverIndex(&k_copy);
			subnets->Insert(v, new_entry_val);
			Unref(v);
			}
		else
			subnets->Insert(index, new_entry_val);
		}

	if ( LoggingAccess() && op != OP_NONE )
		{
		Val* rec_index = 0;
		if ( ! index )
			index = rec_index = RecoverIndex(&k_copy);

		if ( new_val )
			{
			// A table.
			if ( new_val->IsMutableVal() )
				new_val->AsMutableVal()->AddProperties(GetProperties());

			bool unref_old_val = false;
			Val* old_val = old_entry_val ?
					old_entry_val->Value() : 0;
			if ( op == OP_INCR && ! old_val )
				// If it's an increment, somebody has already
				// checked that the index is there.  If it's
				// not, that can only be due to using the
				// default.
				{
				old_val = Default(index);
				unref_old_val = true;
				}

			assert(op != OP_INCR || old_val);

			StateAccess::Log(
				new StateAccess(
					op == OP_INCR ?
						OP_INCR_IDX : OP_ASSIGN_IDX,
					this, index, new_val, old_val));

			if ( unref_old_val )
				Unref(old_val);
			}

		else
			{
			// A set.
			StateAccess::Log(
				new StateAccess(OP_ADD, this,
						index, 0, 0));
			}

		if ( rec_index )
			Unref(rec_index);
		}

	// Keep old expiration time if necessary.
	if ( old_entry_val && attrs && attrs->FindAttr(ATTR_EXPIRE_CREATE) )
		new_entry_val->SetExpireAccess(old_entry_val->ExpireAccessTime());

	if ( old_entry_val )
		{
		old_entry_val->Unref();
		delete old_entry_val;
		}

	Modified();
	return 1;
	}

int TableVal::AddTo(Val* val, int is_first_init) const
	{
	return AddTo(val, is_first_init, true);
	}

int TableVal::AddTo(Val* val, int is_first_init, bool propagate_ops) const
	{
	if ( val->Type()->Tag() != TYPE_TABLE )
		{
		val->Error("not a table");
		return 0;
		}

	TableVal* t = val->AsTableVal();

	if ( ! same_type(type, t->Type()) )
		{
		type->Error("table type clash", t->Type());
		return 0;
		}

	const PDict(TableEntryVal)* tbl = AsTable();
	IterCookie* c = tbl->InitForIteration();

	HashKey* k;
	TableEntryVal* v;
	while ( (v = tbl->NextEntry(k, c)) )
		{
		if ( is_first_init && t->AsTable()->Lookup(k) )
			{
			Val* key = table_hash->RecoverVals(k);
			// ### Shouldn't complain if their values are equal.
			key->Warn("multiple initializations for index");
			Unref(key);
			continue;
			}

		if ( type->IsSet() )
			{
			if ( ! t->Assign(v->Value(), k, 0,
					propagate_ops ? OP_ASSIGN : OP_NONE) )
				 return 0;
			}
		else
			{
			v->Ref();
			if ( ! t->Assign(0, k, v->Value(),
					propagate_ops ? OP_ASSIGN : OP_NONE) )
				 return 0;
			}
		}

	return 1;
	}

int TableVal::RemoveFrom(Val* val) const
	{
	if ( val->Type()->Tag() != TYPE_TABLE )
		{
		val->Error("not a table");
		return 0;
		}

	TableVal* t = val->AsTableVal();

	if ( ! same_type(type, t->Type()) )
		{
		type->Error("table type clash", t->Type());
		return 0;
		}

	const PDict(TableEntryVal)* tbl = AsTable();
	IterCookie* c = tbl->InitForIteration();

	HashKey* k;
	while ( tbl->NextEntry(k, c) )
		{
		// Not sure that this is 100% sound, since the HashKey
		// comes from one table but is being used in another.
		// OTOH, they are both the same type, so as long as
		// we don't have hash keys that are keyed per dictionary,
		// it should work ...
		Unref(t->Delete(k));
		delete k;
		}

	return 1;
	}

TableVal* TableVal::Intersect(const TableVal* tv) const
	{
	TableVal* result = new TableVal(table_type);

	const PDict(TableEntryVal)* t0 = AsTable();
	const PDict(TableEntryVal)* t1 = tv->AsTable();
	PDict(TableEntryVal)* t2 = result->AsNonConstTable();

	// Figure out which is smaller; assign it to t1.
	if ( t1->Length() > t0->Length() )
		{ // Swap.
		const PDict(TableEntryVal)* tmp = t1;
		t1 = t0;
		t0 = tmp;
		}

	IterCookie* c = t1->InitForIteration();
	HashKey* k;
	while ( t1->NextEntry(k, c) )
		{
		// Here we leverage the same assumption about consistent
		// hashes as in TableVal::RemoveFrom above.
		if ( t0->Lookup(k) )
			t2->Insert(k, new TableEntryVal(0));

		delete k;
		}

	return result;
	}

bool TableVal::EqualTo(const TableVal* tv) const
	{
	const PDict(TableEntryVal)* t0 = AsTable();
	const PDict(TableEntryVal)* t1 = tv->AsTable();

	if ( t0->Length() != t1->Length() )
		return false;

	IterCookie* c = t0->InitForIteration();
	HashKey* k;
	while ( t0->NextEntry(k, c) )
		{
		// Here we leverage the same assumption about consistent
		// hashes as in TableVal::RemoveFrom above.
		if ( ! t1->Lookup(k) )
			{
			delete k;
			t0->StopIteration(c);
			return false;
			}

		delete k;
		}

	return true;
	}

bool TableVal::IsSubsetOf(const TableVal* tv) const
	{
	const PDict(TableEntryVal)* t0 = AsTable();
	const PDict(TableEntryVal)* t1 = tv->AsTable();

	if ( t0->Length() > t1->Length() )
		return false;

	IterCookie* c = t0->InitForIteration();
	HashKey* k;
	while ( t0->NextEntry(k, c) )
		{
		// Here we leverage the same assumption about consistent
		// hashes as in TableVal::RemoveFrom above.
		if ( ! t1->Lookup(k) )
			{
			delete k;
			t0->StopIteration(c);
			return false;
			}

		delete k;
		}

	return true;
	}

int TableVal::ExpandAndInit(Val* index, Val* new_val)
	{
	BroType* index_type = index->Type();

	if ( index_type->IsSet() )
		{
		Val* new_index = index->AsTableVal()->ConvertToList();
		Unref(index);
		return ExpandAndInit(new_index, new_val);
		}

	if ( index_type->Tag() != TYPE_LIST )
		// Nothing to expand.
		return CheckAndAssign(index, new_val);

	ListVal* iv = index->AsListVal();
	if ( iv->BaseTag() != TYPE_ANY )
		{
		if ( table_type->Indices()->Types()->length() != 1 )
			reporter->InternalError("bad singleton list index");

		for ( int i = 0; i < iv->Length(); ++i )
			if ( ! ExpandAndInit(iv->Index(i), new_val ? new_val->Ref() : 0) )
				return 0;

		Unref(new_val);
		return 1;
		}

	else
		{ // Compound table.
		val_list* vl = iv->Vals();
		loop_over_list(*vl, i)
			{
			// ### if CompositeHash::ComputeHash did flattening
			// of 1-element lists (like ComputeSingletonHash does),
			// then we could optimize here.
			BroType* t = (*vl)[i]->Type();
			if ( t->IsSet() || t->Tag() == TYPE_LIST )
				break;
			}

		if ( i >= vl->length() )
			// Nothing to expand.
			return CheckAndAssign(index, new_val);
		else
			{
			int result = ExpandCompoundAndInit(vl, i, new_val);
			Unref(new_val);
			return result;
			}
		}
	}


Val* TableVal::Default(Val* index)
	{
	Attr* def_attr = FindAttr(ATTR_DEFAULT);

	if ( ! def_attr )
		return 0;

	if ( ! def_val )
		{
		BroType* ytype = Type()->YieldType();
		BroType* dtype = def_attr->AttrExpr()->Type();

		if ( dtype->Tag() == TYPE_RECORD && ytype->Tag() == TYPE_RECORD &&
		     ! same_type(dtype, ytype) &&
		     record_promotion_compatible(dtype->AsRecordType(),
						 ytype->AsRecordType()) )
			{
			Expr* coerce = new RecordCoerceExpr(def_attr->AttrExpr()->Ref(),
			                                    ytype->AsRecordType());
			def_val = coerce->Eval(0);
			Unref(coerce);
			}

		else
			def_val = def_attr->AttrExpr()->Eval(0);
		}

	if ( ! def_val )
		{
		Error("non-constant default attribute");
		return 0;
		}

	if ( def_val->Type()->Tag() != TYPE_FUNC ||
	     same_type(def_val->Type(), Type()->YieldType()) )
		return def_attr->AttrExpr()->IsConst() ? def_val->Ref() : def_val->Clone();

	const Func* f = def_val->AsFunc();
	val_list vl;

	if ( index->Type()->Tag() == TYPE_LIST )
		{
		const val_list* vl0 = index->AsListVal()->Vals();
		vl = val_list(vl0->length());
		loop_over_list(*vl0, i)
			vl.append((*vl0)[i]->Ref());
		}
	else
		{
		vl = val_list{index->Ref()};
		}

	Val* result = 0;

	try
		{
		result = f->Call(&vl);
		}

	catch ( InterpreterException& e )
		{ /* Already reported. */ }

	if ( ! result )
		{
		Error("no value returned from &default function");
		return 0;
		}

	return result;
	}

Val* TableVal::Lookup(Val* index, bool use_default_val)
	{
	static Val* last_default = 0;

	if ( last_default )
		{
		Unref(last_default);
		last_default = 0;
		}

	if ( subnets )
		{
		TableEntryVal* v = (TableEntryVal*) subnets->Lookup(index);
		if ( v )
			{
			if ( attrs && attrs->FindAttr(ATTR_EXPIRE_READ) )
					{
					v->SetExpireAccess(network_time);
					if ( LoggingAccess() && ExpirationEnabled() )
						ReadOperation(index, v);
					}

			return v->Value() ? v->Value() : this;
			}

		if ( ! use_default_val )
			return 0;

		Val* def = Default(index);
		last_default = def;

		return def;
		}

	const PDict(TableEntryVal)* tbl = AsTable();

	if ( tbl->Length() > 0 )
		{
		HashKey* k = ComputeHash(index);
		if ( k )
			{
			TableEntryVal* v = AsTable()->Lookup(k);
			delete k;

			if ( v )
				{
				if ( attrs && attrs->FindAttr(ATTR_EXPIRE_READ) )
					{
					v->SetExpireAccess(network_time);
					if ( LoggingAccess() && ExpirationEnabled() )
						ReadOperation(index, v);
					}

				return v->Value() ? v->Value() : this;
				}
			}
		}

	if ( ! use_default_val )
		return 0;

	Val* def = Default(index);

	last_default = def;
	return def;
	}

VectorVal* TableVal::LookupSubnets(const SubNetVal* search)
	{
	if ( ! subnets )
		reporter->InternalError("LookupSubnets called on wrong table type");

	VectorVal* result = new VectorVal(internal_type("subnet_vec")->AsVectorType());

	auto matches = subnets->FindAll(search);
	for ( auto element : matches )
		{
		SubNetVal* s = new SubNetVal(get<0>(element));
		result->Assign(result->Size(), s);
		}

	return result;
	}

TableVal* TableVal::LookupSubnetValues(const SubNetVal* search)
	{
	if ( ! subnets )
		reporter->InternalError("LookupSubnetValues called on wrong table type");

	TableVal* nt = new TableVal(this->Type()->Ref()->AsTableType());

	auto matches = subnets->FindAll(search);
	for ( auto element : matches )
		{
		SubNetVal* s = new SubNetVal(get<0>(element));
		TableEntryVal* entry = reinterpret_cast<TableEntryVal*>(get<1>(element));

		if ( entry && entry->Value() )
			nt->Assign(s, entry->Value()->Ref());
		else
			nt->Assign(s, 0); // set

		if ( entry )
			{
			if ( attrs && attrs->FindAttr(ATTR_EXPIRE_READ) )
				{
				entry->SetExpireAccess(network_time);
				if ( LoggingAccess() && ExpirationEnabled() )
					ReadOperation(s, entry);
				}
			}

		Unref(s); // assign does not consume index
		}

	return nt;
	}

bool TableVal::UpdateTimestamp(Val* index)
	{
	TableEntryVal* v;

	if ( subnets )
		v = (TableEntryVal*) subnets->Lookup(index);
	else
		{
		HashKey* k = ComputeHash(index);
		if ( ! k )
			return false;

		v = AsTable()->Lookup(k);

		delete k;
		}

	if ( ! v )
		return false;

	v->SetExpireAccess(network_time);
	if ( LoggingAccess() && attrs->FindAttr(ATTR_EXPIRE_READ) )
		ReadOperation(index, v);

	return true;
	}

ListVal* TableVal::RecoverIndex(const HashKey* k) const
	{
	return table_hash->RecoverVals(k);
	}

Val* TableVal::Delete(const Val* index)
	{
	HashKey* k = ComputeHash(index);
	TableEntryVal* v = k ? AsNonConstTable()->RemoveEntry(k) : 0;
	Val* va = v ? (v->Value() ? v->Value() : this->Ref()) : 0;

	if ( subnets && ! subnets->Remove(index) )
		reporter->InternalWarning("index not in prefix table");

	if ( LoggingAccess() )
		{
		if ( v )
			{
			// A set.
			Val* has_old_val = val_mgr->GetInt(1);
			StateAccess::Log(
				new StateAccess(OP_DEL, this, index,
						has_old_val));
			Unref(has_old_val);
			}
		else
			StateAccess::Log(
				new StateAccess(OP_DEL, this, index, 0));
		}

	delete k;
	delete v;

	Modified();
	return va;
	}

Val* TableVal::Delete(const HashKey* k)
	{
	TableEntryVal* v = AsNonConstTable()->RemoveEntry(k);
	Val* va = v ? (v->Value() ? v->Value() : this->Ref()) : 0;

	if ( subnets )
		{
		Val* index = table_hash->RecoverVals(k);
		if ( ! subnets->Remove(index) )
			reporter->InternalWarning("index not in prefix table");
		Unref(index);
		}

	delete v;

	if ( LoggingAccess() )
		StateAccess::Log(new StateAccess(OP_DEL, this, k));

	Modified();
	return va;
	}

ListVal* TableVal::ConvertToList(TypeTag t) const
	{
	ListVal* l = new ListVal(t);

	const PDict(TableEntryVal)* tbl = AsTable();
	IterCookie* c = tbl->InitForIteration();

	HashKey* k;
	while ( tbl->NextEntry(k, c) )
		{
		ListVal* index = table_hash->RecoverVals(k);

		if ( t == TYPE_ANY )
			l->Append(index);
		else
			{
			// We're expecting a pure list, flatten the
			// ListVal.
			if ( index->Length() != 1 )
				InternalWarning("bad index in TableVal::ConvertToList");
			Val* flat_v = index->Index(0)->Ref();
			Unref(index);
			l->Append(flat_v);
			}

		delete k;
		}

	return l;
	}

ListVal* TableVal::ConvertToPureList() const
	{
	type_list* tl = table_type->Indices()->Types();
	if ( tl->length() != 1 )
		{
		InternalWarning("bad index type in TableVal::ConvertToPureList");
		return 0;
		}

	return ConvertToList((*tl)[0]->Tag());
	}

void TableVal::Describe(ODesc* d) const
	{
	const PDict(TableEntryVal)* tbl = AsTable();
	int n = tbl->Length();

	if ( d->IsBinary() || d->IsPortable() )
		{
		table_type->Describe(d);
		d->SP();
		d->Add(n);
		d->SP();
		}

	if ( d->IsPortable() || d->IsReadable() )
		{
		d->Add("{");
		d->PushIndent();
		}

	IterCookie* c = tbl->InitForIteration();

	for ( int i = 0; i < n; ++i )
		{
		HashKey* k;
		TableEntryVal* v = tbl->NextEntry(k, c);

		if ( ! v )
			reporter->InternalError("hash table underflow in TableVal::Describe");

		ListVal* vl = table_hash->RecoverVals(k);
		int dim = vl->Length();

		if ( i > 0 )
			{
			if ( ! d->IsBinary() )
				d->Add(",");

			d->NL();
			}

		if ( d->IsReadable() )
			{
			if ( dim != 1 || ! table_type->IsSet() )
				d->Add("[");
			}
		else
			{
			d->Add(dim);
			d->SP();
			}

		vl->Describe(d);

		delete k;
		Unref(vl);

		if ( table_type->IsSet() )
			{ // We're a set, not a table.
			if ( d->IsReadable() )
				if ( dim != 1 )
					d->AddSP("]");
			}
		else
			{
			if ( d->IsReadable() )
				d->AddSP("] =");
			if ( v->Value() )
				v->Value()->Describe(d);
			}

		if ( d->IsReadable() && ! d->IsShort() && d->IncludeStats() )
			{
			d->Add(" @");
			d->Add(fmt_access_time(v->ExpireAccessTime()));
			}
		}

	if ( tbl->NextEntry(c) )
		reporter->InternalError("hash table overflow in TableVal::Describe");

	if ( d->IsPortable() || d->IsReadable() )
		{
		d->PopIndent();
		d->Add("}");
		}
	}

int TableVal::ExpandCompoundAndInit(val_list* vl, int k, Val* new_val)
	{
	Val* ind_k_v = (*vl)[k];
	ListVal* ind_k = ind_k_v->Type()->IsSet() ?
				ind_k_v->AsTableVal()->ConvertToList() :
				ind_k_v->Ref()->AsListVal();

	for ( int i = 0; i < ind_k->Length(); ++i )
		{
		Val* ind_k_i = ind_k->Index(i);
		ListVal* expd = new ListVal(TYPE_ANY);
		loop_over_list(*vl, j)
			{
			if ( j == k )
				expd->Append(ind_k_i->Ref());
			else
				expd->Append((*vl)[j]->Ref());
			}

		int success = ExpandAndInit(expd, new_val ? new_val->Ref() : 0);
		Unref(expd);

		if ( ! success )
			{
			Unref(ind_k);
			return 0;
			}
		}

	Unref(ind_k);
	return 1;
	}

int TableVal::CheckAndAssign(Val* index, Val* new_val, Opcode op)
	{
	Val* v = 0;
	if ( subnets )
		// We need an exact match here.
		v = (Val*) subnets->Lookup(index, true);
	else
		v = Lookup(index, false);

	if ( v )
		index->Warn("multiple initializations for index");

	return Assign(index, new_val, op);
	}

void TableVal::InitTimer(double delay)
	{
	timer = new TableValTimer(this, network_time + delay);
	timer_mgr->Add(timer);
	}

void TableVal::DoExpire(double t)
	{
	if ( ! type )
		return; // FIX ME ###

	PDict(TableEntryVal)* tbl = AsNonConstTable();

	double timeout = GetExpireTime();

	if ( timeout < 0 )
		// Skip in case of unset/invalid expiration value. If it's an
		// error, it has been reported already.
		return;

	if ( ! expire_cookie )
		{
		expire_cookie = tbl->InitForIteration();
		tbl->MakeRobustCookie(expire_cookie);
		}

	HashKey* k = 0;
	TableEntryVal* v = 0;
	TableEntryVal* v_saved = 0;

	for ( int i = 0; i < table_incremental_step &&
			 (v = tbl->NextEntry(k, expire_cookie)); ++i )
		{
		if ( v->ExpireAccessTime() == 0 )
			{
			// This happens when we insert val while network_time
			// hasn't been initialized yet (e.g. in zeek_init()), and
			// also when bro_start_network_time hasn't been initialized
			// (e.g. before first packet).  The expire_access_time is
			// correct, so we just need to wait.
			}

		else if ( v->ExpireAccessTime() + timeout < t )
			{
			if ( expire_func )
				{
				Val* idx = RecoverIndex(k);
				double secs = CallExpireFunc(idx);

				// It's possible that the user-provided
				// function modified or deleted the table
				// value, so look it up again.
				v_saved = v;
				v = tbl->Lookup(k);

				if ( ! v )
					{ // user-provided function deleted it
					v = v_saved;
					delete k;
					continue;
					}

				if ( secs > 0 )
					{
					// User doesn't want us to expire
					// this now.
					v->SetExpireAccess(network_time - timeout + secs);
					delete k;
					continue;
					}

				}

			if ( subnets )
				{
				Val* index = RecoverIndex(k);
				if ( ! subnets->Remove(index) )
					reporter->InternalWarning("index not in prefix table");
				Unref(index);
				}

			if ( LoggingAccess() )
				StateAccess::Log(
					new StateAccess(OP_EXPIRE, this, k));

			tbl->RemoveEntry(k);
			Unref(v->Value());
			delete v;
			Modified();
			}

		delete k;
		}

	if ( ! v )
		{
		expire_cookie = 0;
		InitTimer(table_expire_interval);
		}
	else
		InitTimer(table_expire_delay);
	}

double TableVal::GetExpireTime()
	{
	if ( ! expire_time )
		return -1;

	double interval;

	try
		{
		Val* timeout = expire_time->Eval(0);
		interval = (timeout ? timeout->AsInterval() : -1);
		Unref(timeout);
		}
	catch ( InterpreterException& e )
		{
		interval = -1;
		}

	if ( interval >= 0 )
		return interval;

	expire_time = 0;

	if ( timer )
		timer_mgr->Cancel(timer);

	return -1;
	}

double TableVal::CallExpireFunc(Val* idx)
	{
	if ( ! expire_func )
		{
		Unref(idx);
		return 0;
		}

	double secs = 0;

	try
		{
		Val* vf = expire_func->Eval(0);

		if ( ! vf )
			{
			// Will have been reported already.
			Unref(idx);
			return 0;
			}

		if ( vf->Type()->Tag() != TYPE_FUNC )
			{
			vf->Error("not a function");
			Unref(vf);
			Unref(idx);
			return 0;
			}


		// Flatten lists of a single element.
		if ( idx->Type()->Tag() == TYPE_LIST &&
		     idx->AsListVal()->Length() == 1 )
			{
			Val* old = idx;
			idx = idx->AsListVal()->Index(0);
			idx->Ref();
			Unref(old);
			}

		val_list vl{Ref(), idx};
		Val* vs = vf->AsFunc()->Call(&vl);

		if ( vs )
			{
			secs = vs->AsInterval();
			Unref(vs);
			}

		Unref(vf);
		}

	catch ( InterpreterException& e )
		{
		}

	return secs;
	}

void TableVal::ReadOperation(Val* index, TableEntryVal* v)
	{
	double timeout = GetExpireTime();

	if ( timeout < 0 )
		// Skip in case of unset/invalid expiration value. If it's an
		// error, it has been reported already.
		return;

	// In theory we need to only propagate one update per &read_expire
	// interval to prevent peers from expiring intervals. To account for
	// practical issues such as latency, we send one update every half
	// &read_expire.
	if ( network_time - v->LastReadUpdate() > timeout / 2 )
		{
		StateAccess::Log(new StateAccess(OP_READ_IDX, this, index));
		v->SetLastReadUpdate(network_time);
		}
	}

Val* TableVal::DoClone(CloneState* state)
	{
	auto tv = new TableVal(table_type);

	const PDict(TableEntryVal)* tbl = AsTable();
	IterCookie* cookie = tbl->InitForIteration();

	HashKey* key;
	TableEntryVal* val;
	while ( (val = tbl->NextEntry(key, cookie)) )
		{
		TableEntryVal* nval = val->Clone();
		tv->AsNonConstTable()->Insert(key, nval);

		if ( subnets )
			{
			Val* idx = RecoverIndex(key);
			tv->subnets->Insert(idx, nval);
			Unref(idx);
			}

		delete key;
		}

	if ( attrs )
		{
		::Ref(attrs);
		tv->attrs = attrs;
		}

	if ( expire_time )
		{
		tv->expire_time = expire_time->Ref();

		// As network_time is not necessarily initialized yet, we set
		// a timer which fires immediately.
		timer = new TableValTimer(this, 1);
		timer_mgr->Add(timer);
		}

	if ( expire_func )
		tv->expire_func = expire_func->Ref();

	if ( def_val )
		tv->def_val = def_val->Ref();

	return tv;
	}

IMPLEMENT_SERIAL(TableVal, SER_TABLE_VAL);

// This is getting rather complex due to the ability to suspend even within
// deeply-nested values.
bool TableVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE_WITH_SUSPEND(SER_TABLE_VAL, MutableVal);

	// The current state of the serialization.
	struct State {
		IterCookie* c;
		TableEntryVal* v;	// current value
		bool did_index;	// already wrote the val's index
	}* state = 0;

	PDict(TableEntryVal)* tbl =
		const_cast<TableVal*>(this)->AsNonConstTable();

	if ( info->cont.NewInstance() )
		{
		// For simplicity, we disable suspension for the objects
		// serialized here.  (In fact we know that *currently*
		// they won't even try).
		DisableSuspend suspend(info);

		state = new State;
		state->c = tbl->InitForIteration();
		tbl->MakeRobustCookie(state->c);
		state->v = 0;
		state->did_index = false;
		info->s->WriteOpenTag(table_type->IsSet() ? "set" : "table");

		SERIALIZE_OPTIONAL(attrs);
		SERIALIZE_OPTIONAL(expire_time);
		SERIALIZE_OPTIONAL(expire_func);

		// Make sure nobody kills us in between.
		const_cast<TableVal*>(this)->Ref();
		}

	else if ( info->cont.ChildSuspended() )
		state = (State*) info->cont.RestoreState();

	else if ( info->cont.Resuming() )
		{
		info->cont.Resume();
		state = (State*) info->cont.RestoreState();
		}
	else
		reporter->InternalError("unknown continuation state");

	HashKey* k = 0;
	int count = 0;

	assert((!info->cont.ChildSuspended()) || state->v);

	while ( true )
		{
		if ( ! state->v )
			{
			state->v = tbl->NextEntry(k, state->c);
			if ( ! state->c )
				{
				// No next one.
				if ( ! SERIALIZE(false) )
					{
					delete k;
					return false;
					}

				break;
				}

			// There's a value coming.
			if ( ! SERIALIZE(true) )
				{
				delete k;
				return false;
				}

			if ( state->v->Value() )
				state->v->Ref();

			state->did_index = false;
			}

		// Serialize index.
		if ( k && ! state->did_index )
			{
			// Indices are rather small, so we disable suspension
			// here again.
			DisableSuspend suspend(info);
			info->s->WriteOpenTag("key");
			ListVal* index = table_hash->RecoverVals(k)->AsListVal();
			delete k;

			if ( ! index->Serialize(info) )
				return false;

			Unref(index);
			info->s->WriteCloseTag("key");

			state->did_index = true;

			// Start serializing data.
			if ( ! type->IsSet() )
				info->s->WriteOpenTag("value");
			}

		if ( ! type->IsSet() )
			{
			info->cont.SaveState(state);
			info->cont.SaveContext();
			bool result = state->v->val->Serialize(info);
			info->cont.RestoreContext();

			if ( ! result )
				return false;

			if ( info->cont.ChildSuspended() )
				return true;
			}

		double eat = state->v->ExpireAccessTime();

		if ( ! (SERIALIZE(state->v->last_access_time) &&
			SERIALIZE(eat)) )
			return false;

		info->s->WriteCloseTag("value");

		if ( state->v->Value() )
			state->v->Unref();
		state->v = 0; // Next value.

		// Suspend if we've done enough for now (which means we
		// have serialized more than table_incremental_step entries
		// in a row; if an entry has suspended itself in between,
		// we start counting from 0).
		if ( info->may_suspend && ++count > table_incremental_step)
			{
			info->cont.SaveState(state);
			info->cont.Suspend();
			reporter->Info("TableVals serialization suspended right in the middle.");
			return true;
			}
		}

	info->s->WriteCloseTag(table_type->IsSet() ? "set" : "table");
	delete state;

	Unref(const_cast<TableVal*>(this));
	return true;
	}

bool TableVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(MutableVal);

	Init((TableType*) type);

	UNSERIALIZE_OPTIONAL(attrs, Attributes::Unserialize(info));
	UNSERIALIZE_OPTIONAL(expire_time, Expr::Unserialize(info));
	UNSERIALIZE_OPTIONAL(expire_func, Expr::Unserialize(info));

	while ( true )
		{
		// Anymore?
		bool next;
		if ( ! UNSERIALIZE(&next) )
			return false;

		if ( ! next )
			break;

		// Unserialize index.
		ListVal* index =
			(ListVal*) Val::Unserialize(info, table_type->Indices());
		if ( ! index )
			return false;

		// Unserialize data.
		Val* entry;
		if ( ! table_type->IsSet() )
			{
			entry = Val::Unserialize(info, type->YieldType());
			if ( ! entry )
				return false;
			}
		else
			entry = 0;

		TableEntryVal* entry_val = new TableEntryVal(entry);

		double eat;

		if ( ! UNSERIALIZE(&entry_val->last_access_time) ||
		     ! UNSERIALIZE(&eat) )
			{
			entry_val->Unref();
			delete entry_val;
			return false;
			}

		entry_val->SetExpireAccess(eat);

		HashKey* key = ComputeHash(index);
		TableEntryVal* old_entry_val =
			AsNonConstTable()->Insert(key, entry_val);
		assert(! old_entry_val);

		delete key;

		if ( subnets )
			subnets->Insert(index, entry_val);

		Unref(index);
		}

	// If necessary, activate the expire timer.
	if ( attrs )
		{
		CheckExpireAttr(ATTR_EXPIRE_READ);
		CheckExpireAttr(ATTR_EXPIRE_WRITE);
		CheckExpireAttr(ATTR_EXPIRE_CREATE);
		}

	return true;
	}

bool TableVal::AddProperties(Properties arg_props)
	{
	if ( ! MutableVal::AddProperties(arg_props) )
		return false;

	if ( Type()->IsSet() || ! RecursiveProps(arg_props) )
		return true;

	// For a large table, this could get expensive. So, let's hope
	// that nobody creates such a table *before* making it persistent
	// (for example by inserting it into another table).
	TableEntryVal* v;
	PDict(TableEntryVal)* tbl = val.table_val;
	IterCookie* c = tbl->InitForIteration();
	while ( (v = tbl->NextEntry(c)) )
		if ( v->Value()->IsMutableVal() )
			v->Value()->AsMutableVal()->AddProperties(RecursiveProps(arg_props));

	return true;
	}

bool TableVal::RemoveProperties(Properties arg_props)
	{
	if ( ! MutableVal::RemoveProperties(arg_props) )
		return false;

	if ( Type()->IsSet() || ! RecursiveProps(arg_props) )
		return true;

	// For a large table, this could get expensive.  So, let's hope
	// that nobody creates such a table *before* making it persistent
	// (for example by inserting it into another table).
	TableEntryVal* v;
	PDict(TableEntryVal)* tbl = val.table_val;
	IterCookie* c = tbl->InitForIteration();
	while ( (v = tbl->NextEntry(c)) )
		if ( v->Value()->IsMutableVal() )
			v->Value()->AsMutableVal()->RemoveProperties(RecursiveProps(arg_props));

	return true;
	}

unsigned int TableVal::MemoryAllocation() const
	{
	unsigned int size = 0;

	PDict(TableEntryVal)* v = val.table_val;
	IterCookie* c = v->InitForIteration();

	TableEntryVal* tv;
	while ( (tv = v->NextEntry(c)) )
		{
		if ( tv->Value() )
			size += tv->Value()->MemoryAllocation();
		size += padded_sizeof(TableEntryVal);
		}

	return size + padded_sizeof(*this) + val.table_val->MemoryAllocation()
		+ table_hash->MemoryAllocation();
	}

vector<RecordVal*> RecordVal::parse_time_records;

RecordVal::RecordVal(RecordType* t, bool init_fields) : MutableVal(t)
	{
	origin = 0;
	int n = t->NumFields();
	val_list* vl = val.val_list_val = new val_list(n);

	if ( is_parsing )
		{
		parse_time_records.emplace_back(this);
		Ref();
		}

	if ( ! init_fields )
		return;

	// Initialize to default values from RecordType (which are nil
	// by default).
	for ( int i = 0; i < n; ++i )
		{
		Attributes* a = t->FieldDecl(i)->attrs;
		Attr* def_attr = a ? a->FindAttr(ATTR_DEFAULT) : 0;
		Val* def = def_attr ? def_attr->AttrExpr()->Eval(0) : 0;
		BroType* type = t->FieldDecl(i)->type;

		if ( def && type->Tag() == TYPE_RECORD &&
		     def->Type()->Tag() == TYPE_RECORD &&
		     ! same_type(def->Type(), type) )
			{
			Val* tmp = def->AsRecordVal()->CoerceTo(type->AsRecordType());
			if ( tmp )
				{
				Unref(def);
				def = tmp;
				}
			}

		if ( ! def && ! (a && a->FindAttr(ATTR_OPTIONAL)) )
			{
			TypeTag tag = type->Tag();

			if ( tag == TYPE_RECORD )
				def = new RecordVal(type->AsRecordType());

			else if ( tag == TYPE_TABLE )
				def = new TableVal(type->AsTableType(), a);

			else if ( tag == TYPE_VECTOR )
				def = new VectorVal(type->AsVectorType());
			}

		vl->append(def ? def->Ref() : 0);

		Unref(def);
		}
	}

RecordVal::~RecordVal()
	{
	delete_vals(AsNonConstRecord());
	}

void RecordVal::Assign(int field, Val* new_val, Opcode op)
	{
	Val* old_val = AsNonConstRecord()->replace(field, new_val);

	if ( LoggingAccess() && op != OP_NONE )
		{
		if ( new_val && new_val->IsMutableVal() )
			new_val->AsMutableVal()->AddProperties(GetProperties());

		StringVal* index = new StringVal(Type()->AsRecordType()->FieldName(field));
		StateAccess::Log(
			new StateAccess(
				op == OP_INCR ? OP_INCR_IDX : OP_ASSIGN_IDX,
				this, index, new_val, old_val));
		Unref(index); // The logging may keep a cached copy.
		}

	Unref(old_val);
	Modified();
	}

Val* RecordVal::Lookup(int field) const
	{
	return (*AsRecord())[field];
	}

Val* RecordVal::LookupWithDefault(int field) const
	{
	Val* val = (*AsRecord())[field];

	if ( val )
		return val->Ref();

	return Type()->AsRecordType()->FieldDefault(field);
	}

void RecordVal::ResizeParseTimeRecords()
	{
	for ( auto& rv : parse_time_records )
		{
		auto vs = rv->val.val_list_val;
		auto rt = rv->Type()->AsRecordType();
		auto current_length = vs->length();
		auto required_length = rt->NumFields();

		if ( required_length > current_length )
			{
			vs->resize(required_length);

			for ( auto i = current_length; i < required_length; ++i )
				vs->replace(i, nullptr);
			}

		Unref(rv);
		}

	parse_time_records.clear();
	}

Val* RecordVal::Lookup(const char* field, bool with_default) const
	{
	int idx = Type()->AsRecordType()->FieldOffset(field);

	if ( idx < 0 )
		reporter->InternalError("missing record field: %s", field);

	return with_default ? LookupWithDefault(idx) : Lookup(idx);
	}

RecordVal* RecordVal::CoerceTo(const RecordType* t, Val* aggr, bool allow_orphaning) const
	{
	if ( ! record_promotion_compatible(t->AsRecordType(), Type()->AsRecordType()) )
		return 0;

	if ( ! aggr )
		aggr = new RecordVal(const_cast<RecordType*>(t->AsRecordType()));

	RecordVal* ar = aggr->AsRecordVal();
	RecordType* ar_t = aggr->Type()->AsRecordType();

	const RecordType* rv_t = Type()->AsRecordType();

	int i;
	for ( i = 0; i < rv_t->NumFields(); ++i )
		{
		int t_i = ar_t->FieldOffset(rv_t->FieldName(i));

		if ( t_i < 0 )
			{
			if ( allow_orphaning )
				continue;

			char buf[512];
			safe_snprintf(buf, sizeof(buf),
					"orphan field \"%s\" in initialization",
					rv_t->FieldName(i));
			Error(buf);
			break;
			}

		Val* v = Lookup(i);

		if ( ! v )
			// Check for allowable optional fields is outside the loop, below.
			continue;

		if ( ar_t->FieldType(t_i)->Tag() == TYPE_RECORD
				&& ! same_type(ar_t->FieldType(t_i), v->Type()) )
			{
			Expr* rhs = new ConstExpr(v->Ref());
			Expr* e = new RecordCoerceExpr(rhs, ar_t->FieldType(t_i)->AsRecordType());
			ar->Assign(t_i, e->Eval(0));
			continue;
			}

		ar->Assign(t_i, v->Ref());
		}

	for ( i = 0; i < ar_t->NumFields(); ++i )
		if ( ! ar->Lookup(i) &&
			 ! ar_t->FieldDecl(i)->FindAttr(ATTR_OPTIONAL) )
			{
			char buf[512];
			safe_snprintf(buf, sizeof(buf),
					"non-optional field \"%s\" missing in initialization", ar_t->FieldName(i));
			Error(buf);
			}

	return ar;
	}

RecordVal* RecordVal::CoerceTo(RecordType* t, bool allow_orphaning)
	{
	if ( same_type(Type(), t) )
		{
		this->Ref();
		return this;
		}

	return CoerceTo(t, 0, allow_orphaning);
	}

void RecordVal::Describe(ODesc* d) const
	{
	const val_list* vl = AsRecord();
	int n = vl->length();
	auto record_type = Type()->AsRecordType();

	if ( d->IsBinary() || d->IsPortable() )
		{
		record_type->Describe(d);
		d->SP();
		d->Add(n);
		d->SP();
		}
	else
		d->Add("[");

	loop_over_list(*vl, i)
		{
		if ( ! d->IsBinary() && i > 0 )
			d->Add(", ");

		d->Add(record_type->FieldName(i));

		if ( ! d->IsBinary() )
			d->Add("=");

		Val* v = (*vl)[i];
		if ( v )
			v->Describe(d);
		else
			d->Add("<uninitialized>");
		}

	if ( d->IsReadable() )
		d->Add("]");
	}

void RecordVal::DescribeReST(ODesc* d) const
	{
	const val_list* vl = AsRecord();
	int n = vl->length();
	auto record_type = Type()->AsRecordType();

	d->Add("{");
	d->PushIndent();

	loop_over_list(*vl, i)
		{
		if ( i > 0 )
			d->NL();

		d->Add(record_type->FieldName(i));
		d->Add("=");

		Val* v = (*vl)[i];

		if ( v )
			v->Describe(d);
		else
			d->Add("<uninitialized>");
		}

	d->PopIndent();
	d->Add("}");
	}

Val* RecordVal::DoClone(CloneState* state)
	{
	// We set origin to 0 here.  Origin only seems to be used for exactly one
	// purpose - to find the connection record that is associated with a
	// record. As we cannot guarantee that it will ber zeroed out at the
	// approproate time (as it seems to be guaranteed for the original record)
	// we don't touch it.
	auto rv = new RecordVal(Type()->AsRecordType(), false);
	rv->origin = nullptr;

	loop_over_list(*val.val_list_val, i)
		{
		Val* v = (*val.val_list_val)[i] ? (*val.val_list_val)[i]->Clone(state) : nullptr;
  		rv->val.val_list_val->append(v);
		}

	return rv;
	}

IMPLEMENT_SERIAL(RecordVal, SER_RECORD_VAL);

bool RecordVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_RECORD_VAL, MutableVal);

	// We could use the type name as a tag here.
	info->s->WriteOpenTag("record");
	auto record_type = Type()->AsRecordType();

	// FIXME: What about origin?

	if ( ! SERIALIZE(val.val_list_val->length()) )
		return false;

	loop_over_list(*val.val_list_val, i)
		{
		info->s->WriteOpenTag(record_type->FieldName(i));
		Val* v = (*val.val_list_val)[i];
		SERIALIZE_OPTIONAL(v);
		info->s->WriteCloseTag(record_type->FieldName(i));
		}

	info->s->WriteCloseTag("record");

	return true;
	}

bool RecordVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(MutableVal);

	origin = 0;

	int len;
	if ( ! UNSERIALIZE(&len) )
		{
		val.val_list_val = new val_list;
		return false;
		}

	val.val_list_val = new val_list(len);

	for ( int i = 0; i < len; ++i )
		{
		Val* v;
		UNSERIALIZE_OPTIONAL(v, Val::Unserialize(info));
		AsNonConstRecord()->append(v);	// correct for v==0, too.
		}

	return true;
	}

bool RecordVal::AddProperties(Properties arg_props)
	{
	if ( ! MutableVal::AddProperties(arg_props) )
		return false;

	if ( ! RecursiveProps(arg_props) )
		return true;

	loop_over_list(*val.val_list_val, i)
		{
		Val* v = (*val.val_list_val)[i];
		if ( v && v->IsMutableVal() )
			v->AsMutableVal()->AddProperties(RecursiveProps(arg_props));
		}
	return true;
	}


bool RecordVal::RemoveProperties(Properties arg_props)
	{
	if ( ! MutableVal::RemoveProperties(arg_props) )
		return false;

	if ( ! RecursiveProps(arg_props) )
		return true;

	loop_over_list(*val.val_list_val, i)
		{
		Val* v = (*val.val_list_val)[i];
		if ( v && v->IsMutableVal() )
			v->AsMutableVal()->RemoveProperties(RecursiveProps(arg_props));
		}
	return true;
	}

unsigned int RecordVal::MemoryAllocation() const
	{
	unsigned int size = 0;

	const val_list* vl = AsRecord();

	loop_over_list(*vl, i)
		{
		Val* v = (*vl)[i];
		if ( v )
		    size += v->MemoryAllocation();
		}

	return size + padded_sizeof(*this) + val.val_list_val->MemoryAllocation();
	}

void EnumVal::ValDescribe(ODesc* d) const
	{
	const char* ename = type->AsEnumType()->Lookup(val.int_val);

	if ( ! ename )
		ename = "<undefined>";

	d->Add(ename);
	}

Val* EnumVal::DoClone(CloneState* state)
	{
	// Immutable.
	return Ref();
	}

IMPLEMENT_SERIAL(EnumVal, SER_ENUM_VAL);

bool EnumVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_ENUM_VAL, Val);
	return true;
	}

bool EnumVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);
	return true;
	}

VectorVal::VectorVal(VectorType* t) : MutableVal(t)
	{
	vector_type = t->Ref()->AsVectorType();
	val.vector_val = new vector<Val*>();
	}

VectorVal::~VectorVal()
	{
	for ( unsigned int i = 0; i < val.vector_val->size(); ++i )
		Unref((*val.vector_val)[i]);

	Unref(vector_type);

	delete val.vector_val;
	}

bool VectorVal::Assign(unsigned int index, Val* element, Opcode op)
	{
	if ( element &&
	     ! same_type(element->Type(), vector_type->YieldType(), 0) )
		{
		Unref(element);
		return false;
		}

	Val* val_at_index = 0;

	if ( index < val.vector_val->size() )
		val_at_index = (*val.vector_val)[index];
	else
		val.vector_val->resize(index + 1);

	if ( LoggingAccess() && op != OP_NONE )
		{
		if ( element->IsMutableVal() )
			element->AsMutableVal()->AddProperties(GetProperties());

		Val* ival = val_mgr->GetCount(index);

		StateAccess::Log(new StateAccess(op == OP_INCR ?
				OP_INCR_IDX : OP_ASSIGN_IDX,
				this, ival, element, val_at_index));
		Unref(ival);
		}

	Unref(val_at_index);

	// Note: we do *not* Ref() the element, if any, at this point.
	// AssignExpr::Eval() already does this; other callers must remember
	// to do it similarly.
	(*val.vector_val)[index] = element;

	Modified();
	return true;
	}

bool VectorVal::AssignRepeat(unsigned int index, unsigned int how_many,
				Val* element)
	{
	ResizeAtLeast(index + how_many);

	for ( unsigned int i = index; i < index + how_many; ++i )
		if ( ! Assign(i, element->Ref() ) )
			return false;

	return true;
	}

int VectorVal::AddTo(Val* val, int /* is_first_init */) const
	{
	if ( val->Type()->Tag() != TYPE_VECTOR )
		{
		val->Error("not a vector");
		return 0;
		}

	VectorVal* v = val->AsVectorVal();

	if ( ! same_type(type, v->Type()) )
		{
		type->Error("vector type clash", v->Type());
		return 0;
		}

	auto last_idx = v->Size();

	for ( auto i = 0u; i < Size(); ++i )
		v->Assign(last_idx++, Lookup(i)->Ref());

	return 1;
	}

Val* VectorVal::Lookup(unsigned int index) const
	{
	if ( index >= val.vector_val->size() )
		return 0;

	return (*val.vector_val)[index];
	}

unsigned int VectorVal::Resize(unsigned int new_num_elements)
	{
	unsigned int oldsize = val.vector_val->size();
	val.vector_val->reserve(new_num_elements);
	val.vector_val->resize(new_num_elements);
	return oldsize;
	}

unsigned int VectorVal::ResizeAtLeast(unsigned int new_num_elements)
	 {
	 unsigned int old_size = val.vector_val->size();
	 if ( new_num_elements <= old_size )
		 return old_size;

	 return Resize(new_num_elements);
	 }

bool VectorVal::AddProperties(Properties arg_props)
	{
	if ( ! MutableVal::AddProperties(arg_props) )
		return false;

	if ( ! RecursiveProps(arg_props) )
		return true;

	for ( unsigned int i = 0; i < val.vector_val->size(); ++i )
		if ( (*val.vector_val)[i]->IsMutableVal() )
			(*val.vector_val)[i]->AsMutableVal()->AddProperties(RecursiveProps(arg_props));

	return true;
	}

bool VectorVal::RemoveProperties(Properties arg_props)
	{
	if ( ! MutableVal::RemoveProperties(arg_props) )
		return false;

	if ( ! RecursiveProps(arg_props) )
		return true;

	for ( unsigned int i = 0; i < val.vector_val->size(); ++i )
		if ( (*val.vector_val)[i]->IsMutableVal() )
			(*val.vector_val)[i]->AsMutableVal()->RemoveProperties(RecursiveProps(arg_props));

	return true;
	}


Val* VectorVal::DoClone(CloneState* state)
	{
	auto vv = new VectorVal(vector_type);
	vv->val.vector_val->reserve(val.vector_val->size());

	for ( unsigned int i = 0; i < val.vector_val->size(); ++i )
		{
		auto v = (*val.vector_val)[i]->Clone(state);
		vv->val.vector_val->push_back(v);
		}

	return vv;
	}

IMPLEMENT_SERIAL(VectorVal, SER_VECTOR_VAL);

bool VectorVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_VECTOR_VAL, MutableVal);

	info->s->WriteOpenTag("vector");

	if ( ! SERIALIZE(unsigned(val.vector_val->size())) )
		return false;

	for ( unsigned int i = 0; i < val.vector_val->size(); ++i )
		{
		info->s->WriteOpenTag("value");
		Val* v = (*val.vector_val)[i];
		SERIALIZE_OPTIONAL(v);
		info->s->WriteCloseTag("value");
		}

	info->s->WriteCloseTag("vector");

	return true;
	}

bool VectorVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(MutableVal);

	val.vector_val = new vector<Val*>;
	vector_type = type->Ref()->AsVectorType();

	int len;
	if ( ! UNSERIALIZE(&len) )
		return false;

	for ( int i = 0; i < len; ++i )
		{
		Val* v;
		UNSERIALIZE_OPTIONAL(v, Val::Unserialize(info, TYPE_ANY)); // accept any type
		Assign(i, v);
		}

	return true;
	}

void VectorVal::ValDescribe(ODesc* d) const
	{
	d->Add("[");

	if ( val.vector_val->size() > 0 )
		for ( unsigned int i = 0; i < (val.vector_val->size() - 1); ++i )
			{
			if ( (*val.vector_val)[i] )
				(*val.vector_val)[i]->Describe(d);
			d->Add(", ");
			}

	if ( val.vector_val->size() &&
	     (*val.vector_val)[val.vector_val->size() - 1] )
		(*val.vector_val)[val.vector_val->size() - 1]->Describe(d);

	d->Add("]");
	}

OpaqueVal::OpaqueVal(OpaqueType* t) : Val(t)
	{
	}

OpaqueVal::~OpaqueVal()
	{
	}

Val* OpaqueVal::DoClone(CloneState* state)
	{
	reporter->InternalError("cloning opaque type without clone implementation");
	return nullptr;
	}

IMPLEMENT_SERIAL(OpaqueVal, SER_OPAQUE_VAL);

bool OpaqueVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_OPAQUE_VAL, Val);
	return true;
	}

bool OpaqueVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(Val);
	return true;
	}

Val* check_and_promote(Val* v, const BroType* t, int is_init, const Location* expr_location)
	{
	if ( ! v )
		return 0;

	BroType* vt = v->Type();

	vt = flatten_type(vt);
	t = flatten_type(t);

	TypeTag t_tag = t->Tag();
	TypeTag v_tag = vt->Tag();

	// More thought definitely needs to go into this.
	if ( t_tag == TYPE_ANY || v_tag == TYPE_ANY )
		return v;

	if ( ! EitherArithmetic(t_tag, v_tag) ||
	     /* allow sets as initializers */
	     (is_init && v_tag == TYPE_TABLE) )
		{
		if ( same_type(t, vt, is_init) )
			return v;

		t->Error("type clash", v, 0, expr_location);
		Unref(v);
		return 0;
		}

	if ( ! BothArithmetic(t_tag, v_tag) &&
	     (! IsArithmetic(v_tag) || t_tag != TYPE_TIME || ! v->IsZero()) )
		{
		if ( t_tag == TYPE_LIST || v_tag == TYPE_LIST )
			t->Error("list mixed with scalar", v, 0, expr_location);
		else
			t->Error("arithmetic mixed with non-arithmetic", v, 0, expr_location);
		Unref(v);
		return 0;
		}

	if ( v_tag == t_tag )
		return v;

	if ( t_tag != TYPE_TIME )
		{
		TypeTag mt = max_type(t_tag, v_tag);
		if ( mt != t_tag )
			{
			t->Error("over-promotion of arithmetic value", v, 0, expr_location);
			Unref(v);
			return 0;
			}
		}

	// Need to promote v to type t.
	InternalTypeTag it = t->InternalType();
	InternalTypeTag vit = vt->InternalType();

	if ( it == vit )
		// Already has the right internal type.
		return v;

	Val* promoted_v;
	switch ( it ) {
	case TYPE_INTERNAL_INT:
		if ( t_tag == TYPE_INT )
			promoted_v = val_mgr->GetInt(v->CoerceToInt());
		else if ( t_tag == TYPE_BOOL )
			promoted_v = val_mgr->GetBool(v->CoerceToInt());
		else // enum
			{
			reporter->InternalError("bad internal type in check_and_promote()");
			Unref(v);
			return 0;
			}

		break;

	case TYPE_INTERNAL_UNSIGNED:
		if ( t_tag == TYPE_COUNT || t_tag == TYPE_COUNTER )
			promoted_v = val_mgr->GetCount(v->CoerceToUnsigned());
		else // port
			{
			reporter->InternalError("bad internal type in check_and_promote()");
			Unref(v);
			return 0;
			}

		break;

	case TYPE_INTERNAL_DOUBLE:
		promoted_v = new Val(v->CoerceToDouble(), t_tag);
		break;

	default:
		reporter->InternalError("bad internal type in check_and_promote()");
		Unref(v);
		return 0;
	}

	Unref(v);
	return promoted_v;
	}

int same_val(const Val* /* v1 */, const Val* /* v2 */)
	{
	reporter->InternalError("same_val not implemented");
	return 0;
	}

bool is_atomic_val(const Val* v)
	{
	return is_atomic_type(v->Type());
	}

int same_atomic_val(const Val* v1, const Val* v2)
	{
	// This is a very preliminary implementation of same_val(),
	// true only for equal, simple atomic values of same type.
	if ( v1->Type()->Tag() != v2->Type()->Tag() )
		return 0;

	switch ( v1->Type()->InternalType() ) {
	case TYPE_INTERNAL_INT:
		return v1->InternalInt() == v2->InternalInt();
	case TYPE_INTERNAL_UNSIGNED:
		return v1->InternalUnsigned() == v2->InternalUnsigned();
	case TYPE_INTERNAL_DOUBLE:
		return v1->InternalDouble() == v2->InternalDouble();
	case TYPE_INTERNAL_STRING:
		return Bstr_eq(v1->AsString(), v2->AsString());
	case TYPE_INTERNAL_ADDR:
		return v1->AsAddr() == v2->AsAddr();
	case TYPE_INTERNAL_SUBNET:
		return v1->AsSubNet() == v2->AsSubNet();

	default:
		reporter->InternalWarning("same_atomic_val called for non-atomic value");
		return 0;
	}

	return 0;
	}

void describe_vals(const val_list* vals, ODesc* d, int offset)
	{
	if ( ! d->IsReadable() )
		{
		d->Add(vals->length());
		d->SP();
		}

	for ( int i = offset; i < vals->length(); ++i )
		{
		if ( i > offset && d->IsReadable() && d->Style() != RAW_STYLE )
			d->Add(", ");

		(*vals)[i]->Describe(d);
		}
	}

void delete_vals(val_list* vals)
	{
	if ( vals )
		{
		loop_over_list(*vals, i)
			Unref((*vals)[i]);
		delete vals;
		}
	}

Val* cast_value_to_type(Val* v, BroType* t)
	{
	// Note: when changing this function, adapt all three of
	// cast_value_to_type()/can_cast_value_to_type()/can_cast_value_to_type().

	if ( ! v )
		return 0;

	// Always allow casting to same type. This also covers casting 'any'
	// to the actual type.
	if ( same_type(v->Type(), t) )
		return v->Ref();

	if ( same_type(v->Type(), bro_broker::DataVal::ScriptDataType()) )
		{
		auto dv = v->AsRecordVal()->Lookup(0);

		if ( ! dv )
			return 0;

		return static_cast<bro_broker::DataVal *>(dv)->castTo(t);
		}

	return 0;
	}

bool can_cast_value_to_type(const Val* v, BroType* t)
	{
	// Note: when changing this function, adapt all three of
	// cast_value_to_type()/can_cast_value_to_type()/can_cast_value_to_type().

	if ( ! v )
		return false;

	// Always allow casting to same type. This also covers casting 'any'
	// to the actual type.
	if ( same_type(v->Type(), t) )
		return true;

	if ( same_type(v->Type(), bro_broker::DataVal::ScriptDataType()) )
		{
		auto dv = v->AsRecordVal()->Lookup(0);

		if ( ! dv )
			return false;

		return static_cast<const bro_broker::DataVal *>(dv)->canCastTo(t);
		}

	return false;
	}

bool can_cast_value_to_type(const BroType* s, BroType* t)
	{
	// Note: when changing this function, adapt all three of
	// cast_value_to_type()/can_cast_value_to_type()/can_cast_value_to_type().

	// Always allow casting to same type. This also covers casting 'any'
	// to the actual type.
	if ( same_type(s, t) )
		return true;

	if ( same_type(s, bro_broker::DataVal::ScriptDataType()) )
		// As Broker is dynamically typed, we don't know if we will be able
		// to convert the type as intended. We optimistically assume that we
		// will.
		return true;

	return false;
	}

ValManager::ValManager()
	{
	empty_string = new StringVal("");
	b_false = Val::MakeBool(false);
	b_true = Val::MakeBool(true);
	counts = new Val*[PREALLOCATED_COUNTS];
	ints = new Val*[PREALLOCATED_INTS];

	for ( auto i = 0u; i < PREALLOCATED_COUNTS; ++i )
		counts[i] = Val::MakeCount(i);

	for ( auto i = 0u; i < PREALLOCATED_INTS; ++i )
		ints[i] = Val::MakeInt(PREALLOCATED_INT_LOWEST + i);

	for ( auto i = 0u; i < ports.size(); ++i )
		{
		auto& arr = ports[i];
		auto port_type = (TransportProto)i;

		for ( auto j = 0u; j < arr.size(); ++j )
			arr[j] = new PortVal(PortVal::Mask(j, port_type), true);
		}
	}

ValManager::~ValManager()
	{
	Unref(empty_string);
	Unref(b_true);
	Unref(b_false);

	for ( auto i = 0u; i < PREALLOCATED_COUNTS; ++i )
		Unref(counts[i]);

	for ( auto i = 0u; i < PREALLOCATED_INTS; ++i )
		Unref(ints[i]);

	delete [] counts;
	delete [] ints;

	for ( auto& arr : ports )
		for ( auto& pv : arr )
			Unref(pv);
	}

StringVal* ValManager::GetEmptyString() const
	{
	::Ref(empty_string);
	return empty_string;
	}

PortVal* ValManager::GetPort(uint32 port_num, TransportProto port_type) const
	{
	if ( port_num >= 65536 )
		{
		reporter->Warning("bad port number %d", port_num);
		port_num = 0;
		}

	auto rval = ports[port_type][port_num];
	::Ref(rval);
	return rval;
	}

PortVal* ValManager::GetPort(uint32 port_num) const
	{
	auto mask = port_num & PORT_SPACE_MASK;
	port_num &= ~PORT_SPACE_MASK;

	if ( mask == TCP_PORT_MASK )
		return GetPort(port_num, TRANSPORT_TCP);
	else if ( mask == UDP_PORT_MASK )
		return GetPort(port_num, TRANSPORT_UDP);
	else if ( mask == ICMP_PORT_MASK )
		return GetPort(port_num, TRANSPORT_ICMP);
	else
		return GetPort(port_num, TRANSPORT_UNKNOWN);
	}
