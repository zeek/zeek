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
#include "PrefixTable.h"
#include "Conn.h"
#include "Reporter.h"
#include "IPAddr.h"

#include "broker/Data.h"

#include "3rdparty/json.hpp"
#include "3rdparty/tsl-ordered-map/ordered_map.h"


// Define a class for use with the json library that orders the keys in the same order that
// they were inserted. By default, the json library orders them alphabetically and we don't
// want it like that.
template<class Key, class T, class Ignore, class Allocator,
         class Hash = std::hash<Key>, class KeyEqual = std::equal_to<Key>,
         class AllocatorPair = typename std::allocator_traits<Allocator>::template rebind_alloc<std::pair<Key, T>>,
         class ValueTypeContainer = std::vector<std::pair<Key, T>, AllocatorPair>>
using ordered_map = tsl::ordered_map<Key, T, Hash, KeyEqual, AllocatorPair, ValueTypeContainer>;

using ZeekJson = nlohmann::basic_json<ordered_map>;

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
	auto v = Clone(&state);
	return v;
	}

Val* Val::Clone(CloneState* state)
	{
	auto i = state->clones.find(this);

	if ( i != state->clones.end() )
		return i->second->Ref();

	auto c = DoClone(state);

	if ( ! c )
		reporter->RuntimeError(GetLocationInfo(), "cannot clone value");

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
			return new Val(AsFunc()->DoClone());

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


bool Val::WouldOverflow(const BroType* from_type, const BroType* to_type, const Val* val)
	{
	if ( !to_type || !from_type )
		return true;
	else if ( same_type(to_type, from_type) )
		return false;

	if ( to_type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return false;
	else if ( to_type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		{
		if ( from_type->InternalType() == TYPE_INTERNAL_DOUBLE )
			return (val->InternalDouble() < 0.0 || val->InternalDouble() > static_cast<double>(UINT64_MAX));
		else if ( from_type->InternalType() == TYPE_INTERNAL_INT )
			return (val->InternalInt() < 0);
		}
	else if ( to_type->InternalType() == TYPE_INTERNAL_INT )
		{
		if ( from_type->InternalType() == TYPE_INTERNAL_DOUBLE )
			return (val->InternalDouble() < static_cast<double>(INT64_MIN) ||
			        val->InternalDouble() > static_cast<double>(INT64_MAX));
		else if ( from_type->InternalType() == TYPE_INTERNAL_UNSIGNED )
			return (val->InternalUnsigned() > INT64_MAX);
		}

	return false;
	}

TableVal* Val::GetRecordFields()
	{
	auto t = Type();

	if ( t->Tag() != TYPE_RECORD && t->Tag() != TYPE_TYPE )
		{
		reporter->Error("non-record value/type passed to record_fields");
		return new TableVal(internal_type("record_field_table")->AsTableType());
		}

	RecordType* rt = nullptr;
	RecordVal* rv = nullptr;

	if ( t->Tag() == TYPE_RECORD )
		{
		rt = t->AsRecordType();
		rv = AsRecordVal();
		}
	else
		{
		t = t->AsTypeType()->Type();

		if ( t->Tag() != TYPE_RECORD )
			{
			reporter->Error("non-record value/type passed to record_fields");
			return new TableVal(internal_type("record_field_table")->AsTableType());
			}

		rt = t->AsRecordType();
		}

	return rt->GetRecordFieldsVal(rv);
	}

// This is a static method in this file to avoid including json.hpp in Val.h since it's huge.
static ZeekJson BuildJSON(Val* val, bool only_loggable=false, RE_Matcher* re=nullptr)
	{
	// If the value wasn't set, return a nullptr. This will get turned into a 'null' in the json output.
	if ( ! val )
		return nullptr;

	ZeekJson j;
	BroType* type = val->Type();
	switch ( type->Tag() )
		{
		case TYPE_BOOL:
			j = val->AsBool();
			break;

		case TYPE_INT:
			j = val->AsInt();
			break;

		case TYPE_COUNT:
			j = val->AsCount();
			break;

		case TYPE_COUNTER:
			j = val->AsCounter();
			break;

		case TYPE_TIME:
			j = val->AsTime();
			break;

		case TYPE_DOUBLE:
			j = val->AsDouble();
			break;

		case TYPE_PORT:
			{
			auto* pval = val->AsPortVal();
			j.emplace("port", pval->Port());
			j.emplace("proto", pval->Protocol());
			break;
			}

		case TYPE_PATTERN:
		case TYPE_INTERVAL:
		case TYPE_ADDR:
		case TYPE_SUBNET:
			{
			ODesc d;
			d.SetStyle(RAW_STYLE);
			val->Describe(&d);
			j = string(reinterpret_cast<const char*>(d.Bytes()), d.Len());
			break;
			}

		case TYPE_FILE:
		case TYPE_FUNC:
		case TYPE_ENUM:
		case TYPE_STRING:
			{
			ODesc d;
			d.SetStyle(RAW_STYLE);
			val->Describe(&d);
			j = json_escape_utf8(string(reinterpret_cast<const char*>(d.Bytes()), d.Len()));
			break;
			}

		case TYPE_TABLE:
			{
			auto* table = val->AsTable();
			auto* tval = val->AsTableVal();

			if ( tval->Type()->IsSet() )
				j = ZeekJson::array();
			else
				j = ZeekJson::object();

			HashKey* k;
			TableEntryVal* entry;
			auto c = table->InitForIteration();
			while ( (entry = table->NextEntry(k, c)) )
				{
				auto lv = tval->RecoverIndex(k);
				delete k;

				Val* entry_key;
				if ( lv->Length() == 1 )
					entry_key = lv->Index(0)->Ref();
				else
					entry_key = lv->Ref();

				ZeekJson key_json = BuildJSON(entry_key, only_loggable, re);

				if ( tval->Type()->IsSet() )
					j.emplace_back(std::move(key_json));
				else
					{
					Val* entry_value = entry->Value();

					string key_string;
					if ( key_json.is_string() )
						key_string = key_json;
					else
						key_string = key_json.dump();

					j.emplace(key_string, BuildJSON(entry_value, only_loggable, re));
					}

				Unref(entry_key);
				Unref(lv);
				}

			break;
			}

		case TYPE_RECORD:
			{
			j = ZeekJson::object();
			auto* rval = val->AsRecordVal();
			auto rt = rval->Type()->AsRecordType();

			for ( auto i = 0; i < rt->NumFields(); ++i )
				{
				auto field_name = rt->FieldName(i);
				std::string key_string;

				if ( re && re->MatchAnywhere(field_name) != 0 )
					{
					StringVal blank("");
					StringVal fn_val(field_name);
					auto key_val = fn_val.Substitute(re, &blank, 0)->AsStringVal();
					key_string = key_val->ToStdString();
					Unref(key_val);
					}
				else
					key_string = field_name;

				Val* value = rval->LookupWithDefault(i);

				if ( value && ( ! only_loggable || rt->FieldHasAttr(i, ATTR_LOG) ) )
					j.emplace(key_string, BuildJSON(value, only_loggable, re));

				Unref(value);
				}

			break;
			}

		case TYPE_LIST:
			{
			j = ZeekJson::array();
			auto* lval = val->AsListVal();
			size_t size = lval->Length();
			for (size_t i = 0; i < size; i++)
				j.push_back(BuildJSON(lval->Index(i), only_loggable, re));

			break;
			}

		case TYPE_VECTOR:
			{
			j = ZeekJson::array();
			auto* vval = val->AsVectorVal();
			size_t size = vval->SizeVal()->AsCount();
			for (size_t i = 0; i < size; i++)
				j.push_back(BuildJSON(vval->Lookup(i), only_loggable, re));

			break;
			}

		case TYPE_OPAQUE:
			{
			auto* oval = val->AsOpaqueVal();
			j = { { "opaque_type", OpaqueMgr::mgr()->TypeID(oval) } };
			break;
			}

		default: break;
		}

	return j;
	}

StringVal* Val::ToJSON(bool only_loggable, RE_Matcher* re)
	{
	ZeekJson j = BuildJSON(this, only_loggable, re);
	return new StringVal(j.dump());
	}

IntervalVal::IntervalVal(double quantity, double units) :
	Val(quantity * units, TYPE_INTERVAL)
	{
	}

void IntervalVal::ValDescribe(ODesc* d) const
	{
	using unit_word = std::pair<double, const char*>;

	constexpr std::array<unit_word, 6> units = {
		unit_word{ Days, "day" },
		unit_word{ Hours, "hr" },
		unit_word{ Minutes, "min" },
		unit_word{ Seconds, "sec" },
		unit_word{ Milliseconds, "msec" },
		unit_word{ Microseconds, "usec" },
	};

	double v = val.double_val;

	if ( v == 0.0 )
		{
		d->Add("0 secs");
		return;
		}

	bool did_one = false;
	constexpr auto last_idx = units.size() - 1;

	auto approx_equal = [](double a, double b, double tolerance = 1e-6) -> bool
		{
		auto v = a - b;
		return v < 0 ? -v < tolerance : v < tolerance;
		};

	for ( size_t i = 0; i < units.size(); ++i )
		{
		auto unit = units[i].first;
		auto word = units[i].second;
		double to_print = 0;

		if ( i == last_idx )
			{
			to_print = v / unit;

			if ( approx_equal(to_print, 0) )
				{
				if ( ! did_one )
					d->Add("0 secs");

				break;
				}
			}
		else
			{
			if ( ! (v >= unit || v <= -unit) )
				continue;

			double num = static_cast<double>(static_cast<int64_t>(v / unit));
			v -= num * unit;
			to_print = num;
			}

		if ( did_one )
			d->SP();

		d->Add(to_print);
		d->SP();
		d->Add(word);

		if ( ! approx_equal(to_print, 1) && ! approx_equal(to_print, -1) )
			d->Add("s");

		did_one = true;
		}
	}

PortVal* PortManager::Get(uint32_t port_num) const
	{
	return val_mgr->GetPort(port_num);
	}

PortVal* PortManager::Get(uint32_t port_num, TransportProto port_type) const
	{
	return val_mgr->GetPort(port_num, port_type);
	}

uint32_t PortVal::Mask(uint32_t port_num, TransportProto port_type)
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

PortVal::PortVal(uint32_t p, TransportProto port_type) : Val(TYPE_PORT)
	{
	auto port_num = PortVal::Mask(p, port_type);
	val.uint_val = static_cast<bro_uint_t>(port_num);
	}

PortVal::PortVal(uint32_t p, bool unused) : Val(TYPE_PORT)
	{
	val.uint_val = static_cast<bro_uint_t>(p);
	}

PortVal::PortVal(uint32_t p) : Val(TYPE_PORT)
	{
	if ( p >= 65536 * NUM_PORT_SPACES )
		{
		InternalWarning("bad port number");
		p = 0;
		}

	val.uint_val = static_cast<bro_uint_t>(p);
	}

uint32_t PortVal::Port() const
	{
	uint32_t p = static_cast<uint32_t>(val.uint_val);
	return p & ~PORT_SPACE_MASK;
	}

string PortVal::Protocol() const
	{
	if ( IsUDP() )
		return "udp";
	else if ( IsTCP() )
		return "tcp";
	else if ( IsICMP() )
		return "icmp";
	else
		return "unknown";
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
	uint32_t p = static_cast<uint32_t>(val.uint_val);
	d->Add(p & ~PORT_SPACE_MASK);
	d->Add("/");
	d->Add(Protocol());
	}

Val* PortVal::DoClone(CloneState* state)
	{
	// Immutable.
	return Ref();
	}

AddrVal::AddrVal(const char* text) : Val(TYPE_ADDR)
	{
	val.addr_val = new IPAddr(text);
	}

AddrVal::AddrVal(const std::string& text) : Val(TYPE_ADDR)
	{
	val.addr_val = new IPAddr(text);
	}

AddrVal::AddrVal(uint32_t addr) : Val(TYPE_ADDR)
	{
	// ### perhaps do gethostbyaddr here?
	val.addr_val = new IPAddr(IPv4, &addr, IPAddr::Network);
	}

AddrVal::AddrVal(const uint32_t addr[4]) : Val(TYPE_ADDR)
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

SubNetVal::SubNetVal(const char* text) : Val(TYPE_SUBNET)
	{
	val.subnet_val = new IPPrefix();

	if ( ! IPPrefix::ConvertString(text, val.subnet_val) )
		reporter->Error("Bad string in SubNetVal ctor: %s", text);
	}

SubNetVal::SubNetVal(const char* text, int width) : Val(TYPE_SUBNET)
	{
	val.subnet_val = new IPPrefix(text, width);
	}

SubNetVal::SubNetVal(uint32_t addr, int width) : Val(TYPE_SUBNET)
	{
	IPAddr a(IPv4, &addr, IPAddr::Network);
	val.subnet_val = new IPPrefix(a, width);
	}

SubNetVal::SubNetVal(const uint32_t* addr, int width) : Val(TYPE_SUBNET)
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
		uint32_t m[4];
		for ( unsigned int i = 0; i < 4; ++i )
			m[i] = 0;
		IPAddr rval(IPv6, m, IPAddr::Host);
		return rval;
		}

	uint32_t m[4];
	uint32_t* mp = m;

	uint32_t w;
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
	val.string_val = new BroString(reinterpret_cast<const u_char*>(s.data()), s.length(), 1);
	}

string StringVal::ToStdString() const
	{
	auto* bs = AsString();
	return string((char*)bs->Bytes(), bs->Len());
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

Val* StringVal::Substitute(RE_Matcher* re, StringVal* repl, bool do_all)
	{
	const u_char* s = Bytes();
	int offset = 0;
	int n = Len();

	// cut_points is a set of pairs of indices in str that should
	// be removed/replaced.  A pair <x,y> means "delete starting
	// at offset x, up to but not including offset y".
	vector<std::pair<int, int>> cut_points;

	int size = 0;	// size of result

	while ( n > 0 )
		{
		// Find next match offset.
		int end_of_match;
		while ( n > 0 &&
		        (end_of_match = re->MatchPrefix(&s[offset], n)) <= 0 )
			{
			// This character is going to be copied to the result.
			++size;

			// Move on to next character.
			++offset;
			--n;
			}

		if ( n <= 0 )
			break;

		// s[offset .. offset+end_of_match-1] matches re.
		cut_points.push_back({offset, offset + end_of_match});

		offset += end_of_match;
		n -= end_of_match;

		if ( ! do_all )
			{
			// We've now done the first substitution - finished.
			// Include the remainder of the string in the result.
			size += n;
			break;
			}
		}

	// size now reflects amount of space copied.  Factor in amount
	// of space for replacement text.
	size += cut_points.size() * repl->Len();

	// And a final NUL for good health.
	++size;

	byte_vec result = new u_char[size];
	byte_vec r = result;

	// Copy it all over.
	int start_offset = 0;
	for ( const auto& point : cut_points )
		{
		int num_to_copy = point.first - start_offset;
		memcpy(r, s + start_offset, num_to_copy);

		r += num_to_copy;
		start_offset = point.second;

		// Now add in replacement text.
		memcpy(r, repl->Bytes(), repl->Len());
		r += repl->Len();
		}

	// Copy final trailing characters.
	int num_to_copy = Len() - start_offset;
	memcpy(r, s + start_offset, num_to_copy);
	r += num_to_copy;

	// Final NUL.  No need to increment r, since the length
	// computed from it in the next statement does not include
	// the NUL.
	r[0] = '\0';

	return new StringVal(new BroString(1, result, r - result));
	}

Val* StringVal::DoClone(CloneState* state)
	{
	// We could likely treat this type as immutable and return a reference
	// instead of creating a new copy, but we first need to be careful and
	// audit whether anything internal actually does mutate it.
	return state->NewClone(this, new StringVal(
	        new BroString((u_char*) val.string_val->Bytes(),
	                      val.string_val->Len(), 1)));
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
	// We could likely treat this type as immutable and return a reference
	// instead of creating a new copy, but we first need to be careful and
	// audit whether anything internal actually does mutate it.
	auto re = new RE_Matcher(val.re_val->PatternText(),
	                         val.re_val->AnywherePatternText());
	re->Compile();
	return state->NewClone(this, new PatternVal(re));
	}

ListVal::ListVal(TypeTag t)
: Val(new TypeList(t == TYPE_ANY ? 0 : base_type_no_ref(t)))
	{
	tag = t;
	}

ListVal::~ListVal()
	{
	for ( const auto& val : vals )
		Unref(val);
	Unref(type);
	}

RE_Matcher* ListVal::BuildRE() const
	{
	if ( tag != TYPE_STRING )
		Internal("non-string list in ListVal::IncludedInString");

	RE_Matcher* re = new RE_Matcher();
	for ( const auto& val : vals )
		{
		const char* vs = (const char*) (val->AsString()->Bytes());
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

	vals.push_back(v);
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

	for ( const auto& val : vals )
		t->Assign(val, 0);

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
	state->NewClone(this, lv);

	for ( const auto& val : vals )
		lv->Append(val->Clone(state));

	return lv;
	}

unsigned int ListVal::MemoryAllocation() const
	{
	unsigned int size = 0;
	for ( const auto& val : vals )
		size += val->MemoryAllocation();

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

TableVal::TableVal(TableType* t, Attributes* a) : Val(t)
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
	val.table_val = new PDict<TableEntryVal>;
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
	val.table_val = new PDict<TableEntryVal>;
	val.table_val->SetDeleteFunc(table_entry_val_delete_func);
	}

int TableVal::RecursiveSize() const
	{
	int n = AsTable()->Length();

	if ( Type()->IsSet() ||
	     const_cast<TableType*>(Type()->AsTableType())->YieldType()->Tag()
			!= TYPE_TABLE )
		return n;

	PDict<TableEntryVal>* v = val.table_val;
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

int TableVal::Assign(Val* index, Val* new_val)
	{
	HashKey* k = ComputeHash(index);
	if ( ! k )
		{
		Unref(new_val);
		index->Error("index type doesn't match table", table_type->Indices());
		return 0;
		}

	return Assign(index, k, new_val);
	}

int TableVal::Assign(Val* index, HashKey* k, Val* new_val)
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

	const PDict<TableEntryVal>* tbl = AsTable();
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
			if ( ! t->Assign(v->Value(), k, 0) )
				 return 0;
			}
		else
			{
			v->Ref();
			if ( ! t->Assign(0, k, v->Value()) )
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

	const PDict<TableEntryVal>* tbl = AsTable();
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

	const PDict<TableEntryVal>* t0 = AsTable();
	const PDict<TableEntryVal>* t1 = tv->AsTable();
	PDict<TableEntryVal>* t2 = result->AsNonConstTable();

	// Figure out which is smaller; assign it to t1.
	if ( t1->Length() > t0->Length() )
		{ // Swap.
		const PDict<TableEntryVal>* tmp = t1;
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
	const PDict<TableEntryVal>* t0 = AsTable();
	const PDict<TableEntryVal>* t1 = tv->AsTable();

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
	const PDict<TableEntryVal>* t0 = AsTable();
	const PDict<TableEntryVal>* t1 = tv->AsTable();

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
		{
		if ( def_attr->AttrExpr()->IsConst() )
			return def_val->Ref();

		try
			{
			return def_val->Clone();
			}
		catch ( InterpreterException& e )
			{ /* Already reported. */ }

		Error("&default value for table is not clone-able");
		return 0;
		}

	const Func* f = def_val->AsFunc();
	val_list vl;

	if ( index->Type()->Tag() == TYPE_LIST )
		{
		const val_list* vl0 = index->AsListVal()->Vals();
		vl = val_list(vl0->length());
		for ( const auto& v : *vl0 )
			vl.push_back(v->Ref());
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
					v->SetExpireAccess(network_time);

			return v->Value() ? v->Value() : this;
			}

		if ( ! use_default_val )
			return 0;

		Val* def = Default(index);
		last_default = def;

		return def;
		}

	const PDict<TableEntryVal>* tbl = AsTable();

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
					v->SetExpireAccess(network_time);

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
				entry->SetExpireAccess(network_time);
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

	Modified();
	return va;
	}

ListVal* TableVal::ConvertToList(TypeTag t) const
	{
	ListVal* l = new ListVal(t);

	const PDict<TableEntryVal>* tbl = AsTable();
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
	const PDict<TableEntryVal>* tbl = AsTable();
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

int TableVal::CheckAndAssign(Val* index, Val* new_val)
	{
	Val* v = 0;
	if ( subnets )
		// We need an exact match here.
		v = (Val*) subnets->Lookup(index, true);
	else
		v = Lookup(index, false);

	if ( v )
		index->Warn("multiple initializations for index");

	return Assign(index, new_val);
	}

void TableVal::InitDefaultFunc(Frame* f)
	{
	// Value aready initialized.
	if ( def_val )
		return;

	Attr* def_attr = FindAttr(ATTR_DEFAULT);
	if ( ! def_attr )
		return;

	BroType* ytype = Type()->YieldType();
	BroType* dtype = def_attr->AttrExpr()->Type();

	if ( dtype->Tag() == TYPE_RECORD && ytype->Tag() == TYPE_RECORD &&
	     ! same_type(dtype, ytype) &&
	     record_promotion_compatible(dtype->AsRecordType(),
					 ytype->AsRecordType()) )
		return; // TableVal::Default will handle this.

	def_val = def_attr->AttrExpr()->Eval(f);
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

	PDict<TableEntryVal>* tbl = AsNonConstTable();

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
	bool modified = false;

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

			tbl->RemoveEntry(k);
			Unref(v->Value());
			delete v;
			modified = true;
			}

		delete k;
		}

	if ( modified )
		Modified();

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

		const Func* f = vf->AsFunc();
		val_list vl { Ref() };

		const auto func_args = f->FType()->ArgTypes()->Types();

		// backwards compatibility with idx: any idiom
		bool any_idiom = func_args->length() == 2 && func_args->back()->Tag() == TYPE_ANY;

		if ( idx->Type()->Tag() == TYPE_LIST )
			{
			if ( ! any_idiom )
				{
				for ( const auto& v : *idx->AsListVal()->Vals() )
					vl.append(v->Ref());

				Unref(idx);
				}
			else
				{
				ListVal* idx_list = idx->AsListVal();
				// Flatten if only one element
				if ( idx_list->Length() == 1 )
					{
					Val* old = idx;
					idx = idx_list->Index(0)->Ref();
					Unref(old);
					}

				vl.append(idx);
				}
			}
		else
			vl.append(idx);

		Val* result = 0;

		result = f->Call(&vl);

		if ( result )
			{
			secs = result->AsInterval();
			Unref(result);
			}

		Unref(vf);
		}

	catch ( InterpreterException& e )
		{
		}

	return secs;
	}

Val* TableVal::DoClone(CloneState* state)
	{
	auto tv = new TableVal(table_type);
	state->NewClone(this, tv);

	const PDict<TableEntryVal>* tbl = AsTable();
	IterCookie* cookie = tbl->InitForIteration();

	HashKey* key;
	TableEntryVal* val;
	while ( (val = tbl->NextEntry(key, cookie)) )
		{
		TableEntryVal* nval = val->Clone(state);
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
		tv->def_val = def_val->Clone();

	return tv;
	}

unsigned int TableVal::MemoryAllocation() const
	{
	unsigned int size = 0;

	PDict<TableEntryVal>* v = val.table_val;
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

RecordVal::RecordVal(RecordType* t, bool init_fields) : Val(t)
	{
	origin = nullptr;
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

		vl->push_back(def ? def->Ref() : 0);

		Unref(def);
		}
	}

RecordVal::~RecordVal()
	{
	delete_vals(AsNonConstRecord());
	}

void RecordVal::Assign(int field, Val* new_val)
	{
	Val* old_val = AsNonConstRecord()->replace(field, new_val);
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

TableVal* RecordVal::GetRecordFieldsVal() const
	{
	return Type()->AsRecordType()->GetRecordFieldsVal(this);
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
	state->NewClone(this, rv);

	for ( const auto& vlv : *val.val_list_val )
		{
		Val* v = vlv ? vlv->Clone(state) : nullptr;
  		rv->val.val_list_val->push_back(v);
		}

	return rv;
	}

unsigned int RecordVal::MemoryAllocation() const
	{
	unsigned int size = 0;
	const val_list* vl = AsRecord();

	for ( const auto& v : *vl )
		{
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

VectorVal::VectorVal(VectorType* t) : Val(t)
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

bool VectorVal::Assign(unsigned int index, Val* element)
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

bool VectorVal::Insert(unsigned int index, Val* element)
	{
	if ( element &&
	     ! same_type(element->Type(), vector_type->YieldType(), 0) )
		{
		Unref(element);
		return false;
		}

	vector<Val*>::iterator it;

	if ( index < val.vector_val->size() )
		it = std::next(val.vector_val->begin(), index);
	else
		it = val.vector_val->end();

	// Note: we do *not* Ref() the element, if any, at this point.
	// AssignExpr::Eval() already does this; other callers must remember
	// to do it similarly.
	val.vector_val->insert(it, element);

	Modified();
	return true;
	}

bool VectorVal::Remove(unsigned int index)
	{
	if ( index >= val.vector_val->size() )
		return false;

	Val* val_at_index = (*val.vector_val)[index];
	auto it = std::next(val.vector_val->begin(), index);
	val.vector_val->erase(it);
	Unref(val_at_index);

	Modified();
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
		return nullptr;

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

Val* VectorVal::DoClone(CloneState* state)
	{
	auto vv = new VectorVal(vector_type);
	vv->val.vector_val->reserve(val.vector_val->size());
	state->NewClone(this, vv);

	for ( unsigned int i = 0; i < val.vector_val->size(); ++i )
		{
		auto v = (*val.vector_val)[i]->Clone(state);
		vv->val.vector_val->push_back(v);
		}

	return vv;
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

	if ( t_tag != TYPE_TIME && ! BothArithmetic(t_tag, v_tag) )
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
		if ( ( vit == TYPE_INTERNAL_UNSIGNED || vit == TYPE_INTERNAL_DOUBLE ) && Val::WouldOverflow(vt, t, v) )
			{
			t->Error("overflow promoting from unsigned/double to signed arithmetic value", v, 0, expr_location);
			Unref(v);
			return 0;
			}
		else if ( t_tag == TYPE_INT )
			promoted_v = val_mgr->GetInt(v->CoerceToInt());
		else // enum
			{
			reporter->InternalError("bad internal type in check_and_promote()");
			Unref(v);
			return 0;
			}

		break;

	case TYPE_INTERNAL_UNSIGNED:
		if ( ( vit == TYPE_INTERNAL_DOUBLE || vit == TYPE_INTERNAL_INT) && Val::WouldOverflow(vt, t, v) )
			{
			t->Error("overflow promoting from signed/double to unsigned arithmetic value", v, 0, expr_location);
			Unref(v);
			return 0;
			}
		else if ( t_tag == TYPE_COUNT || t_tag == TYPE_COUNTER )
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
		for ( const auto& val : *vals )
			Unref(val);
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

		return static_cast<bro_broker::DataVal *>(dv)->castTo(t).detach();
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

PortVal* ValManager::GetPort(uint32_t port_num, TransportProto port_type) const
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

PortVal* ValManager::GetPort(uint32_t port_num) const
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
