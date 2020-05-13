// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "Val.h"

#include <sys/types.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

#include <cmath>
#include <set>

#include "Attr.h"
#include "BroString.h"
#include "CompHash.h"
#include "Dict.h"
#include "Net.h"
#include "File.h"
#include "Func.h"
#include "Desc.h"
#include "IntrusivePtr.h"
#include "ID.h"
#include "RE.h"
#include "Scope.h"
#include "NetVar.h"
#include "Expr.h"
#include "PrefixTable.h"
#include "Conn.h"
#include "Reporter.h"
#include "IPAddr.h"
#include "ID.h"

#include "broker/Data.h"

#include "threading/formatters/JSON.h"

using namespace std;

Val::Val(Func* f)
	: val(f), type({NewRef{}, f->FType()})
	{
	::Ref(val.func_val);
	}

static const IntrusivePtr<FileType>& GetStringFileType() noexcept
	{
	static IntrusivePtr<FileType> string_file_type
		= make_intrusive<FileType>(base_type(TYPE_STRING));

	return string_file_type;
	}

Val::Val(BroFile* f)
	: val(f), type(GetStringFileType())
	{
	assert(f->FType()->Tag() == TYPE_STRING);
	}

Val::~Val()
	{
	if ( type->InternalType() == TYPE_INTERNAL_STRING )
		delete val.string_val;

	else if ( type->Tag() == TYPE_FUNC )
		Unref(val.func_val);

	else if ( type->Tag() == TYPE_FILE )
		Unref(val.file_val);

#ifdef DEBUG
	delete [] bound_id;
#endif
	}

IntrusivePtr<Val> Val::CloneState::NewClone(Val* src, IntrusivePtr<Val> dst)
	{
	clones.insert(std::make_pair(src, dst.get()));
	return dst;
	}

IntrusivePtr<Val> Val::Clone()
	{
	Val::CloneState state;
	return Clone(&state);
	}

IntrusivePtr<Val> Val::Clone(CloneState* state)
	{
	auto i = state->clones.find(this);

	if ( i != state->clones.end() )
		return {NewRef{}, i->second};

	auto c = DoClone(state);

	if ( ! c )
		reporter->RuntimeError(GetLocationInfo(), "cannot clone value");

	return c;
	}

IntrusivePtr<Val> Val::DoClone(CloneState* state)
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:
	case TYPE_INTERNAL_UNSIGNED:
	case TYPE_INTERNAL_DOUBLE:
	 	// Immutable.
		return {NewRef{}, this};

	case TYPE_INTERNAL_OTHER:
		// Derived classes are responsible for this. Exception:
		// Functions and files. There aren't any derived classes.
		if ( type->Tag() == TYPE_FUNC )
			return make_intrusive<Val>(AsFunc()->DoClone().get());

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
			return {NewRef{}, this};
			}

		if ( type->Tag() == TYPE_TYPE )
			// These are immutable, essentially.
			return {NewRef{}, this};

		// Fall-through.

	default:
		reporter->InternalError("cloning illegal base type");
	}

	reporter->InternalError("cannot be reached");
	return nullptr;
 	}

bool Val::IsZero() const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:		return val.int_val == 0;
	case TYPE_INTERNAL_UNSIGNED:	return val.uint_val == 0;
	case TYPE_INTERNAL_DOUBLE:	return val.double_val == 0.0;

	default:			return false;
	}
	}

bool Val::IsOne() const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:		return val.int_val == 1;
	case TYPE_INTERNAL_UNSIGNED:	return val.uint_val == 1;
	case TYPE_INTERNAL_DOUBLE:	return val.double_val == 1.0;

	default:			return false;
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

IntrusivePtr<Val> Val::SizeVal() const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:
		// Return abs value. However abs() only works on ints and llabs
		// doesn't work on Mac OS X 10.5. So we do it by hand
		if ( val.int_val < 0 )
			return val_mgr->Count(-val.int_val);
		else
			return val_mgr->Count(val.int_val);

	case TYPE_INTERNAL_UNSIGNED:
		return val_mgr->Count(val.uint_val);

	case TYPE_INTERNAL_DOUBLE:
		return make_intrusive<Val>(fabs(val.double_val), TYPE_DOUBLE);

	case TYPE_INTERNAL_OTHER:
		if ( type->Tag() == TYPE_FUNC )
			return val_mgr->Count(val.func_val->FType()->ArgTypes()->Types().size());

		if ( type->Tag() == TYPE_FILE )
			return make_intrusive<Val>(val.file_val->Size(), TYPE_DOUBLE);
		break;

	default:
		break;
	}

	return val_mgr->Count(0);
	}

unsigned int Val::MemoryAllocation() const
	{
	return padded_sizeof(*this);
	}

bool Val::AddTo(Val* v, bool is_first_init) const
	{
	Error("+= initializer only applies to aggregate values");
	return false;
	}

bool Val::RemoveFrom(Val* v) const
	{
	Error("-= initializer only applies to aggregate values");
	return false;
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


#ifdef DEBUG
ID* Val::GetID() const
	{
	return bound_id ? global_scope()->Lookup(bound_id) : nullptr;
	}

void Val::SetID(ID* id)
	{
	delete [] bound_id;
	bound_id = id ? copy_string(id->Name()) : nullptr;
	}
#endif

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

IntrusivePtr<TableVal> Val::GetRecordFields()
	{
	static auto record_field_table = zeek::id::lookup_type<TableType>("record_field_table");
	auto t = GetType().get();

	if ( t->Tag() != TYPE_RECORD && t->Tag() != TYPE_TYPE )
		{
		reporter->Error("non-record value/type passed to record_fields");
		return make_intrusive<TableVal>(record_field_table);
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
			return make_intrusive<TableVal>(record_field_table);
			}

		rt = t->AsRecordType();
		}

	return rt->GetRecordFieldsVal(rv);
	}

// This is a static method in this file to avoid including rapidjson's headers in Val.h because they're huge.
static void BuildJSON(threading::formatter::JSON::NullDoubleWriter& writer, Val* val, bool only_loggable=false, RE_Matcher* re=nullptr, const string& key="")
	{
	if ( !key.empty() )
		writer.Key(key);

	// If the value wasn't set, write a null into the stream and return.
	if ( ! val )
		{
		writer.Null();
		return;
		}

	rapidjson::Value j;

	switch ( val->GetType()->Tag() )
		{
		case TYPE_BOOL:
			writer.Bool(val->AsBool());
			break;

		case TYPE_INT:
			writer.Int64(val->AsInt());
			break;

		case TYPE_COUNT:
			writer.Uint64(val->AsCount());
			break;

		case TYPE_COUNTER:
			writer.Uint64(val->AsCounter());
			break;

		case TYPE_TIME:
			writer.Double(val->AsTime());
			break;

		case TYPE_DOUBLE:
			writer.Double(val->AsDouble());
			break;

		case TYPE_PORT:
			{
			auto* pval = val->AsPortVal();
			writer.StartObject();
			writer.Key("port");
			writer.Int64(pval->Port());
			writer.Key("proto");
			writer.String(pval->Protocol());
			writer.EndObject();
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
			writer.String(reinterpret_cast<const char*>(d.Bytes()), d.Len());
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
			writer.String(json_escape_utf8(string(reinterpret_cast<const char*>(d.Bytes()), d.Len())));
			break;
			}

		case TYPE_TABLE:
			{
			auto* table = val->AsTable();
			auto* tval = val->AsTableVal();

			if ( tval->GetType()->IsSet() )
				writer.StartArray();
			else
				writer.StartObject();

			HashKey* k;
			TableEntryVal* entry;
			auto c = table->InitForIteration();
			while ( (entry = table->NextEntry(k, c)) )
				{
				auto lv = tval->RecoverIndex(k);
				delete k;
				Val* entry_key = lv->Length() == 1 ? lv->Idx(0).get() : lv.get();

				if ( tval->GetType()->IsSet() )
					BuildJSON(writer, entry_key, only_loggable, re);
				else
					{
					rapidjson::StringBuffer buffer;
					threading::formatter::JSON::NullDoubleWriter key_writer(buffer);
					BuildJSON(key_writer, entry_key, only_loggable, re);
					string key_str = buffer.GetString();

					if ( key_str.length() >= 2 &&
					     key_str[0] == '"' &&
					     key_str[key_str.length() - 1] == '"' )
						// Strip quotes.
						key_str = key_str.substr(1, key_str.length() - 2);

					BuildJSON(writer, entry->Value(), only_loggable, re, key_str);
					}
				}

			if ( tval->GetType()->IsSet() )
				writer.EndArray();
			else
				writer.EndObject();

			break;
			}

		case TYPE_RECORD:
			{
			writer.StartObject();

			auto* rval = val->AsRecordVal();
			auto rt = rval->GetType()->AsRecordType();

			for ( auto i = 0; i < rt->NumFields(); ++i )
				{
				auto value = rval->LookupWithDefault(i);

				if ( value && ( ! only_loggable || rt->FieldHasAttr(i, ATTR_LOG) ) )
					{
					string key_str;
					auto field_name = rt->FieldName(i);

					if ( re && re->MatchAnywhere(field_name) != 0 )
						{
						auto blank = make_intrusive<StringVal>("");
						auto fn_val = make_intrusive<StringVal>(field_name);
						auto key_val = fn_val->Substitute(re, blank.get(), false);
						key_str = key_val->ToStdString();
						}
					else
						key_str = field_name;

					BuildJSON(writer, value.get(), only_loggable, re, key_str);
					}
				}

			writer.EndObject();
			break;
			}

		case TYPE_LIST:
			{
			writer.StartArray();

			auto* lval = val->AsListVal();
			size_t size = lval->Length();
			for (size_t i = 0; i < size; i++)
				BuildJSON(writer, lval->Idx(i).get(), only_loggable, re);

			writer.EndArray();
			break;
			}

		case TYPE_VECTOR:
			{
			writer.StartArray();

			auto* vval = val->AsVectorVal();
			size_t size = vval->SizeVal()->AsCount();
			for (size_t i = 0; i < size; i++)
				BuildJSON(writer, vval->Lookup(i), only_loggable, re);

			writer.EndArray();
			break;
			}

		case TYPE_OPAQUE:
			{
			writer.StartObject();

			writer.Key("opaque_type");
			auto* oval = val->AsOpaqueVal();
			writer.String(OpaqueMgr::mgr()->TypeID(oval));

			writer.EndObject();
			break;
			}

		default:
		  writer.Null();
		  break;
		}
	}

IntrusivePtr<StringVal> Val::ToJSON(bool only_loggable, RE_Matcher* re)
	{
	rapidjson::StringBuffer buffer;
	threading::formatter::JSON::NullDoubleWriter writer(buffer);

	BuildJSON(writer, this, only_loggable, re, "");

	return make_intrusive<StringVal>(buffer.GetString());
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

			double num = v / unit;
			num = num < 0 ? std::ceil(num) : std::floor(num);
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

IntrusivePtr<Val> PortVal::SizeVal() const
	{
	return val_mgr->Int(val.uint_val);
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

PortVal::PortVal(uint32_t p) : Val(bro_uint_t(p), TYPE_PORT)
	{
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

bool PortVal::IsTCP() const
	{
	return (val.uint_val & PORT_SPACE_MASK) == TCP_PORT_MASK;
	}

bool PortVal::IsUDP() const
	{
	return (val.uint_val & PORT_SPACE_MASK) == UDP_PORT_MASK;
	}

bool PortVal::IsICMP() const
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

IntrusivePtr<Val> PortVal::DoClone(CloneState* state)
	{
	// Immutable.
	return {NewRef{}, this};
	}

AddrVal::AddrVal(const char* text) : Val(new IPAddr(text), TYPE_ADDR)
	{
	}

AddrVal::AddrVal(const std::string& text) : AddrVal(text.c_str())
	{
	}

AddrVal::AddrVal(uint32_t addr) : Val(new IPAddr(IPv4, &addr, IPAddr::Network), TYPE_ADDR)
	{
	// ### perhaps do gethostbyaddr here?
	}

AddrVal::AddrVal(const uint32_t addr[4]) : Val(new IPAddr(IPv6, addr, IPAddr::Network), TYPE_ADDR)
	{
	}

AddrVal::AddrVal(const IPAddr& addr) : Val(new IPAddr(addr), TYPE_ADDR)
	{
	}

AddrVal::~AddrVal()
	{
	delete val.addr_val;
	}

unsigned int AddrVal::MemoryAllocation() const
	{
	return padded_sizeof(*this) + val.addr_val->MemoryAllocation();
	}

IntrusivePtr<Val> AddrVal::SizeVal() const
	{
	if ( val.addr_val->GetFamily() == IPv4 )
		return val_mgr->Count(32);
	else
		return val_mgr->Count(128);
	}

IntrusivePtr<Val> AddrVal::DoClone(CloneState* state)
	{
	// Immutable.
	return {NewRef{}, this};
	}

SubNetVal::SubNetVal(const char* text) : Val(new IPPrefix(), TYPE_SUBNET)
	{
	if ( ! IPPrefix::ConvertString(text, val.subnet_val) )
		reporter->Error("Bad string in SubNetVal ctor: %s", text);
	}

SubNetVal::SubNetVal(const char* text, int width) : Val(new IPPrefix(text, width), TYPE_SUBNET)
	{
	}

SubNetVal::SubNetVal(uint32_t addr, int width) : SubNetVal(IPAddr{IPv4, &addr, IPAddr::Network}, width)
	{
	}

SubNetVal::SubNetVal(const uint32_t* addr, int width) : SubNetVal(IPAddr{IPv6, addr, IPAddr::Network}, width)
	{
	}

SubNetVal::SubNetVal(const IPAddr& addr, int width) : Val(new IPPrefix(addr, width), TYPE_SUBNET)
	{
	}

SubNetVal::SubNetVal(const IPPrefix& prefix) : Val(new IPPrefix(prefix), TYPE_SUBNET)
	{
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

IntrusivePtr<Val> SubNetVal::SizeVal() const
	{
	int retained = 128 - val.subnet_val->LengthIPv6();
	return make_intrusive<Val>(pow(2.0, double(retained)), TYPE_DOUBLE);
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
	return val.subnet_val->Contains(addr);
	}

IntrusivePtr<Val> SubNetVal::DoClone(CloneState* state)
	{
	// Immutable.
	return {NewRef{}, this};
	}

StringVal::StringVal(BroString* s) : Val(s, TYPE_STRING)
	{
	}

// The following adds a NUL at the end.
StringVal::StringVal(int length, const char* s)
	: StringVal(new BroString(reinterpret_cast<const u_char*>(s), length, true))
	{
	}

StringVal::StringVal(const char* s) : StringVal(new BroString(s))
	{
	}

StringVal::StringVal(const string& s) : StringVal(s.length(), s.data())
	{
	}

IntrusivePtr<Val> StringVal::SizeVal() const
	{
	return val_mgr->Count(val.string_val->Len());
	}

int StringVal::Len()
	{
	return AsString()->Len();
	}

const u_char* StringVal::Bytes()
	{
	return AsString()->Bytes();
	}

const char* StringVal::CheckString()
	{
	return AsString()->CheckString();
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

IntrusivePtr<StringVal> StringVal::Substitute(RE_Matcher* re, StringVal* repl, bool do_all)
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

	return make_intrusive<StringVal>(new BroString(true, result, r - result));
	}

IntrusivePtr<Val> StringVal::DoClone(CloneState* state)
	{
	// We could likely treat this type as immutable and return a reference
	// instead of creating a new copy, but we first need to be careful and
	// audit whether anything internal actually does mutate it.
	return state->NewClone(this, make_intrusive<StringVal>(
	        new BroString((u_char*) val.string_val->Bytes(),
	                      val.string_val->Len(), true)));
	}

PatternVal::PatternVal(RE_Matcher* re)
	: Val(base_type(TYPE_PATTERN))
	{
	val.re_val = re;
	}

PatternVal::~PatternVal()
	{
	delete AsPattern();
	}

bool PatternVal::AddTo(Val* v, bool /* is_first_init */) const
	{
	if ( v->GetType()->Tag() != TYPE_PATTERN )
		{
		v->Error("not a pattern");
		return false;
		}

	PatternVal* pv = v->AsPatternVal();

	RE_Matcher* re = new RE_Matcher(AsPattern()->PatternText());
	re->AddPat(pv->AsPattern()->PatternText());
	re->Compile();

	pv->SetMatcher(re);

	return true;
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

IntrusivePtr<Val> PatternVal::DoClone(CloneState* state)
	{
	// We could likely treat this type as immutable and return a reference
	// instead of creating a new copy, but we first need to be careful and
	// audit whether anything internal actually does mutate it.
	auto re = new RE_Matcher(val.re_val->PatternText(),
	                         val.re_val->AnywherePatternText());
	re->Compile();
	return state->NewClone(this, make_intrusive<PatternVal>(re));
	}

ListVal::ListVal(TypeTag t)
	: Val(make_intrusive<TypeList>(t == TYPE_ANY ? nullptr : base_type(t)))
	{
	tag = t;
	}

ListVal::~ListVal()
	{
	}

IntrusivePtr<Val> ListVal::SizeVal() const
	{
	return val_mgr->Count(vals.size());
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

void ListVal::Append(IntrusivePtr<Val> v)
	{
	if ( type->AsTypeList()->IsPure() )
		{
		if ( v->GetType()->Tag() != tag )
			Internal("heterogeneous list in ListVal::Append");
		}

	const auto& vt = v->GetType();
	vals.emplace_back(std::move(v));
	type->AsTypeList()->Append(vt);
	}

void ListVal::Append(Val* v)
	{
	Append({AdoptRef{}, v});
	}

IntrusivePtr<TableVal> ListVal::ToSetVal() const
	{
	if ( tag == TYPE_ANY )
		Internal("conversion of heterogeneous list to set");

	const auto& pt = type->AsTypeList()->GetPureType();
	auto set_index = make_intrusive<TypeList>(pt);
	set_index->Append(base_type(tag));
	auto s = make_intrusive<SetType>(std::move(set_index), nullptr);
	auto t = make_intrusive<TableVal>(std::move(s));

	for ( const auto& val : vals )
		t->Assign(val.get(), nullptr);

	return t;
	}

TableVal* ListVal::ConvertToSet() const
	{
	return ToSetVal().release();
	}

void ListVal::Describe(ODesc* d) const
	{
	if ( d->IsBinary() || d->IsPortable() )
		{
		type->Describe(d);
		d->SP();
		d->Add(static_cast<uint64_t>(vals.size()));
		d->SP();
		}

	for ( auto i = 0u; i < vals.size(); ++i )
		{
		if ( i > 0u )
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

IntrusivePtr<Val> ListVal::DoClone(CloneState* state)
	{
	auto lv = make_intrusive<ListVal>(tag);
	lv->vals.reserve(vals.size());
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

	size += pad_size(vals.capacity() * sizeof(decltype(vals)::value_type));
	return size + padded_sizeof(*this) + type->MemoryAllocation();
	}

TableEntryVal* TableEntryVal::Clone(Val::CloneState* state)
	{
	auto rval = new TableEntryVal(val ? val->Clone(state) : nullptr);
	rval->last_access_time = last_access_time;
	rval->expire_access_time = expire_access_time;
	return rval;
	}

TableValTimer::TableValTimer(TableVal* val, double t) : Timer(t, TIMER_TABLE_VAL)
	{
	table = val;
	}

TableValTimer::~TableValTimer()
	{
	table->ClearTimer(this);
	}

void TableValTimer::Dispatch(double t, bool is_expire)
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
	delete tv;
	}

static void find_nested_record_types(BroType* t, std::set<RecordType*>* found)
	{
	if ( ! t )
		return;

	switch ( t->Tag() ) {
	case TYPE_RECORD:
		{
		auto rt = t->AsRecordType();
		found->emplace(rt);

		for ( auto i = 0; i < rt->NumFields(); ++i )
			find_nested_record_types(rt->FieldDecl(i)->type.get(), found);
		}
		return;
	case TYPE_TABLE:
		find_nested_record_types(t->AsTableType()->Indices(), found);
		find_nested_record_types(t->AsTableType()->Yield().get(), found);
		return;
	case TYPE_LIST:
		{
		for ( const auto& type : t->AsTypeList()->Types() )
			find_nested_record_types(type.get(), found);
		}
		return;
	case TYPE_FUNC:
		find_nested_record_types(t->AsFuncType()->Args(), found);
		find_nested_record_types(t->AsFuncType()->Yield().get(), found);
		return;
	case TYPE_VECTOR:
		find_nested_record_types(t->AsVectorType()->Yield().get(), found);
		return;
	case TYPE_TYPE:
		find_nested_record_types(t->AsTypeType()->Type(), found);
		return;
	default:
		return;
	}
	}

TableVal::TableVal(IntrusivePtr<TableType> t, IntrusivePtr<Attributes> a) : Val(t)
	{
	Init(std::move(t));
	SetAttrs(std::move(a));

	if ( ! is_parsing )
		return;

	for ( const auto& t : table_type->IndexTypes() )
		{
		std::set<RecordType*> found;
		// TODO: this likely doesn't have to be repeated for each new TableVal,
		//       can remember the resulting dependencies per TableType
		find_nested_record_types(t.get(), &found);

		for ( auto rt : found )
			parse_time_table_record_dependencies[rt].emplace_back(NewRef{}, this);
		}
	}

void TableVal::Init(IntrusivePtr<TableType> t)
	{
	table_type = std::move(t);
	expire_func = nullptr;
	expire_time = nullptr;
	expire_cookie = nullptr;
	timer = nullptr;
	def_val = nullptr;

	if ( table_type->IsSubNetIndex() )
		subnets = new PrefixTable;
	else
		subnets = nullptr;

	table_hash = new CompositeHash(IntrusivePtr<TypeList>(NewRef{},
	                               table_type->Indices()));
	val.table_val = new PDict<TableEntryVal>;
	val.table_val->SetDeleteFunc(table_entry_val_delete_func);
	}

TableVal::~TableVal()
	{
	if ( timer )
		timer_mgr->Cancel(timer);

	delete table_hash;
	delete AsTable();
	delete subnets;
	}

void TableVal::RemoveAll()
	{
	// Here we take the brute force approach.
	delete AsTable();
	val.table_val = new PDict<TableEntryVal>;
	val.table_val->SetDeleteFunc(table_entry_val_delete_func);
	}

int TableVal::Size() const
	{
	return AsTable()->Length();
	}

int TableVal::RecursiveSize() const
	{
	int n = AsTable()->Length();

	if ( GetType()->IsSet() ||
	     GetType()->AsTableType()->Yield()->Tag() != TYPE_TABLE )
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

void TableVal::SetAttrs(IntrusivePtr<Attributes> a)
	{
	attrs = std::move(a);

	if ( ! attrs )
		return;

	CheckExpireAttr(ATTR_EXPIRE_READ);
	CheckExpireAttr(ATTR_EXPIRE_WRITE);
	CheckExpireAttr(ATTR_EXPIRE_CREATE);

	Attr* ef = attrs->FindAttr(ATTR_EXPIRE_FUNC);

	if ( ef )
		expire_func = {NewRef{}, ef->AttrExpr()};

	auto cf = attrs->FindAttr(ATTR_ON_CHANGE);

	if ( cf )
		change_func = {NewRef{}, cf->AttrExpr()};
	}

void TableVal::CheckExpireAttr(attr_tag at)
	{
	Attr* a = attrs->FindAttr(at);

	if ( a )
		{
		expire_time = {NewRef{}, a->AttrExpr()};

		if ( expire_time->GetType()->Tag() != TYPE_INTERVAL )
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

bool TableVal::Assign(Val* index, IntrusivePtr<Val> new_val)
	{
	HashKey* k = ComputeHash(index);
	if ( ! k )
		{
		index->Error("index type doesn't match table", table_type->Indices());
		return false;
		}

	return Assign(index, k, std::move(new_val));
	}

bool TableVal::Assign(Val* index, Val* new_val)
	{
	return Assign(index, {AdoptRef{}, new_val});
	}

bool TableVal::Assign(Val* index, HashKey* k, IntrusivePtr<Val> new_val)
	{
	bool is_set = table_type->IsSet();

	if ( (is_set && new_val) || (! is_set && ! new_val) )
		InternalWarning("bad set/table in TableVal::Assign");

	TableEntryVal* new_entry_val = new TableEntryVal(new_val);
	HashKey k_copy(k->Key(), k->Size(), k->Hash());
	TableEntryVal* old_entry_val = AsNonConstTable()->Insert(k, new_entry_val);

	// If the dictionary index already existed, the insert may free up the
	// memory allocated to the key bytes, so have to assume k is invalid
	// from here on out.
	delete k;
	k = nullptr;

	if ( subnets )
		{
		if ( ! index )
			{
			auto v = RecoverIndex(&k_copy);
			subnets->Insert(v.get(), new_entry_val);
			}
		else
			subnets->Insert(index, new_entry_val);
		}

	// Keep old expiration time if necessary.
	if ( old_entry_val && attrs && attrs->FindAttr(ATTR_EXPIRE_CREATE) )
		new_entry_val->SetExpireAccess(old_entry_val->ExpireAccessTime());

	Modified();

	if ( change_func )
		{
		auto change_index = index ? IntrusivePtr<Val>{NewRef{}, index}
		                          : RecoverIndex(&k_copy);
		Val* v = old_entry_val ? old_entry_val->Value() : new_val.get();
		CallChangeFunc(change_index.get(), v, old_entry_val ? ELEMENT_CHANGED : ELEMENT_NEW);
		}

	delete old_entry_val;

	return true;
	}

bool TableVal::Assign(Val* index, HashKey* k, Val* new_val)
	{
	return Assign(index, k, {AdoptRef{}, new_val});
	}

IntrusivePtr<Val> TableVal::SizeVal() const
	{
	return val_mgr->Count(Size());
	}

bool TableVal::AddTo(Val* val, bool is_first_init) const
	{
	return AddTo(val, is_first_init, true);
	}

bool TableVal::AddTo(Val* val, bool is_first_init, bool propagate_ops) const
	{
	if ( val->GetType()->Tag() != TYPE_TABLE )
		{
		val->Error("not a table");
		return false;
		}

	TableVal* t = val->AsTableVal();

	if ( ! same_type(type.get(), t->GetType().get()) )
		{
		type->Error("table type clash", t->GetType().get());
		return false;
		}

	const PDict<TableEntryVal>* tbl = AsTable();
	IterCookie* c = tbl->InitForIteration();

	HashKey* k;
	TableEntryVal* v;
	while ( (v = tbl->NextEntry(k, c)) )
		{
		if ( is_first_init && t->AsTable()->Lookup(k) )
			{
			auto key = table_hash->RecoverVals(k);
			// ### Shouldn't complain if their values are equal.
			key->Warn("multiple initializations for index");
			continue;
			}

		if ( type->IsSet() )
			{
			if ( ! t->Assign(v->Value(), k, nullptr) )
				 return false;
			}
		else
			{
			if ( ! t->Assign(nullptr, k, {NewRef{}, v->Value()}) )
				 return false;
			}
		}

	return true;
	}

bool TableVal::RemoveFrom(Val* val) const
	{
	if ( val->GetType()->Tag() != TYPE_TABLE )
		{
		val->Error("not a table");
		return false;
		}

	TableVal* t = val->AsTableVal();

	if ( ! same_type(type.get(), t->GetType().get()) )
		{
		type->Error("table type clash", t->GetType().get());
		return false;
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
		t->Delete(k);
		delete k;
		}

	return true;
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
			t2->Insert(k, new TableEntryVal(nullptr));

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

bool TableVal::ExpandAndInit(IntrusivePtr<Val> index, IntrusivePtr<Val> new_val)
	{
	const auto& index_type = index->GetType();

	if ( index_type->IsSet() )
		{
		index = index->AsTableVal()->ToListVal();
		return ExpandAndInit(std::move(index), std::move(new_val));
		}

	if ( index_type->Tag() != TYPE_LIST )
		// Nothing to expand.
		return CheckAndAssign(index.get(), std::move(new_val));

	ListVal* iv = index->AsListVal();
	if ( iv->BaseTag() != TYPE_ANY )
		{
		if ( table_type->Indices()->Types().size() != 1 )
			reporter->InternalError("bad singleton list index");

		for ( int i = 0; i < iv->Length(); ++i )
			if ( ! ExpandAndInit(iv->Idx(i), new_val) )
				return false;

		return true;
		}

	else
		{ // Compound table.
		int i;

		for ( i = 0; i < iv->Length(); ++i )
			{
			const auto& v = iv->Idx(i);
			// ### if CompositeHash::ComputeHash did flattening
			// of 1-element lists (like ComputeSingletonHash does),
			// then we could optimize here.
			const auto& t = v->GetType();

			if ( t->IsSet() || t->Tag() == TYPE_LIST )
				break;
			}

		if ( i >= iv->Length() )
			// Nothing to expand.
			return CheckAndAssign(index.get(), std::move(new_val));
		else
			return ExpandCompoundAndInit(iv, i, std::move(new_val));
		}
	}


IntrusivePtr<Val> TableVal::Default(Val* index)
	{
	Attr* def_attr = FindAttr(ATTR_DEFAULT);

	if ( ! def_attr )
		return nullptr;

	if ( ! def_val )
		{
		const auto& ytype = GetType()->Yield();
		const auto& dtype = def_attr->AttrExpr()->GetType();

		if ( dtype->Tag() == TYPE_RECORD && ytype->Tag() == TYPE_RECORD &&
		     ! same_type(dtype.get(), ytype.get()) &&
		     record_promotion_compatible(dtype->AsRecordType(),
						 ytype->AsRecordType()) )
			{
			auto coerce = make_intrusive<RecordCoerceExpr>(
			        IntrusivePtr{NewRef{}, def_attr->AttrExpr()},
			        IntrusivePtr{NewRef{}, ytype->AsRecordType()});
			def_val = coerce->Eval(nullptr);
			}

		else
			def_val = def_attr->AttrExpr()->Eval(nullptr);
		}

	if ( ! def_val )
		{
		Error("non-constant default attribute");
		return nullptr;
		}

	if ( def_val->GetType()->Tag() != TYPE_FUNC ||
	     same_type(def_val->GetType().get(), GetType()->Yield().get()) )
		{
		if ( def_attr->AttrExpr()->IsConst() )
			return def_val;

		try
			{
			return def_val->Clone();
			}
		catch ( InterpreterException& e )
			{ /* Already reported. */ }

		Error("&default value for table is not clone-able");
		return nullptr;
		}

	const Func* f = def_val->AsFunc();
	zeek::Args vl;

	if ( index->GetType()->Tag() == TYPE_LIST )
		{
		auto lv = index->AsListVal();
		vl.reserve(lv->Length());

		for ( const auto& v : lv->Vals() )
			vl.emplace_back(v);
		}
	else
		vl.emplace_back(NewRef{}, index);

	IntrusivePtr<Val> result;

	try
		{
		result = f->Call(vl);
		}

	catch ( InterpreterException& e )
		{ /* Already reported. */ }

	if ( ! result )
		{
		Error("no value returned from &default function");
		return nullptr;
		}

	return result;
	}

IntrusivePtr<Val> TableVal::Lookup(Val* index, bool use_default_val)
	{
	if ( subnets )
		{
		TableEntryVal* v = (TableEntryVal*) subnets->Lookup(index);
		if ( v )
			{
			if ( attrs && attrs->FindAttr(ATTR_EXPIRE_READ) )
					v->SetExpireAccess(network_time);

			return {NewRef{}, v->Value() ? v->Value() : this};
			}

		if ( ! use_default_val )
			return nullptr;

		return Default(index);
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

				return {NewRef{}, v->Value() ? v->Value() : this};
				}
			}
		}

	if ( ! use_default_val )
		return nullptr;

	return Default(index);
	}

IntrusivePtr<VectorVal> TableVal::LookupSubnets(const SubNetVal* search)
	{
	if ( ! subnets )
		reporter->InternalError("LookupSubnets called on wrong table type");

	auto result = make_intrusive<VectorVal>(zeek::id::lookup_type<VectorType>("subnet_vec"));

	auto matches = subnets->FindAll(search);
	for ( auto element : matches )
		result->Assign(result->Size(), make_intrusive<SubNetVal>(get<0>(element)));

	return result;
	}

IntrusivePtr<TableVal> TableVal::LookupSubnetValues(const SubNetVal* search)
	{
	if ( ! subnets )
		reporter->InternalError("LookupSubnetValues called on wrong table type");

	auto nt = make_intrusive<TableVal>(this->GetType<TableType>());

	auto matches = subnets->FindAll(search);
	for ( auto element : matches )
		{
		SubNetVal* s = new SubNetVal(get<0>(element));
		TableEntryVal* entry = reinterpret_cast<TableEntryVal*>(get<1>(element));

		if ( entry && entry->Value() )
			nt->Assign(s, {NewRef{}, entry->Value()});
		else
			nt->Assign(s, nullptr); // set

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

IntrusivePtr<ListVal> TableVal::RecoverIndex(const HashKey* k) const
	{
	return table_hash->RecoverVals(k);
	}

void TableVal::CallChangeFunc(const Val* index, Val* old_value, OnChangeType tpe)
	{
	if ( ! change_func || ! index || in_change_func )
		return;

	if ( ! table_type->IsSet() && ! old_value )
		return;

	try
		{
		auto thefunc = change_func->Eval(nullptr);

		if ( ! thefunc )
			{
			return;
			}

		if ( thefunc->GetType()->Tag() != TYPE_FUNC )
			{
			thefunc->Error("not a function");
			return;
			}

		const Func* f = thefunc->AsFunc();
		auto lv = index->AsListVal();

		zeek::Args vl;
		vl.reserve(2 + lv->Length() + table_type->IsTable());
		vl.emplace_back(NewRef{}, this);

		switch ( tpe )
			{
			case ELEMENT_NEW:
				vl.emplace_back(BifType::Enum::TableChange->GetVal(BifEnum::TableChange::TABLE_ELEMENT_NEW));
				break;
			case ELEMENT_CHANGED:
				vl.emplace_back(BifType::Enum::TableChange->GetVal(BifEnum::TableChange::TABLE_ELEMENT_CHANGED));
				break;
			case ELEMENT_REMOVED:
				vl.emplace_back(BifType::Enum::TableChange->GetVal(BifEnum::TableChange::TABLE_ELEMENT_REMOVED));
				break;
			case ELEMENT_EXPIRED:
				vl.emplace_back(BifType::Enum::TableChange->GetVal(BifEnum::TableChange::TABLE_ELEMENT_EXPIRED));
			}

		for ( const auto& v : lv->Vals() )
			vl.emplace_back(v);

		if ( table_type->IsTable() )
			vl.emplace_back(NewRef{}, old_value);

		in_change_func = true;
		f->Call(vl);
		}
	catch ( InterpreterException& e )
		{
		}

	in_change_func = false;
	}

IntrusivePtr<Val> TableVal::Delete(const Val* index)
	{
	HashKey* k = ComputeHash(index);
	TableEntryVal* v = k ? AsNonConstTable()->RemoveEntry(k) : nullptr;
	IntrusivePtr<Val> va{NewRef{}, v ? (v->Value() ? v->Value() : this) : nullptr};

	if ( subnets && ! subnets->Remove(index) )
		reporter->InternalWarning("index not in prefix table");

	delete k;
	delete v;

	Modified();

	if ( change_func )
		CallChangeFunc(index, va.get(), ELEMENT_REMOVED);

	return va;
	}

IntrusivePtr<Val> TableVal::Delete(const HashKey* k)
	{
	TableEntryVal* v = AsNonConstTable()->RemoveEntry(k);
	IntrusivePtr<Val> va{NewRef{}, v ? (v->Value() ? v->Value() : this) : nullptr};

	if ( subnets )
		{
		auto index = table_hash->RecoverVals(k);

		if ( ! subnets->Remove(index.get()) )
			reporter->InternalWarning("index not in prefix table");
		}

	delete v;

	Modified();

	if ( change_func && va )
		{
		auto index = table_hash->RecoverVals(k);
		CallChangeFunc(index.get(), va.get(), ELEMENT_REMOVED);
		}

	return va;
	}

IntrusivePtr<ListVal> TableVal::ToListVal(TypeTag t) const
	{
	auto l = make_intrusive<ListVal>(t);

	const PDict<TableEntryVal>* tbl = AsTable();
	IterCookie* c = tbl->InitForIteration();

	HashKey* k;
	while ( tbl->NextEntry(k, c) )
		{
		auto index = table_hash->RecoverVals(k);

		if ( t == TYPE_ANY )
			l->Append(std::move(index));
		else
			{
			// We're expecting a pure list, flatten the ListVal.
			if ( index->Length() != 1 )
				InternalWarning("bad index in TableVal::ToListVal");

			l->Append(index->Idx(0));
			}

		delete k;
		}

	return l;
	}

ListVal* TableVal::ConvertToList(TypeTag t) const
	{
	return ToListVal().release();
	}

IntrusivePtr<ListVal> TableVal::ToPureListVal() const
	{
	const auto& tl = table_type->Indices()->Types();
	if ( tl.size() != 1 )
		{
		InternalWarning("bad index type in TableVal::ToPureListVal");
		return nullptr;
		}

	return ToListVal(tl[0]->Tag());
	}

ListVal* TableVal::ConvertToPureList() const
	{
	return ToPureListVal().release();
	}

Attr* TableVal::FindAttr(attr_tag t) const
	{
	return attrs ? attrs->FindAttr(t) : nullptr;
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

		auto vl = table_hash->RecoverVals(k);
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

bool TableVal::ExpandCompoundAndInit(ListVal* lv, int k, IntrusivePtr<Val> new_val)
	{
	Val* ind_k_v = lv->Idx(k).get();
	auto ind_k = ind_k_v->GetType()->IsSet() ?
	      ind_k_v->AsTableVal()->ToListVal() :
	      IntrusivePtr<ListVal>{NewRef{}, ind_k_v->AsListVal()};

	for ( int i = 0; i < ind_k->Length(); ++i )
		{
		const auto& ind_k_i = ind_k->Idx(i);
		auto expd = make_intrusive<ListVal>(TYPE_ANY);

		for ( auto j = 0; j < lv->Length(); ++j )
			{
			const auto& v = lv->Idx(j);

			if ( j == k )
				expd->Append(ind_k_i);
			else
				expd->Append(v);
			}

		if ( ! ExpandAndInit(std::move(expd), new_val) )
			return false;
		}

	return true;
	}

bool TableVal::CheckAndAssign(Val* index, IntrusivePtr<Val> new_val)
	{
	Val* v = nullptr;
	if ( subnets )
		// We need an exact match here.
		v = (Val*) subnets->Lookup(index, true);
	else
		v = Lookup(index, false).get();

	if ( v )
		index->Warn("multiple initializations for index");

	return Assign(index, std::move(new_val));
	}

void TableVal::InitDefaultFunc(Frame* f)
	{
	// Value aready initialized.
	if ( def_val )
		return;

	Attr* def_attr = FindAttr(ATTR_DEFAULT);
	if ( ! def_attr )
		return;

	const auto& ytype = GetType()->Yield();
	const auto& dtype = def_attr->AttrExpr()->GetType();

	if ( dtype->Tag() == TYPE_RECORD && ytype->Tag() == TYPE_RECORD &&
	     ! same_type(dtype.get(), ytype.get()) &&
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

	HashKey* k = nullptr;
	TableEntryVal* v = nullptr;
	TableEntryVal* v_saved = nullptr;
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
			IntrusivePtr<ListVal> idx = nullptr;

			if ( expire_func )
				{
				idx = RecoverIndex(k);
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
				if ( ! idx )
					idx = RecoverIndex(k);
				if ( ! subnets->Remove(idx.get()) )
					reporter->InternalWarning("index not in prefix table");
				}

			tbl->RemoveEntry(k);
			if ( change_func )
				{
				if ( ! idx )
					idx = RecoverIndex(k);
				CallChangeFunc(idx.get(), v->Value(), ELEMENT_EXPIRED);
				}

			delete v;
			modified = true;
			}

		delete k;
		}

	if ( modified )
		Modified();

	if ( ! v )
		{
		expire_cookie = nullptr;
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
		auto timeout = expire_time->Eval(nullptr);
		interval = (timeout ? timeout->AsInterval() : -1);
		}
	catch ( InterpreterException& e )
		{
		interval = -1;
		}

	if ( interval >= 0 )
		return interval;

	expire_time = nullptr;

	if ( timer )
		timer_mgr->Cancel(timer);

	return -1;
	}

double TableVal::CallExpireFunc(IntrusivePtr<ListVal> idx)
	{
	if ( ! expire_func )
		return 0;

	double secs = 0;

	try
		{
		auto vf = expire_func->Eval(nullptr);

		if ( ! vf )
			// Will have been reported already.
			return 0;

		if ( vf->GetType()->Tag() != TYPE_FUNC )
			{
			vf->Error("not a function");
			return 0;
			}

		const Func* f = vf->AsFunc();
		zeek::Args vl;

		const auto& func_args = f->FType()->ArgTypes()->Types();
		// backwards compatibility with idx: any idiom
		bool any_idiom = func_args.size() == 2 && func_args.back()->Tag() == TYPE_ANY;

		if ( ! any_idiom )
			{
			auto lv = idx->AsListVal();
			vl.reserve(1 + lv->Length());
			vl.emplace_back(NewRef{}, this);

			for ( const auto& v : lv->Vals() )
				vl.emplace_back(v);
			}
		else
			{
			vl.reserve(2);
			vl.emplace_back(NewRef{}, this);

			ListVal* idx_list = idx->AsListVal();
			// Flatten if only one element
			if ( idx_list->Length() == 1 )
				vl.emplace_back(idx_list->Idx(0));
			else
				vl.emplace_back(std::move(idx));
			}

		auto result = f->Call(vl);

		if ( result )
			secs = result->AsInterval();
		}

	catch ( InterpreterException& e )
		{
		}

	return secs;
	}

IntrusivePtr<Val> TableVal::DoClone(CloneState* state)
	{
	auto tv = make_intrusive<TableVal>(table_type);
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
			auto idx = RecoverIndex(key);
			tv->subnets->Insert(idx.get(), nval);
			}

		delete key;
		}

	tv->attrs = attrs;

	if ( expire_time )
		{
		tv->expire_time = expire_time;

		// As network_time is not necessarily initialized yet, we set
		// a timer which fires immediately.
		timer = new TableValTimer(this, 1);
		timer_mgr->Add(timer);
		}

	if ( expire_func )
		tv->expire_func = expire_func;

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

HashKey* TableVal::ComputeHash(const Val* index) const
	{
	return table_hash->ComputeHash(index, true);
	}

void TableVal::SaveParseTimeTableState(RecordType* rt)
	{
	auto it = parse_time_table_record_dependencies.find(rt);

	if ( it == parse_time_table_record_dependencies.end() )
		return;

	auto& table_vals = it->second;

	for ( auto& tv : table_vals )
		parse_time_table_states[tv.get()] = tv->DumpTableState();
	}

void TableVal::RebuildParseTimeTables()
	{
	for ( auto& [tv, ptts] : parse_time_table_states )
		tv->RebuildTable(std::move(ptts));

	parse_time_table_states.clear();
	}

void TableVal::DoneParsing()
	{
	parse_time_table_record_dependencies.clear();
	}

TableVal::ParseTimeTableState TableVal::DumpTableState()
	{
	const PDict<TableEntryVal>* tbl = AsTable();
	IterCookie* cookie = tbl->InitForIteration();

	HashKey* key;
	TableEntryVal* val;

	ParseTimeTableState rval;

	while ( (val = tbl->NextEntry(key, cookie)) )
		{
		rval.emplace_back(RecoverIndex(key),
		                  IntrusivePtr<Val>{NewRef{}, val->Value()});

		delete key;
		}

	RemoveAll();
	return rval;
	}

void TableVal::RebuildTable(ParseTimeTableState ptts)
	{
	delete table_hash;
	table_hash = new CompositeHash(IntrusivePtr<TypeList>(NewRef{},
	                               table_type->Indices()));

	for ( auto& [key, val] : ptts )
		Assign(key.get(), val.release());
	}

TableVal::ParseTimeTableStates TableVal::parse_time_table_states;

TableVal::TableRecordDependencies TableVal::parse_time_table_record_dependencies;

RecordVal::RecordTypeValMap RecordVal::parse_time_records;

RecordVal::RecordVal(RecordType* t, bool init_fields)
	: RecordVal({NewRef{}, t}, init_fields)
	{}

RecordVal::RecordVal(IntrusivePtr<RecordType> t, bool init_fields) : Val(std::move(t))
	{
	origin = nullptr;
	auto rt = GetType()->AsRecordType();
	int n = rt->NumFields();
	val_list* vl = val.val_list_val = new val_list(n);

	if ( is_parsing )
		parse_time_records[rt].emplace_back(NewRef{}, this);

	if ( ! init_fields )
		return;

	// Initialize to default values from RecordType (which are nil
	// by default).
	for ( int i = 0; i < n; ++i )
		{
		Attributes* a = rt->FieldDecl(i)->attrs.get();
		Attr* def_attr = a ? a->FindAttr(ATTR_DEFAULT) : nullptr;
		auto def = def_attr ? def_attr->AttrExpr()->Eval(nullptr) : nullptr;
		const auto& type = rt->FieldDecl(i)->type;

		if ( def && type->Tag() == TYPE_RECORD &&
		     def->GetType()->Tag() == TYPE_RECORD &&
		     ! same_type(def->GetType().get(), type.get()) )
			{
			auto tmp = def->AsRecordVal()->CoerceTo(type->AsRecordType());

			if ( tmp )
				def = std::move(tmp);
			}

		if ( ! def && ! (a && a->FindAttr(ATTR_OPTIONAL)) )
			{
			TypeTag tag = type->Tag();

			if ( tag == TYPE_RECORD )
				def = make_intrusive<RecordVal>(type->AsRecordType());

			else if ( tag == TYPE_TABLE )
				def = make_intrusive<TableVal>(IntrusivePtr{NewRef{}, type->AsTableType()},
				                               IntrusivePtr{NewRef{}, a});

			else if ( tag == TYPE_VECTOR )
				def = make_intrusive<VectorVal>(cast_intrusive<VectorType>(type));
			}

		vl->push_back(def.release());
		}
	}

RecordVal::~RecordVal()
	{
	delete_vals(AsNonConstRecord());
	}

IntrusivePtr<Val> RecordVal::SizeVal() const
	{
	return val_mgr->Count(GetType()->AsRecordType()->NumFields());
	}

void RecordVal::Assign(int field, IntrusivePtr<Val> new_val)
	{
	Val* old_val = AsNonConstRecord()->replace(field, new_val.release());
	Unref(old_val);
	Modified();
	}

void RecordVal::Assign(int field, Val* new_val)
	{
	Assign(field, {AdoptRef{}, new_val});
	}

Val* RecordVal::Lookup(int field) const
	{
	return (*AsRecord())[field];
	}

IntrusivePtr<Val> RecordVal::LookupWithDefault(int field) const
	{
	Val* val = (*AsRecord())[field];

	if ( val )
		return {NewRef{}, val};

	return GetType()->AsRecordType()->FieldDefault(field);
	}

void RecordVal::ResizeParseTimeRecords(RecordType* rt)
	{
	auto it = parse_time_records.find(rt);

	if ( it == parse_time_records.end() )
		return;

	auto& rvs = it->second;

	for ( auto& rv : rvs )
		{
		auto vs = rv->val.val_list_val;
		auto current_length = vs->length();
		auto required_length = rt->NumFields();

		if ( required_length > current_length )
			{
			vs->resize(required_length);

			for ( auto i = current_length; i < required_length; ++i )
				vs->replace(i, rt->FieldDefault(i).release());
			}
		}
	}

void RecordVal::DoneParsing()
	{
	parse_time_records.clear();
	}

IntrusivePtr<Val> RecordVal::Lookup(const char* field, bool with_default) const
	{
	int idx = GetType()->AsRecordType()->FieldOffset(field);

	if ( idx < 0 )
		reporter->InternalError("missing record field: %s", field);

	return with_default ? LookupWithDefault(idx) : IntrusivePtr{NewRef{}, Lookup(idx)};
	}

IntrusivePtr<RecordVal> RecordVal::CoerceTo(const RecordType* t, Val* aggr, bool allow_orphaning) const
	{
	if ( ! record_promotion_compatible(t->AsRecordType(), GetType()->AsRecordType()) )
		return nullptr;

	if ( ! aggr )
		aggr = new RecordVal(const_cast<RecordType*>(t->AsRecordType()));

	RecordVal* ar = aggr->AsRecordVal();
	RecordType* ar_t = aggr->GetType()->AsRecordType();

	const RecordType* rv_t = GetType()->AsRecordType();

	int i;
	for ( i = 0; i < rv_t->NumFields(); ++i )
		{
		int t_i = ar_t->FieldOffset(rv_t->FieldName(i));

		if ( t_i < 0 )
			{
			if ( allow_orphaning )
				continue;

			char buf[512];
			snprintf(buf, sizeof(buf),
					"orphan field \"%s\" in initialization",
					rv_t->FieldName(i));
			Error(buf);
			break;
			}

		Val* v = Lookup(i);

		if ( ! v )
			// Check for allowable optional fields is outside the loop, below.
			continue;

		const auto& ft = ar_t->GetFieldType(t_i);

		if ( ft->Tag() == TYPE_RECORD && ! same_type(ft.get(), v->GetType().get()) )
			{
			auto rhs = make_intrusive<ConstExpr>(IntrusivePtr{NewRef{}, v});
			auto e = make_intrusive<RecordCoerceExpr>(std::move(rhs),
			                                          cast_intrusive<RecordType>(ft));
			ar->Assign(t_i, e->Eval(nullptr));
			continue;
			}

		ar->Assign(t_i, {NewRef{}, v});
		}

	for ( i = 0; i < ar_t->NumFields(); ++i )
		if ( ! ar->Lookup(i) &&
			 ! ar_t->FieldDecl(i)->FindAttr(ATTR_OPTIONAL) )
			{
			char buf[512];
			snprintf(buf, sizeof(buf),
					"non-optional field \"%s\" missing in initialization", ar_t->FieldName(i));
			Error(buf);
			}

	return {AdoptRef{}, ar};
	}

IntrusivePtr<RecordVal> RecordVal::CoerceTo(RecordType* t, bool allow_orphaning)
	{
	if ( same_type(GetType().get(), t) )
		return {NewRef{}, this};

	return CoerceTo(t, nullptr, allow_orphaning);
	}

IntrusivePtr<TableVal> RecordVal::GetRecordFieldsVal() const
	{
	return GetType()->AsRecordType()->GetRecordFieldsVal(this);
	}

void RecordVal::Describe(ODesc* d) const
	{
	const val_list* vl = AsRecord();
	int n = vl->length();
	auto record_type = GetType()->AsRecordType();

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
	auto record_type = GetType()->AsRecordType();

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

IntrusivePtr<Val> RecordVal::DoClone(CloneState* state)
	{
	// We set origin to 0 here.  Origin only seems to be used for exactly one
	// purpose - to find the connection record that is associated with a
	// record. As we cannot guarantee that it will ber zeroed out at the
	// approproate time (as it seems to be guaranteed for the original record)
	// we don't touch it.
	auto rv = make_intrusive<RecordVal>(GetType()->AsRecordType(), false);
	rv->origin = nullptr;
	state->NewClone(this, rv);

	for ( const auto& vlv : *val.val_list_val )
		{
		auto v = vlv ? vlv->Clone(state) : nullptr;
  		rv->val.val_list_val->push_back(v.release());
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

IntrusivePtr<Val> EnumVal::SizeVal() const
	{
	return val_mgr->Int(val.int_val);
	}

void EnumVal::ValDescribe(ODesc* d) const
	{
	const char* ename = type->AsEnumType()->Lookup(val.int_val);

	if ( ! ename )
		ename = "<undefined>";

	d->Add(ename);
	}

IntrusivePtr<Val> EnumVal::DoClone(CloneState* state)
	{
	// Immutable.
	return {NewRef{}, this};
	}

VectorVal::VectorVal(VectorType* t) : VectorVal({NewRef{}, t})
	{ }

VectorVal::VectorVal(IntrusivePtr<VectorType> t) : Val(std::move(t))
	{
	val.vector_val = new vector<Val*>();
	}

VectorVal::~VectorVal()
	{
	for ( unsigned int i = 0; i < val.vector_val->size(); ++i )
		Unref((*val.vector_val)[i]);

	delete val.vector_val;
	}

IntrusivePtr<Val> VectorVal::SizeVal() const
	{
	return val_mgr->Count(uint32_t(val.vector_val->size()));
	}

bool VectorVal::Assign(unsigned int index, IntrusivePtr<Val> element)
	{
	if ( element &&
	     ! same_type(element->GetType().get(), GetType()->AsVectorType()->Yield().get(), false) )
		return false;

	Val* val_at_index = nullptr;

	if ( index < val.vector_val->size() )
		val_at_index = (*val.vector_val)[index];
	else
		val.vector_val->resize(index + 1);

	Unref(val_at_index);

	// Note: we do *not* Ref() the element, if any, at this point.
	// AssignExpr::Eval() already does this; other callers must remember
	// to do it similarly.
	(*val.vector_val)[index] = element.release();

	Modified();
	return true;
	}

bool VectorVal::Assign(unsigned int index, Val* element)
	{
	return Assign(index, {AdoptRef{}, element});
	}

bool VectorVal::AssignRepeat(unsigned int index, unsigned int how_many,
				Val* element)
	{
	ResizeAtLeast(index + how_many);

	for ( unsigned int i = index; i < index + how_many; ++i )
		if ( ! Assign(i, {NewRef{}, element}) )
			return false;

	return true;
	}

bool VectorVal::Insert(unsigned int index, Val* element)
	{
	if ( element &&
	     ! same_type(element->GetType().get(), GetType()->AsVectorType()->Yield().get(), false) )
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

bool VectorVal::AddTo(Val* val, bool /* is_first_init */) const
	{
	if ( val->GetType()->Tag() != TYPE_VECTOR )
		{
		val->Error("not a vector");
		return false;
		}

	VectorVal* v = val->AsVectorVal();

	if ( ! same_type(type.get(), v->GetType().get()) )
		{
		type->Error("vector type clash", v->GetType().get());
		return false;
		}

	auto last_idx = v->Size();

	for ( auto i = 0u; i < Size(); ++i )
		v->Assign(last_idx++, {NewRef{}, Lookup(i)});

	return true;
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

IntrusivePtr<Val> VectorVal::DoClone(CloneState* state)
	{
	auto vv = make_intrusive<VectorVal>(GetType<VectorType>());
	vv->val.vector_val->reserve(val.vector_val->size());
	state->NewClone(this, vv);

	for ( unsigned int i = 0; i < val.vector_val->size(); ++i )
		{
		auto v = (*val.vector_val)[i]->Clone(state);
		vv->val.vector_val->push_back(v.release());
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

IntrusivePtr<Val> check_and_promote(IntrusivePtr<Val> v, const BroType* t,
                                    bool is_init,
                                    const Location* expr_location)
	{
	if ( ! v )
		return nullptr;

	BroType* vt = v->GetType().get();

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

		t->Error("type clash", v.get(), false, expr_location);
		return nullptr;
		}

	if ( ! BothArithmetic(t_tag, v_tag) &&
	     (! IsArithmetic(v_tag) || t_tag != TYPE_TIME || ! v->IsZero()) )
		{
		if ( t_tag == TYPE_LIST || v_tag == TYPE_LIST )
			t->Error("list mixed with scalar", v.get(), false, expr_location);
		else
			t->Error("arithmetic mixed with non-arithmetic", v.get(), false, expr_location);
		return nullptr;
		}

	if ( v_tag == t_tag )
		return v;

	if ( t_tag != TYPE_TIME && ! BothArithmetic(t_tag, v_tag) )
		{
		TypeTag mt = max_type(t_tag, v_tag);
		if ( mt != t_tag )
			{
			t->Error("over-promotion of arithmetic value", v.get(), false, expr_location);
			return nullptr;
			}
		}

	// Need to promote v to type t.
	InternalTypeTag it = t->InternalType();
	InternalTypeTag vit = vt->InternalType();

	if ( it == vit )
		// Already has the right internal type.
		return v;

	IntrusivePtr<Val> promoted_v;

	switch ( it ) {
	case TYPE_INTERNAL_INT:
		if ( ( vit == TYPE_INTERNAL_UNSIGNED || vit == TYPE_INTERNAL_DOUBLE ) && Val::WouldOverflow(vt, t, v.get()) )
			{
			t->Error("overflow promoting from unsigned/double to signed arithmetic value", v.get(), false, expr_location);
			return nullptr;
			}
		else if ( t_tag == TYPE_INT )
			promoted_v = val_mgr->Int(v->CoerceToInt());
		else // enum
			{
			reporter->InternalError("bad internal type in check_and_promote()");
			return nullptr;
			}

		break;

	case TYPE_INTERNAL_UNSIGNED:
		if ( ( vit == TYPE_INTERNAL_DOUBLE || vit == TYPE_INTERNAL_INT) && Val::WouldOverflow(vt, t, v.get()) )
			{
			t->Error("overflow promoting from signed/double to unsigned arithmetic value", v.get(), false, expr_location);
			return nullptr;
			}
		else if ( t_tag == TYPE_COUNT || t_tag == TYPE_COUNTER )
			promoted_v = val_mgr->Count(v->CoerceToUnsigned());
		else // port
			{
			reporter->InternalError("bad internal type in check_and_promote()");
			return nullptr;
			}

		break;

	case TYPE_INTERNAL_DOUBLE:
		promoted_v = make_intrusive<Val>(v->CoerceToDouble(), t_tag);
		break;

	default:
		reporter->InternalError("bad internal type in check_and_promote()");
		return nullptr;
	}

	return promoted_v;
	}

bool same_val(const Val* /* v1 */, const Val* /* v2 */)
	{
	reporter->InternalError("same_val not implemented");
	return false;
	}

bool is_atomic_val(const Val* v)
	{
	return is_atomic_type(v->GetType().get());
	}

bool same_atomic_val(const Val* v1, const Val* v2)
	{
	// This is a very preliminary implementation of same_val(),
	// true only for equal, simple atomic values of same type.
	if ( v1->GetType()->Tag() != v2->GetType()->Tag() )
		return false;

	switch ( v1->GetType()->InternalType() ) {
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
		return false;
	}

	return false;
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

void describe_vals(const std::vector<IntrusivePtr<Val>>& vals,
                   ODesc* d, size_t offset)
	{
	if ( ! d->IsReadable() )
		{
		d->Add(static_cast<uint64_t>(vals.size()));
		d->SP();
		}

	for ( auto i = offset; i < vals.size(); ++i )
		{
		if ( i > offset && d->IsReadable() && d->Style() != RAW_STYLE )
			d->Add(", ");

		vals[i]->Describe(d);
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

IntrusivePtr<Val> cast_value_to_type(Val* v, BroType* t)
	{
	// Note: when changing this function, adapt all three of
	// cast_value_to_type()/can_cast_value_to_type()/can_cast_value_to_type().

	if ( ! v )
		return nullptr;

	// Always allow casting to same type. This also covers casting 'any'
	// to the actual type.
	if ( same_type(v->GetType().get(), t) )
		return {NewRef{}, v};

	if ( same_type(v->GetType().get(), bro_broker::DataVal::ScriptDataType()) )
		{
		auto dv = v->AsRecordVal()->Lookup(0);

		if ( ! dv )
			return nullptr;

		return static_cast<bro_broker::DataVal*>(dv)->castTo(t);
		}

	return nullptr;
	}

bool can_cast_value_to_type(const Val* v, BroType* t)
	{
	// Note: when changing this function, adapt all three of
	// cast_value_to_type()/can_cast_value_to_type()/can_cast_value_to_type().

	if ( ! v )
		return false;

	// Always allow casting to same type. This also covers casting 'any'
	// to the actual type.
	if ( same_type(v->GetType().get(), t) )
		return true;

	if ( same_type(v->GetType().get(), bro_broker::DataVal::ScriptDataType()) )
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

IntrusivePtr<Val> Val::MakeBool(bool b)
	{
	return IntrusivePtr{AdoptRef{}, new Val(bro_int_t(b), TYPE_BOOL)};
	}

IntrusivePtr<Val> Val::MakeInt(bro_int_t i)
	{
	return IntrusivePtr{AdoptRef{}, new Val(i, TYPE_INT)};
	}

IntrusivePtr<Val> Val::MakeCount(bro_uint_t u)
	{
	return IntrusivePtr{AdoptRef{}, new Val(u, TYPE_COUNT)};
	}

ValManager::ValManager()
	{
	empty_string = make_intrusive<StringVal>("");
	b_false = Val::MakeBool(false);
	b_true = Val::MakeBool(true);

	for ( auto i = 0u; i < PREALLOCATED_COUNTS; ++i )
		counts[i] = Val::MakeCount(i);

	for ( auto i = 0u; i < PREALLOCATED_INTS; ++i )
		ints[i] = Val::MakeInt(PREALLOCATED_INT_LOWEST + i);

	for ( auto i = 0u; i < ports.size(); ++i )
		{
		auto& arr = ports[i];
		auto port_type = (TransportProto)i;

		for ( auto j = 0u; j < arr.size(); ++j )
			arr[j] = IntrusivePtr{AdoptRef{}, new PortVal(PortVal::Mask(j, port_type))};
		}
	}

StringVal* ValManager::GetEmptyString() const
	{
	return empty_string->Ref()->AsStringVal();
	}

const IntrusivePtr<PortVal>& ValManager::Port(uint32_t port_num, TransportProto port_type) const
	{
	if ( port_num >= 65536 )
		{
		reporter->Warning("bad port number %d", port_num);
		port_num = 0;
		}

	return ports[port_type][port_num];
	}

PortVal* ValManager::GetPort(uint32_t port_num, TransportProto port_type) const
	{
	return Port(port_num, port_type)->Ref()->AsPortVal();
	}

const IntrusivePtr<PortVal>& ValManager::Port(uint32_t port_num) const
	{
	auto mask = port_num & PORT_SPACE_MASK;
	port_num &= ~PORT_SPACE_MASK;

	if ( mask == TCP_PORT_MASK )
		return Port(port_num, TRANSPORT_TCP);
	else if ( mask == UDP_PORT_MASK )
		return Port(port_num, TRANSPORT_UDP);
	else if ( mask == ICMP_PORT_MASK )
		return Port(port_num, TRANSPORT_ICMP);
	else
		return Port(port_num, TRANSPORT_UNKNOWN);
	}

PortVal* ValManager::GetPort(uint32_t port_num) const
	{
	return Port(port_num)->Ref()->AsPortVal();
	}
