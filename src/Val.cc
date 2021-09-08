// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/Val.h"
#include "zeek/Overflow.h"

#include <sys/types.h>
#include <sys/param.h>

#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>

#include <cmath>
#include <set>

#include "zeek/Attr.h"
#include "zeek/ZeekString.h"
#include "zeek/CompHash.h"
#include "zeek/Dict.h"
#include "zeek/RunState.h"
#include "zeek/File.h"
#include "zeek/Func.h"
#include "zeek/Desc.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/ID.h"
#include "zeek/RE.h"
#include "zeek/Scope.h"
#include "zeek/NetVar.h"
#include "zeek/Expr.h"
#include "zeek/PrefixTable.h"
#include "zeek/Conn.h"
#include "zeek/Reporter.h"
#include "zeek/IPAddr.h"
#include "zeek/ID.h"

#include "zeek/broker/Data.h"
#include "zeek/broker/Store.h"
#include "zeek/broker/Manager.h"

#include "zeek/threading/formatters/JSON.h"

using namespace std;

namespace zeek {

Val::~Val()
	{
#ifdef DEBUG
	delete [] bound_id;
#endif
	}

#define CONVERTER(tag, ctype, name) \
	ctype name() \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::CONVERTER", type_name) \
		return (ctype)(this); \
		}

#define CONST_CONVERTER(tag, ctype, name) \
	const ctype name() const \
		{ \
		CHECK_TAG(type->Tag(), tag, "Val::CONVERTER", type_name) \
		return (const ctype)(this); \
		}

#define CONVERTERS(tag, ctype, name) \
	CONVERTER(tag, ctype, name) \
	CONST_CONVERTER(tag, ctype, name)

CONVERTERS(TYPE_FUNC, FuncVal*, Val::AsFuncVal)
CONVERTERS(TYPE_FILE, FileVal*, Val::AsFileVal)
CONVERTERS(TYPE_PATTERN, PatternVal*, Val::AsPatternVal)
CONVERTERS(TYPE_PORT, PortVal*, Val::AsPortVal)
CONVERTERS(TYPE_SUBNET, SubNetVal*, Val::AsSubNetVal)
CONVERTERS(TYPE_ADDR, AddrVal*, Val::AsAddrVal)
CONVERTERS(TYPE_TABLE, TableVal*, Val::AsTableVal)
CONVERTERS(TYPE_RECORD, RecordVal*, Val::AsRecordVal)
CONVERTERS(TYPE_LIST, ListVal*, Val::AsListVal)
CONVERTERS(TYPE_STRING, StringVal*, Val::AsStringVal)
CONVERTERS(TYPE_VECTOR, VectorVal*, Val::AsVectorVal)
CONVERTERS(TYPE_ENUM, EnumVal*, Val::AsEnumVal)
CONVERTERS(TYPE_OPAQUE, OpaqueVal*, Val::AsOpaqueVal)
CONVERTERS(TYPE_TYPE, TypeVal*, Val::AsTypeVal)

ValPtr Val::CloneState::NewClone(Val* src, ValPtr dst)
	{
	clones.insert(std::make_pair(src, dst.get()));
	return dst;
	}

ValPtr Val::Clone()
	{
	Val::CloneState state;
	return Clone(&state);
	}

ValPtr Val::Clone(CloneState* state)
	{
	auto i = state->clones.find(this);

	if ( i != state->clones.end() )
		return {NewRef{}, i->second};

	auto c = DoClone(state);

	if ( ! c )
		reporter->RuntimeError(GetLocationInfo(), "cannot clone value");

	return c;
	}

ValPtr Val::DoClone(CloneState* state)
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:
	case TYPE_INTERNAL_UNSIGNED:
	case TYPE_INTERNAL_DOUBLE:
	 	// Immutable.
		return {NewRef{}, this};

	default:
		reporter->InternalError("cloning illegal base type");
	}

	reporter->InternalError("cannot be reached");
	return nullptr;
 	}

bool Val::IsZero() const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:		return AsInt() == 0;
	case TYPE_INTERNAL_UNSIGNED:	return AsCount() == 0;
	case TYPE_INTERNAL_DOUBLE:	return AsDouble() == 0.0;

	default:			return false;
	}
	}

bool Val::IsOne() const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:		return AsInt() == 1;
	case TYPE_INTERNAL_UNSIGNED:	return AsCount() == 1;
	case TYPE_INTERNAL_DOUBLE:	return AsDouble() == 1.0;

	default:			return false;
	}
	}

bro_int_t Val::InternalInt() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_INT )
		return AsInt();
	else if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		// ### should check here for overflow
		return static_cast<bro_int_t>(AsCount());
	else
		InternalWarning("bad request for InternalInt");

	return 0;
	}

bro_uint_t Val::InternalUnsigned() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return AsCount();
	else
		InternalWarning("bad request for InternalUnsigned");

	return 0;
	}

double Val::InternalDouble() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return AsDouble();
	else
		InternalWarning("bad request for InternalDouble");

	return 0.0;
	}

bro_int_t Val::CoerceToInt() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_INT )
		return AsInt();
	else if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return static_cast<bro_int_t>(AsCount());
	else if ( type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return static_cast<bro_int_t>(AsDouble());
	else
		InternalWarning("bad request for CoerceToInt");

	return 0;
	}

bro_uint_t Val::CoerceToUnsigned() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return AsCount();
	else if ( type->InternalType() == TYPE_INTERNAL_INT )
		return static_cast<bro_uint_t>(AsInt());
	else if ( type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return static_cast<bro_uint_t>(AsDouble());
	else
		InternalWarning("bad request for CoerceToUnsigned");

	return 0;
	}

double Val::CoerceToDouble() const
	{
	if ( type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return AsDouble();
	else if ( type->InternalType() == TYPE_INTERNAL_INT )
		return static_cast<double>(AsInt());
	else if ( type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		return static_cast<double>(AsCount());
	else
		InternalWarning("bad request for CoerceToDouble");

	return 0.0;
	}

ValPtr Val::SizeVal() const
	{
	switch ( type->InternalType() ) {
	case TYPE_INTERNAL_INT:
		if ( AsInt() < 0 )
			return val_mgr->Count(-AsInt());
		else
			return val_mgr->Count(AsInt());

	case TYPE_INTERNAL_UNSIGNED:
		return val_mgr->Count(AsCount());

	case TYPE_INTERNAL_DOUBLE:
		return make_intrusive<DoubleVal>(fabs(AsDouble()));

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
	case TYPE_INTERNAL_INT:		d->Add(AsInt()); break;
	case TYPE_INTERNAL_UNSIGNED:	d->Add(AsCount()); break;
	case TYPE_INTERNAL_DOUBLE:	d->Add(AsDouble()); break;
	case TYPE_INTERNAL_STRING:	d->AddBytes(AsString()); break;

	case TYPE_INTERNAL_ADDR:
		d->Add(AsAddr().AsString().c_str());
		break;

	case TYPE_INTERNAL_SUBNET:
		d->Add(AsSubNet().AsString().c_str());
		break;

	case TYPE_INTERNAL_ERROR:	d->AddCS("error"); break;

	case TYPE_INTERNAL_OTHER:
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
detail::ID* Val::GetID() const
	{
	return bound_id ? detail::global_scope()->Find(bound_id).get() : nullptr;
	}

void Val::SetID(detail::ID* id)
	{
	delete [] bound_id;
	bound_id = id ? util::copy_string(id->Name()) : nullptr;
	}
#endif


TableValPtr Val::GetRecordFields()
	{
	static auto record_field_table = id::find_type<TableType>("record_field_table");
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
		t = t->AsTypeType()->GetType().get();

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
static void BuildJSON(threading::formatter::JSON::NullDoubleWriter& writer, Val* val,
                      bool only_loggable=false, RE_Matcher* re=nullptr, const string& key="")
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
			writer.String(util::json_escape_utf8(std::string(reinterpret_cast<const char*>(d.Bytes()), d.Len())));
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

			std::unique_ptr<detail::HashKey> k;
			TableEntryVal* entry;

			for ( const auto& te : *table )
				{
				entry = te.GetValue<TableEntryVal*>();
				k = te.GetHashKey();

				auto lv = tval->RecreateIndex(*k);
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

					BuildJSON(writer, entry->GetVal().get(), only_loggable, re, key_str);
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
				auto value = rval->GetFieldOrDefault(i);

				if ( value && ( ! only_loggable || rt->FieldHasAttr(i, detail::ATTR_LOG) ) )
					{
					string key_str;
					auto field_name = rt->FieldName(i);

					if ( re && re->MatchAnywhere(field_name) != 0 )
						{
						auto blank = make_intrusive<StringVal>("");
						auto fn_val = make_intrusive<StringVal>(field_name);
						const auto& bs = *blank->AsString();
						auto key_val = fn_val->Replace(re, bs, false);
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
				BuildJSON(writer, vval->ValAt(i).get(), only_loggable, re);

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

StringValPtr Val::ToJSON(bool only_loggable, RE_Matcher* re)
	{
	rapidjson::StringBuffer buffer;
	threading::formatter::JSON::NullDoubleWriter writer(buffer);

	BuildJSON(writer, this, only_loggable, re, "");

	return make_intrusive<StringVal>(buffer.GetString());
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

	double v = AsDouble();

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

ValPtr PortVal::SizeVal() const
	{
	return val_mgr->Int(uint_val);
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

PortVal::PortVal(uint32_t p)
	: UnsignedValImplementation(base_type(TYPE_PORT), bro_uint_t(p))
	{
	}

uint32_t PortVal::Port() const
	{
	uint32_t p = static_cast<uint32_t>(uint_val);
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
	return (uint_val & PORT_SPACE_MASK) == TCP_PORT_MASK;
	}

bool PortVal::IsUDP() const
	{
	return (uint_val & PORT_SPACE_MASK) == UDP_PORT_MASK;
	}

bool PortVal::IsICMP() const
	{
	return (uint_val & PORT_SPACE_MASK) == ICMP_PORT_MASK;
	}

void PortVal::ValDescribe(ODesc* d) const
	{
	uint32_t p = static_cast<uint32_t>(uint_val);
	d->Add(p & ~PORT_SPACE_MASK);
	d->Add("/");
	d->Add(Protocol());
	}

ValPtr PortVal::DoClone(CloneState* state)
	{
	// Immutable.
	return {NewRef{}, this};
	}

AddrVal::AddrVal(const char* text) : Val(base_type(TYPE_ADDR))
	{
	addr_val = new IPAddr(text);
	}

AddrVal::AddrVal(const std::string& text) : AddrVal(text.c_str())
	{
	}

AddrVal::AddrVal(uint32_t addr) : Val(base_type(TYPE_ADDR))
	{
	addr_val = new IPAddr(IPv4, &addr, IPAddr::Network);
	// ### perhaps do gethostbyaddr here?
	}

AddrVal::AddrVal(const uint32_t addr[4]) : Val(base_type(TYPE_ADDR))
	{
	addr_val = new IPAddr(IPv6, addr, IPAddr::Network);
	}

AddrVal::AddrVal(const IPAddr& addr) : Val(base_type(TYPE_ADDR))
	{
	addr_val = new IPAddr(addr);
	}

AddrVal::~AddrVal()
	{
	delete addr_val;
	}

unsigned int AddrVal::MemoryAllocation() const
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	return padded_sizeof(*this) + addr_val->MemoryAllocation();
#pragma GCC diagnostic pop
	}

ValPtr AddrVal::SizeVal() const
	{
	if ( addr_val->GetFamily() == IPv4 )
		return val_mgr->Count(32);
	else
		return val_mgr->Count(128);
	}

ValPtr AddrVal::DoClone(CloneState* state)
	{
	// Immutable.
	return {NewRef{}, this};
	}

SubNetVal::SubNetVal(const char* text) : Val(base_type(TYPE_SUBNET))
	{
	subnet_val = new IPPrefix();

	if ( ! IPPrefix::ConvertString(text, subnet_val) )
		reporter->Error("Bad string in SubNetVal ctor: %s", text);
	}

SubNetVal::SubNetVal(const char* text, int width) : Val(base_type(TYPE_SUBNET))
	{
	subnet_val = new IPPrefix(text, width);
	}

SubNetVal::SubNetVal(uint32_t addr, int width) : SubNetVal(IPAddr{IPv4, &addr, IPAddr::Network}, width)
	{
	}

SubNetVal::SubNetVal(const uint32_t* addr, int width) : SubNetVal(IPAddr{IPv6, addr, IPAddr::Network}, width)
	{
	}

SubNetVal::SubNetVal(const IPAddr& addr, int width) : Val(base_type(TYPE_SUBNET))
	{
	subnet_val = new IPPrefix(addr, width);
	}

SubNetVal::SubNetVal(const IPPrefix& prefix) : Val(base_type(TYPE_SUBNET))
	{
	subnet_val = new IPPrefix(prefix);
	}

SubNetVal::~SubNetVal()
	{
	delete subnet_val;
	}

const IPAddr& SubNetVal::Prefix() const
	{
	return subnet_val->Prefix();
	}

int SubNetVal::Width() const
	{
	return subnet_val->Length();
	}

unsigned int SubNetVal::MemoryAllocation() const
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	return padded_sizeof(*this) + subnet_val->MemoryAllocation();
#pragma GCC diagnostic pop
	}

ValPtr SubNetVal::SizeVal() const
	{
	int retained = 128 - subnet_val->LengthIPv6();
	return make_intrusive<DoubleVal>(pow(2.0, double(retained)));
	}

void SubNetVal::ValDescribe(ODesc* d) const
	{
	d->Add(string(*subnet_val).c_str());
	}

IPAddr SubNetVal::Mask() const
	{
	if ( subnet_val->Length() == 0 )
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
	for ( w = subnet_val->Length(); w >= 32; w -= 32 )
		   *(mp++) = 0xffffffff;

	*mp = ~((1 << (32 - w)) - 1);

	while ( ++mp < m + 4 )
		   *mp = 0;

	IPAddr rval(IPv6, m, IPAddr::Host);
	return rval;
	}

bool SubNetVal::Contains(const IPAddr& addr) const
	{
	return subnet_val->Contains(addr);
	}

ValPtr SubNetVal::DoClone(CloneState* state)
	{
	// Immutable.
	return {NewRef{}, this};
	}

StringVal::StringVal(String* s) : Val(base_type(TYPE_STRING))
	{
	string_val = s;
	}

// The following adds a NUL at the end.
StringVal::StringVal(int length, const char* s)
	: StringVal(new String(reinterpret_cast<const u_char*>(s), length, true))
	{
	}

StringVal::StringVal(const char* s) : StringVal(new String(s))
	{
	}

StringVal::StringVal(const string& s) : StringVal(s.length(), s.data())
	{
	}

StringVal::~StringVal()
	{
	delete string_val;
	}

ValPtr StringVal::SizeVal() const
	{
	return val_mgr->Count(string_val->Len());
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

string_view StringVal::ToStdStringView() const
	{
	auto* bs = AsString();
	return string_view((char*)bs->Bytes(), bs->Len());
	}

StringVal* StringVal::ToUpper()
	{
	string_val->ToUpper();
	return this;
	}

void StringVal::ValDescribe(ODesc* d) const
	{
	// Should reintroduce escapes ? ###
	if ( d->WantQuotes() )
		d->Add("\"");
	d->AddBytes(string_val);
	if ( d->WantQuotes() )
		d->Add("\"");
	}

unsigned int StringVal::MemoryAllocation() const
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	return padded_sizeof(*this) + string_val->MemoryAllocation();
#pragma GCC diagnostic pop
	}

StringValPtr StringVal::Replace(
	RE_Matcher* re, const String& repl, bool do_all)
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
	size += cut_points.size() * repl.Len();

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
		memcpy(r, repl.Bytes(), repl.Len());
		r += repl.Len();
		}

	// Copy final trailing characters.
	int num_to_copy = Len() - start_offset;
	memcpy(r, s + start_offset, num_to_copy);
	r += num_to_copy;

	// Final NUL.  No need to increment r, since the length
	// computed from it in the next statement does not include
	// the NUL.
	r[0] = '\0';

	return make_intrusive<StringVal>(new String(true, result, r - result));
	}

ValPtr StringVal::DoClone(CloneState* state)
	{
	// We could likely treat this type as immutable and return a reference
	// instead of creating a new copy, but we first need to be careful and
	// audit whether anything internal actually does mutate it.
	return state->NewClone(this, make_intrusive<StringVal>(
	        new String((u_char*) string_val->Bytes(),
	                   string_val->Len(), true)));
	}

FuncVal::FuncVal(FuncPtr f) : Val(f->GetType())
	{
	func_val = std::move(f);
	}

FuncPtr FuncVal::AsFuncPtr() const
	{
	return func_val;
	}

ValPtr FuncVal::SizeVal() const
	{
	return val_mgr->Count(func_val->GetType()->ParamList()->GetTypes().size());
	}

void FuncVal::ValDescribe(ODesc* d) const
	{
	func_val->Describe(d);
	}

ValPtr FuncVal::DoClone(CloneState* state)
	{
	return make_intrusive<FuncVal>(func_val->DoClone());
	}

FileVal::FileVal(FilePtr f)
: Val(make_intrusive<FileType>(base_type(TYPE_STRING)))
	{
	file_val = std::move(f);
	assert(file_val->GetType()->Tag() == TYPE_STRING);
	}

ValPtr FileVal::SizeVal() const
	{
	return make_intrusive<DoubleVal>(file_val->Size());
	}

void FileVal::ValDescribe(ODesc* d) const
	{
	file_val->Describe(d);
	}

ValPtr FileVal::DoClone(CloneState* state)
	{
	// I think we can just ref the file here - it is unclear what else
	// to do.  In the case of cached files, I think this is equivalent
	// to what happened before - serialization + unserialization just
	// gave you the same pointer that you already had.  In the case of
	// non-cached files, the behavior now is different; in the past,
	// serialize + unserialize gave you a new file object because the
	// old one was not in the list anymore. This object was
	// automatically opened. This does not happen anymore - instead you
	// get the non-cached pointer back which is brought back into the
	// cache when written to.
	return {NewRef{}, this};
	}

PatternVal::PatternVal(RE_Matcher* re)
	: Val(base_type(TYPE_PATTERN))
	{
	re_val = re;
	}

PatternVal::~PatternVal()
	{
	delete re_val;
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
	re_val = re;
	}

bool PatternVal::MatchExactly(const String* s) const
	{
	return re_val->MatchExactly(s);
	}

bool PatternVal::MatchAnywhere(const String* s) const
	{
	return re_val->MatchAnywhere(s);
	}

void PatternVal::ValDescribe(ODesc* d) const
	{
	d->Add("/");
	d->Add(AsPattern()->PatternText());
	d->Add("/");
	}

unsigned int PatternVal::MemoryAllocation() const
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	return padded_sizeof(*this) + re_val->MemoryAllocation();
#pragma GCC diagnostic pop
	}

ValPtr PatternVal::DoClone(CloneState* state)
	{
	// We could likely treat this type as immutable and return a reference
	// instead of creating a new copy, but we first need to be careful and
	// audit whether anything internal actually does mutate it.
	auto re = new RE_Matcher(re_val->PatternText(),
	                         re_val->AnywherePatternText());
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

ValPtr ListVal::SizeVal() const
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

void ListVal::Append(ValPtr v)
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

TableValPtr ListVal::ToSetVal() const
	{
	if ( tag == TYPE_ANY )
		Internal("conversion of heterogeneous list to set");

	const auto& pt = type->AsTypeList()->GetPureType();
	auto set_index = make_intrusive<TypeList>(pt);
	set_index->Append(base_type(tag));
	auto s = make_intrusive<SetType>(std::move(set_index), nullptr);
	auto t = make_intrusive<TableVal>(std::move(s));

	for ( const auto& val : vals )
		t->Assign(val, nullptr);

	return t;
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

ValPtr ListVal::DoClone(CloneState* state)
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
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	unsigned int size = 0;
	for ( const auto& val : vals )
		size += val->MemoryAllocation();

	size += util::pad_size(vals.capacity() * sizeof(decltype(vals)::value_type));
	return size + padded_sizeof(*this) + type->MemoryAllocation();
#pragma GCC diagnostic pop
	}

TableEntryVal* TableEntryVal::Clone(Val::CloneState* state)
	{
	auto rval = new TableEntryVal(val ? val->Clone(state) : nullptr);
	rval->expire_access_time = expire_access_time;
	return rval;
	}

TableValTimer::TableValTimer(TableVal* val, double t) : detail::Timer(t, detail::TIMER_TABLE_VAL)
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

static void find_nested_record_types(const TypePtr& t, std::set<RecordType*>* found)
	{
	if ( ! t )
		return;

	switch ( t->Tag() ) {
	case TYPE_RECORD:
		{
		auto rt = t->AsRecordType();
		found->emplace(rt);

		for ( auto i = 0; i < rt->NumFields(); ++i )
			find_nested_record_types(rt->FieldDecl(i)->type, found);
		}
		return;
	case TYPE_TABLE:
		find_nested_record_types(t->AsTableType()->GetIndices(), found);
		find_nested_record_types(t->AsTableType()->Yield(), found);
		return;
	case TYPE_LIST:
		{
		for ( const auto& type : t->AsTypeList()->GetTypes() )
			find_nested_record_types(type, found);
		}
		return;
	case TYPE_FUNC:
		find_nested_record_types(t->AsFuncType()->Params(), found);
		find_nested_record_types(t->AsFuncType()->Yield(), found);
		return;
	case TYPE_VECTOR:
		find_nested_record_types(t->AsVectorType()->Yield(), found);
		return;
	case TYPE_TYPE:
		find_nested_record_types(t->AsTypeType()->GetType(), found);
		return;
	default:
		return;
	}
	}

TableVal::TableVal(TableTypePtr t, detail::AttributesPtr a) : Val(t)
	{
	Init(std::move(t));
	SetAttrs(std::move(a));

	if ( ! run_state::is_parsing )
		return;

	for ( const auto& t : table_type->GetIndexTypes() )
		{
		std::set<RecordType*> found;
		// TODO: this likely doesn't have to be repeated for each new TableVal,
		//       can remember the resulting dependencies per TableType
		find_nested_record_types(t, &found);

		for ( auto rt : found )
			parse_time_table_record_dependencies[rt].emplace_back(NewRef{}, this);
		}
	}

void TableVal::Init(TableTypePtr t)
	{
	table_type = std::move(t);
	expire_func = nullptr;
	expire_time = nullptr;
	expire_iterator = nullptr;
	timer = nullptr;
	def_val = nullptr;

	if ( table_type->IsSubNetIndex() )
		subnets = new detail::PrefixTable;
	else
		subnets = nullptr;

	table_hash = new detail::CompositeHash(table_type->GetIndices());
	table_val = new PDict<TableEntryVal>;
	table_val->SetDeleteFunc(table_entry_val_delete_func);
	}

TableVal::~TableVal()
	{
	if ( timer )
		detail::timer_mgr->Cancel(timer);

	delete table_hash;
	delete table_val;
	delete subnets;
	delete expire_iterator;
	}

void TableVal::RemoveAll()
	{
	delete expire_iterator;
	expire_iterator = nullptr;
	// Here we take the brute force approach.
	delete table_val;
	table_val = new PDict<TableEntryVal>;
	table_val->SetDeleteFunc(table_entry_val_delete_func);
	}

int TableVal::Size() const
	{
	return table_val->Length();
	}

int TableVal::RecursiveSize() const
	{
	int n = table_val->Length();

	if ( GetType()->IsSet() ||
	     GetType()->AsTableType()->Yield()->Tag() != TYPE_TABLE )
		return n;

	for ( const auto& ve : *table_val )
		{
		auto* tv = ve.GetValue<TableEntryVal*>();
		if ( tv->GetVal() )
			n += tv->GetVal()->AsTableVal()->RecursiveSize();
		}

	return n;
	}

void TableVal::SetAttrs(detail::AttributesPtr a)
	{
	attrs = std::move(a);

	if ( ! attrs )
		return;

	CheckExpireAttr(detail::ATTR_EXPIRE_READ);
	CheckExpireAttr(detail::ATTR_EXPIRE_WRITE);
	CheckExpireAttr(detail::ATTR_EXPIRE_CREATE);

	const auto& ef = attrs->Find(detail::ATTR_EXPIRE_FUNC);

	if ( ef )
		{
		if ( GetType()->AsTableType()->CheckExpireFuncCompatibility(ef) )
			expire_func = ef->GetExpr();
		else
			expire_func = nullptr;
		}

	const auto& cf = attrs->Find(detail::ATTR_ON_CHANGE);

	if ( cf )
		change_func = cf->GetExpr();

	auto bs = attrs->Find(detail::ATTR_BROKER_STORE);
	if ( bs && broker_store.empty() )
		{
		auto c = bs->GetExpr()->Eval(nullptr);
		assert(c);
		assert(c->GetType()->Tag() == TYPE_STRING);
		broker_store = c->AsStringVal()->AsString()->CheckString();
		broker_mgr->AddForwardedStore(broker_store, {NewRef{}, this});
		}
	}

void TableVal::CheckExpireAttr(detail::AttrTag at)
	{
	const auto& a = attrs->Find(at);

	if ( a )
		{
		expire_time = a->GetExpr();

		if ( expire_time->GetType()->Tag() != TYPE_INTERVAL )
			{
			if ( ! expire_time->IsError() )
				expire_time->SetError("expiration interval has wrong type");

			return;
			}

		if ( timer )
			detail::timer_mgr->Cancel(timer);

		// As network_time is not necessarily initialized yet,
		// we set a timer which fires immediately.
		timer = new TableValTimer(this, 1);
		detail::timer_mgr->Add(timer);
		}
	}

bool TableVal::Assign(ValPtr index, ValPtr new_val, bool broker_forward,
                      bool* iterators_invalidated)
	{
	auto k = MakeHashKey(*index);

	if ( ! k )
		{
		index->Error("index type doesn't match table", table_type->GetIndices().get());
		return false;
		}

	return Assign(std::move(index), std::move(k), std::move(new_val), broker_forward, iterators_invalidated);
	}

bool TableVal::Assign(ValPtr index, std::unique_ptr<detail::HashKey> k,
                      ValPtr new_val, bool broker_forward, bool* iterators_invalidated)
	{
	bool is_set = table_type->IsSet();

	if ( (is_set && new_val) || (! is_set && ! new_val) )
		InternalWarning("bad set/table in TableVal::Assign");

	TableEntryVal* new_entry_val = new TableEntryVal(std::move(new_val));
	detail::HashKey k_copy(k->Key(), k->Size(), k->Hash());
	TableEntryVal* old_entry_val = table_val->Insert(k.get(), new_entry_val, iterators_invalidated);

	// If the dictionary index already existed, the insert may free up the
	// memory allocated to the key bytes, so have to assume k is invalid
	// from here on out.
	k = nullptr;

	if ( subnets )
		{
		if ( ! index )
			{
			auto v = RecreateIndex(k_copy);
			subnets->Insert(v.get(), new_entry_val);
			}
		else
			subnets->Insert(index.get(), new_entry_val);
		}

	// Keep old expiration time if necessary.
	if ( old_entry_val && attrs && attrs->Find(detail::ATTR_EXPIRE_CREATE) )
		new_entry_val->SetExpireAccess(old_entry_val->ExpireAccessTime());

	Modified();

	if ( change_func || ( broker_forward && ! broker_store.empty() ) )
		{
		auto change_index = index ? std::move(index)
		                          : RecreateIndex(k_copy);

		if ( broker_forward && ! broker_store.empty() )
			SendToStore(change_index.get(), new_entry_val, old_entry_val ? ELEMENT_CHANGED : ELEMENT_NEW);

		if ( change_func )
			{
			const auto& v = old_entry_val ? old_entry_val->GetVal() : new_entry_val->GetVal();
			CallChangeFunc(change_index, v, old_entry_val ? ELEMENT_CHANGED : ELEMENT_NEW);
			}
		}

	delete old_entry_val;

	return true;
	}

ValPtr TableVal::SizeVal() const
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

	if ( ! same_type(type, t->GetType()) )
		{
		type->Error("table type clash", t->GetType().get());
		return false;
		}

	for ( const auto& tble : *table_val )
		{
		auto k = tble.GetHashKey();
		auto* v = tble.GetValue<TableEntryVal*>();

		if ( is_first_init && t->AsTable()->Lookup(k.get()) )
			{
			auto key = table_hash->RecoverVals(*k);
			// ### Shouldn't complain if their values are equal.
			key->Warn("multiple initializations for index");
			continue;
			}

		if ( type->IsSet() )
			{
			if ( ! t->Assign(v->GetVal(), std::move(k), nullptr) )
				 return false;
			}
		else
			{
			if ( ! t->Assign(nullptr, std::move(k), v->GetVal()) )
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

	if ( ! same_type(type, t->GetType()) )
		{
		type->Error("table type clash", t->GetType().get());
		return false;
		}

	for ( const auto& tble : *table_val )
		{
		// Not sure that this is 100% sound, since the HashKey
		// comes from one table but is being used in another.
		// OTOH, they are both the same type, so as long as
		// we don't have hash keys that are keyed per dictionary,
		// it should work ...
		auto k = tble.GetHashKey();
		t->Remove(*k);
		}

	return true;
	}

TableValPtr TableVal::Intersection(const TableVal& tv) const
	{
	auto result = make_intrusive<TableVal>(table_type);

	const PDict<TableEntryVal>* t0 = table_val;
	const PDict<TableEntryVal>* t1 = tv.AsTable();

	// Figure out which is smaller; assign it to t1.
	if ( t1->Length() > t0->Length() )
		{ // Swap.
		const PDict<TableEntryVal>* tmp = t1;
		t1 = t0;
		t0 = tmp;
		}

	const PDict<TableEntryVal>* tbl = AsTable();
	for ( const auto& tble : *tbl )
		{
		auto k = tble.GetHashKey();

		// Here we leverage the same assumption about consistent
		// hashes as in TableVal::RemoveFrom above.
		if ( t0->Lookup(k.get()) )
			result->table_val->Insert(k.get(), new TableEntryVal(nullptr));
		}

	return result;
	}

bool TableVal::EqualTo(const TableVal& tv) const
	{
	const PDict<TableEntryVal>* t0 = table_val;
	const PDict<TableEntryVal>* t1 = tv.AsTable();

	if ( t0->Length() != t1->Length() )
		return false;

	for ( const auto& tble : *t0 )
		{
		auto k = tble.GetHashKey();

		// Here we leverage the same assumption about consistent
		// hashes as in TableVal::RemoveFrom above.
		if ( ! t1->Lookup(k.get()) )
			return false;
		}

	return true;
	}

bool TableVal::IsSubsetOf(const TableVal& tv) const
	{
	const PDict<TableEntryVal>* t0 = table_val;
	const PDict<TableEntryVal>* t1 = tv.AsTable();

	if ( t0->Length() > t1->Length() )
		return false;

	for ( const auto& tble : *t0 )
		{
		auto k = tble.GetHashKey();

		// Here we leverage the same assumption about consistent
		// hashes as in TableVal::RemoveFrom above.
		if ( ! t1->Lookup(k.get()) )
			return false;
		}

	return true;
	}

bool TableVal::ExpandAndInit(ValPtr index, ValPtr new_val)
	{
	const auto& index_type = index->GetType();

	if ( index_type->IsSet() )
		{
		index = index->AsTableVal()->ToListVal();
		return ExpandAndInit(std::move(index), std::move(new_val));
		}

	if ( index_type->Tag() != TYPE_LIST )
		// Nothing to expand.
		return CheckAndAssign(std::move(index), std::move(new_val));

	ListVal* iv = index->AsListVal();
	if ( iv->BaseTag() != TYPE_ANY )
		{
		if ( table_type->GetIndices()->GetTypes().size() != 1 )
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
			return CheckAndAssign(std::move(index), std::move(new_val));
		else
			return ExpandCompoundAndInit(iv, i, std::move(new_val));
		}
	}


ValPtr TableVal::Default(const ValPtr& index)
	{
	const auto& def_attr = GetAttr(detail::ATTR_DEFAULT);

	if ( ! def_attr )
		return nullptr;

	if ( ! def_val )
		{
		const auto& ytype = GetType()->Yield();
		const auto& dtype = def_attr->GetExpr()->GetType();

		if ( dtype->Tag() == TYPE_RECORD && ytype->Tag() == TYPE_RECORD &&
		     ! same_type(dtype, ytype) &&
		     record_promotion_compatible(dtype->AsRecordType(),
						 ytype->AsRecordType()) )
			{
			auto rt = cast_intrusive<RecordType>(ytype);
			auto coerce = make_intrusive<detail::RecordCoerceExpr>(
				def_attr->GetExpr(), std::move(rt));

			def_val = coerce->Eval(nullptr);
			}

		else
			def_val = def_attr->GetExpr()->Eval(nullptr);
		}

	if ( ! def_val )
		{
		Error("non-constant default attribute");
		return nullptr;
		}

	if ( def_val->GetType()->Tag() != TYPE_FUNC ||
	     same_type(def_val->GetType(), GetType()->Yield()) )
		{
		if ( def_attr->GetExpr()->IsConst() )
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
	Args vl;

	if ( index->GetType()->Tag() == TYPE_LIST )
		{
		auto lv = index->AsListVal();
		vl.reserve(lv->Length());

		for ( const auto& v : lv->Vals() )
			vl.emplace_back(v);
		}
	else
		vl.emplace_back(index);

	ValPtr result;

	try
		{
		result = f->Invoke(&vl);
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

const ValPtr& TableVal::Find(const ValPtr& index)
	{
	if ( subnets )
		{
		TableEntryVal* v = (TableEntryVal*) subnets->Lookup(index.get());
		if ( v )
			{
			if ( attrs && attrs->Find(detail::ATTR_EXPIRE_READ) )
				v->SetExpireAccess(run_state::network_time);

			if ( v->GetVal() )
				return v->GetVal();

			return val_mgr->True();
			}

		return Val::nil;
		}

	if ( table_val->Length() > 0 )
		{
		auto k = MakeHashKey(*index);

		if ( k )
			{
			TableEntryVal* v = table_val->Lookup(k.get());

			if ( v )
				{
				if ( attrs && attrs->Find(detail::ATTR_EXPIRE_READ) )
					v->SetExpireAccess(run_state::network_time);

				if ( v->GetVal() )
					return v->GetVal();

				return val_mgr->True();
				}
			}
		}

	return Val::nil;
	}

ValPtr TableVal::FindOrDefault(const ValPtr& index)
	{
	if ( auto rval = Find(index) )
		return rval;

	return Default(index);
	}

bool TableVal::Contains(const IPAddr& addr) const
	{
	if ( ! subnets )
		{
		reporter->InternalError("'Contains' called on wrong table/set type");
		return false;
		}

	return (subnets->Lookup(addr, 128, false) != 0);
	}

VectorValPtr TableVal::LookupSubnets(const SubNetVal* search)
	{
	if ( ! subnets )
		reporter->InternalError("LookupSubnets called on wrong table type");

	auto result = make_intrusive<VectorVal>(id::find_type<VectorType>("subnet_vec"));

	auto matches = subnets->FindAll(search);
	for ( auto element : matches )
		result->Assign(result->Size(), make_intrusive<SubNetVal>(get<0>(element)));

	return result;
	}

TableValPtr TableVal::LookupSubnetValues(const SubNetVal* search)
	{
	if ( ! subnets )
		reporter->InternalError("LookupSubnetValues called on wrong table type");

	auto nt = make_intrusive<TableVal>(this->GetType<TableType>());

	auto matches = subnets->FindAll(search);
	for ( auto element : matches )
		{
		auto s = make_intrusive<SubNetVal>(get<0>(element));
		TableEntryVal* entry = reinterpret_cast<TableEntryVal*>(get<1>(element));

		if ( entry && entry->GetVal() )
			nt->Assign(std::move(s), entry->GetVal());
		else
			nt->Assign(std::move(s), nullptr); // set

		if ( entry )
			{
			if ( attrs && attrs->Find(detail::ATTR_EXPIRE_READ) )
				entry->SetExpireAccess(run_state::network_time);
			}
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
		auto k = MakeHashKey(*index);

		if ( ! k )
			return false;

		v = table_val->Lookup(k.get());
		}

	if ( ! v )
		return false;

	v->SetExpireAccess(run_state::network_time);

	return true;
	}

ListValPtr TableVal::RecreateIndex(const detail::HashKey& k) const
	{
	return table_hash->RecoverVals(k);
	}

void TableVal::CallChangeFunc(const ValPtr& index,
                              const ValPtr& old_value,
                              OnChangeType tpe)
	{
	if ( ! change_func || ! index || in_change_func )
		return;

	if ( ! table_type->IsSet() && ! old_value )
		return;

	try
		{
		auto thefunc = change_func->Eval(nullptr);

		if ( ! thefunc )
			return;

		if ( thefunc->GetType()->Tag() != TYPE_FUNC )
			{
			thefunc->Error("not a function");
			return;
			}

		const Func* f = thefunc->AsFunc();
		Args vl;

		// we either get passed the raw index_val - or a ListVal with exactly one element.
		if ( index->GetType()->Tag() == TYPE_LIST )
			vl.reserve(2 + index->AsListVal()->Length() + table_type->IsTable());
		else
			vl.reserve(3 + table_type->IsTable());

		vl.emplace_back(NewRef{}, this);

		switch ( tpe )
			{
			case ELEMENT_NEW:
				vl.emplace_back(BifType::Enum::TableChange->GetEnumVal(BifEnum::TableChange::TABLE_ELEMENT_NEW));
				break;
			case ELEMENT_CHANGED:
				vl.emplace_back(BifType::Enum::TableChange->GetEnumVal(BifEnum::TableChange::TABLE_ELEMENT_CHANGED));
				break;
			case ELEMENT_REMOVED:
				vl.emplace_back(BifType::Enum::TableChange->GetEnumVal(BifEnum::TableChange::TABLE_ELEMENT_REMOVED));
				break;
			case ELEMENT_EXPIRED:
				vl.emplace_back(BifType::Enum::TableChange->GetEnumVal(BifEnum::TableChange::TABLE_ELEMENT_EXPIRED));
			}


		if ( index->GetType()->Tag() == TYPE_LIST )
			{
			for ( const auto& v : index->AsListVal()->Vals() )
				vl.emplace_back(v);
			}
		else
			vl.emplace_back(index);

		if ( table_type->IsTable() )
			vl.emplace_back(old_value);

		in_change_func = true;
		f->Invoke(&vl);
		}
	catch ( InterpreterException& e )
		{
		}

	in_change_func = false;
	}

void TableVal::SendToStore(const Val* index, const TableEntryVal* new_entry_val, OnChangeType tpe)
	{
	if ( broker_store.empty() || ! index )
		return;

	try
		{
		auto handle = broker_mgr->LookupStore(broker_store);

		if ( ! handle )
			return;

		// For simple indexes, we either get passed the raw index_val - or a ListVal with exactly one element.
		// We unoll this in the second case.
		// For complex indexes, we just pass the ListVal.
		const Val* index_val;
		if ( index->GetType()->Tag() == TYPE_LIST && index->AsListVal()->Length() == 1)
			index_val = index->AsListVal()->Idx(0).get();
		else
			index_val = index;

		auto broker_index = Broker::detail::val_to_data(index_val);

		if ( ! broker_index )
			{
			emit_builtin_error("invalid Broker data conversation for table index");
			return;
			}

		switch ( tpe )
			{
			case ELEMENT_NEW:
			case ELEMENT_CHANGED:
				{
				#ifndef __clang__
				#pragma GCC diagnostic push
				#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
				#endif
				broker::optional<broker::timespan> expiry;
				#ifndef __clang__
				#pragma GCC diagnostic pop
				#endif

				auto expire_time = GetExpireTime();
				if ( expire_time == 0 )
					// Entry is set to immediately expire. Let's not forward it.
					break;

				if ( expire_time > 0 )
					{
					if ( attrs->Find(detail::ATTR_EXPIRE_CREATE) )
						{
						// for create expiry, we have to substract the already elapsed time from the expiry.
						auto e = expire_time - (run_state::network_time - new_entry_val->ExpireAccessTime());
						if ( e <= 0 )
							// element already expired? Let's not insert it.
							break;

						expiry = Broker::detail::convert_expiry(e);
						}
					else
						expiry = Broker::detail::convert_expiry(expire_time);
					}

				if ( table_type->IsSet() )
					handle->store.put(std::move(*broker_index), broker::data(), expiry);
				else
					{
					if ( ! new_entry_val )
						{
						emit_builtin_error("did not receive new value for Broker datastore send operation");
						return;
						}

					auto new_value = new_entry_val->GetVal().get();
					auto broker_val = Broker::detail::val_to_data(new_value);
					if ( ! broker_val )
						{
						emit_builtin_error("invalid Broker data conversation for table value");
						return;
						}

					handle->store.put(std::move(*broker_index), std::move(*broker_val), expiry);
					}
				break;
				}

			case ELEMENT_REMOVED:
				handle->store.erase(std::move(*broker_index));
				break;

			case ELEMENT_EXPIRED:
				// we do nothing here. The Broker store does its own expiration - so the element
				// should expire at about the same time.
				break;
			}
		}
	catch ( InterpreterException& e )
		{
		emit_builtin_error("The previous error was encountered while trying to resolve the &broker_store attribute of the set/table. Potentially the Broker::Store has not been initialized before being used.");
		}
	}

ValPtr TableVal::Remove(const Val& index, bool broker_forward, bool* iterators_invalidated)
	{
	auto k = MakeHashKey(index);

	TableEntryVal* v = k ? table_val->RemoveEntry(k.get(), iterators_invalidated) : nullptr;
	ValPtr va;

	if ( v )
		va = v->GetVal() ? v->GetVal() : IntrusivePtr{NewRef{}, this};

	if ( subnets && ! subnets->Remove(&index) )
		reporter->InternalWarning("index not in prefix table");

	delete v;

	Modified();

	if ( broker_forward && ! broker_store.empty() )
		SendToStore(&index, nullptr, ELEMENT_REMOVED);

	if ( change_func )
		{
		// this is totally cheating around the fact that we need a Intrusive pointer.
		ValPtr changefunc_val = RecreateIndex(*(k.get()));
		CallChangeFunc(changefunc_val, va, ELEMENT_REMOVED);
		}

	return va;
	}

ValPtr TableVal::Remove(const detail::HashKey& k, bool* iterators_invalidated)
	{
	TableEntryVal* v = table_val->RemoveEntry(k, iterators_invalidated);
	ValPtr va;

	if ( v )
		va = v->GetVal() ? v->GetVal() : IntrusivePtr{NewRef{}, this};

	if ( subnets )
		{
		auto index = table_hash->RecoverVals(k);

		if ( ! subnets->Remove(index.get()) )
			reporter->InternalWarning("index not in prefix table");
		}

	delete v;

	Modified();

	if ( va && ( change_func || ! broker_store.empty() ) )
		{
		auto index = table_hash->RecoverVals(k);
		if ( ! broker_store.empty() )
			SendToStore(index.get(), nullptr, ELEMENT_REMOVED);

		if ( change_func && va )
			CallChangeFunc(index, va, ELEMENT_REMOVED);
		}

	return va;
	}

ListValPtr TableVal::ToListVal(TypeTag t) const
	{
	auto l = make_intrusive<ListVal>(t);

	for ( const auto& tble : *table_val )
		{
		auto k = tble.GetHashKey();
		auto index = table_hash->RecoverVals(*k);

		if ( t == TYPE_ANY )
			l->Append(std::move(index));
		else
			{
			// We're expecting a pure list, flatten the ListVal.
			if ( index->Length() != 1 )
				InternalWarning("bad index in TableVal::ToListVal");

			l->Append(index->Idx(0));
			}
		}

	return l;
	}

ListValPtr TableVal::ToPureListVal() const
	{
	const auto& tl = table_type->GetIndices()->GetTypes();
	if ( tl.size() != 1 )
		{
		InternalWarning("bad index type in TableVal::ToPureListVal");
		return nullptr;
		}

	return ToListVal(tl[0]->Tag());
	}

std::unordered_map<ValPtr, ValPtr> TableVal::ToMap() const
	{
	std::unordered_map<ValPtr, ValPtr> res;

	for ( const auto& iter : *table_val )
		{
		auto k = iter.GetHashKey();
		auto v = iter.GetValue<TableEntryVal*>();
		auto vl = table_hash->RecoverVals(*k);

		res[std::move(vl)] = v->GetVal();
		}

	return res;
	}

const detail::AttrPtr& TableVal::GetAttr(detail::AttrTag t) const
	{
	return attrs ? attrs->Find(t) : detail::Attr::nil;
	}

void TableVal::Describe(ODesc* d) const
	{
	int n = table_val->Length();

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

	bool determ = d->WantDeterminism();
	std::vector<std::string> elem_descs;

	auto iter = table_val->begin();

	for ( int i = 0; i < n; ++i )
		{
		if ( iter == table_val->end() )
			reporter->InternalError("hash table underflow in TableVal::Describe");

		auto k = iter->GetHashKey();
		auto* v = iter->GetValue<TableEntryVal*>();

		auto vl = table_hash->RecoverVals(*k);
		int dim = vl->Length();

		ODesc intermediary_d;
		ODesc* d_ptr = determ ? &intermediary_d : d;

		if ( ! determ && i > 0 )
			{
			if ( ! d->IsBinary() )
				d->Add(",");

			d->NL();
			}

		if ( d->IsReadable() )
			{
			if ( dim != 1 || ! table_type->IsSet() )
				d_ptr->Add("[");
			}
		else
			{
			d_ptr->Add(dim);
			d_ptr->SP();
			}

		vl->Describe(d_ptr);

		if ( table_type->IsSet() )
			{ // We're a set, not a table.
			if ( d->IsReadable() )
				if ( dim != 1 )
					d_ptr->AddSP("]");
			}
		else
			{
			if ( d->IsReadable() )
				d_ptr->AddSP("] =");
			if ( v->GetVal() )
				v->GetVal()->Describe(d_ptr);
			}

		if ( d->IsReadable() && ! d->IsShort() && d->IncludeStats() )
			{
			d_ptr->Add(" @");
			d_ptr->Add(util::detail::fmt_access_time(v->ExpireAccessTime()));
			}

		if ( determ )
			elem_descs.emplace_back(d_ptr->Description());

		++iter;
		}

	if ( iter != table_val->end() )
		reporter->InternalError("hash table overflow in TableVal::Describe");

	if ( determ )
		{
		sort(elem_descs.begin(), elem_descs.end());
		bool did_elems = false;

		for ( const auto& ed : elem_descs )
			{
			if ( did_elems )
				{
				if ( ! d->IsBinary() )
					d->Add(",");

				d->NL();
				}

			d->Add(ed);
			did_elems = true;
			}
		}

	if ( d->IsPortable() || d->IsReadable() )
		{
		d->PopIndent();
		d->Add("}");
		}
	}

bool TableVal::ExpandCompoundAndInit(ListVal* lv, int k, ValPtr new_val)
	{
	Val* ind_k_v = lv->Idx(k).get();
	auto ind_k = ind_k_v->GetType()->IsSet() ?
	      ind_k_v->AsTableVal()->ToListVal() :
	      ListValPtr{NewRef{}, ind_k_v->AsListVal()};

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

bool TableVal::CheckAndAssign(ValPtr index, ValPtr new_val)
	{
	Val* v = nullptr;
	if ( subnets )
		// We need an exact match here.
		v = (Val*) subnets->Lookup(index.get(), true);
	else
		v = Find(index).get();

	if ( v )
		index->Warn("multiple initializations for index");

	return Assign(std::move(index), std::move(new_val));
	}

void TableVal::InitDefaultFunc(detail::Frame* f)
	{
	// Value aready initialized.
	if ( def_val )
		return;

	const auto& def_attr = GetAttr(detail::ATTR_DEFAULT);

	if ( ! def_attr )
		return;

	const auto& ytype = GetType()->Yield();
	const auto& dtype = def_attr->GetExpr()->GetType();

	if ( dtype->Tag() == TYPE_RECORD && ytype->Tag() == TYPE_RECORD &&
	     ! same_type(dtype, ytype) &&
	     record_promotion_compatible(dtype->AsRecordType(),
					 ytype->AsRecordType()) )
		return; // TableVal::Default will handle this.

	def_val = def_attr->GetExpr()->Eval(f);
	}

void TableVal::InitTimer(double delay)
	{
	timer = new TableValTimer(this, run_state::network_time + delay);
	detail::timer_mgr->Add(timer);
	}

void TableVal::DoExpire(double t)
	{
	if ( ! type )
		return; // FIX ME ###

	double timeout = GetExpireTime();

	if ( timeout < 0 )
		// Skip in case of unset/invalid expiration value. If it's an
		// error, it has been reported already.
		return;

	if ( ! expire_iterator )
		{
		auto it = table_val->begin_robust();
		expire_iterator = new RobustDictIterator(std::move(it));
		}

	bool modified = false;

	for ( int i = 0; i < zeek::detail::table_incremental_step &&
		      *expire_iterator != table_val->end_robust(); ++i, ++(*expire_iterator) )
		{
		auto v = (*expire_iterator)->GetValue<TableEntryVal*>();

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
			auto k = (*expire_iterator)->GetHashKey();
			ListValPtr idx = nullptr;

			if ( expire_func )
				{
				idx = RecreateIndex(*k);
				double secs = CallExpireFunc(idx);

				// It's possible that the user-provided
				// function modified or deleted the table
				// value, so look it up again.
				v = table_val->Lookup(k.get());

				if ( ! v )
					{ // user-provided function deleted it
					if ( ! expire_iterator )
						// Entire table got dropped (e.g. clear_table() / RemoveAll())
						break;

					continue;
					}

				if ( secs > 0 )
					{
					// User doesn't want us to expire
					// this now.
					v->SetExpireAccess(run_state::network_time - timeout + secs);
					continue;
					}

				}

			if ( subnets )
				{
				if ( ! idx )
					idx = RecreateIndex(*k);
				if ( ! subnets->Remove(idx.get()) )
					reporter->InternalWarning("index not in prefix table");
				}

			table_val->RemoveEntry(k.get());
			if ( change_func )
				{
				if ( ! idx )
					idx = RecreateIndex(*k);

				CallChangeFunc(idx, v->GetVal(), ELEMENT_EXPIRED);
				}

			delete v;
			modified = true;
			}
		}

	if ( modified )
		Modified();

	if ( ! expire_iterator || (*expire_iterator) == table_val->end_robust() )
		{
		delete expire_iterator;
		expire_iterator = nullptr;
		InitTimer(zeek::detail::table_expire_interval);
		}
	else
		InitTimer(zeek::detail::table_expire_delay);
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
		detail::timer_mgr->Cancel(timer);

	return -1;
	}

double TableVal::CallExpireFunc(ListValPtr idx)
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
		Args vl;

		const auto& func_args = f->GetType()->ParamList()->GetTypes();
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

		auto result = f->Invoke(&vl);

		if ( result )
			secs = result->AsInterval();
		}

	catch ( InterpreterException& e )
		{
		}

	return secs;
	}

ValPtr TableVal::DoClone(CloneState* state)
	{
	auto tv = make_intrusive<TableVal>(table_type);
	state->NewClone(this, tv);

	const PDict<TableEntryVal>* tbl = AsTable();
	for ( const auto& tble : *table_val )
		{
		auto key = tble.GetHashKey();
		auto* val = tble.GetValue<TableEntryVal*>();
		TableEntryVal* nval = val->Clone(state);
		tv->table_val->Insert(key.get(), nval);

		if ( subnets )
			{
			auto idx = RecreateIndex(*key);
			tv->subnets->Insert(idx.get(), nval);
			}
		}

	tv->attrs = attrs;

	if ( expire_time )
		{
		tv->expire_time = expire_time;

		// As network_time is not necessarily initialized yet, we set
		// a timer which fires immediately.
		tv->timer = new TableValTimer(tv.get(), 1);
		detail::timer_mgr->Add(tv->timer);
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	for ( const auto& ve : *table_val )
		{
		auto* tv = ve.GetValue<TableEntryVal*>();
		if ( tv->GetVal() )
			size += tv->GetVal()->MemoryAllocation();
		size += padded_sizeof(TableEntryVal);
		}

	return size + padded_sizeof(*this) + table_val->MemoryAllocation()
		+ table_hash->MemoryAllocation();
#pragma GCC diagnostic pop
	}

std::unique_ptr<detail::HashKey> TableVal::MakeHashKey(const Val& index) const
	{
	return table_hash->MakeHashKey(index, true);
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
	ParseTimeTableState rval;
	for ( const auto& tble : *table_val )
		{
		auto key = tble.GetHashKey();
		auto* val = tble.GetValue<TableEntryVal*>();

		rval.emplace_back(RecreateIndex(*key), val->GetVal());
		}

	RemoveAll();
	return rval;
	}

void TableVal::RebuildTable(ParseTimeTableState ptts)
	{
	delete table_hash;
	table_hash = new detail::CompositeHash(table_type->GetIndices());

	for ( auto& [key, val] : ptts )
		Assign(std::move(key), std::move(val));
	}

TableVal::ParseTimeTableStates TableVal::parse_time_table_states;

TableVal::TableRecordDependencies TableVal::parse_time_table_record_dependencies;

RecordVal::RecordTypeValMap RecordVal::parse_time_records;

RecordVal::RecordVal(RecordTypePtr t, bool init_fields)
: Val(t), is_managed(t->ManagedFields())
	{
	origin = nullptr;
	rt = std::move(t);

	int n = rt->NumFields();

	record_val = new std::vector<std::optional<ZVal>>;
	record_val->reserve(n);

	if ( run_state::is_parsing )
		parse_time_records[rt.get()].emplace_back(NewRef{}, this);

	if ( init_fields )
		{
		try
			{
			rt->Create(*record_val);
			}
		catch ( InterpreterException& e )
			{
			if ( run_state::is_parsing )
				parse_time_records[rt.get()].pop_back();
			throw;
			}
		}
	}

RecordVal::~RecordVal()
	{
	auto n = record_val->size();

	for ( unsigned int i = 0; i < n; ++i )
		if ( HasField(i) && IsManaged(i) )
			ZVal::DeleteManagedType(*(*record_val)[i]);

	delete record_val;
	}

ValPtr RecordVal::SizeVal() const
	{
	return val_mgr->Count(GetType()->AsRecordType()->NumFields());
	}

void RecordVal::Assign(int field, ValPtr new_val)
	{
	if ( new_val )
		{
		DeleteFieldIfManaged(field);

		auto t = rt->GetFieldType(field);
		(*record_val)[field] = ZVal(new_val, t);
		Modified();
		}
	else
		Remove(field);
	}

void RecordVal::Remove(int field)
	{
	if ( HasField(field) )
		{
		if ( IsManaged(field) )
			ZVal::DeleteManagedType(*(*record_val)[field]);

		(*record_val)[field] = std::nullopt;

		Modified();
		}
	}

ValPtr RecordVal::GetFieldOrDefault(int field) const
	{
	auto val = GetField(field);

	if ( val )
		return val;

	return GetType()->AsRecordType()->FieldDefault(field);
	}

void RecordVal::ResizeParseTimeRecords(RecordType* revised_rt)
	{
	auto it = parse_time_records.find(revised_rt);

	if ( it == parse_time_records.end() )
		return;

	auto& rvs = it->second;

	for ( auto& rv : rvs )
		{
		int current_length = rv->NumFields();
		auto required_length = revised_rt->NumFields();

		if ( required_length > current_length )
			{
			for ( auto i = current_length; i < required_length; ++i )
				rv->AppendField(revised_rt->FieldDefault(i),
				                revised_rt->GetFieldType(i));
			}
		}
	}

void RecordVal::DoneParsing()
	{
	parse_time_records.clear();
	}

ValPtr RecordVal::GetField(const char* field) const
	{
	int idx = GetType()->AsRecordType()->FieldOffset(field);

	if ( idx < 0 )
		reporter->InternalError("missing record field: %s", field);

	return GetField(idx);
	}

ValPtr RecordVal::GetFieldOrDefault(const char* field) const
	{
	int idx = GetType()->AsRecordType()->FieldOffset(field);

	if ( idx < 0 )
		reporter->InternalError("missing record field: %s", field);

	return GetFieldOrDefault(idx);
	}

RecordValPtr RecordVal::CoerceTo(RecordTypePtr t,
                                 RecordValPtr aggr,
                                 bool allow_orphaning) const
	{
	if ( ! record_promotion_compatible(t.get(), GetType()->AsRecordType()) )
		return nullptr;

	if ( ! aggr )
		aggr = make_intrusive<RecordVal>(std::move(t));

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

		const auto& v = GetField(i);

		if ( ! v )
			// Check for allowable optional fields is outside the loop, below.
			continue;

		const auto& ft = ar_t->GetFieldType(t_i);

		if ( ft->Tag() == TYPE_RECORD && ! same_type(ft, v->GetType()) )
			{
			auto rhs = make_intrusive<detail::ConstExpr>(v);
			auto e = make_intrusive<detail::RecordCoerceExpr>(
				std::move(rhs), cast_intrusive<RecordType>(ft));
			aggr->Assign(t_i, e->Eval(nullptr));
			continue;
			}

		aggr->Assign(t_i, v);
		}

	for ( i = 0; i < ar_t->NumFields(); ++i )
		if ( ! aggr->HasField(i) &&
		     ! ar_t->FieldDecl(i)->GetAttr(detail::ATTR_OPTIONAL) )
			{
			char buf[512];
			snprintf(buf, sizeof(buf),
					"non-optional field \"%s\" missing in initialization", ar_t->FieldName(i));
			Error(buf);
			}

	return aggr;
	}

RecordValPtr RecordVal::CoerceTo(RecordTypePtr t, bool allow_orphaning)
	{
	if ( same_type(GetType(), t) )
		return {NewRef{}, this};

	return CoerceTo(std::move(t), nullptr, allow_orphaning);
	}

TableValPtr RecordVal::GetRecordFieldsVal() const
	{
	return GetType()->AsRecordType()->GetRecordFieldsVal(this);
	}

void RecordVal::Describe(ODesc* d) const
	{
	auto n = record_val->size();

	if ( d->IsBinary() || d->IsPortable() )
		{
		rt->Describe(d);
		d->SP();
		d->Add(static_cast<uint64_t>(n));
		d->SP();
		}
	else
		d->Add("[");

	for ( size_t i = 0; i < n; ++i )
		{
		if ( ! d->IsBinary() && i > 0 )
			d->Add(", ");

		d->Add(rt->FieldName(i));

		if ( ! d->IsBinary() )
			d->Add("=");

		auto v = GetField(i);

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
	auto n = record_val->size();
	auto rt = GetType()->AsRecordType();

	d->Add("{");
	d->PushIndent();

	for ( size_t i = 0; i < n; ++i )
		{
		if ( i > 0 )
			d->NL();

		d->Add(rt->FieldName(i));
		d->Add("=");

		auto v = GetField(i);

		if ( v )
			v->Describe(d);
		else
			d->Add("<uninitialized>");
		}

	d->PopIndent();
	d->Add("}");
	}

ValPtr RecordVal::DoClone(CloneState* state)
	{
	// We set origin to 0 here.  Origin only seems to be used for exactly one
	// purpose - to find the connection record that is associated with a
	// record. As we cannot guarantee that it will ber zeroed out at the
	// approproate time (as it seems to be guaranteed for the original record)
	// we don't touch it.
	auto rv = make_intrusive<RecordVal>(rt, false);
	rv->origin = nullptr;
	state->NewClone(this, rv);

	int n = NumFields();
	for ( auto i = 0; i < n; ++i )
		{
		auto f_i = GetField(i);
		auto v = f_i ? f_i->Clone(state) : nullptr;
		rv->AppendField(std::move(v), rt->GetFieldType(i));
		}

	return rv;
	}

unsigned int RecordVal::MemoryAllocation() const
	{
	unsigned int size = 0;

	int n = NumFields();
	for ( auto i = 0; i < n; ++i )
		{
		auto f_i = GetField(i);
		if ( f_i )
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
			size += f_i->MemoryAllocation();
#pragma GCC diagnostic pop
		}

	size += util::pad_size(record_val->capacity() * sizeof(ZVal));
	size += padded_sizeof(*record_val);

	return size + padded_sizeof(*this);
	}

ValPtr EnumVal::SizeVal() const
	{
	return val_mgr->Int(AsInt());
	}

void EnumVal::ValDescribe(ODesc* d) const
	{
	const char* ename = type->AsEnumType()->Lookup(int_val);

	if ( ! ename )
		ename = "<undefined>";

	d->Add(ename);
	}

ValPtr EnumVal::DoClone(CloneState* state)
	{
	// Immutable.
	return {NewRef{}, this};
	}

void TypeVal::ValDescribe(ODesc* d) const
	{
	d->Add(type->AsTypeType()->GetType()->GetName());
	}

ValPtr TypeVal::DoClone(CloneState* state)
	{
	// Immutable.
	return {NewRef{}, this};
	}

VectorVal::VectorVal(VectorTypePtr t) :
VectorVal(t, new vector<std::optional<ZVal>>())
	{
	}

VectorVal::VectorVal(VectorTypePtr t, std::vector<std::optional<ZVal>>* vals)
: Val(t)
	{
	vector_val = vals;
	yield_type = t->Yield();

	auto y_tag = yield_type->Tag();
	any_yield = (y_tag == TYPE_VOID || y_tag == TYPE_ANY);
	managed_yield = ZVal::IsManagedType(yield_type);
	}

VectorVal::~VectorVal()
	{
	if ( yield_types )
		{
		int n = yield_types->size();
		for ( auto i = 0; i < n; ++i )
			{
			auto& elem = (*vector_val)[i];
			if ( elem )
				ZVal::DeleteIfManaged(*elem, (*yield_types)[i]);
			}
		delete yield_types;
		}

	else if ( managed_yield )
		{
		for ( auto& elem : *vector_val )
			if ( elem )
				ZVal::DeleteManagedType(*elem);
		}

	delete vector_val;
	}

ValPtr VectorVal::SizeVal() const
	{
	return val_mgr->Count(uint32_t(vector_val->size()));
	}

bool VectorVal::CheckElementType(const ValPtr& element)
	{
	if ( ! element )
		// Insertion isn't actually going to happen.
		return true;

	if ( yield_types )
		// We're already a heterogeneous vector-of-any.
		return true;

	if ( any_yield )
		{
		int n = vector_val->size();

		if ( n == 0 )
			// First addition to an empty vector-of-any, perhaps
			// it will be homogeneous.
			yield_type = element->GetType();

		else
			{
			yield_types = new std::vector<TypePtr>();

			// Since we're only now switching to the heterogeneous
			// representation, capture the types of the existing
			// elements.

			for ( auto i = 0; i < n; ++i )
				yield_types->emplace_back(yield_type);
			}
		}

	else if ( ! same_type(element->GetType(), yield_type, false) )
		return false;

	return true;
	}

bool VectorVal::Assign(unsigned int index, ValPtr element)
	{
	if ( ! CheckElementType(element) )
		return false;

	unsigned int n = vector_val->size();

	if ( index >= n )
		{
		if ( index > n )
			AddHoles(index - n);

		vector_val->resize(index + 1);
		if ( yield_types )
			yield_types->resize(index + 1);
		}

	if ( yield_types )
		{
		const auto& t = element->GetType();
		(*yield_types)[index] = t;
		auto& elem = (*vector_val)[index];
		if ( elem )
			ZVal::DeleteIfManaged(*elem, t);
		elem = ZVal(std::move(element), t);
		}
	else
		{
		auto& elem = (*vector_val)[index];
		if ( managed_yield && elem )
			ZVal::DeleteManagedType(*elem);

		if ( element )
			elem = ZVal(std::move(element), yield_type);
		else
			elem = std::nullopt;
		}

	Modified();
	return true;
	}

bool VectorVal::AssignRepeat(unsigned int index, unsigned int how_many,
                             ValPtr element)
	{
	ResizeAtLeast(index + how_many);

	for ( unsigned int i = index; i < index + how_many; ++i )
		if ( ! Assign(i, element) )
			return false;

	return true;
	}

bool VectorVal::Insert(unsigned int index, ValPtr element)
	{
	if ( ! CheckElementType(element) )
		return false;

	vector<std::optional<ZVal>>::iterator it;
	vector<TypePtr>::iterator types_it;

	auto n = vector_val->size();

	if ( index < n )
		{ // May need to delete previous element
		it = std::next(vector_val->begin(), index);
		if ( yield_types )
			{
			if ( *it )
				ZVal::DeleteIfManaged(**it, element->GetType());
			types_it = std::next(yield_types->begin(), index);
			}
		else if ( managed_yield )
			{
			if ( *it )
				ZVal::DeleteManagedType(**it);
			}
		}
	else
		{
		it = vector_val->end();
		if ( yield_types )
			types_it = yield_types->end();

		if ( index > n )
			AddHoles(index - n);
		}

	if ( element )
		{
		if ( yield_types )
			{
			const auto& t = element->GetType();
			yield_types->insert(types_it, t);
			vector_val->insert(it, ZVal(std::move(element), t));
			}
		else
			vector_val->insert(it, ZVal(std::move(element), yield_type));
		}
	else
		vector_val->insert(it, std::nullopt);

	Modified();
	return true;
	}

void VectorVal::AddHoles(int nholes)
	{
	TypePtr fill_t = yield_type;
	if ( yield_type->Tag() == TYPE_VOID )
		fill_t = base_type(TYPE_ANY);

	for ( auto i = 0; i < nholes; ++i )
		vector_val->emplace_back(std::nullopt);
	}

bool VectorVal::Remove(unsigned int index)
	{
	if ( index >= vector_val->size() )
		return false;

	auto it = std::next(vector_val->begin(), index);

	if ( yield_types )
		{
		auto types_it = std::next(yield_types->begin(), index);
		if ( *it )
			ZVal::DeleteIfManaged(**it, *types_it);
		yield_types->erase(types_it);
		}

	else if ( managed_yield )
		{
		if ( *it )
			ZVal::DeleteManagedType(**it);
		}

	vector_val->erase(it);

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

	if ( ! same_type(type, v->GetType()) )
		{
		type->Error("vector type clash", v->GetType().get());
		return false;
		}

	auto last_idx = v->Size();

	for ( auto i = 0u; i < Size(); ++i )
		v->Assign(last_idx++, At(i));

	return true;
	}

ValPtr VectorVal::At(unsigned int index) const
	{
	if ( index >= vector_val->size() )
		return Val::nil;

	auto& elem = (*vector_val)[index];
	if ( ! elem )
		return Val::nil;

	const auto& t = yield_types ? (*yield_types)[index] : yield_type;

	return elem->ToVal(t);
	}

static Func* sort_function_comp = nullptr;

// Used for indirect sorting to support order().
static std::vector<const std::optional<ZVal>*> index_map;

// The yield type of the vector being sorted.
static TypePtr sort_type;

static bool sort_function(const std::optional<ZVal>& a, const std::optional<ZVal>& b)
	{
	if ( ! a )
		return false;

	if ( ! b )
		return true;

	auto a_v = a->ToVal(sort_type);
	auto b_v = b->ToVal(sort_type);

	auto result = sort_function_comp->Invoke(a_v, b_v);
	int int_result = result->CoerceToInt();

	return int_result < 0;
	}

static bool signed_sort_function(const std::optional<ZVal>& a, const std::optional<ZVal>& b)
	{
	if ( ! a )
		return false;

	if ( ! b )
		return true;

	return a->AsInt() < b->AsInt();
	}

static bool unsigned_sort_function(const std::optional<ZVal>& a, const std::optional<ZVal>& b)
	{
	if ( ! a )
		return false;

	if ( ! b )
		return true;

	return a->AsCount() < b->AsCount();
	}

static bool double_sort_function(const std::optional<ZVal>& a, const std::optional<ZVal>& b)
	{
	if ( ! a )
		return false;

	if ( ! b )
		return true;

	return a->AsDouble() < b->AsDouble();
	}

static bool indirect_sort_function(size_t a, size_t b)
	{
	return sort_function(*index_map[a], *index_map[b]);
	}

static bool indirect_signed_sort_function(size_t a, size_t b)
	{
	return signed_sort_function(*index_map[a], *index_map[b]);
	}

static bool indirect_unsigned_sort_function(size_t a, size_t b)
	{
	return unsigned_sort_function(*index_map[a], *index_map[b]);
	}

static bool indirect_double_sort_function(size_t a, size_t b)
	{
	return double_sort_function(*index_map[a], *index_map[b]);
	}

void VectorVal::Sort(Func* cmp_func)
	{
	if ( yield_types )
		reporter->RuntimeError(GetLocationInfo(), "cannot sort a vector-of-any");

	sort_type = yield_type;

	bool (*sort_func)(const std::optional<ZVal>&, const std::optional<ZVal>&);

	if ( cmp_func )
		{
		sort_function_comp = cmp_func;
		sort_func = sort_function;
		}

	else
		{
		auto eti = sort_type->InternalType();

		if ( eti == TYPE_INTERNAL_INT )
			sort_func = signed_sort_function;
		else if ( eti == TYPE_INTERNAL_UNSIGNED )
			sort_func = unsigned_sort_function;
		else
			{
			ASSERT(eti == TYPE_INTERNAL_DOUBLE);
			sort_func = double_sort_function;
			}
		}

	sort(vector_val->begin(), vector_val->end(), sort_func);
	}

VectorValPtr VectorVal::Order(Func* cmp_func)
	{
	if ( yield_types )
		{
		reporter->RuntimeError(GetLocationInfo(), "cannot order a vector-of-any");
		return nullptr;
		}

	sort_type = yield_type;

	bool (*sort_func)(size_t, size_t);

	if ( cmp_func )
		{
		sort_function_comp = cmp_func;
		sort_func = indirect_sort_function;
		}

	else
		{
		auto eti = sort_type->InternalType();

		if ( eti == TYPE_INTERNAL_INT )
			sort_func = indirect_signed_sort_function;
		else if ( eti == TYPE_INTERNAL_UNSIGNED )
			sort_func = indirect_unsigned_sort_function;
		else
			{
			ASSERT(eti == TYPE_INTERNAL_DOUBLE);
			sort_func = indirect_double_sort_function;
			}
		}

	int n = Size();

	// Set up initial mapping of indices directly to corresponding
	// elements.
	vector<size_t> ind_vv(n);
	int i;
	for ( i = 0; i < n; ++i )
		{
		ind_vv[i] = i;
		index_map.emplace_back(&(*vector_val)[i]);
		}

	sort(ind_vv.begin(), ind_vv.end(), sort_func);

	index_map.clear();

	// Now spin through ind_vv to read out the rearrangement.
	auto result_v = make_intrusive<VectorVal>(zeek::id::index_vec);
	for ( i = 0; i < n; ++i )
		{
		int ind = ind_vv[i];
		result_v->Assign(i, zeek::val_mgr->Count(ind));
		}

	return result_v;
	}

bool VectorVal::Concretize(const TypePtr& t)
	{
	if ( ! any_yield )
		// Could do a same_type() call here, but really this case
		// shouldn't happen in any case.
		return yield_type->Tag() == t->Tag();

	if ( ! vector_val )
		// Trivially concretized.
		return true;

	auto n = vector_val->size();
	for ( auto i = 0U; i < n; ++i )
		{
		auto& v = (*vector_val)[i];
		if ( ! v )
			// Vector hole does not require concretization.
			continue;

		auto& vt_i = yield_types ? (*yield_types)[i] : yield_type;
		if ( vt_i->Tag() == TYPE_ANY )
			{ // Do the concretization.
			ValPtr any_v = {NewRef{}, v->AsAny()};
			auto& vt = any_v->GetType();
			if ( vt->Tag() != t->Tag() )
				return false;

			v = ZVal(any_v, t);
			}

		else if ( vt_i->Tag() != t->Tag() )
			return false;
		}

	// Require that this vector be treated consistently in the future.
	yield_type = t;
	managed_yield = ZVal::IsManagedType(yield_type);
	delete yield_types;
	yield_types = nullptr;
	any_yield = false;

	return true;
	}

unsigned int VectorVal::Resize(unsigned int new_num_elements)
	{
	unsigned int oldsize = vector_val->size();
	vector_val->reserve(new_num_elements);
	vector_val->resize(new_num_elements);

	if ( yield_types )
		{
		yield_types->reserve(new_num_elements);
		yield_types->resize(new_num_elements);
		}

	return oldsize;
	}

unsigned int VectorVal::ResizeAtLeast(unsigned int new_num_elements)
	 {
	 unsigned int old_size = vector_val->size();
	 if ( new_num_elements <= old_size )
		 return old_size;

	 return Resize(new_num_elements);
	 }

void VectorVal::Reserve(unsigned int num_elements)
	{
	vector_val->reserve(num_elements);

	if ( yield_types )
		yield_types->reserve(num_elements);
	}

ValPtr VectorVal::DoClone(CloneState* state)
	{
	auto vv = make_intrusive<VectorVal>(GetType<VectorType>());
	vv->Reserve(vector_val->size());
	state->NewClone(this, vv);

	int n = vector_val->size();

	for ( auto i = 0; i < n; ++i )
		{
		auto elem = At(i);
		vv->Assign(i, elem ? elem->Clone(state) : nullptr);
		}

	return vv;
	}

void VectorVal::ValDescribe(ODesc* d) const
	{
	d->Add("[");

	size_t vector_size = vector_val->size();

	if ( vector_size != 0 )
		{
		auto last_ind = vector_size - 1;
		for ( unsigned int i = 0; i < last_ind; ++i )
			{
			auto v = At(i);
			if ( v )
				v->Describe(d);
			d->Add(", ");
			}

		auto v = At(last_ind);
		if ( v )
			v->Describe(d);
		}

	d->Add("]");
	}

ValPtr check_and_promote(ValPtr v,
                         const Type* t,
                         bool is_init,
                         const detail::Location* expr_location)
	{
	if ( ! v )
		return nullptr;

	Type* vt = flatten_type(v->GetType().get());
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

	ValPtr promoted_v;

	switch ( it ) {
	case TYPE_INTERNAL_INT:
		if ( ( vit == TYPE_INTERNAL_UNSIGNED || vit == TYPE_INTERNAL_DOUBLE ) && detail::would_overflow(vt, t, v.get()) )
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
		if ( ( vit == TYPE_INTERNAL_DOUBLE || vit == TYPE_INTERNAL_INT) && detail::would_overflow(vt, t, v.get()) )
			{
			t->Error("overflow promoting from signed/double to unsigned arithmetic value", v.get(), false, expr_location);
			return nullptr;
			}
		else if ( t_tag == TYPE_COUNT )
			promoted_v = val_mgr->Count(v->CoerceToUnsigned());
		else // port
			{
			reporter->InternalError("bad internal type in check_and_promote()");
			return nullptr;
			}

		break;

	case TYPE_INTERNAL_DOUBLE:
		switch ( t_tag ) {
		case TYPE_DOUBLE:
			promoted_v = make_intrusive<DoubleVal>(v->CoerceToDouble());
			break;
		case TYPE_INTERVAL:
			promoted_v = make_intrusive<IntervalVal>(v->CoerceToDouble());
			break;
		case TYPE_TIME:
			promoted_v = make_intrusive<TimeVal>(v->CoerceToDouble());
			break;
		default:
			reporter->InternalError("bad internal type in check_and_promote()");
			return nullptr;
		}
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
	return is_atomic_type(v->GetType());
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
		return &v1->AsAddr() == &v2->AsAddr();
	case TYPE_INTERNAL_SUBNET:
		return &v1->AsSubNet() == &v2->AsSubNet();

	default:
		reporter->InternalWarning("same_atomic_val called for non-atomic value");
		return false;
	}

	return false;
	}

void describe_vals(const ValPList* vals, ODesc* d, int offset)
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

void describe_vals(const std::vector<ValPtr>& vals,
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

		if ( vals[i] )
			vals[i]->Describe(d);
		}
	}

void delete_vals(ValPList* vals)
	{
	if ( vals )
		{
		for ( const auto& val : *vals )
			Unref(val);
		delete vals;
		}
	}

ValPtr cast_value_to_type(Val* v, Type* t)
	{
	// Note: when changing this function, adapt all three of
	// cast_value_to_type()/can_cast_value_to_type()/can_cast_value_to_type().

	if ( ! v )
		return nullptr;

	// Always allow casting to same type. This also covers casting 'any'
	// to the actual type.
	if ( same_type(v->GetType(), t) )
		return {NewRef{}, v};

	if ( same_type(v->GetType(), Broker::detail::DataVal::ScriptDataType()) )
		{
		const auto& dv = v->AsRecordVal()->GetField(0);

		if ( ! dv )
			return nullptr;

		return static_cast<Broker::detail::DataVal*>(dv.get())->castTo(t);
		}

	return nullptr;
	}

bool can_cast_value_to_type(const Val* v, Type* t)
	{
	// Note: when changing this function, adapt all three of
	// cast_value_to_type()/can_cast_value_to_type()/can_cast_value_to_type().

	if ( ! v )
		return false;

	// Always allow casting to same type. This also covers casting 'any'
	// to the actual type.
	if ( same_type(v->GetType(), t) )
		return true;

	if ( same_type(v->GetType(), Broker::detail::DataVal::ScriptDataType()) )
		{
		const auto& dv = v->AsRecordVal()->GetField(0);

		if ( ! dv )
			return false;

		return static_cast<const Broker::detail::DataVal *>(dv.get())->canCastTo(t);
		}

	return false;
	}

bool can_cast_value_to_type(const Type* s, Type* t)
	{
	// Note: when changing this function, adapt all three of
	// cast_value_to_type()/can_cast_value_to_type()/can_cast_value_to_type().

	// Always allow casting to same type. This also covers casting 'any'
	// to the actual type.
	if ( same_type(s, t) )
		return true;

	if ( same_type(s, Broker::detail::DataVal::ScriptDataType()) )
		// As Broker is dynamically typed, we don't know if we will be able
		// to convert the type as intended. We optimistically assume that we
		// will.
		return true;

	return false;
	}

ValPtr Val::MakeBool(bool b)
	{
	return make_intrusive<BoolVal>(b);
	}

ValPtr Val::MakeInt(bro_int_t i)
	{
	return make_intrusive<IntVal>(i);
	}

ValPtr Val::MakeCount(bro_uint_t u)
	{
	return make_intrusive<CountVal>(u);
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

const PortValPtr& ValManager::Port(uint32_t port_num, TransportProto port_type) const
	{
	if ( port_num >= 65536 )
		{
		reporter->Warning("bad port number %d", port_num);
		port_num = 0;
		}

	return ports[port_type][port_num];
	}

const PortValPtr& ValManager::Port(uint32_t port_num) const
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

}
