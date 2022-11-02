// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/CompHash.h"

#include "zeek/zeek-config.h"

#include <cstring>
#include <map>
#include <vector>

#include "zeek/Func.h"
#include "zeek/IPAddr.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"

namespace zeek::detail
	{

// A comparison callable to assist with consistent iteration order over tables
// during reservation & writes.
struct HashKeyComparer
	{
	bool operator()(const std::unique_ptr<HashKey>& a, const std::unique_ptr<HashKey>& b) const
		{
		if ( a->Hash() != b->Hash() )
			return a->Hash() < b->Hash();
		if ( a->Size() != b->Size() )
			return a->Size() < b->Size();
		return memcmp(a->Key(), b->Key(), a->Size()) < 0;
		}
	};

using HashkeyMap = std::map<std::unique_ptr<HashKey>, ListValPtr, HashKeyComparer>;
using HashkeyMapPtr = std::unique_ptr<HashkeyMap>;

// Helper that produces a table from HashKeys to the ListVal indexes into the
// table, that we can iterate over in sorted-Hashkey order.
const HashkeyMapPtr ordered_hashkeys(const TableVal* tv)
	{
	auto res = std::make_unique<HashkeyMap>();
	auto tbl = tv->AsTable();
	auto idx = 0;

	for ( const auto& entry : *tbl )
		{
		auto k = entry.GetHashKey();
		// Potential optimization: we could do without the following if
		// the caller uses k directly to determine key length &
		// content. But: the way k got serialized might differ somewhat
		// from how we'll end up doing it (e.g. singleton vs
		// non-singleton), and looking up a table value with the hashkey
		// is tricky in case of subnets (consider the special-casing in
		// TableVal::Find()).
		auto lv = tv->RecreateIndex(*k);
		res->insert_or_assign(std::move(k), lv);
		}

	return res;
	}

CompositeHash::CompositeHash(TypeListPtr composite_type) : type(std::move(composite_type))
	{
	if ( type->GetTypes().size() == 1 )
		is_singleton = true;
	}

std::unique_ptr<HashKey> CompositeHash::MakeHashKey(const Val& argv, bool type_check) const
	{
	auto res = std::make_unique<HashKey>();
	const auto& tl = type->GetTypes();

	if ( is_singleton )
		{
		const Val* v = &argv;

		// This is the "singleton" case -- actually just a single value
		// that may come bundled in a list. If so, unwrap it.
		if ( v->GetType()->Tag() == TYPE_LIST )
			{
			auto lv = v->AsListVal();

			if ( type_check && lv->Length() != 1 )
				return nullptr;

			v = lv->Idx(0).get();
			}

		if ( SingleValHash(*res, v, tl[0].get(), type_check, false, true) )
			return res;

		return nullptr;
		}

	if ( type_check && argv.GetType()->Tag() != TYPE_LIST )
		return nullptr;

	if ( ! ReserveKeySize(*res, &argv, type_check, false) )
		return nullptr;

	// Size computation has done requested type-checking, no further need
	type_check = false;

	// The size computation resulted in a requested buffer size; allocate it.
	res->Allocate();

	for ( auto i = 0u; i < tl.size(); ++i )
		{
		if ( ! SingleValHash(*res, argv.AsListVal()->Idx(i).get(), tl[i].get(), type_check, false,
		                     false) )
			return nullptr;
		}

	return res;
	}

ListValPtr CompositeHash::RecoverVals(const HashKey& hk) const
	{
	auto l = make_intrusive<ListVal>(TYPE_ANY);
	const auto& tl = type->GetTypes();

	hk.ResetRead();

	for ( const auto& type : tl )
		{
		ValPtr v;

		if ( ! RecoverOneVal(hk, type.get(), &v, false, is_singleton) )
			reporter->InternalError("value recovery failure in CompositeHash::RecoverVals");

		ASSERT(v);
		l->Append(std::move(v));
		}

	return l;
	}

bool CompositeHash::RecoverOneVal(const HashKey& hk, Type* t, ValPtr* pval, bool optional,
                                  bool singleton) const
	{
	TypeTag tag = t->Tag();
	InternalTypeTag it = t->InternalType();

	if ( optional )
		{
		bool opt;
		hk.Read("optional", opt);

		if ( ! opt )
			{
			*pval = nullptr;
			return true;
			}
		}

	switch ( it )
		{
		case TYPE_INTERNAL_INT:
			{
			zeek_int_t i;
			hk.Read("int", i);

			if ( tag == TYPE_ENUM )
				*pval = t->AsEnumType()->GetEnumVal(i);
			else if ( tag == TYPE_BOOL )
				*pval = val_mgr->Bool(i);
			else if ( tag == TYPE_INT )
				*pval = val_mgr->Int(i);
			else
				{
				reporter->InternalError(
					"bad internal unsigned int in CompositeHash::RecoverOneVal()");
				*pval = nullptr;
				return false;
				}
			}
			break;

		case TYPE_INTERNAL_UNSIGNED:
			{
			zeek_uint_t u;
			hk.Read("unsigned", u);

			switch ( tag )
				{
				case TYPE_COUNT:
					*pval = val_mgr->Count(u);
					break;

				case TYPE_PORT:
					*pval = val_mgr->Port(u);
					break;

				default:
					reporter->InternalError(
						"bad internal unsigned int in CompositeHash::RecoverOneVal()");
					*pval = nullptr;
					return false;
				}
			}
			break;

		case TYPE_INTERNAL_DOUBLE:
			{
			double d;
			hk.Read("double", d);

			if ( tag == TYPE_INTERVAL )
				*pval = make_intrusive<IntervalVal>(d, 1.0);
			else if ( tag == TYPE_TIME )
				*pval = make_intrusive<TimeVal>(d);
			else
				*pval = make_intrusive<DoubleVal>(d);
			}
			break;

		case TYPE_INTERNAL_ADDR:
			{
			hk.AlignRead(sizeof(uint32_t));
			hk.EnsureReadSpace(sizeof(uint32_t) * 4);
			IPAddr addr(IPv6, static_cast<const uint32_t*>(hk.KeyAtRead()), IPAddr::Network);
			hk.SkipRead("addr", sizeof(uint32_t) * 4);

			switch ( tag )
				{
				case TYPE_ADDR:
					*pval = make_intrusive<AddrVal>(addr);
					break;

				default:
					reporter->InternalError(
						"bad internal address in CompositeHash::RecoverOneVal()");
					*pval = nullptr;
					return false;
				}
			}
			break;

		case TYPE_INTERNAL_SUBNET:
			{
			hk.AlignRead(sizeof(uint32_t));
			hk.EnsureReadSpace(sizeof(uint32_t) * 4);
			IPAddr addr(IPv6, static_cast<const uint32_t*>(hk.KeyAtRead()), IPAddr::Network);
			hk.SkipRead("subnet", sizeof(uint32_t) * 4);

			uint32_t width;
			hk.Read("subnet-width", width);
			*pval = make_intrusive<SubNetVal>(addr, width);
			}
			break;

		case TYPE_INTERNAL_VOID:
		case TYPE_INTERNAL_OTHER:
			{
			switch ( t->Tag() )
				{
				case TYPE_FUNC:
					{
					uint32_t id;
					hk.Read("func", id);

					ASSERT(func_id_to_func != nullptr);

					if ( id >= func_id_to_func->size() )
						reporter->InternalError("failed to look up unique function id %" PRIu32
						                        " in CompositeHash::RecoverOneVal()",
						                        id);

					const auto& f = func_id_to_func->at(id);

					*pval = make_intrusive<FuncVal>(f);
					const auto& pvt = (*pval)->GetType();

					if ( ! pvt )
						reporter->InternalError(
							"bad aggregate Val in CompositeHash::RecoverOneVal()");

					else if ( t->Tag() != TYPE_FUNC && ! same_type(pvt, t) )
						// ### Maybe fix later, but may be fundamentally un-checkable --US
						{
						reporter->InternalError(
							"inconsistent aggregate Val in CompositeHash::RecoverOneVal()");
						*pval = nullptr;
						return false;
						}

					// ### A crude approximation for now.
					else if ( t->Tag() == TYPE_FUNC && pvt->Tag() != TYPE_FUNC )
						{
						reporter->InternalError(
							"inconsistent aggregate Val in CompositeHash::RecoverOneVal()");
						*pval = nullptr;
						return false;
						}
					}
					break;

				case TYPE_PATTERN:
					{
					const char* texts[2] = {nullptr, nullptr};
					uint64_t lens[2] = {0, 0};

					if ( ! singleton )
						{
						hk.Read("pattern-len1", lens[0]);
						hk.Read("pattern-len2", lens[1]);
						}

					texts[0] = static_cast<const char*>(hk.KeyAtRead());
					hk.SkipRead("pattern-string1", strlen(texts[0]) + 1);
					texts[1] = static_cast<const char*>(hk.KeyAtRead());
					hk.SkipRead("pattern-string2", strlen(texts[1]) + 1);

					RE_Matcher* re = new RE_Matcher(texts[0], texts[1]);

					if ( ! re->Compile() )
						reporter->InternalError("failed compiling table/set key pattern: %s",
						                        re->PatternText());

					*pval = make_intrusive<PatternVal>(re);
					}
					break;

				case TYPE_RECORD:
					{
					auto rt = t->AsRecordType();
					int num_fields = rt->NumFields();

					std::vector<ValPtr> values;
					int i;
					for ( i = 0; i < num_fields; ++i )
						{
						ValPtr v;
						Attributes* a = rt->FieldDecl(i)->attrs.get();
						bool is_optional = (a && a->Find(ATTR_OPTIONAL));

						if ( ! RecoverOneVal(hk, rt->GetFieldType(i).get(), &v, is_optional,
						                     false) )
							{
							*pval = nullptr;
							return false;
							}

						// An earlier call to reporter->InternalError would have called
						// abort() and broken the call tree that clang-tidy is relying on to
						// get the error described.
						// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch)
						if ( ! (v || is_optional) )
							{
							reporter->InternalError(
								"didn't recover expected number of fields from HashKey");
							*pval = nullptr;
							return false;
							}

						values.emplace_back(std::move(v));
						}

					ASSERT(int(values.size()) == num_fields);

					auto rv = make_intrusive<RecordVal>(IntrusivePtr{NewRef{}, rt});

					for ( int i = 0; i < num_fields; ++i )
						rv->Assign(i, std::move(values[i]));

					*pval = std::move(rv);
					}
					break;

				case TYPE_TABLE:
					{
					int n;
					hk.Read("table-size", n);
					auto tt = t->AsTableType();
					auto tv = make_intrusive<TableVal>(IntrusivePtr{NewRef{}, tt});

					for ( int i = 0; i < n; ++i )
						{
						ValPtr key;
						if ( ! RecoverOneVal(hk, tt->GetIndices().get(), &key, false, false) )
							{
							*pval = nullptr;
							return false;
							}

						if ( t->IsSet() )
							tv->Assign(std::move(key), nullptr);
						else
							{
							ValPtr value;
							if ( ! RecoverOneVal(hk, tt->Yield().get(), &value, false, false) )
								{
								*pval = nullptr;
								return false;
								}
							tv->Assign(std::move(key), std::move(value));
							}
						}

					*pval = std::move(tv);
					}
					break;

				case TYPE_VECTOR:
					{
					unsigned int n;
					hk.Read("vector-size", n);
					auto vt = t->AsVectorType();
					auto vv = make_intrusive<VectorVal>(IntrusivePtr{NewRef{}, vt});

					for ( unsigned int i = 0; i < n; ++i )
						{
						unsigned int index;
						hk.Read("vector-idx", index);
						bool have_val;
						hk.Read("vector-idx-present", have_val);
						ValPtr value;

						if ( have_val &&
						     ! RecoverOneVal(hk, vt->Yield().get(), &value, false, false) )
							{
							*pval = nullptr;
							return false;
							}

						vv->Assign(index, std::move(value));
						}

					*pval = std::move(vv);
					}
					break;

				case TYPE_LIST:
					{
					int n;
					hk.Read("list-size", n);
					auto tl = t->AsTypeList();
					auto lv = make_intrusive<ListVal>(TYPE_ANY);

					for ( int i = 0; i < n; ++i )
						{
						ValPtr v;
						Type* it = tl->GetTypes()[i].get();
						if ( ! RecoverOneVal(hk, it, &v, false, false) )
							return false;
						lv->Append(std::move(v));
						}

					*pval = std::move(lv);
					}
					break;

				default:
					{
					reporter->InternalError("bad index type in CompositeHash::RecoverOneVal");
					*pval = nullptr;
					return false;
					}
				}
			}
			break;

		case TYPE_INTERNAL_STRING:
			{
			int n = hk.Size();

			if ( ! singleton )
				{
				hk.Read("string-len", n);
				hk.EnsureReadSpace(n);
				}

			*pval = make_intrusive<StringVal>(new String((const byte_vec)hk.KeyAtRead(), n, true));
			hk.SkipRead("string", n);
			}
			break;

		case TYPE_INTERNAL_ERROR:
			break;
		}

	return true;
	}

bool CompositeHash::SingleValHash(HashKey& hk, const Val* v, Type* bt, bool type_check,
                                  bool optional, bool singleton) const
	{
	InternalTypeTag t = bt->InternalType();

	if ( type_check && v )
		{
		InternalTypeTag vt = v->GetType()->InternalType();
		if ( vt != t )
			return false;
		}

	if ( optional )
		{
		// Add a marker saying whether the optional field is set.
		hk.Write("optional", v != nullptr);

		if ( ! v )
			return true;
		}

	// All of the rest of the code here depends on v not being null, since it needs
	// to get values from it.
	if ( ! v )
		return false;

	switch ( t )
		{
		case TYPE_INTERNAL_INT:
			hk.Write("int", v->AsInt());
			break;

		case TYPE_INTERNAL_UNSIGNED:
			hk.Write("unsigned", v->AsCount());
			break;

		case TYPE_INTERNAL_ADDR:
			if ( ! EnsureTypeReserve(hk, v, bt, type_check) )
				return false;

			hk.AlignWrite(sizeof(uint32_t));
			hk.EnsureWriteSpace(sizeof(uint32_t) * 4);
			v->AsAddr().CopyIPv6(static_cast<uint32_t*>(hk.KeyAtWrite()));
			hk.SkipWrite("addr", sizeof(uint32_t) * 4);
			break;

		case TYPE_INTERNAL_SUBNET:
			if ( ! EnsureTypeReserve(hk, v, bt, type_check) )
				return false;

			hk.AlignWrite(sizeof(uint32_t));
			hk.EnsureWriteSpace(sizeof(uint32_t) * 5);
			v->AsSubNet().Prefix().CopyIPv6(static_cast<uint32_t*>(hk.KeyAtWrite()));
			hk.SkipWrite("subnet", sizeof(uint32_t) * 4);
			hk.Write("subnet-width", v->AsSubNet().Length());
			break;

		case TYPE_INTERNAL_DOUBLE:
			hk.Write("double", v->InternalDouble());
			break;

		case TYPE_INTERNAL_VOID:
		case TYPE_INTERNAL_OTHER:
			{
			switch ( v->GetType()->Tag() )
				{
				case TYPE_FUNC:
					{
					auto f = v->AsFunc();

					if ( ! func_to_func_id )
						const_cast<CompositeHash*>(this)->BuildFuncMappings();

					auto id_mapping = func_to_func_id->find(f);
					uint32_t id;

					if ( id_mapping == func_to_func_id->end() )
						{
						// We need the pointer to stick around
						// for our lifetime, so we have to get
						// a non-const version we can ref.
						FuncPtr fptr = {NewRef{}, const_cast<Func*>(f)};

						id = func_id_to_func->size();
						func_id_to_func->push_back(std::move(fptr));
						func_to_func_id->insert_or_assign(f, id);
						}
					else
						id = id_mapping->second;

					hk.Write("func", id);
					}
					break;

				case TYPE_PATTERN:
					{
					const char* texts[2] = {v->AsPattern()->PatternText(),
					                        v->AsPattern()->AnywherePatternText()};
					uint64_t lens[2] = {strlen(texts[0]) + 1, strlen(texts[1]) + 1};

					if ( ! singleton )
						{
						hk.Write("pattern-len1", lens[0]);
						hk.Write("pattern-len2", lens[1]);
						}
					else
						{
						hk.Reserve("pattern", lens[0] + lens[1]);
						hk.Allocate();
						}

					hk.Write("pattern-string1", static_cast<const void*>(texts[0]), lens[0]);
					hk.Write("pattern-string2", static_cast<const void*>(texts[1]), lens[1]);
					break;
					}

				case TYPE_RECORD:
					{
					auto rv = v->AsRecordVal();
					auto rt = bt->AsRecordType();
					int num_fields = rt->NumFields();

					if ( ! EnsureTypeReserve(hk, v, bt, type_check) )
						return false;

					for ( int i = 0; i < num_fields; ++i )
						{
						auto rv_i = rv->GetField(i);

						Attributes* a = rt->FieldDecl(i)->attrs.get();
						bool optional_attr = (a && a->Find(ATTR_OPTIONAL));

						if ( ! (rv_i || optional_attr) )
							return false;

						if ( ! SingleValHash(hk, rv_i.get(), rt->GetFieldType(i).get(), type_check,
						                     optional_attr, false) )
							return false;
						}
					break;
					}

				case TYPE_TABLE:
					{
					if ( ! EnsureTypeReserve(hk, v, bt, type_check) )
						return false;

					auto tv = v->AsTableVal();
					auto hashkeys = ordered_hashkeys(tv);

					hk.Write("table-size", tv->Size());

					for ( auto& kv : *hashkeys )
						{
						auto key = kv.second;

						if ( ! SingleValHash(hk, key.get(), key->GetType().get(), type_check, false,
						                     false) )
							return false;

						if ( ! v->GetType()->IsSet() )
							{
							auto val = const_cast<TableVal*>(tv)->FindOrDefault(key);

							if ( ! SingleValHash(hk, val.get(), val->GetType().get(), type_check,
							                     false, false) )
								return false;
							}
						}
					}
					break;

				case TYPE_VECTOR:
					{
					if ( ! EnsureTypeReserve(hk, v, bt, type_check) )
						return false;

					auto vv = v->AsVectorVal();
					auto vt = v->GetType()->AsVectorType();

					hk.Write("vector-size", vv->Size());

					for ( unsigned int i = 0; i < vv->Size(); ++i )
						{
						auto val = vv->ValAt(i);
						hk.Write("vector-idx", i);
						hk.Write("vector-idx-present", val != nullptr);

						if ( val && ! SingleValHash(hk, val.get(), vt->Yield().get(), type_check,
						                            false, false) )
							return false;
						}
					}
					break;

				case TYPE_LIST:
					{
					if ( ! hk.IsAllocated() )
						{
						if ( ! ReserveSingleTypeKeySize(hk, bt, v, type_check, false, false,
						                                false) )
							return false;

						hk.Allocate();
						}

					auto lv = v->AsListVal();

					hk.Write("list-size", lv->Length());

					for ( int i = 0; i < lv->Length(); ++i )
						{
						Val* entry_val = lv->Idx(i).get();
						if ( ! SingleValHash(hk, entry_val, entry_val->GetType().get(), type_check,
						                     false, false) )
							return false;
						}
					}
					break;

				default:
					{
					reporter->InternalError("bad index type in CompositeHash::SingleValHash");
					return false;
					}
				}

			break; // case TYPE_INTERNAL_VOID/OTHER
			}

		case TYPE_INTERNAL_STRING:
			{
			if ( ! EnsureTypeReserve(hk, v, bt, type_check) )
				return false;

			const auto sval = v->AsString();

			if ( ! singleton )
				hk.Write("string-len", sval->Len());

			hk.Write("string", sval->Bytes(), sval->Len());
			}
			break;

		default:
			return false;
		}

	return true;
	}

bool CompositeHash::EnsureTypeReserve(HashKey& hk, const Val* v, Type* bt, bool type_check) const
	{
	if ( hk.IsAllocated() )
		return true;

	if ( ! ReserveSingleTypeKeySize(hk, bt, v, type_check, false, false, true) )
		return false;

	hk.Allocate();
	return true;
	}

bool CompositeHash::ReserveKeySize(HashKey& hk, const Val* v, bool type_check,
                                   bool calc_static_size) const
	{
	const auto& tl = type->GetTypes();

	for ( auto i = 0u; i < tl.size(); ++i )
		{
		if ( ! ReserveSingleTypeKeySize(hk, tl[i].get(), v ? v->AsListVal()->Idx(i).get() : nullptr,
		                                type_check, false, calc_static_size, is_singleton) )
			return false;
		}

	return true;
	}

bool CompositeHash::ReserveSingleTypeKeySize(HashKey& hk, Type* bt, const Val* v, bool type_check,
                                             bool optional, bool calc_static_size,
                                             bool singleton) const
	{
	InternalTypeTag t = bt->InternalType();

	if ( optional )
		{
		hk.ReserveType<bool>("optional");
		if ( ! v )
			return true;
		}

	if ( type_check && v )
		{
		InternalTypeTag vt = v->GetType()->InternalType();
		if ( vt != t )
			return false;
		}

	switch ( t )
		{
		case TYPE_INTERNAL_INT:
			hk.ReserveType<zeek_int_t>("int");
			break;

		case TYPE_INTERNAL_UNSIGNED:
			hk.ReserveType<zeek_int_t>("unsigned");
			break;

		case TYPE_INTERNAL_ADDR:
			hk.Reserve("addr", sizeof(uint32_t) * 4, sizeof(uint32_t));
			break;

		case TYPE_INTERNAL_SUBNET:
			hk.Reserve("subnet", sizeof(uint32_t) * 5, sizeof(uint32_t));
			break;

		case TYPE_INTERNAL_DOUBLE:
			hk.ReserveType<double>("double");
			break;

		case TYPE_INTERNAL_VOID:
		case TYPE_INTERNAL_OTHER:
			{
			switch ( bt->Tag() )
				{
				case TYPE_FUNC:
					{
					hk.ReserveType<uint32_t>("func");
					break;
					}

				case TYPE_PATTERN:
					{
					if ( ! v )
						return (optional && ! calc_static_size);

					if ( ! singleton )
						{
						hk.ReserveType<uint64_t>("pattern-len1");
						hk.ReserveType<uint64_t>("pattern-len2");
						}

					// +1 in the following to include null terminators
					hk.Reserve("pattern-string1", strlen(v->AsPattern()->PatternText()) + 1, 0);
					hk.Reserve("pattern-string1", strlen(v->AsPattern()->AnywherePatternText()) + 1,
					           0);
					break;
					}

				case TYPE_RECORD:
					{
					if ( ! v )
						return (optional && ! calc_static_size);

					const RecordVal* rv = v->AsRecordVal();
					RecordType* rt = bt->AsRecordType();
					int num_fields = rt->NumFields();

					for ( int i = 0; i < num_fields; ++i )
						{
						Attributes* a = rt->FieldDecl(i)->attrs.get();
						bool optional_attr = (a && a->Find(ATTR_OPTIONAL));

						auto rv_v = rv ? rv->GetField(i) : nullptr;
						if ( ! ReserveSingleTypeKeySize(hk, rt->GetFieldType(i).get(), rv_v.get(),
						                                type_check, optional_attr, calc_static_size,
						                                false) )
							return false;
						}
					break;
					}

				case TYPE_TABLE:
					{
					if ( ! v )
						return (optional && ! calc_static_size);

					auto tv = v->AsTableVal();
					auto hashkeys = ordered_hashkeys(tv);

					hk.ReserveType<int>("table-size");

					for ( auto& kv : *hashkeys )
						{
						auto key = kv.second;

						if ( ! ReserveSingleTypeKeySize(hk, key->GetType().get(), key.get(),
						                                type_check, false, calc_static_size,
						                                false) )
							return false;

						if ( ! bt->IsSet() )
							{
							auto val = const_cast<TableVal*>(tv)->FindOrDefault(key);
							if ( ! ReserveSingleTypeKeySize(hk, val->GetType().get(), val.get(),
							                                type_check, false, calc_static_size,
							                                false) )
								return false;
							}
						}

					break;
					}

				case TYPE_VECTOR:
					{
					if ( ! v )
						return (optional && ! calc_static_size);

					hk.ReserveType<int>("vector-size");
					VectorVal* vv = const_cast<VectorVal*>(v->AsVectorVal());
					for ( unsigned int i = 0; i < vv->Size(); ++i )
						{
						auto val = vv->ValAt(i);
						hk.ReserveType<unsigned int>("vector-idx");
						hk.ReserveType<unsigned int>("vector-idx-present");
						if ( val && ! ReserveSingleTypeKeySize(
										hk, bt->AsVectorType()->Yield().get(), val.get(),
										type_check, false, calc_static_size, false) )
							return false;
						}
					break;
					}

				case TYPE_LIST:
					{
					if ( ! v )
						return (optional && ! calc_static_size);

					hk.ReserveType<int>("list-size");
					ListVal* lv = const_cast<ListVal*>(v->AsListVal());
					for ( int i = 0; i < lv->Length(); ++i )
						{
						if ( ! ReserveSingleTypeKeySize(hk, lv->Idx(i)->GetType().get(),
						                                lv->Idx(i).get(), type_check, false,
						                                calc_static_size, false) )
							return false;
						}

					break;
					}

				default:
					{
					reporter->InternalError(
						"bad index type in CompositeHash::ReserveSingleTypeKeySize");
					return 0;
					}
				}

			break; // case TYPE_INTERNAL_VOID/OTHER
			}

		case TYPE_INTERNAL_STRING:
			if ( ! v )
				return (optional && ! calc_static_size);
			if ( ! singleton )
				hk.ReserveType<int>("string-len");
			hk.Reserve("string", v->AsString()->Len());
			break;

		case TYPE_INTERNAL_ERROR:
			return false;
		}

	return true;
	}

	} // namespace zeek::detail
