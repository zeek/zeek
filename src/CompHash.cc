// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "CompHash.h"
#include "Val.h"
#include "Reporter.h"
#include "Func.h"

#include <vector>
#include <map>

CompositeHash::CompositeHash(TypeList* composite_type)
	{
	type = composite_type;
	Ref(type);
	singleton_tag = TYPE_INTERNAL_ERROR;

	// If the only element is a record, don't treat it as a
	// singleton, since it needs to be evaluated specially.

	if ( type->Types()->length() == 1 )
		{
		if ( (*type->Types())[0]->Tag() == TYPE_RECORD )
			{
			is_complex_type = 1;
			is_singleton = 0;
			}
		else
			{
			is_complex_type = 0;
			is_singleton = 1;
			}
		}

	else
		{
		is_singleton = 0;
		is_complex_type = 0;
		}

	if ( is_singleton )
		{
		// Don't do any further key computations - we'll do them
		// via the singleton later.
		singleton_tag = (*type->Types())[0]->InternalType();
		size = 0;
		key = 0;
		}

	else
		{
		size = ComputeKeySize(0, 1, true);

		if ( size > 0 )
			// Fixed size.  Make sure what we get is fully aligned.
			key = reinterpret_cast<char*>
				(new double[size/sizeof(double) + 1]);
		else
			key = 0;
		}
	}

CompositeHash::~CompositeHash()
	{
	Unref(type);
	delete [] key;
	}

// Computes the piece of the hash for Val*, returning the new kp.
char* CompositeHash::SingleValHash(int type_check, char* kp0,
				   BroType* bt, Val* v, bool optional) const
	{
	char* kp1 = 0;
	InternalTypeTag t = bt->InternalType();

	if ( optional )
		{
		// Add a marker saying whether the optional field is set.
		char* kp = AlignAndPadType<char>(kp0);
		*kp = ( v ? 1 : 0);
		kp0 = reinterpret_cast<char*>(kp+1);

		if ( ! v )
			return kp0;
		}

	if ( type_check )
		{
		InternalTypeTag vt = v->Type()->InternalType();
		if ( vt != t )
			return 0;
		}

	switch ( t ) {
	case TYPE_INTERNAL_INT:
		{
		bro_int_t* kp = AlignAndPadType<bro_int_t>(kp0);
		*kp = v->ForceAsInt();
		kp1 = reinterpret_cast<char*>(kp+1);
		}
		break;

	case TYPE_INTERNAL_UNSIGNED:
		{
		bro_uint_t* kp = AlignAndPadType<bro_uint_t>(kp0);
		*kp = v->ForceAsUInt();
		kp1 = reinterpret_cast<char*>(kp+1);
		}
		break;

	case TYPE_INTERNAL_ADDR:
		{
		uint32_t* kp = AlignAndPadType<uint32_t>(kp0);
		v->AsAddr().CopyIPv6(kp);
		kp1 = reinterpret_cast<char*>(kp+4);
		}
		break;

	case TYPE_INTERNAL_SUBNET:
		{
		uint32_t* kp = AlignAndPadType<uint32_t>(kp0);
		v->AsSubNet().Prefix().CopyIPv6(kp);
		kp[4] = v->AsSubNet().Length();
		kp1 = reinterpret_cast<char*>(kp+5);
		}
		break;

	case TYPE_INTERNAL_DOUBLE:
		{
		double* kp = AlignAndPadType<double>(kp0);
		*kp = v->InternalDouble();
		kp1 = reinterpret_cast<char*>(kp+1);
		}
		break;

	case TYPE_INTERNAL_VOID:
	case TYPE_INTERNAL_OTHER:
		{
		switch ( v->Type()->Tag() ) {
		case TYPE_FUNC:
			{
			uint32_t* kp = AlignAndPadType<uint32_t>(kp0);
			*kp = v->AsFunc()->GetUniqueFuncID();
			kp1 = reinterpret_cast<char*>(kp+1);
			break;
			}

		case TYPE_PATTERN:
			{
			const char* texts[2] = {
				v->AsPattern()->PatternText(),
				v->AsPattern()->AnywherePatternText()
			};

			size_t* kp;
			for ( int i = 0; i < 2; i++ )
				{
				kp = AlignAndPadType<size_t>(kp0+i);
				*kp = strlen(texts[i]) + 1;
				}

			kp1 = reinterpret_cast<char*>(kp+1);
			for ( int i = 0; i < 2; i++ )
				{
				memcpy(kp1, texts[i], strlen(texts[i]) + 1);
				kp1 += strlen(texts[i]) + 1;
				}

			break;
			}

		case TYPE_RECORD:
			{
			char* kp = kp0;
			RecordVal* rv = v->AsRecordVal();
			RecordType* rt = bt->AsRecordType();
			int num_fields = rt->NumFields();

			for ( int i = 0; i < num_fields; ++i )
				{
				Val* rv_i = rv->Lookup(i);

				Attributes* a = rt->FieldDecl(i)->attrs;
				bool optional = (a && a->FindAttr(ATTR_OPTIONAL));

				if ( ! (rv_i || optional) )
					return 0;

				if ( ! (kp = SingleValHash(type_check, kp,
							   rt->FieldType(i),
							   rv_i, optional)) )
					return 0;
				}

			kp1 = kp;
			break;
			}

		case TYPE_TABLE:
			{
			int* kp = AlignAndPadType<int>(kp0);
			TableVal* tv = v->AsTableVal();
			*kp = tv->Size();
			kp1 = reinterpret_cast<char*>(kp+1);

			auto tbl = tv->AsTable();
			auto it = tbl->InitForIteration();
			ListVal* lv = new ListVal(TYPE_ANY);

			struct HashKeyComparer {
				bool operator()(const HashKey* a, const HashKey* b) const
					{
					if ( a->Hash() != b->Hash() )
						return a->Hash() < b->Hash();
					if ( a->Size() != b->Size() )
						return a->Size() < b->Size();
					return strncmp(static_cast<const char*>(a->Key()),
					               static_cast<const char*>(b->Key()),
					               a->Size()) < 0;
					}
			};

			std::map<HashKey*, int, HashKeyComparer> hashkeys;
			HashKey* k;
			auto idx = 0;

			while ( tbl->NextEntry(k, it) )
				{
				hashkeys[k] = idx++;
				lv->Append(tv->RecoverIndex(k));
				}

			for ( auto& kv : hashkeys )
				delete kv.first;

			for ( auto& kv : hashkeys )
				{
				auto idx = kv.second;
				Val* key = lv->Index(idx);

				if ( ! (kp1 = SingleValHash(type_check, kp1, key->Type(), key,
				                            false)) )
					{
					Unref(lv);
					return 0;
					}

				if ( ! v->Type()->IsSet() )
					{
					Val* val = tv->Lookup(key);
					if ( ! (kp1 = SingleValHash(type_check, kp1, val->Type(),
								    val, false)) )
						{
						Unref(lv);
						return 0;
						}
					}
				}

			Unref(lv);
			}
			break;

		case TYPE_VECTOR:
			{
			unsigned int* kp = AlignAndPadType<unsigned int>(kp0);
			VectorVal* vv = v->AsVectorVal();
			VectorType* vt = v->Type()->AsVectorType();
			*kp = vv->Size();
			kp1 = reinterpret_cast<char*>(kp+1);
			for ( unsigned int i = 0; i < vv->Size(); ++i )
				{
				Val* val = vv->Lookup(i);
				unsigned int* kp = AlignAndPadType<unsigned int>(kp1);
				*kp = i;
				kp1 = reinterpret_cast<char*>(kp+1);
				kp = AlignAndPadType<unsigned int>(kp1);
				*kp = val ? 1 : 0;
				kp1 = reinterpret_cast<char*>(kp+1);

				if ( val )
					{
					if ( ! (kp1 = SingleValHash(type_check, kp1,
					                            vt->YieldType(), val, false)) )
						return 0;
					}
				}
			}
			break;

		case TYPE_LIST:
			{
			int* kp = AlignAndPadType<int>(kp0);
			ListVal* lv = v->AsListVal();
			*kp = lv->Length();
			kp1 = reinterpret_cast<char*>(kp+1);
			for ( int i = 0; i < lv->Length(); ++i )
				{
				Val* v = lv->Index(i);
				if ( ! (kp1 = SingleValHash(type_check, kp1, v->Type(), v,
				                            false)) )
					return 0;
				}
			}
			break;

		default:
			{
			reporter->InternalError("bad index type in CompositeHash::SingleValHash");
			return 0;
			}
		}

		break; // case TYPE_INTERNAL_VOID/OTHER
		}

	case TYPE_INTERNAL_STRING:
		{
		// Align to int for the length field.
		int* kp = AlignAndPadType<int>(kp0);
		const BroString* sval = v->AsString();

		*kp = sval->Len();	// so we can recover the value

		kp1 = reinterpret_cast<char*>(kp+1);

		memcpy(kp1, sval->Bytes(), sval->Len());
		kp1 += sval->Len();
		}
		break;

	case TYPE_INTERNAL_ERROR:
		return 0;
	}

	return kp1;
	}


HashKey* CompositeHash::ComputeHash(const Val* v, int type_check) const
	{
	if ( ! v )
		reporter->InternalError("null value given to CompositeHash::ComputeHash");

	if ( is_singleton )
		return ComputeSingletonHash(v, type_check);

	if ( is_complex_type && v->Type()->Tag() != TYPE_LIST )
		{
		ListVal lv(TYPE_ANY);

		// Cast away const to use ListVal - but since we
		// re-introduce const on the recursive call, it should
		// be okay; the only thing is that the ListVal unref's it.
		Val* ncv = (Val*) v;
		ncv->Ref();
		lv.Append(ncv);
	        HashKey* hk = ComputeHash(&lv, type_check);
		return hk;
		}

	char* k = key;

	if ( ! k )
		{
		int sz = ComputeKeySize(v, type_check, false);
		if ( sz == 0 )
			return 0;

		k = reinterpret_cast<char*>(new double[sz/sizeof(double) + 1]);
		type_check = 0;	// no need to type-check again.
		}

	const type_list* tl = type->Types();

	if ( type_check && v->Type()->Tag() != TYPE_LIST )
		return 0;

	const val_list* vl = v->AsListVal()->Vals();
	if ( type_check && vl->length() != tl->length() )
		return 0;

	char* kp = k;
	loop_over_list(*tl, i)
		{
		kp = SingleValHash(type_check, kp, (*tl)[i], (*vl)[i], false);
		if ( ! kp )
			return 0;
		}

	return new HashKey((k == key), (void*) k, kp - k);
	}

HashKey* CompositeHash::ComputeSingletonHash(const Val* v, int type_check) const
	{
	if ( v->Type()->Tag() == TYPE_LIST )
		{
		const val_list* vl = v->AsListVal()->Vals();
		if ( type_check && vl->length() != 1 )
			return 0;

		v = (*vl)[0];
		}

	if ( type_check && v->Type()->InternalType() != singleton_tag )
		return 0;

	switch ( singleton_tag ) {
	case TYPE_INTERNAL_INT:
	case TYPE_INTERNAL_UNSIGNED:
		return new HashKey(v->ForceAsInt());

	case TYPE_INTERNAL_ADDR:
		return v->AsAddr().GetHashKey();

	case TYPE_INTERNAL_SUBNET:
		return v->AsSubNet().GetHashKey();

	case TYPE_INTERNAL_DOUBLE:
		return new HashKey(v->InternalDouble());

	case TYPE_INTERNAL_VOID:
	case TYPE_INTERNAL_OTHER:
		if ( v->Type()->Tag() == TYPE_FUNC )
			return new HashKey(v->AsFunc()->GetUniqueFuncID());

		if ( v->Type()->Tag() == TYPE_PATTERN )
			{
			const char* texts[2] = {
				v->AsPattern()->PatternText(),
				v->AsPattern()->AnywherePatternText()
			};
			int n = strlen(texts[0]) + strlen(texts[1]) + 2; // 2 for null
			char* key = new char[n];
			std::memcpy(key, texts[0], strlen(texts[0]) + 1);
			std::memcpy(key + strlen(texts[0]) + 1, texts[1], strlen(texts[1]) + 1);
			return new HashKey(false, key, n);
			}

		reporter->InternalError("bad index type in CompositeHash::ComputeSingletonHash");
		return 0;

	case TYPE_INTERNAL_STRING:
		return new HashKey(v->AsString());

	case TYPE_INTERNAL_ERROR:
		return 0;

	default:
		reporter->InternalError("bad internal type in CompositeHash::ComputeSingletonHash");
		return 0;
	}
	}

int CompositeHash::SingleTypeKeySize(BroType* bt, const Val* v,
				     int type_check, int sz, bool optional,
				     bool calc_static_size) const
	{
	InternalTypeTag t = bt->InternalType();

	if ( optional )
		sz = SizeAlign(sz, sizeof(char));

	if ( type_check && v )
		{
		InternalTypeTag vt = v->Type()->InternalType();
		if ( vt != t )
			return 0;
		}

	switch ( t ) {
	case TYPE_INTERNAL_INT:
	case TYPE_INTERNAL_UNSIGNED:
		sz = SizeAlign(sz, sizeof(bro_int_t));
		break;

	case TYPE_INTERNAL_ADDR:
		sz = SizeAlign(sz, sizeof(uint32_t));
		sz += sizeof(uint32_t) * 3;	// to make a total of 4 words
		break;

	case TYPE_INTERNAL_SUBNET:
		sz = SizeAlign(sz, sizeof(uint32_t));
		sz += sizeof(uint32_t) * 4;	// to make a total of 5 words
		break;

	case TYPE_INTERNAL_DOUBLE:
		sz = SizeAlign(sz, sizeof(double));
		break;

	case TYPE_INTERNAL_VOID:
	case TYPE_INTERNAL_OTHER:
		{
		switch ( bt->Tag() ) {
		case TYPE_FUNC:
			{
			sz = SizeAlign(sz, sizeof(uint32_t));
			break;
			}

		case TYPE_PATTERN:
			{
			if ( ! v )
				return (optional && ! calc_static_size) ? sz : 0;

			sz = SizeAlign(sz, 2 * sizeof(size_t));
			sz += strlen(v->AsPattern()->PatternText())
				+ strlen(v->AsPattern()->AnywherePatternText()) + 2; // 2 for null terminators
			break;
			}

		case TYPE_RECORD:
			{
			const RecordVal* rv = v ? v->AsRecordVal() : 0;
			RecordType* rt = bt->AsRecordType();
			int num_fields = rt->NumFields();

			for ( int i = 0; i < num_fields; ++i )
				{
				Attributes* a = rt->FieldDecl(i)->attrs;
				bool optional = (a && a->FindAttr(ATTR_OPTIONAL));

				sz = SingleTypeKeySize(rt->FieldType(i),
						       rv ? rv->Lookup(i) : 0,
						       type_check, sz, optional,
						       calc_static_size);
				if ( ! sz )
					return 0;
				}

			break;
			}

		case TYPE_TABLE:
			{
			if ( ! v )
				return (optional && ! calc_static_size) ? sz : 0;

			sz = SizeAlign(sz, sizeof(int));
			TableVal* tv = const_cast<TableVal*>(v->AsTableVal());
			ListVal* lv = tv->ConvertToList();
			for ( int i = 0; i < tv->Size(); ++i )
				{
				Val* key = lv->Index(i);
				sz = SingleTypeKeySize(key->Type(), key, type_check, sz, false,
				                       calc_static_size);
				if ( ! sz )
					{
					Unref(lv);
					return 0;
					}

				if ( ! bt->IsSet() )
					{
					Val* val = tv->Lookup(key);
					sz = SingleTypeKeySize(val->Type(), val, type_check, sz,
					                       false, calc_static_size);
					if ( ! sz )
						{
						Unref(lv);
						return 0;
						}
					}
				}

			Unref(lv);

			break;
			}

		case TYPE_VECTOR:
			{
			if ( ! v )
				return (optional && ! calc_static_size) ? sz : 0;

			sz = SizeAlign(sz, sizeof(unsigned int));
			VectorVal* vv = const_cast<VectorVal*>(v->AsVectorVal());
			for ( unsigned int i = 0; i < vv->Size(); ++i )
				{
				Val* val = vv->Lookup(i);
				sz = SizeAlign(sz, sizeof(unsigned int));
				sz = SizeAlign(sz, sizeof(unsigned int));
				if ( val )
					sz = SingleTypeKeySize(bt->AsVectorType()->YieldType(),
					                       val, type_check, sz, false,
					                       calc_static_size);
				if ( ! sz ) return 0;
				}

			break;
			}

		case TYPE_LIST:
			{
			if ( ! v )
				return (optional && ! calc_static_size) ? sz : 0;

			sz = SizeAlign(sz, sizeof(int));
			ListVal* lv = const_cast<ListVal*>(v->AsListVal());
			for ( int i = 0; i < lv->Length(); ++i )
				{
				sz = SingleTypeKeySize(lv->Index(i)->Type(), lv->Index(i),
				                       type_check, sz, false, calc_static_size);
				if ( ! sz) return 0;
				}

			break;
			}

		default:
			{
			reporter->InternalError("bad index type in CompositeHash::CompositeHash");
			return 0;
			}
		}

		break; // case TYPE_INTERNAL_VOID/OTHER
		}

	case TYPE_INTERNAL_STRING:
		if ( ! v )
			return (optional && ! calc_static_size) ? sz : 0;

		// Factor in length field.
		sz = SizeAlign(sz, sizeof(int));
		sz += v->AsString()->Len();
		break;

	case TYPE_INTERNAL_ERROR:
		return 0;
	}

	return sz;
	}

int CompositeHash::ComputeKeySize(const Val* v, int type_check, bool calc_static_size) const
	{
	const type_list* tl = type->Types();
	const val_list* vl = 0;
	if ( v )
		{
		if ( type_check && v->Type()->Tag() != TYPE_LIST )
			return 0;

		vl = v->AsListVal()->Vals();
		if ( type_check && vl->length() != tl->length() )
			return 0;
		}

	int sz = 0;
	loop_over_list(*tl, i)
		{
		sz = SingleTypeKeySize((*tl)[i], v ? v->AsListVal()->Index(i) : 0,
				       type_check, sz, false, calc_static_size);
		if ( ! sz )
			return 0;
		}

	return sz;
	}

namespace
	{
	inline bool is_power_of_2(bro_uint_t x)
		{
		return ((x - 1) & x) == 0;
		}
	}

const void* CompositeHash::Align(const char* ptr, unsigned int size) const
	{
	if ( ! size )
		return ptr;

	ASSERT(is_power_of_2(size));

	unsigned int mask = size - 1;	// Assume size is a power of 2.
	unsigned long l_ptr = reinterpret_cast<unsigned long>(ptr);
	unsigned long offset = l_ptr & mask;

	if ( offset > 0 )
		return reinterpret_cast<const void*>(ptr - offset + size);
	else
		return reinterpret_cast<const void*>(ptr);
	}

void* CompositeHash::AlignAndPad(char* ptr, unsigned int size) const
	{
	if ( ! size )
		return ptr;

	ASSERT(is_power_of_2(size));

	unsigned int mask = size - 1;	// Assume size is a power of 2.
	while ( (reinterpret_cast<unsigned long>(ptr) & mask) != 0 )
		// Not aligned - zero pad.
		*ptr++ = '\0';

	return reinterpret_cast<void *>(ptr);
	}

int CompositeHash::SizeAlign(int offset, unsigned int size) const
	{
	if ( ! size )
		return offset;

	ASSERT(is_power_of_2(size));

	unsigned int mask = size - 1;	// Assume size is a power of 2.
	if ( offset & mask )
		{
		offset &= ~mask;	// Round down.
		offset += size;		// Round up.
		}

	offset += size;		// Add in size.

	return offset;
	}

ListVal* CompositeHash::RecoverVals(const HashKey* k) const
	{
	ListVal* l = new ListVal(TYPE_ANY);
	const type_list* tl = type->Types();
	const char* kp = (const char*) k->Key();
	const char* const k_end = kp + k->Size();

	for ( const auto& type : *tl )
		{
		Val* v = nullptr;
		kp = RecoverOneVal(k, kp, k_end, type, v, false);
		ASSERT(v);
		l->Append(v);
		}

	if ( kp != k_end )
		reporter->InternalError("under-ran key in CompositeHash::DescribeKey %zd", k_end - kp);

	return l;
	}

const char* CompositeHash::RecoverOneVal(const HashKey* k, const char* kp0,
					 const char* const k_end, BroType* t,
					 Val*& pval, bool optional) const
	{
	// k->Size() == 0 for a single empty string.
	if ( kp0 >= k_end && k->Size() > 0 )
		reporter->InternalError("over-ran key in CompositeHash::RecoverVals");

	TypeTag tag = t->Tag();
	InternalTypeTag it = t->InternalType();
	const char* kp1 = 0;

	if ( optional )
		{
		const char* kp = AlignType<char>(kp0);
		kp0 = kp1 = reinterpret_cast<const char*>(kp+1);

		if ( ! *kp )
			{
			pval = 0;
			return kp0;
			}
		}

	switch ( it ) {
	case TYPE_INTERNAL_INT:
		{
		const bro_int_t* const kp = AlignType<bro_int_t>(kp0);
		kp1 = reinterpret_cast<const char*>(kp+1);

		if ( tag == TYPE_ENUM )
			pval = t->AsEnumType()->GetVal(*kp);
		else if ( tag == TYPE_BOOL )
			pval = val_mgr->GetBool(*kp);
		else if ( tag == TYPE_INT )
			pval = val_mgr->GetInt(*kp);
		else
			{
			reporter->InternalError("bad internal unsigned int in CompositeHash::RecoverOneVal()");
			pval = 0;
			}
		}
		break;

	case TYPE_INTERNAL_UNSIGNED:
		{
		const bro_uint_t* const kp = AlignType<bro_uint_t>(kp0);
		kp1 = reinterpret_cast<const char*>(kp+1);

		switch ( tag ) {
		case TYPE_COUNT:
		case TYPE_COUNTER:
			pval = val_mgr->GetCount(*kp);
			break;

		case TYPE_PORT:
			pval = val_mgr->GetPort(*kp);
			break;

		default:
			reporter->InternalError("bad internal unsigned int in CompositeHash::RecoverOneVal()");
			pval = 0;
			break;
		}
		}
		break;

	case TYPE_INTERNAL_DOUBLE:
		{
		const double* const kp = AlignType<double>(kp0);
		kp1 = reinterpret_cast<const char*>(kp+1);

		if ( tag == TYPE_INTERVAL )
			pval = new IntervalVal(*kp, 1.0);
		else
			pval = new Val(*kp, tag);
		}
		break;

	case TYPE_INTERNAL_ADDR:
		{
		const uint32_t* const kp = AlignType<uint32_t>(kp0);
		kp1 = reinterpret_cast<const char*>(kp+4);

		IPAddr addr(IPv6, kp, IPAddr::Network);

		switch ( tag ) {
		case TYPE_ADDR:
			pval = new AddrVal(addr);
			break;

		default:
			reporter->InternalError("bad internal address in CompositeHash::RecoverOneVal()");
			pval = 0;
			break;
		}
		}
		break;

	case TYPE_INTERNAL_SUBNET:
		{
		const uint32_t* const kp = AlignType<uint32_t>(kp0);
		kp1 = reinterpret_cast<const char*>(kp+5);
		pval = new SubNetVal(kp, kp[4]);
		}
		break;

	case TYPE_INTERNAL_VOID:
	case TYPE_INTERNAL_OTHER:
		{
		switch ( t->Tag() ) {
		case TYPE_FUNC:
			{
			const uint32_t* const kp = AlignType<uint32_t>(kp0);
			kp1 = reinterpret_cast<const char*>(kp+1);

			Func* f = Func::GetFuncPtrByID(*kp);

			if ( ! f )
				reporter->InternalError("failed to look up unique function id %" PRIu32 " in CompositeHash::RecoverOneVal()", *kp);

			pval = new Val(f);

			if ( ! pval->Type() )
				reporter->InternalError("bad aggregate Val in CompositeHash::RecoverOneVal()");

			else if ( t->Tag() != TYPE_FUNC &&
				  ! same_type(pval->Type(), t) )
				// ### Maybe fix later, but may be fundamentally
				// un-checkable --US
				reporter->InternalError("inconsistent aggregate Val in CompositeHash::RecoverOneVal()");

			// ### A crude approximation for now.
			else if ( t->Tag() == TYPE_FUNC &&
				  pval->Type()->Tag() != TYPE_FUNC )
				reporter->InternalError("inconsistent aggregate Val in CompositeHash::RecoverOneVal()");
			}
			break;

		case TYPE_PATTERN:
			{
			RE_Matcher* re = nullptr;
			if ( is_singleton )
				{
				kp1 = kp0;
				int divider = strlen(kp0) + 1;
				re = new RE_Matcher(kp1, kp1 + divider);
				kp1 += k->Size();
				}
			else
				{
				const size_t* const len = AlignType<size_t>(kp0);

				kp1 = reinterpret_cast<const char*>(len+2);
				re = new RE_Matcher(kp1, kp1 + len[0]);
				kp1 += len[0] + len[1];
				}
			pval = new PatternVal(re);
			}
			break;

		case TYPE_RECORD:
			{
			const char* kp = kp0;
			RecordType* rt = t->AsRecordType();
			int num_fields = rt->NumFields();

			vector<Val*> values;
			int i;
			for ( i = 0; i < num_fields; ++i )
				{
				Val* v;

				Attributes* a = rt->FieldDecl(i)->attrs;
				bool optional = (a && a->FindAttr(ATTR_OPTIONAL));

				kp = RecoverOneVal(k, kp, k_end,
				                   rt->FieldType(i), v, optional);

				// An earlier call to reporter->InternalError would have called abort() and broken the
				// call tree that clang-tidy is relying on to get the error described.
				// NOLINTNEXTLINE(clang-analyzer-core.uninitialized.Branch)
				if ( ! (v || optional) )
					{
					reporter->InternalError("didn't recover expected number of fields from HashKey");
					pval = 0;
					break;
					}

				values.push_back(v);
				}

			ASSERT(int(values.size()) == num_fields);

			RecordVal* rv = new RecordVal(rt);

			for ( int i = 0; i < num_fields; ++i )
				rv->Assign(i, values[i]);

			pval = rv;
			kp1 = kp;
			}
			break;

		case TYPE_TABLE:
			{
			int n;
			const int* const kp = AlignType<int>(kp0);
			n = *kp;
			kp1 = reinterpret_cast<const char*>(kp+1);
			TableType* tt = t->AsTableType();
			TableVal* tv = new TableVal(tt);
			vector<Val*> keys, values;
			for ( int i = 0; i < n; ++i )
				{
				Val* key;
				kp1 = RecoverOneVal(k, kp1, k_end, tt->Indices(), key, false);
				keys.push_back(key);
				if ( ! t->IsSet() )
					{
					Val* value;
					kp1 = RecoverOneVal(k, kp1, k_end, tt->YieldType(), value,
					                    false);
					values.push_back(value);
					}
				}

			for ( int i = 0; i < n; ++i )
				{
				tv->Assign(keys[i], t->IsSet() ? 0 : values[i]);
				Unref(keys[i]);
				}

			pval = tv;
			}
			break;

		case TYPE_VECTOR:
			{
			unsigned int n;
			const unsigned int* kp = AlignType<unsigned int>(kp0);
			n = *kp;
			kp1 = reinterpret_cast<const char*>(kp+1);
			VectorType* vt = t->AsVectorType();
			VectorVal* vv = new VectorVal(vt);
			for ( unsigned int i = 0; i < n; ++i )
				{
				kp = AlignType<unsigned int>(kp1);
				unsigned int index = *kp;
				kp1 = reinterpret_cast<const char*>(kp+1);
				kp = AlignType<unsigned int>(kp1);
				unsigned int have_val = *kp;
				kp1 = reinterpret_cast<const char*>(kp+1);
				Val* value = 0;
				if ( have_val )
					kp1 = RecoverOneVal(k, kp1, k_end, vt->YieldType(), value,
					                    false);
				vv->Assign(index, value);
				}

			pval = vv;
			}
			break;

		case TYPE_LIST:
			{
			int n;
			const int* const kp = AlignType<int>(kp0);
			n = *kp;
			kp1 = reinterpret_cast<const char*>(kp+1);
			TypeList* tl = t->AsTypeList();
			ListVal* lv = new ListVal(TYPE_ANY);
			for ( int i = 0; i < n; ++i )
				{
				Val* v;
				BroType* it = (*tl->Types())[i];
				kp1 = RecoverOneVal(k, kp1, k_end, it, v, false);
				lv->Append(v);
				}

			pval = lv;
			}
			break;

		default:
			{
			reporter->InternalError("bad index type in CompositeHash::DescribeKey");
			}
		}
		}
		break;

	case TYPE_INTERNAL_STRING:
		{
		// There is a minor issue here -- the pointer does not have to
		// be aligned by int in the singleton case.

		int n;
		if ( is_singleton )
			{
			kp1 = kp0;
			n = k->Size();
			}
		else
			{
			const int* const kp = AlignType<int>(kp0);
			n = *kp;
			kp1 = reinterpret_cast<const char*>(kp+1);
			}

		pval = new StringVal(new BroString((const byte_vec) kp1, n, 1));
		kp1 += n;
		}
		break;

	case TYPE_INTERNAL_ERROR:
		break;
	}

	return kp1;
	}
