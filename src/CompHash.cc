// $Id: CompHash.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "CompHash.h"
#include "Val.h"

CompositeHash::CompositeHash(TypeList* composite_type)
	{
	type = composite_type;
	Ref(type);

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
		size = ComputeKeySize();

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
					BroType* bt, Val* v) const
	{
	char* kp1 = 0;
	InternalTypeTag t = bt->InternalType();

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
		// Use uint32 instead of int, because 'int' is not
		// guaranteed to be 32-bit.
		uint32* kp = AlignAndPadType<uint32>(kp0);
#ifdef BROv6
		const addr_type av = v->AsAddr();
		kp[0] = av[0];
		kp[1] = av[1];
		kp[2] = av[2];
		kp[3] = av[3];
		kp1 = reinterpret_cast<char*>(kp+4);
#else
		*kp = v->AsAddr();
		kp1 = reinterpret_cast<char*>(kp+1);
#endif
		}
		break;

	case TYPE_INTERNAL_SUBNET:
		{
		uint32* kp = AlignAndPadType<uint32>(kp0);
#ifdef BROv6
		const subnet_type* sv = v->AsSubNet();
		kp[0] = sv->net[0];
		kp[1] = sv->net[1];
		kp[2] = sv->net[2];
		kp[3] = sv->net[3];
		kp[4] = sv->width;
		kp1 = reinterpret_cast<char*>(kp+5);
#else
		const subnet_type* sv = v->AsSubNet();
		kp[0] = sv->net;
		kp[1] = sv->width;
		kp1 = reinterpret_cast<char*>(kp+2);
#endif
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
		if ( v->Type()->Tag() == TYPE_FUNC )
			{
			Val** kp = AlignAndPadType<Val*>(kp0);
			v->Ref();
			// Ref((BroObj*) v->AsFunc());
			*kp = v;
			kp1 = reinterpret_cast<char*>(kp+1);
			}

		else if ( v->Type()->Tag() == TYPE_RECORD )
			{
			char* kp = kp0;
			RecordVal* rv = v->AsRecordVal();
			RecordType* rt = v->Type()->AsRecordType();
			int num_fields = rt->NumFields();

			for ( int i = 0; i < num_fields; ++i )
				{
				Val* rv_i = rv->Lookup(i);
				if ( ! rv_i )
					return 0;

				if ( ! (kp = SingleValHash(type_check, kp,
							   rt->FieldType(i),
							   rv_i)) )
					return 0;
				}

			kp1 = kp;
			}
		else
			{
			internal_error("bad index type in CompositeHash::SingleValHash");
			return 0;
			}
		}
		break;

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
		int sz = ComputeKeySize(v, type_check);
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
		kp = SingleValHash(type_check, kp, (*tl)[i], (*vl)[i]);
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

	uint32 tmp_addr;
	switch ( singleton_tag ) {
	case TYPE_INTERNAL_INT:
	case TYPE_INTERNAL_UNSIGNED:
		return new HashKey(v->ForceAsInt());

	case TYPE_INTERNAL_ADDR:
#ifdef BROv6
		return new HashKey(v->AsAddr(), 4);
#else
		return new HashKey(v->AsAddr());
#endif

	case TYPE_INTERNAL_SUBNET:
#ifdef BROv6
		return new HashKey((const uint32*) v->AsSubNet(), 5);
#else
		return new HashKey((const uint32*) v->AsSubNet(), 2);

#endif

	case TYPE_INTERNAL_DOUBLE:
		return new HashKey(v->InternalDouble());

	case TYPE_INTERNAL_VOID:
	case TYPE_INTERNAL_OTHER:
		if ( v->Type()->Tag() == TYPE_FUNC )
			return new HashKey(v);

		internal_error("bad index type in CompositeHash::ComputeSingletonHash");
		return 0;

	case TYPE_INTERNAL_STRING:
		return new HashKey(v->AsString());

	case TYPE_INTERNAL_ERROR:
		return 0;

	default:
		internal_error("bad internal type in CompositeHash::ComputeSingletonHash");
		return 0;
	}
	}

int CompositeHash::SingleTypeKeySize(BroType* bt, const Val* v,
					int type_check, int sz) const
	{
	InternalTypeTag t = bt->InternalType();

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
#ifdef BROv6
		sz = SizeAlign(sz, sizeof(uint32));
		sz += sizeof(uint32) * 3;	// to make a total of 4 words
#else
		sz = SizeAlign(sz, sizeof(uint32));
#endif
		break;

	case TYPE_INTERNAL_SUBNET:
#ifdef BROv6
		sz = SizeAlign(sz, sizeof(uint32));
		sz += sizeof(uint32) * 4;	// to make a total of 5 words
#else
		sz = SizeAlign(sz, sizeof(uint32));
		sz += sizeof(uint32);	// make room for width
#endif
		break;

	case TYPE_INTERNAL_DOUBLE:
		sz = SizeAlign(sz, sizeof(double));
		break;

	case TYPE_INTERNAL_VOID:
	case TYPE_INTERNAL_OTHER:
		{
		if ( bt->Tag() == TYPE_FUNC )
			sz = SizeAlign(sz, sizeof(Val*));

		else if ( bt->Tag() == TYPE_RECORD )
			{
			const RecordVal* rv = v ? v->AsRecordVal() : 0;
			RecordType* rt = bt->AsRecordType();
			int num_fields = rt->NumFields();

			for ( int i = 0; i < num_fields; ++i )
				{
				sz = SingleTypeKeySize(rt->FieldType(i),
							rv ? rv->Lookup(i) : 0,
							type_check, sz);
				if ( ! sz )
					return 0;
				}
			}
		else
			{
			internal_error("bad index type in CompositeHash::CompositeHash");
			return 0;
			}
		}
		break;

	case TYPE_INTERNAL_STRING:
		if ( ! v )
			return 0;

		// Factor in length field.
		sz = SizeAlign(sz, sizeof(int));
		sz += v->AsString()->Len();
		break;

	case TYPE_INTERNAL_ERROR:
		return 0;
	}

	return sz;
	}

int CompositeHash::ComputeKeySize(const Val* v, int type_check) const
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
				       type_check, sz);
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

	loop_over_list(*tl, i)
		{
		Val* v;
		kp = RecoverOneVal(k, kp, k_end, (*tl)[i], v);
		ASSERT(v);
		l->Append(v);
		}

	if ( kp != k_end )
		internal_error("under-ran key in CompositeHash::DescribeKey");

	return l;
	}

const char* CompositeHash::RecoverOneVal(const HashKey* k, const char* kp0,
					 const char* const k_end, BroType* t,
					 Val*& pval) const
	{
	// k->Size() == 0 for a single empty string.
	if ( kp0 >= k_end && k->Size() > 0 )
		internal_error("over-ran key in CompositeHash::RecoverVals");

	TypeTag tag = t->Tag();
	InternalTypeTag it = t->InternalType();

	const char* kp1 = 0;

	switch ( it ) {
	case TYPE_INTERNAL_INT:
		{
		const bro_int_t* const kp = AlignType<bro_int_t>(kp0);
		kp1 = reinterpret_cast<const char*>(kp+1);

		if ( tag == TYPE_ENUM )
			pval = new EnumVal(*kp, t->AsEnumType());
		else
			pval = new Val(*kp, tag);
		}
		break;

	case TYPE_INTERNAL_UNSIGNED:
		{
		const bro_uint_t* const kp = AlignType<bro_uint_t>(kp0);
		kp1 = reinterpret_cast<const char*>(kp+1);

		switch ( tag ) {
		case TYPE_COUNT:
		case TYPE_COUNTER:
			pval = new Val(*kp, tag);
			break;

		case TYPE_PORT:
			pval = new PortVal(*kp);
			break;

		default:
			internal_error("bad internal unsigned int in CompositeHash::RecoverOneVal()");
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
		const uint32* const kp = AlignType<uint32>(kp0);
#ifdef BROv6
		const_addr_type addr_val = kp;
		kp1 = reinterpret_cast<const char*>(kp+4);
#else
		const_addr_type addr_val = *kp;
		kp1 = reinterpret_cast<const char*>(kp+1);
#endif
		switch ( tag ) {
		case TYPE_ADDR:
			pval = new AddrVal(addr_val);
			break;

		case TYPE_NET:
			pval = new NetVal(addr_val);
			break;

		default:
			internal_error("bad internal address in CompositeHash::RecoverOneVal()");
			pval = 0;
			break;
		}
		}
		break;

	case TYPE_INTERNAL_SUBNET:
		{
		const subnet_type* const kp =
			reinterpret_cast<const subnet_type*>(
				AlignType<uint32>(kp0));
		kp1 = reinterpret_cast<const char*>(kp+1);

		pval = new SubNetVal(kp->net, kp->width);
		}
		break;

	case TYPE_INTERNAL_VOID:
	case TYPE_INTERNAL_OTHER:
		{
		if ( t->Tag() == TYPE_FUNC )
			{
			Val* const * const kp = AlignType<Val*>(kp0);
			kp1 = reinterpret_cast<const char*>(kp+1);

			Val* v = *kp;

			if ( ! v || ! v->Type() )
				internal_error("bad aggregate Val in CompositeHash::RecoverOneVal()");

			if ( t->Tag() != TYPE_FUNC &&
			     // ### Maybe fix later, but may be fundamentally
			     // un-checkable --US
			     ! same_type(v->Type(), t) )
				{
				internal_error("inconsistent aggregate Val in CompositeHash::RecoverOneVal()");
				}

			// ### A crude approximation for now.
			if ( t->Tag() == TYPE_FUNC &&
			     v->Type()->Tag() != TYPE_FUNC )
				{
				internal_error("inconsistent aggregate Val in CompositeHash::RecoverOneVal()");
				}

			pval = v->Ref();
			}

		else if ( t->Tag() == TYPE_RECORD )
			{
			const char* kp = kp0;
			RecordType* rt = t->AsRecordType();
			int num_fields = rt->NumFields();

			vector<Val*> values;
			int i;
			for ( i = 0; i < num_fields; ++i )
				{
				Val* v;
				kp = RecoverOneVal(k, kp, k_end,
				                   rt->FieldType(i), v);
				if ( ! v )
					{
					internal_error("didn't recover expected number of fields from HashKey");
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
		else
			{
			internal_error("bad index type in CompositeHash::DescribeKey");
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
