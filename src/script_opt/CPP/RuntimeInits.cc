// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/RuntimeInits.h"

#include "zeek/Desc.h"
#include "zeek/File.h"
#include "zeek/RE.h"
#include "zeek/ZeekString.h"
#include "zeek/script_opt/CPP/RuntimeInitSupport.h"

using namespace std;

namespace zeek::detail
	{

template <class T>
void CPP_IndexedInits<T>::InitializeCohortWithOffsets(InitsManager* im, int cohort,
                                                      const std::vector<int>& cohort_offsets)
	{
	auto& co = this->inits[cohort];
	for ( auto i = 0U; i < co.size(); ++i )
		Generate(im, this->inits_vec, cohort_offsets[i], co[i]);
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<EnumValPtr>& ivec, int offset,
                                   ValElemVec& init_vals)
	{
	auto& e_type = im->Types(init_vals[0]);
	int val = init_vals[1];
	ivec[offset] = zeek::detail::make_enum__CPP(e_type, val);
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<StringValPtr>& ivec, int offset,
                                   ValElemVec& init_vals)
	{
	auto chars = im->Strings(init_vals[0]);
	int len = init_vals[1];
	ivec[offset] = make_intrusive<StringVal>(len, chars);
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<PatternValPtr>& ivec, int offset,
                                   ValElemVec& init_vals)
	{
	auto re = new RE_Matcher(im->Strings(init_vals[0]));
	if ( init_vals[1] )
		re->MakeCaseInsensitive();
	if ( init_vals[2] )
		re->MakeSingleLine();

	re->Compile();

	ivec[offset] = make_intrusive<PatternVal>(re);
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<ListValPtr>& ivec, int offset,
                                   ValElemVec& init_vals) const
	{
	auto l = make_intrusive<ListVal>(TYPE_ANY);

	for ( auto& iv : init_vals )
		l->Append(im->ConstVals(iv));

	ivec[offset] = l;
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<VectorValPtr>& ivec, int offset,
                                   ValElemVec& init_vals) const
	{
	auto iv_it = init_vals.begin();
	auto iv_end = init_vals.end();
	auto t = *(iv_it++);

	auto vt = cast_intrusive<VectorType>(im->Types(t));
	auto vv = make_intrusive<VectorVal>(vt);

	while ( iv_it != iv_end )
		vv->Append(im->ConstVals(*(iv_it++)));

	ivec[offset] = vv;
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<RecordValPtr>& ivec, int offset,
                                   ValElemVec& init_vals) const
	{
	auto iv_it = init_vals.begin();
	auto iv_end = init_vals.end();
	auto t = *(iv_it++);

	auto rt = cast_intrusive<RecordType>(im->Types(t));
	auto rv = make_intrusive<RecordVal>(rt);

	auto field = 0;
	while ( iv_it != iv_end )
		{
		auto v = *(iv_it++);
		if ( v >= 0 )
			rv->Assign(field, im->ConstVals(v));
		++field;
		}

	ivec[offset] = rv;
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<TableValPtr>& ivec, int offset,
                                   ValElemVec& init_vals) const
	{
	auto iv_it = init_vals.begin();
	auto iv_end = init_vals.end();
	auto t = *(iv_it++);
	auto attrs = *(iv_it++);

	auto tt = cast_intrusive<TableType>(im->Types(t));
	auto tv = make_intrusive<TableVal>(tt);

	if ( attrs >= 0 )
		tv->SetAttrs(im->Attributes(attrs));

	while ( iv_it != iv_end )
		{
		auto index = im->ConstVals(*(iv_it++));
		auto v = *(iv_it++);
		auto value = v >= 0 ? im->ConstVals(v) : nullptr;
		tv->Assign(index, value);
		}

	ivec[offset] = tv;
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<FileValPtr>& ivec, int offset,
                                   ValElemVec& init_vals) const
	{
	// Note, in the following we use element 1, not 0, because we
	// don't need the "type" value in element 0.
	auto fn = im->Strings(init_vals[1]);
	auto fv = make_intrusive<FileVal>(make_intrusive<File>(fn, "w"));

	ivec[offset] = fv;
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<FuncValPtr>& ivec, int offset,
                                   ValElemVec& init_vals) const
	{
	auto iv_it = init_vals.begin();
	auto iv_end = init_vals.end();
	auto t = *(iv_it++);
	auto fn = im->Strings(*(iv_it++));
	auto num_bodies = *(iv_it++);

	std::vector<p_hash_type> hashes;

	while ( iv_it != iv_end )
		hashes.push_back(im->Hashes(*(iv_it++)));

	ivec[offset] = lookup_func__CPP(fn, num_bodies, hashes, im->Types(t));
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<AttrPtr>& ivec, int offset,
                                   ValElemVec& init_vals) const
	{
	auto tag = static_cast<AttrTag>(init_vals[0]);
	auto ae_tag = static_cast<AttrExprType>(init_vals[1]);

	if ( ae_tag == AE_NONE )
		{
		ivec[offset] = make_intrusive<Attr>(tag);
		return;
		}

	ExprPtr e;
	auto e_arg = init_vals[2];

	switch ( ae_tag )
		{
		case AE_NONE:
			// Shouldn't happen, per test above.
			ASSERT(0);
			break;

		case AE_CONST:
			e = make_intrusive<ConstExpr>(im->ConstVals(e_arg));
			break;

		case AE_NAME:
			{
			auto name = im->Strings(e_arg);
			auto gl = lookup_ID(name, GLOBAL_MODULE_NAME, false, false, false);
			ASSERT(gl);
			e = make_intrusive<NameExpr>(gl);
			break;
			}

		case AE_RECORD:
			{
			auto t = im->Types(e_arg);
			auto rt = cast_intrusive<RecordType>(t);
			auto empty_vals = make_intrusive<ListExpr>();
			auto construct = make_intrusive<RecordConstructorExpr>(empty_vals);
			e = make_intrusive<RecordCoerceExpr>(construct, rt);
			break;
			}

		case AE_CALL:
			e = im->CallExprs(e_arg);
			break;
		}

	ivec[offset] = make_intrusive<Attr>(tag, e);
	}

template <class T>
void CPP_IndexedInits<T>::Generate(InitsManager* im, std::vector<AttributesPtr>& ivec, int offset,
                                   ValElemVec& init_vals) const
	{
	std::vector<AttrPtr> a_list;

	for ( auto& iv : init_vals )
		a_list.emplace_back(im->Attrs(iv));

	ivec[offset] = make_intrusive<Attributes>(a_list, nullptr, false, false);
	}

// Instantiate the templates we'll need.

template class CPP_IndexedInits<EnumValPtr>;
template class CPP_IndexedInits<StringValPtr>;
template class CPP_IndexedInits<PatternValPtr>;
template class CPP_IndexedInits<ListValPtr>;
template class CPP_IndexedInits<VectorValPtr>;
template class CPP_IndexedInits<RecordValPtr>;
template class CPP_IndexedInits<TableValPtr>;
template class CPP_IndexedInits<FileValPtr>;
template class CPP_IndexedInits<FuncValPtr>;
template class CPP_IndexedInits<AttrPtr>;
template class CPP_IndexedInits<AttributesPtr>;
template class CPP_IndexedInits<TypePtr>;

void CPP_TypeInits::DoPreInits(InitsManager* im, const std::vector<int>& offsets_vec)
	{
	for ( auto cohort = 0U; cohort < offsets_vec.size(); ++cohort )
		{
		auto& co = inits[cohort];
		auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
		for ( auto i = 0U; i < co.size(); ++i )
			PreInit(im, cohort_offsets[i], co[i]);
		}
	}

void CPP_TypeInits::PreInit(InitsManager* im, int offset, ValElemVec& init_vals)
	{
	auto tag = static_cast<TypeTag>(init_vals[0]);

	if ( tag == TYPE_LIST )
		inits_vec[offset] = make_intrusive<TypeList>();

	else if ( tag == TYPE_RECORD )
		{
		auto name = im->Strings(init_vals[1]);
		if ( name[0] )
			inits_vec[offset] = get_record_type__CPP(name);
		else
			inits_vec[offset] = get_record_type__CPP(nullptr);
		}

	else if ( tag == TYPE_TABLE )
		inits_vec[offset] = make_intrusive<CPPTableType>();

	// else no pre-initialization needed
	}

void CPP_TypeInits::Generate(InitsManager* im, vector<TypePtr>& ivec, int offset,
                             ValElemVec& init_vals) const
	{
	auto tag = static_cast<TypeTag>(init_vals[0]);
	TypePtr t;
	switch ( tag )
		{
		case TYPE_ADDR:
		case TYPE_ANY:
		case TYPE_BOOL:
		case TYPE_COUNT:
		case TYPE_DOUBLE:
		case TYPE_ERROR:
		case TYPE_INT:
		case TYPE_INTERVAL:
		case TYPE_PATTERN:
		case TYPE_PORT:
		case TYPE_STRING:
		case TYPE_TIME:
		case TYPE_VOID:
		case TYPE_SUBNET:
		case TYPE_FILE:
			t = base_type(tag);
			break;

		case TYPE_ENUM:
			t = BuildEnumType(im, init_vals);
			break;

		case TYPE_OPAQUE:
			t = BuildOpaqueType(im, init_vals);
			break;

		case TYPE_TYPE:
			t = BuildTypeType(im, init_vals);
			break;

		case TYPE_VECTOR:
			t = BuildVectorType(im, init_vals);
			break;

		case TYPE_LIST:
			t = BuildTypeList(im, init_vals, offset);
			break;

		case TYPE_TABLE:
			t = BuildTableType(im, init_vals, offset);
			break;

		case TYPE_FUNC:
			t = BuildFuncType(im, init_vals);
			break;

		case TYPE_RECORD:
			t = BuildRecordType(im, init_vals, offset);
			break;

		default:
			ASSERT(0);
		}

	ivec[offset] = t;
	}

TypePtr CPP_TypeInits::BuildEnumType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto iv_it = init_vals.begin();
	auto iv_end = init_vals.end();
	auto name = im->Strings(*++iv_it); // skip element [0]
	auto et = get_enum_type__CPP(name);

	if ( et->Names().empty() )
		{
		++iv_it;
		while ( iv_it != iv_end )
			{
			auto e_name = im->Strings(*(iv_it++));
			auto e_val = *(iv_it++);
			et->AddNameInternal(e_name, e_val);
			}
		}

	return et;
	}

TypePtr CPP_TypeInits::BuildOpaqueType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto name = im->Strings(init_vals[1]);
	return make_intrusive<OpaqueType>(name);
	}

TypePtr CPP_TypeInits::BuildTypeType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto& t = im->Types(init_vals[1]);
	return make_intrusive<TypeType>(t);
	}

TypePtr CPP_TypeInits::BuildVectorType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto& t = im->Types(init_vals[1]);
	return make_intrusive<VectorType>(t);
	}

TypePtr CPP_TypeInits::BuildTypeList(InitsManager* im, ValElemVec& init_vals, int offset) const
	{
	const auto& tl = cast_intrusive<TypeList>(inits_vec[offset]);

	auto iv_it = init_vals.begin();
	auto iv_end = init_vals.end();

	++iv_it;

	while ( iv_it != iv_end )
		tl->Append(im->Types(*(iv_it++)));

	tl->CheckPure();

	return tl;
	}

TypePtr CPP_TypeInits::BuildTableType(InitsManager* im, ValElemVec& init_vals, int offset) const
	{
	auto t = cast_intrusive<CPPTableType>(inits_vec[offset]);
	ASSERT(t);

	auto index = cast_intrusive<TypeList>(im->Types(init_vals[1]));
	auto yield_i = init_vals[2];
	auto yield = yield_i >= 0 ? im->Types(yield_i) : nullptr;

	t->SetIndexAndYield(index, yield);

	return t;
	}

TypePtr CPP_TypeInits::BuildFuncType(InitsManager* im, ValElemVec& init_vals) const
	{
	auto p = cast_intrusive<RecordType>(im->Types(init_vals[1]));
	auto yield_i = init_vals[2];
	auto flavor = static_cast<FunctionFlavor>(init_vals[3]);

	TypePtr y;

	if ( yield_i >= 0 )
		y = im->Types(yield_i);

	else if ( flavor == FUNC_FLAVOR_FUNCTION || flavor == FUNC_FLAVOR_HOOK )
		y = base_type(TYPE_VOID);

	return make_intrusive<FuncType>(p, y, flavor);
	}

TypePtr CPP_TypeInits::BuildRecordType(InitsManager* im, ValElemVec& init_vals, int offset) const
	{
	auto r = cast_intrusive<RecordType>(inits_vec[offset]);
	ASSERT(r);

	if ( r->NumFields() == 0 )
		{
		type_decl_list tl;

		auto n = init_vals.size();
		auto i = 2U;

		while ( i < n )
			{
			auto s = im->Strings(init_vals[i++]);
			auto id = util::copy_string(s);
			auto type = im->Types(init_vals[i++]);
			auto attrs_i = init_vals[i++];

			AttributesPtr attrs;
			if ( attrs_i >= 0 )
				attrs = im->Attributes(attrs_i);

			tl.append(new TypeDecl(id, type, attrs));
			}

		r->AddFieldsDirectly(tl);
		}

	return r;
	}

int CPP_FieldMapping::ComputeOffset(InitsManager* im) const
	{
	auto r = im->Types(rec)->AsRecordType();
	auto fm_offset = r->FieldOffset(field_name.c_str());

	if ( fm_offset < 0 )
		{ // field does not exist, create it
		fm_offset = r->NumFields();

		auto id = util::copy_string(field_name.c_str());
		auto type = im->Types(field_type);

		AttributesPtr attrs;
		if ( field_attrs >= 0 )
			attrs = im->Attributes(field_attrs);

		type_decl_list tl;
		tl.append(new TypeDecl(id, type, attrs));

		r->AddFieldsDirectly(tl);
		}

	return fm_offset;
	}

int CPP_EnumMapping::ComputeOffset(InitsManager* im) const
	{
	auto e = im->Types(e_type)->AsEnumType();

	auto em_offset = e->Lookup(e_name);
	if ( em_offset < 0 )
		{ // enum constant does not exist, create it
		em_offset = e->Names().size();
		if ( e->Lookup(em_offset) )
			reporter->InternalError("enum inconsistency while initializing compiled scripts");
		e->AddNameInternal(e_name, em_offset);
		}

	return em_offset;
	}

void CPP_GlobalInit::Generate(InitsManager* im, std::vector<void*>& /* inits_vec */,
                              int /* offset */) const
	{
	auto& t = im->Types(type);
	global = lookup_global__CPP(name, t, exported);

	if ( ! global->HasVal() )
		{
		if ( val >= 0 )
			// Have explicit initialization value.
			global->SetVal(im->ConstVals(val));

		else if ( t->Tag() == TYPE_FUNC && ! func_with_no_val )
			{
			// Create a matching value so that this global can
			// be used in other initializations.  The code here
			// mirrors that in activate_bodies__CPP().
			auto fn = global->Name();
			auto ft = cast_intrusive<FuncType>(t);

			vector<StmtPtr> no_bodies;
			vector<int> no_priorities;

			auto sf = make_intrusive<ScriptFunc>(fn, ft, no_bodies, no_priorities);

			auto v = make_intrusive<FuncVal>(std::move(sf));
			global->SetVal(v);
			}
		}

	if ( attrs >= 0 )
		global->SetAttrs(im->Attributes(attrs));
	}

void generate_indices_set(int* inits, std::vector<std::vector<int>>& indices_set)
	{
	// First figure out how many groups of indices there are, so we
	// can pre-allocate the outer vector.
	auto i_ptr = inits;
	int num_inits = 0;
	while ( *i_ptr >= 0 )
		{
		++num_inits;
		int n = *i_ptr;
		i_ptr += n + 1; // skip over vector elements
		}

	indices_set.reserve(num_inits);

	i_ptr = inits;
	while ( *i_ptr >= 0 )
		{
		int n = *i_ptr;
		++i_ptr;
		std::vector<int> indices;
		indices.reserve(n);
		for ( int i = 0; i < n; ++i )
			indices.push_back(i_ptr[i]);
		i_ptr += n;

		indices_set.emplace_back(std::move(indices));
		}
	}

	} // zeek::detail
