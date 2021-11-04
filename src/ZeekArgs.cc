#include "zeek/ZeekArgs.h"

#include "zeek/Desc.h"
#include "zeek/ID.h"
#include "zeek/Type.h"
#include "zeek/Val.h"

namespace zeek
	{

Args val_list_to_args(const ValPList& vl)
	{
	Args rval;
	rval.reserve(vl.length());

	for ( auto& v : vl )
		rval.emplace_back(AdoptRef{}, v);

	return rval;
	}

VectorValPtr MakeCallArgumentVector(const Args& vals, const RecordTypePtr& types)
	{
	static auto call_argument_vector = id::find_type<VectorType>("call_argument_vector");

	auto rval = make_intrusive<VectorVal>(call_argument_vector);

	for ( int i = 0; i < types->NumFields(); i++ )
		{
		const char* fname = types->FieldName(i);
		const auto& ftype = types->GetFieldType(i);
		auto fdefault = types->FieldDefault(i);

		static auto call_argument = id::find_type<RecordType>("call_argument");
		auto rec = make_intrusive<RecordVal>(call_argument);
		rec->Assign(0, fname);

		ODesc d;
		d.SetShort();
		ftype->Describe(&d);
		rec->Assign(1, d.Description());

		if ( fdefault )
			rec->Assign(2, std::move(fdefault));

		if ( i < static_cast<int>(vals.size()) && vals[i] )
			rec->Assign(3, vals[i]);

		rval->Assign(i, std::move(rec));
		}

	return rval;
	}

	} // namespace zeek
