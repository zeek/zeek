#include "ZeekArgs.h"
#include "Val.h"
#include "Type.h"
#include "ID.h"
#include "Desc.h"

zeek::Args zeek::val_list_to_args(const val_list& vl)
	{
	zeek::Args rval;
	rval.reserve(vl.length());

	for ( auto& v : vl )
		rval.emplace_back(zeek::AdoptRef{}, v);

	return rval;
	}

zeek::VectorValPtr zeek::MakeCallArgumentVector(const Args& vals,
                                                const RecordTypePtr& types)
    {
	static auto call_argument_vector = zeek::id::find_type<zeek::VectorType>("call_argument_vector");

	auto rval = make_intrusive<VectorVal>(call_argument_vector);

	for ( int i = 0; i < types->NumFields(); i++ )
		{
		const char* fname = types->FieldName(i);
		const auto& ftype = types->GetFieldType(i);
		auto fdefault = types->FieldDefault(i);

		static auto call_argument = zeek::id::find_type<zeek::RecordType>("call_argument");
		auto rec = make_intrusive<RecordVal>(call_argument);
		rec->Assign(0, make_intrusive<StringVal>(fname));

		ODesc d;
		d.SetShort();
		ftype->Describe(&d);
		rec->Assign(1, make_intrusive<StringVal>(d.Description()));

		if ( fdefault )
			rec->Assign(2, std::move(fdefault));

		if ( i < static_cast<int>(vals.size()) && vals[i] )
			rec->Assign(3, vals[i]);

		rval->Assign(i, std::move(rec));
		}

	return rval;
    }
