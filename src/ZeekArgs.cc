#include "ZeekArgs.h"
#include "IntrusivePtr.h"
#include "Val.h"

zeek::Args zeek::val_list_to_args(const val_list& vl)
	{
	zeek::Args rval;
	rval.reserve(vl.length());

	for ( auto& v : vl )
		rval.emplace_back(AdoptRef{}, v);

	return rval;
	}

