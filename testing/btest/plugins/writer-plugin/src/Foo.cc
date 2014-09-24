
#include "Foo.h"

using namespace logging;
using namespace writer;

bool Foo::DoInit(const WriterInfo& info, int num_fields,
	    const threading::Field* const * fields)
	{
	desc.EnableEscaping();
	desc.AddEscapeSequence("|");
    threading::formatter::Ascii::SeparatorInfo sep_info("|", ",", "-", "");
    formatter = new threading::formatter::Ascii(this, sep_info);
    path = info.path;

	return true;
	}

bool Foo::DoWrite(int num_fields, const threading::Field* const* fields,
                   threading::Value** vals)
	{
	desc.Clear();

	if ( ! formatter->Describe(&desc, num_fields, fields, vals) )
		return false;

    printf("[%s] %s\n", path.c_str(), desc.Description());

    return true;
	}

