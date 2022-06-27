
#include "Foo.h"

using namespace btest::logging::writer;

Foo::~Foo()
	{
	delete formatter;
	}

bool Foo::DoInit(const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
                 const zeek::threading::Field* const* fields)
	{
	desc.EnableEscaping();
	desc.AddEscapeSequence("|");
	zeek::threading::formatter::Ascii::SeparatorInfo sep_info("|", ",", "-", "");
	formatter = new zeek::threading::formatter::Ascii(this, sep_info);
	path = info.path;

	return true;
	}

bool Foo::DoWrite(int num_fields, const zeek::threading::Field* const* fields,
                  zeek::threading::Value** vals)
	{
	desc.Clear();

	if ( ! formatter->Describe(&desc, num_fields, fields, vals) )
		return false;

	printf("[%s] %s\n", path.c_str(), desc.Description());

	return true;
	}
