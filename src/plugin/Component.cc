// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"

#include "../Desc.h"
#include "../Reporter.h"

using namespace plugin;

Component::Component(component::Type arg_type)
	{
	type = arg_type;
	}

Component::~Component()
	{
	}

component::Type Component::Type() const
	{
	return type;
	}

void Component::Describe(ODesc* d) const
	{
	d->Add("    ");
	d->Add("[");

	switch ( type ) {
	case component::READER:
		d->Add("Reader");
		break;

	case component::WRITER:
		d->Add("Writer");
		break;

	case component::ANALYZER:
		d->Add("Analyzer");
		break;

	case component::FILE_ANALYZER:
		d->Add("File Analyzer");
		break;

	default:
		reporter->InternalWarning("unknown component type in plugin::Component::Describe");
		d->Add("<unknown component type>");
		break;
	}

	d->Add("]");
	d->Add(" ");
	}
