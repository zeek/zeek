// See the file "COPYING" in the main distribution directory for copyright.

#include "Component.h"
#include "Manager.h"

#include "../Desc.h"
#include "../util.h"

namespace zeek::input {

Component::Component(const std::string& name, factory_callback arg_factory)
	: zeek::plugin::Component(zeek::plugin::component::READER, name)
	{
	factory = arg_factory;
	}

void Component::Initialize()
	{
	InitializeTag();
	input_mgr->RegisterComponent(this, "READER_");
	}

Component::~Component()
	{
	}

void Component::DoDescribe(zeek::ODesc* d) const
	{
	d->Add("Input::READER_");
	d->Add(CanonicalName());
	}

} // namespace zeek::input
