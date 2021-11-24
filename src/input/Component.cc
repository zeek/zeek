// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/input/Component.h"

#include "zeek/Desc.h"
#include "zeek/input/Manager.h"
#include "zeek/util.h"

namespace zeek::input
	{

Component::Component(const std::string& name, factory_callback arg_factory)
	: plugin::Component(plugin::component::READER, name, 0, input_mgr->GetTagType())
	{
	factory = arg_factory;
	}

void Component::Initialize()
	{
	InitializeTag();
	input_mgr->RegisterComponent(this, "READER_");
	}

Component::~Component() { }

void Component::DoDescribe(ODesc* d) const
	{
	d->Add("Input::READER_");
	d->Add(CanonicalName());
	}

	} // namespace zeek::input
