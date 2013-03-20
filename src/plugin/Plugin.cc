
#include <cassert>

#include "Plugin.h"
#include "Component.h"

#include "../Desc.h"

using namespace plugin;

Description::Description()
	{
	name = "<NAME-NOT-SET>";
	api_version = API_VERSION;
	}

Plugin::Plugin()
	{
	}

Description Plugin::GetDescription() const
	{
	return description;
	}

void Plugin::SetDescription(Description& desc)
	{
	description = desc;
	}

Plugin::~Plugin()
	{
	Done();
	}

void Plugin::Init()
	{
	}

void Plugin::Done()
	{
	for ( component_list::const_iterator i = components.begin(); i != components.end(); i++ )
		delete *i;

	components.clear();
	}

Plugin::component_list Plugin::Components()
	{
	return components;
	}

void Plugin::AddComponent(Component* c)
	{
	components.push_back(c);
	}

void Plugin::Describe(ODesc* d)
	{
	d->Add("Plugin: ");
	d->Add(description.name);

	if ( description.description.size() )
		{
		d->Add(" - ");
		d->Add(description.description);
		}

	if ( description.version != API_BUILTIN )
		{
		d->Add(" (version ");
		d->Add(description.version);

		if ( description.url.size() )
			{
			d->Add(", from ");
			d->Add(description.url);
			}

		d->Add(")");
		}

	else
		d->Add(" (built-in)");

	d->NL();

	for ( component_list::const_iterator i = components.begin(); i != components.end(); i++ )
		{
		(*i)->Describe(d);
		d->NL();
		}
	}

