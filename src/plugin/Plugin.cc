// See the file "COPYING" in the main distribution directory for copyright.

#include <cassert>

#include "Plugin.h"
#include "Manager.h"
#include "Component.h"

#include "../Desc.h"

using namespace plugin;

const char* hook_name(HookType h)
	{
	static const char* hook_names[int(NUM_HOOKS) + 1] = {
		// Order must match that of HookType.
		"LoadFile",
		"CallFunction",
		"QueueEvent",
		"DrainEvents",
		"UpdateNetworkTime",
		// End marker.
		"<end>",
	};

	return hook_names[int(h)];
	}

BifItem::BifItem(const std::string& arg_id, Type arg_type)
	{
	id = arg_id;
	type = arg_type;
	}

BifItem::BifItem(const BifItem& other)
	{
	id = other.id;
	type = other.type;
	}

BifItem& BifItem::operator=(const BifItem& other)
	{
	if ( this != &other )
		{
		id = other.id;
		type = other.type;
		}

	return *this;
	}

BifItem::~BifItem()
	{
	}

Plugin::Plugin()
	{
	name = "<NAME-NOT-SET>";
	description = "";

	// These will be reset by the BRO_PLUGIN_* macros.
	version = -9999;
	api_version = -9999;
	dynamic = false;
	base_dir = "";
	sopath = "";

	Manager::RegisterPlugin(this);
	}

Plugin::~Plugin()
	{
	Done();
	}

const std::string& Plugin::Name() const
	{
	return name;
	}

void Plugin::SetName(const std::string& arg_name)
	{
	name = arg_name;
	}

const std::string& Plugin::Description() const
	{
	return description;
	}

void Plugin::SetDescription(const std::string& arg_description)
	{
	description = arg_description;
	}

int Plugin::Version() const
	{
	return dynamic ? version : 0;
	}

void Plugin::SetVersion(int arg_version)
	{
	version = arg_version;
	}

int Plugin::APIVersion() const
	{
	return api_version;
	}

bool Plugin::DynamicPlugin() const
	{
	return dynamic;
	}

const std::string& Plugin::PluginDirectory() const
	{
	return base_dir;
	}

const std::string& Plugin::PluginPath() const
	{
	return sopath;
	}

void Plugin::SetAPIVersion(int arg_version)
	{
	api_version = arg_version;
	}

void Plugin::SetDynamicPlugin(bool arg_dynamic)
	{
	dynamic = arg_dynamic;
	}

void Plugin::SetPluginLocation(const std::string& arg_dir, const std::string& arg_sopath)
	{
	base_dir = arg_dir;
	sopath = arg_sopath;
	}

void Plugin::InitPreScript()
	{
	}

void Plugin::InitPostScript()
	{
	}

void Plugin::InitBifs()
	{
	for ( bif_init_func_list::const_iterator f = bif_inits.begin(); f != bif_inits.end(); f++ )
		(**f)(this);
	}

Plugin::bif_item_list Plugin::BifItems() const
	{
	bif_item_list l1 = bif_items;
	bif_item_list l2 = CustomBifItems();

	for ( bif_item_list::const_iterator i = l2.begin(); i != l2.end(); i++ )
		l1.push_back(*i);

	return l1;
	}

Plugin::bif_item_list Plugin::CustomBifItems() const
	{
	return bif_item_list();
	}

void Plugin::Done()
	{
	for ( component_list::const_iterator i = components.begin(); i != components.end(); i++ )
		delete *i;

	components.clear();
	}

Plugin::component_list Plugin::Components() const
	{
	return components;
	}

static bool component_cmp(const Component* a, const Component* b)
	{
	return a->Name() < b->Name();
	}

bool Plugin::LoadBroFile(const std::string& file)
	{
	::add_input_file(file.c_str());
	return true;
	}

void Plugin::__AddBifInitFunction(bif_init_func c)
	{
	bif_inits.push_back(c);
	}

void Plugin::AddBifItem(const std::string& name, BifItem::Type type)
	{
	BifItem bi(name, (BifItem::Type)type);
	bif_items.push_back(bi);
	}

void Plugin::AddComponent(Component* c)
	{
	components.push_back(c);

	// Sort components by name to make sure we have a deterministic
	// order.
	components.sort(component_cmp);
	}

Plugin::hook_list Plugin::EnabledHooks() const
	{
	return plugin_mgr->HooksEnabledForPlugin(this);
	}

void Plugin::EnableHook(HookType hook, int priority)
	{
	plugin_mgr->EnableHook(hook, this, priority);
	}

void Plugin::DisableHook(HookType hook)
	{
	plugin_mgr->DisableHook(hook, this);
	}

int Plugin::HookLoadFile(const std::string& file)
	{
	return -1;
	}

Val* Plugin::HookCallFunction(const Func* func, val_list* args)
	{
	return 0;
	}

bool Plugin::HookQueueEvent(Event* event)
	{
	return false;
	}

void Plugin::HookDrainEvents()
	{
	}

void Plugin::HookUpdateNetworkTime(double network_time)
	{
	}

void Plugin::Describe(ODesc* d) const
	{
	d->Add("Plugin: ");
	d->Add(name);

	if ( description.size() )
		{
		d->Add(" - ");
		d->Add(description);
		}

	if ( dynamic )
		{
		if ( version > 0 )
			{
			d->Add(" (dynamic, version ");
			d->Add(version);
			d->Add(")");
			}
		else
			d->Add(" (version not set)");
		}

	else
		d->Add(" (built-in)");

	d->Add("\n");

	if ( d->IsShort() )
		return;

	for ( component_list::const_iterator i = components.begin(); i != components.end(); i++ )
		{
		(*i)->Describe(d);
		d->Add("\n");
		}

	bif_item_list items = BifItems();

	for ( bif_item_list::const_iterator i = items.begin(); i != items.end(); i++ )
		{
		const char* type = 0;

		switch ( (*i).GetType() ) {
		case BifItem::FUNCTION:
			type = "Function";
			break;

		case BifItem::EVENT:
			type = "Event";
			break;

		case BifItem::CONSTANT:
			type = "Constant";
			break;

		case BifItem::GLOBAL:
			type = "Global";
			break;

		case BifItem::TYPE:
			type = "Type";
			break;

		default:
			type = "<unknown>";
		}

		d->Add("    ");
		d->Add("[");
		d->Add(type);
		d->Add("] ");
		d->Add((*i).GetID());
		d->Add("\n");
		}

	hook_list hooks = EnabledHooks();

	for ( hook_list::iterator i = hooks.begin(); i != hooks.end(); i++ )
		{
		HookType hook = (*i).first;
		int prio = (*i).second;

		d->Add("    Implements ");
		d->Add(hook_name(hook));
		d->Add(" (priority ");
		d->Add(prio);
		d->Add("]\n");
		}
	}

