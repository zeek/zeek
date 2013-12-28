// See the file "COPYING" in the main distribution directory for copyright.

#include <cassert>

#include "Plugin.h"
#include "Manager.h"
#include "Component.h"

#include "../Desc.h"

using namespace plugin;

BifItem::BifItem(const char* arg_id, Type arg_type)
	{
	id = copy_string(arg_id);
	type = arg_type;
	}

BifItem::BifItem(const BifItem& other)
	{
	id = copy_string(other.id);
	type = other.type;
	}

BifItem& BifItem::operator=(const BifItem& other)
	{
	if ( this != &other )
		{
		id = copy_string(other.id);
		type = other.type;
		}

	return *this;
	}

BifItem::~BifItem()
	{
	delete [] id;
	}

Plugin::Plugin()
	{
	name = copy_string("<NAME-NOT-SET>");
	description = copy_string("");

	// These will be reset by the BRO_PLUGIN_* macros.
	version = -9999;
	api_version = -9999;
	dynamic = false;
	base_dir = 0;
	sopath = 0;
	extensions = 0;

	Manager::RegisterPlugin(this);
	}

Plugin::~Plugin()
	{
	Done();

	delete [] name;
	delete [] description;
	delete [] base_dir;
	delete [] sopath;
	delete [] extensions;
	}

Plugin::Type Plugin::PluginType() const
	{
	return STANDARD;
	}

const char* Plugin::Name() const
	{
	return name;
	}

void Plugin::SetName(const char* arg_name)
	{
	delete [] name;
	name = copy_string(arg_name);
	}

const char* Plugin::Description() const
	{
	return description;
	}

void Plugin::SetDescription(const char* arg_description)
	{
	delete [] description;
	description = copy_string(arg_description);
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

const char* Plugin::PluginDirectory() const
	{
	return base_dir;
	}

const char* Plugin::PluginPath() const
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

void Plugin::SetPluginLocation(const char* arg_dir, const char* arg_sopath)
	{
	delete [] base_dir;
	delete [] sopath;
	base_dir = copy_string(arg_dir);
	sopath = copy_string(arg_sopath);
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

const char* Plugin::FileExtensions() const
	{
	return extensions ? extensions : "";
	}

void Plugin::SetFileExtensions(const char* ext)
	{
	extensions = copy_string(ext);
	}

bool Plugin::LoadFile(const char* file)
	{
	reporter->InternalError("Plugin::LoadFile not overriden for %s", file);
	return false;
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

void Plugin::AddComponent(Component* c)
	{
	components.push_back(c);

	// Sort components by name to make sure we have a deterministic
	// order.
	components.sort(component_cmp);
	}

bool Plugin::LoadBroFile(const char* file)
	{
	add_input_file(file);
	return true;
	}

void Plugin::__AddBifInitFunction(bif_init_func c)
	{
	bif_inits.push_back(c);
	}

void Plugin::AddBifItem(const char* name, BifItem::Type type)
	{
	BifItem bi(name, (BifItem::Type)type);
	bif_items.push_back(bi);
	}

void Plugin::Describe(ODesc* d) const
	{
	d->Add("Plugin: ");
	d->Add(name);

	if ( description && *description )
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

	switch ( PluginType() ) {
	case STANDARD:
		break;

	case INTERPRETER:
		d->Add( " (interpreter plugin)");
		break;

	default:
		reporter->InternalError("unknown plugin type in Plugin::Describe");
	}

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
	}

InterpreterPlugin::InterpreterPlugin(int arg_priority)
	{
	priority = arg_priority;
	}

InterpreterPlugin::~InterpreterPlugin()
	{
	}

int InterpreterPlugin::Priority() const
	{
	return priority;
	}

Plugin::Type InterpreterPlugin::PluginType() const
	{
	return INTERPRETER;
	}

Val* InterpreterPlugin::CallFunction(const Func* func, val_list* args)
	{
	return 0;
	}

bool InterpreterPlugin::QueueEvent(Event* event)
	{
	return false;
	}

void InterpreterPlugin::UpdateNetworkTime(double network_time)
	{
	}

void InterpreterPlugin::DrainEvents()
	{
	}

void InterpreterPlugin::NewConnection(const Connection* c)
	{
	}

void InterpreterPlugin::ConnectionStateRemove(const Connection* c)
	{
	}

void InterpreterPlugin::DisableInterpreterPlugin() const
	{
	plugin_mgr->DisableInterpreterPlugin(this);
	}


