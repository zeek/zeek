
#include "Plugin.h"

#include <Func.h>
#include <Event.h>
#include <Conn.h>
#include <Desc.h>
#include <threading/Formatter.h>
#include <RunState.h>

namespace btest::plugin::Demo_Hooks { Plugin plugin; }

using namespace btest::plugin::Demo_Hooks;

zeek::plugin::Configuration Plugin::Configure()
	{
	EnableHook(zeek::plugin::HOOK_LOAD_FILE);
	EnableHook(zeek::plugin::HOOK_CALL_FUNCTION);
	EnableHook(zeek::plugin::HOOK_QUEUE_EVENT);
	EnableHook(zeek::plugin::HOOK_DRAIN_EVENTS);
	EnableHook(zeek::plugin::HOOK_UPDATE_NETWORK_TIME);
	EnableHook(zeek::plugin::META_HOOK_PRE);
	EnableHook(zeek::plugin::META_HOOK_POST);
	EnableHook(zeek::plugin::HOOK_BRO_OBJ_DTOR);
	EnableHook(zeek::plugin::HOOK_SETUP_ANALYZER_TREE);
	EnableHook(zeek::plugin::HOOK_LOG_INIT);
	EnableHook(zeek::plugin::HOOK_LOG_WRITE);

	zeek::plugin::Configuration config;
	config.name = "Demo::Hooks";
	config.description = "Exercises all plugin hooks";
	config.version.major = 1;
	config.version.minor = 0;
	config.version.patch = 0;
	return config;
	}

static void describe_hook_args(const zeek::plugin::HookArgumentList& args, zeek::ODesc* d)
	{
	bool first = true;

	for ( zeek::plugin::HookArgumentList::const_iterator i = args.begin(); i != args.end(); i++ )
		{
		if ( ! first )
			d->Add(", ");

		i->Describe(d);
		first = false;
		}
	}

int Plugin::HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved)
	{
	fprintf(stderr, "%.6f %-15s %s %s\n", zeek::run_state::network_time, "| HookLoadFile",
		file.c_str(), resolved.c_str());
	return -1;
	}

std::pair<bool, zeek::ValPtr> Plugin::HookFunctionCall(const zeek::Func* func, zeek::detail::Frame* frame,
                                                       zeek::Args* args)
	{
	zeek::ODesc d;
	d.SetShort();
	zeek::plugin::HookArgument(func).Describe(&d);
	zeek::plugin::HookArgument(args).Describe(&d);
	fprintf(stderr, "%.6f %-15s %s\n", zeek::run_state::network_time, "| HookCallFunction",
		d.Description());

	return {false, nullptr};
	}

bool Plugin::HookQueueEvent(zeek::Event* event)
	{
	zeek::ODesc d;
	d.SetShort();
	zeek::plugin::HookArgument(event).Describe(&d);
	fprintf(stderr, "%.6f %-15s %s\n", zeek::run_state::network_time, "| HookQueueEvent",
		d.Description());

	static int i = 0;

	if ( zeek::run_state::network_time && i == 0 )
		{
		fprintf(stderr, "%.6f %-15s %s\n", zeek::run_state::network_time, "| RequestObjDtor",
			d.Description());

		RequestBroObjDtor(event);
		i = 1;
		}

	return false;
	}

void Plugin::HookDrainEvents()
	{
	fprintf(stderr, "%.6f %-15s\n", zeek::run_state::network_time, "| HookDrainEvents");
	}

void Plugin::HookUpdateNetworkTime(double network_time)
	{
	fprintf(stderr, "%.6f  %-15s %.6f\n", zeek::run_state::network_time, "| HookUpdateNetworkTime",
		zeek::run_state::network_time);
	}

void Plugin::HookBroObjDtor(void* obj)
	{
	fprintf(stderr, "%.6f  %-15s\n", zeek::run_state::network_time, "| HookBroObjDtor");
	}

void Plugin::MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args)
	{
	zeek::ODesc d;
	d.SetShort();
	describe_hook_args(args, &d);
	fprintf(stderr, "%.6f %-15s %s(%s)\n", zeek::run_state::network_time, "  MetaHookPre",
		hook_name(hook), d.Description());
	}

void Plugin::MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args, zeek::plugin::HookArgument result)
	{
	zeek::ODesc d1;
	d1.SetShort();
	describe_hook_args(args, &d1);

	zeek::ODesc d2;
	d2.SetShort();
	result.Describe(&d2);

	fprintf(stderr, "%.6f %-15s %s(%s) -> %s\n", zeek::run_state::network_time, "  MetaHookPost",
		hook_name(hook), d1.Description(),
		d2.Description());
	}

void Plugin::HookSetupAnalyzerTree(zeek::Connection* conn)
	{
	zeek::ODesc d;
	d.SetShort();
	conn->Describe(&d);

	fprintf(stderr, "%.6f %-15s %s\n", zeek::run_state::network_time, "| HookSetupAnalyzerTree", d.Description());
	}

void Plugin::HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local, bool remote,
                         const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
                         const zeek::threading::Field* const* fields)
	{
	zeek::ODesc d;

	d.Add("{");
	for ( int i=0; i < num_fields; i++ )
		{
		const zeek::threading::Field* f = fields[i];

		if ( i > 0 )
			d.Add(", ");

		d.Add(f->name);
		d.Add(" (");
		d.Add(f->TypeName());
		d.Add(")");
		}
	d.Add("}");

	fprintf(stderr, "%.6f %-15s %s %d/%d %s\n", zeek::run_state::network_time, "| HookLogInit", info.path, local, remote, d.Description());
	}

void Plugin::RenderVal(const zeek::threading::Value* val, zeek::ODesc &d) const
	{
		if ( ! val->present )
			{
			d.Add("<uninitialized>");
			return;
			}

		switch ( val->type ) {

			case zeek::TYPE_BOOL:
				d.Add(val->val.int_val ? "T" : "F");
				break;

			case zeek::TYPE_INT:
				d.Add(val->val.int_val);
				break;

			case zeek::TYPE_COUNT:
				d.Add(val->val.uint_val);
				break;

			case zeek::TYPE_PORT:
				d.Add(val->val.port_val.port);
				break;

			case zeek::TYPE_SUBNET:
				d.Add(zeek::threading::Formatter::Render(val->val.subnet_val));
				break;

			case zeek::TYPE_ADDR:
				d.Add(zeek::threading::Formatter::Render(val->val.addr_val));
				break;

			case zeek::TYPE_DOUBLE:
				d.Add(val->val.double_val, true);
				break;

			case zeek::TYPE_INTERVAL:
			case zeek::TYPE_TIME:
				d.Add(zeek::threading::Formatter::Render(val->val.double_val));
				break;

			case zeek::TYPE_ENUM:
			case zeek::TYPE_STRING:
			case zeek::TYPE_FILE:
			case zeek::TYPE_FUNC:
				d.AddN(val->val.string_val.data, val->val.string_val.length);
				break;

			case zeek::TYPE_TABLE:
				for ( int j = 0; j < val->val.set_val.size; j++ )
					{
					if ( j > 0 )
						d.Add(",");

					RenderVal(val->val.set_val.vals[j], d);
					}
				break;

			case zeek::TYPE_VECTOR:
				for ( int j = 0; j < val->val.vector_val.size; j++ )
					{
					if ( j > 0 )
						d.Add(",");

					RenderVal(val->val.vector_val.vals[j], d);
					}
				break;

			default:
				assert(false);
		}
	}

bool Plugin::HookLogWrite(const std::string& writer, const std::string& filter,
                          const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
                          const zeek::threading::Field* const* fields, zeek::threading::Value** vals)
	{
	zeek::ODesc d;

	d.Add("[");
	for ( int i=0; i < num_fields; i++ )
		{
		const zeek::threading::Field* f = fields[i];
		const zeek::threading::Value* val = vals[i];

		if ( i > 0 )
			d.Add(", ");

		d.Add(f->name);
		d.Add("=");

		RenderVal(val, d);
		}
	d.Add("]");

	fprintf(stderr, "%.6f %-15s %s %s\n", zeek::run_state::network_time, "| HookLogWrite", info.path, d.Description());
	return true;
	}
