#include "Plugin.h"

#include <zeek/Conn.h>
#include <zeek/Desc.h>
#include <zeek/Event.h>
#include <zeek/Func.h>
#include <zeek/RunState.h>
#include <zeek/threading/Formatter.h>
#include <cstring>
#include <set>

namespace btest::plugin::Demo_Hooks
	{
Plugin plugin;
	}

using namespace btest::plugin::Demo_Hooks;

// Sanitize arguments for the following functions with (...). These
// receiving the current version string or parts of it and make the
// baseline non-deterministic.
static std::set<std::string> sanitized_functions = {
	"Version::parse",
	"gsub",
	"split_string1",
	"lstrip",
	"to_count",
	"cat",
	"Telemetry::__dbl_gauge_metric_get_or_add",
	"Telemetry::gauge_with",
	"Telemetry::make_labels",
	"Telemetry::gauge_family_set",
};

// When a filename given to LOAD_FILE* hooks (and to the meta pre/post hooks)
// contains any of these keywords, no log message is generated.
static std::set<std::string> load_file_filter = {
	"Zeek_AF_Packet",
	"Zeek_JavaScript",
};

static bool skip_load_file_logging_for(const std::string& s)
	{
	for ( const auto& needle : load_file_filter )
		if ( s.find(needle) != std::string::npos )
			return true;

	return false;
	}

zeek::plugin::Configuration Plugin::Configure()
	{
	EnableHook(zeek::plugin::HOOK_LOAD_FILE);
	EnableHook(zeek::plugin::HOOK_LOAD_FILE_EXT);
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
	EnableHook(zeek::plugin::HOOK_UNPROCESSED_PACKET);
	EnableHook(zeek::plugin::HOOK_OBJ_DTOR);

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
	bool serialize_args = true;

	for ( zeek::plugin::HookArgumentList::const_iterator i = args.begin(); i != args.end(); i++ )
		{
		if ( first )
			{
			first = false;

			i->Describe(d);

			// For function calls we remove args for unstable arguments
			// from parsing the version in `base/misc/version`.
			if ( i->GetType() == zeek::plugin::HookArgument::FUNC &&
			     sanitized_functions.count(d->Description()) != 0 )
				serialize_args = false;

			continue;
			}

		d->Add(", ");

		if ( serialize_args )
			i->Describe(d);
		else
			d->Add("...");

		first = false;
		}
	}

int Plugin::HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved)
	{
	if ( skip_load_file_logging_for(resolved) )
		return -1;

	fprintf(stderr, "%.6f %-15s %s %s\n", zeek::run_state::network_time, "| HookLoadFile",
	        file.c_str(), resolved.c_str());
	return -1;
	}

std::pair<int, std::optional<std::string>> Plugin::HookLoadFileExtended(const LoadType type,
                                                                        const std::string& file,
                                                                        const std::string& resolved)
	{
	if ( skip_load_file_logging_for(resolved) )
		return std::make_pair(-1, std::nullopt);

	fprintf(stderr, "%.6f %-15s %s %s\n", zeek::run_state::network_time, "| HookLoadFileExtended",
	        file.c_str(), resolved.c_str());
	return std::make_pair(-1, std::nullopt);
	}

std::pair<bool, zeek::ValPtr> Plugin::HookFunctionCall(const zeek::Func* func,
                                                       zeek::detail::Frame* frame, zeek::Args* args)
	{
	zeek::ODesc d;
	d.SetShort();

	zeek::plugin::HookArgument(func).Describe(&d);

	// For function calls we remove args for unstable arguments
	// from parsing the version in `base/misc/version`.
	//
	if ( sanitized_functions.count(d.Description()) != 0 )
		d.Add("(...)");
	else
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

void Plugin::HookObjDtor(void* obj)
	{
	fprintf(stderr, "%.6f  %-15s\n", zeek::run_state::network_time, "| HookObjDtor");
	}

void Plugin::MetaHookPre(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args)
	{
	zeek::ODesc d;
	d.SetShort();
	describe_hook_args(args, &d);

	// Special case file loading filtering.
	if ( hook == zeek::plugin::HOOK_LOAD_FILE || hook == zeek::plugin::HOOK_LOAD_FILE_EXT )
		if ( skip_load_file_logging_for(std::string(d.Description())) )
			return;

	fprintf(stderr, "%.6f %-15s %s(%s)\n", zeek::run_state::network_time, "  MetaHookPre",
	        hook_name(hook), d.Description());
	}

void Plugin::MetaHookPost(zeek::plugin::HookType hook, const zeek::plugin::HookArgumentList& args,
                          zeek::plugin::HookArgument result)
	{
	zeek::ODesc d1;
	d1.SetShort();
	describe_hook_args(args, &d1);

	// Special case file loading filtering.
	if ( hook == zeek::plugin::HOOK_LOAD_FILE || hook == zeek::plugin::HOOK_LOAD_FILE_EXT )
		if ( skip_load_file_logging_for(std::string(d1.Description())) )
			return;

	zeek::ODesc d2;
	d2.SetShort();
	result.Describe(&d2);

	fprintf(stderr, "%.6f %-15s %s(%s) -> %s\n", zeek::run_state::network_time, "  MetaHookPost",
	        hook_name(hook), d1.Description(), d2.Description());
	}

void Plugin::HookSetupAnalyzerTree(zeek::Connection* conn)
	{
	zeek::ODesc d;
	d.SetShort();
	conn->Describe(&d);

	fprintf(stderr, "%.6f %-15s %s\n", zeek::run_state::network_time, "| HookSetupAnalyzerTree",
	        d.Description());
	}

void Plugin::HookLogInit(const std::string& writer, const std::string& instantiating_filter,
                         bool local, bool remote,
                         const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
                         const zeek::threading::Field* const* fields)
	{
	zeek::ODesc d;

	d.Add("{");
	for ( int i = 0; i < num_fields; i++ )
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

	fprintf(stderr, "%.6f %-15s %s %d/%d %s\n", zeek::run_state::network_time, "| HookLogInit",
	        info.path, local, remote, d.Description());
	}

void Plugin::RenderVal(const zeek::threading::Value* val, zeek::ODesc& d) const
	{
	if ( ! val->present )
		{
		d.Add("<uninitialized>");
		return;
		}

	switch ( val->type )
		{

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
                          const zeek::threading::Field* const* fields,
                          zeek::threading::Value** vals)
	{
	zeek::ODesc d;

	d.Add("[");
	for ( int i = 0; i < num_fields; i++ )
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

	fprintf(stderr, "%.6f %-15s %s %s\n", zeek::run_state::network_time, "| HookLogWrite",
	        info.path, d.Description());
	return true;
	}

void Plugin::HookUnprocessedPacket(const zeek::Packet* packet)
	{
	zeek::ODesc d;
	d.Add("[");
	d.Add("ts=");
	d.Add(packet->time);
	d.Add(" len=");
	d.Add(packet->len);
	d.Add("]");

	fprintf(stderr, "%.6f %-23s %s\n", zeek::run_state::network_time, "| HookUnprocessedPacket",
	        d.Description());
	}
