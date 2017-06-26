
#ifndef BRO_PLUGIN_Log_Hooks
#define BRO_PLUGIN_Log_Hooks

#include <plugin/Plugin.h>

namespace plugin {
namespace Log_Hooks {

class Plugin : public ::plugin::Plugin
{
protected:
	void HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local, bool remote, const logging::WriterBackend::WriterInfo& info, int num_fields, const threading::Field* const* fields) override;
	bool HookLogWrite(const std::string& writer, const std::string& filter, const logging::WriterBackend::WriterInfo& info, int num_fields, const threading::Field* const* fields, threading::Value** vals) override;

	// Overridden from plugin::Plugin.
	plugin::Configuration Configure() override;

private:
	int round;
};

extern Plugin plugin;

}
}

#endif
