
#pragma once

#include <plugin/Plugin.h>

namespace btest::plugin::Log_Hooks {

class Plugin : public zeek::plugin::Plugin {
protected:
    void HookLogInit(const std::string& writer, const std::string& instantiating_filter, bool local, bool remote,
                     const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
                     const zeek::threading::Field* const* fields) override;
    bool HookLogWrite(const std::string& writer, const std::string& filter,
                      const zeek::logging::WriterBackend::WriterInfo& info, int num_fields,
                      const zeek::threading::Field* const* fields, zeek::threading::Value** vals) override;

    // Overridden from plugin::Plugin.
    zeek::plugin::Configuration Configure() override;

    // Overridden from plugin::Plugin.
    void Done() override;

private:
    int round;
    const zeek::logging::WriterBackend::WriterInfo* info_addr_init = nullptr;
    const zeek::logging::WriterBackend::WriterInfo* info_addr_write = nullptr;
};

extern Plugin plugin;

} // namespace btest::plugin::Log_Hooks
