// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#ifndef ENABLE_SPICY_SSL
#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/ssl/DTLS.h"
#include "zeek/analyzer/protocol/ssl/SSL.h"
#endif

namespace zeek::plugin::detail::Zeek_SSL {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
#ifndef ENABLE_SPICY_SSL
        AddComponent(new zeek::analyzer::Component("SSL", zeek::analyzer::ssl::SSL_Analyzer::Instantiate));
        AddComponent(new zeek::analyzer::Component("DTLS", zeek::analyzer::dtls::DTLS_Analyzer::Instantiate));
#endif

        zeek::plugin::Configuration config;
        config.name = "Zeek::SSL";
        config.description = "SSL/TLS and DTLS analyzers";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_SSL
