// See the file  in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/file_analysis/Component.h"
#include "zeek/file_analysis/analyzer/x509/OCSP.h"
#include "zeek/file_analysis/analyzer/x509/X509.h"

namespace zeek::plugin::detail::Zeek_X509
	{

class Plugin : public zeek::plugin::Plugin
	{
public:
	zeek::plugin::Configuration Configure() override
		{
		AddComponent(new zeek::file_analysis::Component(
			"X509", zeek::file_analysis::detail::X509::Instantiate));
		AddComponent(new zeek::file_analysis::Component(
			"OCSP_REQUEST", zeek::file_analysis::detail::OCSP::InstantiateRequest));
		AddComponent(new zeek::file_analysis::Component(
			"OCSP_REPLY", zeek::file_analysis::detail::OCSP::InstantiateReply));

		zeek::plugin::Configuration config;
		config.name = "Zeek::X509";
		config.description = "X509 and OCSP analyzer";
		return config;
		}

	void Done() override
		{
		zeek::plugin::Plugin::Done();
		zeek::file_analysis::detail::X509::FreeRootStore();
		}
	} plugin;

	} // namespace zeek::plugin::detail::Zeek_X509
