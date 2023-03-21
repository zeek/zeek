
#pragma once
#include <zeek/Flare.h>
#include <zeek/plugin/Plugin.h>
#include <string>
#include <string_view>

#include "zeek/iosource/Manager.h"

namespace btest::plugin::Demo_Iosource
	{

class TimeoutSource : public zeek::iosource::IOSource
	{
public:
	TimeoutSource(std::string_view ident) : ident(ident)
		{
		zeek::iosource_mgr->Register(this, true /* don't count */);
		};

	void Process() override
		{
		std::fprintf(stdout, "%.3f %s TimeoutSource.Process()\n", zeek::run_state::network_time,
		             ident.c_str());
		on = false;
		}

	double GetNextTimeout() override { return on ? 0.0 : 0.1; };

	const char* Tag() override { return ident.c_str(); };

	void Fire() { on = true; }

private:
	std::string ident;
	bool on = false;
	};

class FdSource : public zeek::iosource::IOSource
	{
public:
	FdSource(std::string_view ident) : ident(ident)
		{
		zeek::iosource_mgr->Register(this, true /* don't count */);
		if ( ! zeek::iosource_mgr->RegisterFd(flare.FD(), this) )
			zeek::reporter->FatalError("Failed to register flare FD");
		}

	void Process() override
		{
		std::fprintf(stdout, "%.3f %s FdSource.Process()\n", zeek::run_state::network_time,
		             ident.c_str());
		flare.Extinguish();
		}

	double GetNextTimeout() override { return -1; }

	const char* Tag() override { return ident.c_str(); };

	void Fire() { flare.Fire(); }

private:
	std::string ident;
	zeek::detail::Flare flare;
	};

class Plugin : public zeek::plugin::Plugin
	{
protected:
	zeek::plugin::Configuration Configure() override;
	void InitPostScript() override;
	void HookDrainEvents() override;

private:
	int round = 0;
	TimeoutSource* ts1 = nullptr;
	TimeoutSource* ts2 = nullptr;
	FdSource* fd1 = nullptr;
	FdSource* fd2 = nullptr;
	};

extern Plugin plugin;
	}
