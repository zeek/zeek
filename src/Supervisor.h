#pragma once

#include <sys/types.h>
#include <cstdint>
#include <string>
#include <vector>
#include <utility>
#include <memory>

#include "iosource/IOSource.h"
#include "Pipe.h"
#include "Flare.h"

namespace zeek {

class Supervisor : public iosource::IOSource {
public:

	static void RunStem(std::unique_ptr<bro::Pipe> pipe);

	struct Config {
		int num_workers = 1;
		std::vector<std::string> pcaps;
		std::string zeek_exe_path;
	};

	Supervisor(Config cfg, std::unique_ptr<bro::Pipe> stem_pipe, pid_t stem_pid);

	~Supervisor();

	pid_t StemPID() const
		{ return stem_pid; }

	void ObserveChildSignal();

private:

	// IOSource interface overrides:
	void GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
	            iosource::FD_Set* except) override;

	double NextTimestamp(double* local_network_time) override;

	void Process() override;

	void HandleChildSignal();

	const char* Tag() override
		{ return "zeek::Supervisor"; }

	Config config;
	pid_t stem_pid;
	std::unique_ptr<bro::Pipe> stem_pipe;
	bro::Flare signal_flare;
};

extern Supervisor* supervisor;

} // namespace zeek
