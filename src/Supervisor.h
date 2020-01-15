#pragma once

#include <sys/types.h>
#include <optional>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <utility>
#include <memory>
#include <chrono>
#include <map>

#include "iosource/IOSource.h"
#include "Timer.h"
#include "Pipe.h"
#include "Flare.h"
#include "NetVar.h"
#include "IntrusivePtr.h"

namespace zeek {

class ParentProcessCheckTimer : public Timer {
public:

	ParentProcessCheckTimer(double t, double arg_interval);

	void Dispatch(double t, int is_expire) override;

protected:

	double interval;
};

class Supervisor : public iosource::IOSource {
public:

	struct Config {
		std::string zeek_exe_path;
	};

	struct ClusterEndpoint {
		BifEnum::Supervisor::ClusterRole role;
		std::string host;
		int port;
		std::optional<std::string> interface;
	};

	struct NodeConfig {
		static NodeConfig FromRecord(const RecordVal* node_val);
		static NodeConfig FromJSON(std::string_view json);

		std::string ToJSON() const;
		IntrusivePtr<RecordVal> ToRecord() const;

		std::string name;
		std::optional<std::string> interface;
		std::optional<std::string> directory;
		std::optional<std::string> stdout_file;
		std::optional<std::string> stderr_file;
		std::optional<int> cpu_affinity;
		std::vector<std::string> scripts;
		std::map<std::string, ClusterEndpoint> cluster;
	};

	struct SupervisedNode {
		static bool InitCluster();

		NodeConfig config;
		pid_t parent_pid;
	};

	struct Node {
		IntrusivePtr<RecordVal> ToRecord() const;

		const std::string& Name() const
			{ return config.name; }

		Node(NodeConfig arg_config) : config(std::move(arg_config))
			{ }

		NodeConfig config;
		pid_t pid = 0;
		int exit_status = 0;
		int signal_number = 0;
		int revival_attempts = 0;
		int revival_delay = 1;
		std::chrono::time_point<std::chrono::steady_clock> spawn_time;
	};

	static std::optional<SupervisedNode> RunStem(std::unique_ptr<bro::PipePair> pipe,
	                                             pid_t parent_pid);

	using NodeMap = std::map<std::string, Node, std::less<>>;

	Supervisor(Config cfg, std::unique_ptr<bro::PipePair> stem_pipe, pid_t stem_pid);

	~Supervisor();

	pid_t StemPID() const
		{ return stem_pid; }

	void ObserveChildSignal(int signo);

	RecordVal* Status(std::string_view node_name);
	std::string Create(const RecordVal* node);
	std::string Create(const Supervisor::NodeConfig& node);
	bool Destroy(std::string_view node_name);
	bool Restart(std::string_view node_name);

	const NodeMap& Nodes()
		{ return nodes; }

private:

	// IOSource interface overrides:
	void GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
	            iosource::FD_Set* except) override;

	double NextTimestamp(double* local_network_time) override;

	void Process() override;

	size_t ProcessMessages();

	void HandleChildSignal();

	void ReapStem();

	const char* Tag() override
		{ return "zeek::Supervisor"; }

	Config config;
	pid_t stem_pid;
	std::unique_ptr<bro::PipePair> stem_pipe;
	int last_signal = -1;
	bro::Flare signal_flare;
	NodeMap nodes;
	std::string msg_buffer;
};

extern Supervisor* supervisor;
extern std::optional<Supervisor::SupervisedNode> supervised_node;

} // namespace zeek
