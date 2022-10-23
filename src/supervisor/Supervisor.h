// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "zeek/Flare.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/NetVar.h"
#include "zeek/Options.h"
#include "zeek/Pipe.h"
#include "zeek/Timer.h"
#include "zeek/iosource/IOSource.h"

namespace zeek
	{
namespace detail
	{

struct SupervisorStemHandle;
struct SupervisedNode;
struct SupervisorNode;

/**
 * A simple wrapper around a pipe to help do line-buffered output
 * of a Supervisor/Stem child process' redirected stdout/stderr.
 */
struct LineBufferedPipe
	{
	/**
	 * A pipe that a parent process can read from to obtain output
	 * written by a child process.
	 */
	std::unique_ptr<Pipe> pipe;
	/**
	 * A prefix to emit before data read from the pipe.
	 */
	std::string prefix;
	/**
	 * The stream to which data from the pipe will be output.
	 */
	FILE* stream = nullptr;
	/**
	 * Leftover data read from the pipe without yet seeing a newline.
	 * Data is read and output in line-buffered fashion.
	 */
	std::string buffer;

	/**
	 * Completely drain the pipe and close it.  Nothing can be
	 * processed from the pipe anymore unless a new one is assigned.
	 */
	void Drain();

	/**
	 * Read lines from the pipe and emit them.
	 */
	size_t Process();

	/**
	 * Emits a message: either by calling a hook, or if there is no hook
	 * or the hook returns true (no early "break"), printing it to the
	 * associated stream.
	 */
	void Emit(const char* msg) const;

	/**
	 * A hook to call when emitting messages read from the pipe.
	 */
	FuncPtr hook;
	};

	} // namespace zeek::detail

/**
 * A Supervisor object manages a tree of persistent Zeek processes.  If any
 * child process dies it will be re-created with its original configuration.
 * The Supervisor process itself actually only manages a single child process,
 * called the Stem process.  That Stem is created via a fork() just after the
 * command-line arguments have been parsed.  The Stem process is used as the
 * baseline image for spawning and supervising further Zeek child nodes since
 * it has the purest global state without having to risk an exec() using an
 * on-disk binary that's changed in the meantime from the original Supervisor's
 * version of the Zeek binary.  However, if the Stem process itself dies
 * prematurely, the Supervisor will have to fork() and exec() to revive it (and
 * then the revived Stem will re-spawn its own children).  Any node in the tree
 * will self-terminate if it detects its parent has died and that detection is
 * done via polling for change in parent process ID.
 */
class Supervisor : public iosource::IOSource
	{
public:
	/**
	 * Configuration options that change Supervisor behavior.
	 */
	struct Config
		{
		/**
		 * The filesystem path of the Zeek binary/executable.  This is used
		 * if the Stem process ever dies and we need to fork() and exec() to
		 * re-create it.
		 */
		std::string zeek_exe_path;
		};

	/**
	 * Configuration options that influence how a Supervised Zeek node
	 * integrates into the normal Zeek Cluster Framework.
	 */
	struct ClusterEndpoint
		{
		/**
		 * The node's role within the cluster.  E.g. manager, logger, worker.
		 */
		BifEnum::Supervisor::ClusterRole role;
		/**
		 * The TCP port number at which the cluster node listens for connections.
		 */
		int port;
		/**
		 * The host/IP at which the cluster node is listening for connections.
		 */
		std::string host;
		/**
		 * The interface name from which the node read/analyze packets.
		 * Typically used by worker nodes.
		 */
		std::optional<std::string> interface;
		};

	/**
	 * Configuration options that influence behavior of a Supervised Zeek node.
	 */
	struct NodeConfig
		{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		// This block exists because the default implementations
		// themselves trigger deprecation warnings for accessing the
		// "scripts" field. It can go when we remove that deprecation.
		NodeConfig() = default;
		NodeConfig(NodeConfig&) = default;
		NodeConfig(const NodeConfig&) = default;
		NodeConfig(NodeConfig&&) = default;
		~NodeConfig() = default;
		NodeConfig& operator=(const NodeConfig&) = default;
#pragma GCC diagnostic pop

		/**
		 * Create configuration from script-layer record value.
		 * @param node_val  the script-layer record value to convert.
		 */
		static NodeConfig FromRecord(const RecordVal* node_val);

		/**
		 * Create configuration from JSON representation.
		 * @param json  the JSON string to convert.
		 */
		static NodeConfig FromJSON(std::string_view json);

		/**
		 * Convert this object into JSON representation.
		 * @return  the JSON string representing the node config.
		 */
		std::string ToJSON() const;

		/**
		 * Convert his object into script-layer record value.
		 * @return  the script-layer record value representing the node config.
		 */
		RecordValPtr ToRecord() const;

		/**
		 * The name of the supervised Zeek node.  These are unique within
		 * a given supervised process tree and typically human-readable.
		 */
		std::string name;
		/**
		 * The interface name from which the node should read/analyze packets.
		 */
		std::optional<std::string> interface;
		/**
		 * The working directory that should be used by the node.
		 */
		std::optional<std::string> directory;
		/**
		 * The filename/path to which the node's stdout will be redirected.
		 */
		std::optional<std::string> stdout_file;
		/**
		 * The filename/path to which the node's stderr will be redirected.
		 */
		std::optional<std::string> stderr_file;
		/**
		 * A cpu/core number to which the node will try to pin itself.
		 */
		std::optional<int> cpu_affinity;
		/**
		 * Whether to start the node in bare mode. When not present, the
		 * node inherits the bare-mode status of the supervisor.
		 */
		std::optional<bool> bare_mode;
		/**
		 * Additional script filenames/paths that the node should load
		 * after the base scripts, and prior to any user-specified ones.
		 */
		std::vector<std::string> addl_base_scripts;
		/**
		 * Additional script filename/paths that the node should load
		 * after any user-specified scripts.
		 */
		std::vector<std::string> addl_user_scripts;
		/**
		 * The former name for addl_user_scripts, now deprecated.
		 */
		std::vector<std::string> scripts
			[[deprecated("Remove in v6.1. Use NodeConfig::addl_user_scripts.")]];
		/**
		 * Environment variables and values  to define in the node.
		 */
		std::map<std::string, std::string> env;
		/**
		 * The Cluster Layout definition.  Each node in the Cluster Framework
		 * knows about the full, static cluster topology to which it belongs.
		 * Entries in the map use node names for keys.
		 */
		std::map<std::string, ClusterEndpoint> cluster;
		};

	/**
	 * Create and run the Stem process if necessary.
	 * @param supervisor_mode  whether Zeek was invoked with the supervisor
	 * mode specified as command-line argument/option.
	 * @return  state that defines the Stem process if called from the
	 * Supervisor process.  The Stem process itself will not return from this,
	 * function but a node it spawns via fork() will return from it and
	 * information about it is available in ThisNode().
	 */
	static std::optional<detail::SupervisorStemHandle> CreateStem(bool supervisor_mode);

	/**
	 * @return  the state which describes what a supervised node should know
	 * about itself if this is a supervised process.  If called from a process
	 * that is not supervised, this returns an "empty" object.
	 */
	static const std::optional<detail::SupervisedNode>& ThisNode() { return supervised_node; }

	using NodeMap = std::map<std::string, detail::SupervisorNode, std::less<>>;

	/**
	 * Create a new Supervisor object.
	 * @param stem_handle information about the Stem process that was already
	 * created via CreateStem()
	 */
	Supervisor(Config cfg, detail::SupervisorStemHandle stem_handle);

	/**
	 * Destruction also cleanly shuts down the entire supervised process tree.
	 */
	~Supervisor();

	/**
	 * Perform some initialization that needs to happen after scripts are loaded
	 * and the IOSource manager is created.
	 */
	void InitPostScript();

	/**
	 * @return the process ID of the Stem.
	 */
	pid_t StemPID() const { return stem_pid; }

	/**
	 * @return the state of currently supervised processes.  The map uses
	 * node names for keys.
	 */
	const NodeMap& Nodes() { return nodes; }

	/**
	 * Retrieve current status of a supervised node.
	 * @param node_name  the name of the node for which to retrieve status
	 * or an empty string to mean "all nodes".
	 * @return  script-layer Supervisor::Status record value describing the
	 * status of a node or set of nodes.
	 */
	RecordValPtr Status(std::string_view node_name);

	/**
	 * Create a new supervised node.
	 * @param node  the script-layer Supervisor::NodeConfig value that
	 * describes the desired node configuration
	 * @return  an empty string on success or description of the error/failure
	 */
	std::string Create(const RecordVal* node);

	/**
	 * Create a new supervised node.
	 * @param node  the desired node configuration
	 * @return  an empty string on success or description of the error/failure
	 */
	std::string Create(const Supervisor::NodeConfig& node);

	/**
	 * Destroys and removes a supervised node.
	 * @param node_name  the name of the node to destroy or an empty string
	 * to mean "all nodes"
	 * @return  true on success
	 */
	bool Destroy(std::string_view node_name);

	/**
	 * Restart a supervised node process (by destroying and re-recreating).
	 * @param node_name  the name of the node to restart or an empty string
	 * to mean "all nodes"
	 * @return  true on success
	 */
	bool Restart(std::string_view node_name);

	/**
	 * Not meant for public use.  For use in a signal handler to tell the
	 * Supervisor a child process (i.e. the Stem) potentially died.
	 */
	void ObserveChildSignal(int signo);

private:
	// IOSource interface overrides:
	double GetNextTimeout() override;
	void Process() override;

	size_t ProcessMessages();

	void HandleChildSignal();

	void ReapStem();

	const char* Tag() override { return "zeek::Supervisor"; }

	static std::optional<detail::SupervisedNode> supervised_node;

	Config config;
	pid_t stem_pid;
	int last_signal = -1;
	std::unique_ptr<detail::PipePair> stem_pipe;
	detail::LineBufferedPipe stem_stdout;
	detail::LineBufferedPipe stem_stderr;
	detail::Flare signal_flare;
	NodeMap nodes;
	std::string msg_buffer;
	EventHandlerPtr node_status;
	};

namespace detail
	{
/**
 * State used to initialize and talk to the Supervisor Stem process.
 */
struct SupervisorStemHandle
	{
	/**
	 * Bidirectional pipes that allow the Supervisor and Stem to talk.
	 */
	std::unique_ptr<detail::PipePair> pipe;
	/**
	 * A pipe that the Supervisor can read from to obtain
	 * any output written to the Stem's stdout.
	 */
	std::unique_ptr<detail::Pipe> stdout_pipe;
	/**
	 * A pipe that the Supervisor can read from to obtain
	 * any output written to the Stem's stdout.
	 */
	std::unique_ptr<detail::Pipe> stderr_pipe;
	/**
	 * The Stem's process ID.
	 */
	pid_t pid = 0;
	};

/**
 * State which defines a Supervised Zeek node's understanding of itself.
 */
struct SupervisedNode
	{
	/**
	 * Initialize the Supervised node within the Zeek Cluster Framework.
	 * This function populates the "Cluster::nodes" script-layer variable
	 * that otherwise is expected to be populated by a
	 * "cluster-layout.zeek" script in other context (e.g. ZeekCtl
	 * generates that cluster layout).
	 * @return  true if the supervised node is using the Cluster Framework
	 * else false.
	 */
	bool InitCluster() const;

	/**
	 * Initialize the Supervised node.
	 * @param options  the Zeek options to extend/modify as appropriate
	 * for the node's configuration.
	 */
	void Init(Options* options) const;

	/**
	 * The node's configuration options.
	 */
	Supervisor::NodeConfig config;
	/**
	 * The process ID of the supervised node's parent process (i.e. the PID
	 * of the Stem process).
	 */
	pid_t parent_pid;
	};

/**
 * The state of a supervised node from the Supervisor's perspective.
 */
struct SupervisorNode
	{
	/**
	 * Convert the node into script-layer Supervisor::NodeStatus record
	 * representation.
	 */
	RecordValPtr ToRecord() const;

	/**
	 * @return the name of the node.
	 */
	const std::string& Name() const { return config.name; }

	/**
	 * Create a new node state from a given configuration.
	 * @param arg_config  the configuration to use for the node.
	 */
	SupervisorNode(Supervisor::NodeConfig arg_config) : config(std::move(arg_config)) { }

	/**
	 * The desired configuration for the node.
	 */
	Supervisor::NodeConfig config;
	/**
	 * Process ID of the node (positive/non-zero are valid/live PIDs).
	 */
	pid_t pid = 0;
	/**
	 * Whether the node is voluntarily marked for termination by the
	 * Supervisor.
	 */
	bool killed = false;
	/**
	 * The last exit status of the node.
	 */
	int exit_status = 0;
	/**
	 * The last signal which terminated the node.
	 */
	int signal_number = 0;
	/**
	 * Number of process revival attempts made after the node first died
	 * prematurely.
	 */
	int revival_attempts = 0;
	/**
	 * How many seconds to wait until the next revival attempt for the node.
	 */
	int revival_delay = 1;
	/**
	 * The time at which the node's process was last spawned.
	 */
	std::chrono::time_point<std::chrono::steady_clock> spawn_time;
	/**
	 * A pipe that the Supervisor Stem can read from to obtain
	 * any output written to the Nodes's stdout.
	 */
	detail::LineBufferedPipe stdout_pipe;
	/**
	 * A pipe that the Supervisor Stem can read from to obtain
	 * any output written to the Node's stdout.
	 */
	detail::LineBufferedPipe stderr_pipe;
	};

/**
 * A timer used by supervised processes to periodically check whether their
 * parent (supervisor) process has died.  If it has died, the supervised
 * process self-terminates.
 */
class ParentProcessCheckTimer final : public Timer
	{
public:
	/**
	 * Create a timer to check for parent process death.
	 * @param t  the time at which to trigger the timer's check.
	 * @param interval  number of seconds to wait before checking again.
	 */
	ParentProcessCheckTimer(double t, double interval);

protected:
	void Dispatch(double t, bool is_expire) override;

	double interval;
	};
	}

extern Supervisor* supervisor_mgr;

	} // namespace zeek
