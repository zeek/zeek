
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <csignal>
#include <cstdarg>
#include <sstream>

#include "Supervisor.h"
#include "Reporter.h"
#include "DebugLogger.h"
#include "Val.h"
#include "Net.h"
#include "NetVar.h"
#include "zeek-config.h"
#include "util.h"

#include "3rdparty/json.hpp"

extern "C" {
#include "setsignal.h"
}

#ifdef DEBUG
#define DBG_STEM(args...) stem->LogDebug(args);
#else
#define DBG_STEM
#endif

using namespace zeek;

namespace {
struct Stem {
	Stem(std::unique_ptr<bro::PipePair> p, pid_t parent_pid);

	~Stem();

	std::optional<Supervisor::SupervisedNode> Run();

	std::optional<Supervisor::SupervisedNode> Poll();

	std::optional<Supervisor::SupervisedNode> Revive();

	void Reap();

	std::optional<Supervisor::SupervisedNode> Spawn(Supervisor::Node* node);

	int AliveNodeCount() const;

	void KillNodes(int signal) const;

	void KillNode(const Supervisor::Node& node, int signal) const;

	void Destroy(Supervisor::Node* node) const;

	bool Wait(Supervisor::Node* node, int options) const;

	void Shutdown(int exit_code);

	void ReportStatus(const Supervisor::Node& node) const;

	void LogDebug(const char* format, ...) const __attribute__((format(printf, 2, 3)));

	void LogError(const char* format, ...) const __attribute__((format(printf, 2, 3)));

	pid_t parent_pid;
	int last_signal = -1;
	std::unique_ptr<bro::Flare> signal_flare;
	std::unique_ptr<bro::PipePair> pipe;
	std::map<std::string, Supervisor::Node> nodes;
	std::string msg_buffer;
	bool shutting_down = false;
};
}

static Stem* stem = nullptr;

static RETSIGTYPE stem_signal_handler(int signo)
	{
	stem->last_signal = signo;

	if ( stem->shutting_down )
		return RETSIGVAL;

	stem->signal_flare->Fire(true);

	if ( signo == SIGTERM )
		stem->shutting_down = true;

	return RETSIGVAL;
	}

static RETSIGTYPE supervisor_signal_handler(int signo)
	{
	supervisor->ObserveChildSignal(signo);
	return RETSIGVAL;
	}

static std::vector<std::string> extract_messages(std::string* buffer)
	{
	std::vector<std::string> rval;

	for ( ; ; )
		{
		auto msg_end = buffer->find('\0');

		if ( msg_end == std::string::npos )
			// Don't have any full messages left
			break;

		auto msg = buffer->substr(0, msg_end);
		rval.emplace_back(std::move(msg));
		buffer->erase(0, msg_end + 1);
		}

	return rval;
	}

static std::string make_create_message(const Supervisor::NodeConfig& node)
	{
	auto json_str = node.ToJSON();
	return fmt("create %s %s", node.name.data(), json_str.data());
	}

ParentProcessCheckTimer::ParentProcessCheckTimer(double t, double arg_interval)
	: Timer(t, TIMER_PPID_CHECK), interval(arg_interval)
	{
	}

void ParentProcessCheckTimer::Dispatch(double t, int is_expire)
	{
	// Note: only simple + portable way of detecting loss of parent
	// process seems to be polling for change in PPID.  There's platform
	// specific ways if we do end up needing something more responsive
	// and/or have to avoid overhead of polling, but maybe not worth
	// the additional complexity:
	//   Linux:   prctl(PR_SET_PDEATHSIG, ...)
	//   FreeBSD: procctl(PROC_PDEATHSIG_CTL)
	// Also note the Stem process has its own polling loop with similar logic.
	if ( zeek::supervised_node->parent_pid != getppid() )
		zeek_terminate_loop("supervised node was orphaned");

	if ( ! is_expire )
		timer_mgr->Add(new ParentProcessCheckTimer(network_time + interval,
		                                           interval));
	}

Supervisor::Supervisor(Supervisor::Config cfg,
                       std::unique_ptr<bro::PipePair> pipe,
                       pid_t arg_stem_pid)
	: config(std::move(cfg)), stem_pid(arg_stem_pid), stem_pipe(std::move(pipe))
	{
	DBG_LOG(DBG_SUPERVISOR, "forked stem process %d", stem_pid);
	setsignal(SIGCHLD, supervisor_signal_handler);
	SetIdle(true);

	int status;
	auto res = waitpid(stem_pid, &status, WNOHANG);

	if ( res == 0 )
		// Good, stem process is alive and the SIGCHLD handler will keep it so.
		return;

	if ( res == -1 )
		fprintf(stderr, "Supervisor failed to get status of stem process: %s\n",
		        strerror(errno));
	else
		{
		if ( WIFEXITED(status) )
			fprintf(stderr, "Supervisor stem died early with exit code %d\n",
			        WEXITSTATUS(status));
		else if ( WIFSIGNALED(status) )
			fprintf(stderr, "Supervisor stem died early by signal %d\n",
			        WTERMSIG(status));
		else
			fprintf(stderr, "Supervisor stem died early for unknown reason\n",
			        WTERMSIG(status));
		}

	exit(1);
	}

Supervisor::~Supervisor()
	{
	setsignal(SIGCHLD, SIG_DFL);

	if ( ! stem_pid )
		{
		DBG_LOG(DBG_SUPERVISOR, "shutdown, stem process already exited");
		return;
		}

	DBG_LOG(DBG_SUPERVISOR, "shutdown, killing stem process %d", stem_pid);

	auto kill_res = kill(stem_pid, SIGTERM);

	if ( kill_res == -1 )
		{
		char tmp[256];
		bro_strerror_r(errno, tmp, sizeof(tmp));
		reporter->Error("Failed to send SIGTERM to stem process: %s", tmp);
		}
	else
		{
		int status;
		auto wait_res = waitpid(stem_pid, &status, 0);

		if ( wait_res == -1 )
			{
			char tmp[256];
			bro_strerror_r(errno, tmp, sizeof(tmp));
			reporter->Error("Failed to wait for stem process to exit: %s", tmp);
			}
		}

	while ( ProcessMessages() != 0 );
	}

void Supervisor::ObserveChildSignal(int signo)
	{
	last_signal = signo;
	signal_flare.Fire(true);
	}

void Supervisor::ReapStem()
	{
	if ( ! stem_pid )
		return;

	int status;
	auto res = waitpid(stem_pid, &status, WNOHANG);

	if ( res == 0 )
		// Still alive
		return;

	if ( res == -1 )
		{
		char tmp[256];
		bro_strerror_r(errno, tmp, sizeof(tmp));
		reporter->Error("Supervisor failed to get exit status"
			            " of stem process: %s", tmp);
		return;
		}

	stem_pid = 0;

	if ( WIFEXITED(status) )
		{
		DBG_LOG(DBG_SUPERVISOR, "stem process exited with status %d",
		        WEXITSTATUS(status));
		}
	else if ( WIFSIGNALED(status) )
		{
		DBG_LOG(DBG_SUPERVISOR, "stem process terminated by signal %d",
		       WTERMSIG(status));
		}
	else
		reporter->Error("Supervisor failed to get exit status"
		                " of stem process for unknown reason");
	}

void Supervisor::HandleChildSignal()
	{
	if ( last_signal >= 0 )
		{
		DBG_LOG(DBG_SUPERVISOR, "Supervisor received signal %d", last_signal);
		last_signal = -1;
		}

	bool had_child_signal = signal_flare.Extinguish();

	if ( had_child_signal )
		{
		ReapStem();

		DBG_LOG(DBG_SUPERVISOR, "Supervisor processed child signal %s",
		        stem_pid ? "(spurious)" : "");
		}

	if ( stem_pid )
		return;

	// Revive the Stem process
	auto stem_ppid = getpid();
	stem_pid = fork();

	if ( stem_pid == -1 )
		{
		stem_pid = 0;
		char tmp[256];
		bro_strerror_r(errno, tmp, sizeof(tmp));
		reporter->Error("failed to fork Zeek supervisor stem process: %s\n", tmp);
		signal_flare.Fire();
		// Sleep to avoid spinning too fast in a revival-fail loop.
		sleep(1);
		return;
		}

	if ( stem_pid == 0 )
		{
		// Child stem process needs to exec()
		auto stem_env = fmt("%d,%d,%d,%d,%d", stem_ppid,
		              stem_pipe->In().ReadFD(), stem_pipe->In().WriteFD(),
		              stem_pipe->Out().ReadFD(), stem_pipe->Out().WriteFD());

		if ( setenv("ZEEK_STEM", stem_env, true) == -1 )
			{
			fprintf(stderr, "setenv(ZEEK_STEM) failed: %s\n",
			        strerror(errno));
			exit(1);
			}

		stem_pipe->In().UnsetFlags(FD_CLOEXEC);
		stem_pipe->Out().UnsetFlags(FD_CLOEXEC);

		char** args = new char*[bro_argc + 1];
		args[0] = config.zeek_exe_path.data();
		args[bro_argc] = nullptr;

		for ( auto i = 1; i < bro_argc; ++i )
			args[i] = bro_argv[i];

		auto res = execv(config.zeek_exe_path.data(), args);
		fprintf(stderr, "failed to exec Zeek supervisor stem process: %s\n",
		        strerror(errno));
		exit(1);
		}

	DBG_LOG(DBG_SUPERVISOR, "stem process revived, new pid: %d", stem_pid);

	// Parent supervisor process resends node configurations to recreate
	// the desired process hierarchy.

	// Note: there's probably a preferred order in which to create nodes.
	// E.g. logger, manager, proxy, worker.  However, fully synchronizing
	// a startup order like that is slow and complicated: essentially have
	// to wait for each process to start up and reach the point just after
	// it starts listening (and maybe that never happens for some error case).
	for ( const auto& n : nodes )
		{
		const auto& node = n.second;
		auto msg = make_create_message(node.config);
		safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
		}
	}

void Supervisor::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                        iosource::FD_Set* except)
	{
	read->Insert(signal_flare.FD());
	read->Insert(stem_pipe->InFD());
	}

double Supervisor::NextTimestamp(double* local_network_time)
	{
	return timer_mgr->Time();
	}

void Supervisor::Process()
	{
	HandleChildSignal();
	ProcessMessages();
	}

size_t Supervisor::ProcessMessages()
	{
	char buf[256];
	int bytes_read = read(stem_pipe->InFD(), buf, 256);

	if ( bytes_read > 0 )
		msg_buffer.append(buf, bytes_read);

	auto msgs = extract_messages(&msg_buffer);

	for ( auto& msg : msgs )
		{
		DBG_LOG(DBG_SUPERVISOR, "read msg from Stem: %s", msg.data());
		std::vector<std::string> msg_tokens;
		tokenize_string(msg, " ", &msg_tokens);
		const auto& type = msg_tokens[0];

		if ( type == "status" )
			{
			const auto& name = msg_tokens[1];
			auto it = nodes.find(name);

			if ( it != nodes.end() )
				it->second.pid = std::stoi(msg_tokens[2]);
			}
		else if ( type == "debug" )
			{
			// Already logged the unparsed message above.
			}
		else
			reporter->Error("Supervisor got unknown msg: %s", msg.data());
		}

	return msgs.size();
	}

Stem::Stem(std::unique_ptr<bro::PipePair> p, pid_t ppid)
	: parent_pid(ppid), signal_flare(new bro::Flare()), pipe(std::move(p))
	{
	zeek::set_thread_name("zeek.stem");
	pipe->Swap();
	stem = this;
	setsignal(SIGCHLD, stem_signal_handler);
	setsignal(SIGTERM, stem_signal_handler);

	// Note: changing the process group here so that SIGINT to the supervisor
	// doesn't also get passed to the children.  I.e. the supervisor should be
	// in charge of initiating orderly shutdown of the process tree.
	// Technically calling setpgid() like this is a race-condition (if we get a
	// SIGINT in between the fork() and setpgid() calls), but can treat that as
	// mostly be harmless since the only affected node in the process tree at
	// the point will be this Stem process and the Supervisor *should* do the
	// right thing if it also sees SIGINT with the Stem already having exited
	// (since that same type of situation with the Stem dying prematurely can
	// happen for any arbitrary reason, not just for SIGINT).
	auto res = setpgid(0, 0);

	if ( res == -1 )
		LogError("failed to set stem process group: %s", strerror(errno));
	}

Stem::~Stem()
	{
	setsignal(SIGCHLD, SIG_DFL);
	setsignal(SIGTERM, SIG_DFL);
	}

void Stem::Reap()
	{
	for ( auto& n : nodes )
		{
		auto& node = n.second;

		if ( ! node.pid )
			continue;

		Wait(&node, WNOHANG);
		}
	}

bool Stem::Wait(Supervisor::Node* node, int options) const
	{
	int status;
	auto res = waitpid(node->pid, &status, options);

	if ( res == 0 )
		// It's still alive.
		return false;

	if ( res == -1 )
		{
		LogError("Stem failed to get node exit status %s (%d): %s",
		         node->Name().data(), node->pid, strerror(errno));
		return false;
		}

	if ( WIFEXITED(status) )
		{
		node->exit_status = WEXITSTATUS(status);
		DBG_STEM("node '%s' exited with status %d",
		         node->Name().data(), node->exit_status);
		}
	else if ( WIFSIGNALED(status) )
		{
		node->signal_number = WTERMSIG(status);
		DBG_STEM("node '%s' terminated by signal %d",
		         node->Name().data(), node->signal_number);
		}
	else
		LogError("Stem failed to get node exit status %s (%d)",
		         node->Name().data(), node->pid);

	node->pid = 0;
	return true;
	}

void Stem::KillNode(const Supervisor::Node& node, int signal) const
	{
	auto kill_res = kill(node.pid, signal);

	if ( kill_res == -1 )
		LogError("Failed to send signal to node %s: %s",
		         node.Name().data(), strerror(errno));
	}

void Stem::Destroy(Supervisor::Node* node) const
	{
	constexpr auto max_term_attempts = 13;
	constexpr auto kill_delay = 2;
	auto kill_attempts = 0;

	for ( ; ; )
		{
		auto sig = kill_attempts++ < max_term_attempts ? SIGTERM : SIGKILL;
		KillNode(*node, sig);
		usleep(10);

		if ( Wait(node, WNOHANG) )
			break;

		DBG_STEM("Stem waiting to destroy node: %s (%d)",
		         node->Name().data(), node->pid);
		sleep(kill_delay);
		}
	}

std::optional<Supervisor::SupervisedNode> Stem::Revive()
	{
	constexpr auto attempts_before_delay_increase = 3;
	constexpr auto delay_increase_factor = 2;
	constexpr auto reset_revival_state_after = 30;

	for ( auto& n : nodes )
		{
		auto& node = n.second;
		auto now = std::chrono::steady_clock::now();
		auto revival_reset = std::chrono::seconds(reset_revival_state_after);
		auto time_since_spawn = now - node.spawn_time;

		if ( node.pid )
			{
			if ( time_since_spawn > revival_reset )
				{
				node.revival_attempts = 0;
				node.revival_delay = 1;
				}

			continue;
			}

		auto delay = std::chrono::seconds(node.revival_delay);

		if ( time_since_spawn < delay )
			continue;

		++node.revival_attempts;

		if ( node.revival_attempts % attempts_before_delay_increase == 0 )
			node.revival_delay *= delay_increase_factor;

		auto sn = Spawn(&node);

		if ( sn )
			return sn;

		ReportStatus(node);
		}

	return {};
	}

std::optional<Supervisor::SupervisedNode> Stem::Spawn(Supervisor::Node* node)
	{
	auto ppid = getpid();
	auto node_pid = fork();

	if ( node_pid == -1 )
		{
		LogError("failed to fork Zeek node '%s': %s",
		         node->Name().data(), strerror(errno));
		return {};
		}

	if ( node_pid == 0 )
		{
		setsignal(SIGCHLD, SIG_DFL);
		setsignal(SIGTERM, SIG_DFL);
		zeek::set_thread_name(fmt("zeek.%s", node->Name().data()));
		Supervisor::SupervisedNode rval;
		rval.config = node->config;
		rval.parent_pid = ppid;
		return rval;
		}

	node->pid = node_pid;
	node->spawn_time = std::chrono::steady_clock::now();
	DBG_STEM("Stem spawned node: %s (%d)", node->Name().data(), node->pid);
	return {};
	}

int Stem::AliveNodeCount() const
	{
	auto rval = 0;

	for ( const auto& n : nodes )
		if ( n.second.pid )
			++rval;

	return rval;
	}

void Stem::KillNodes(int signal) const
	{
	for ( const auto& n : nodes )
		KillNode(n.second, signal);
	}

void Stem::Shutdown(int exit_code)
	{
	constexpr auto max_term_attempts = 13;
	constexpr auto kill_delay = 2;
	auto kill_attempts = 0;

	for ( ; ; )
		{
		auto sig = kill_attempts++ < max_term_attempts ? SIGTERM : SIGKILL;

		if ( ! nodes.empty() )
			{
			KillNodes(sig);
			DBG_STEM("Stem killed nodes with signal %d", sig);
			usleep(10);
			Reap();
			}

		auto nodes_alive = AliveNodeCount();

		if ( nodes_alive == 0 )
			exit(exit_code);

		DBG_STEM("Stem nodes still alive %d, sleeping for %d seconds",
		         nodes_alive, kill_delay);

		auto sleep_time_left = kill_delay;

		while ( sleep_time_left > 0 )
			{
			sleep_time_left = sleep(sleep_time_left);

			if ( sleep_time_left > 0 )
				{
				// Interrupted by signal, so check if children exited
				Reap();
				nodes_alive = AliveNodeCount();

				if ( nodes_alive == 0 )
					exit(exit_code);
				}
			}
		}
	}

void Stem::ReportStatus(const Supervisor::Node& node) const
	{
	std::string msg = fmt("status %s %d", node.Name().data(), node.pid);
	safe_write(pipe->OutFD(), msg.data(), msg.size() + 1);
	}

void Stem::LogDebug(const char* format, ...) const
	{
	va_list args;
	va_start(args, format);
	auto raw_msg = fmt(format, args);
	va_end(args);

	if ( getenv("ZEEK_DEBUG_STEM_STDERR") )
		{
		// Useful when debugging a breaking change to the IPC mechanism itself.
		fprintf(stderr, "%s\n", raw_msg);
		return;
		}

	std::string msg = "debug ";
	msg += raw_msg;
	safe_write(pipe->OutFD(), msg.data(), msg.size() + 1);
	}

void Stem::LogError(const char* format, ...) const
	{
	va_list args;
	va_start(args, format);
	std::string msg = fmt(format, args);
	va_end(args);

	fprintf(stderr, "%s\n", msg.data());

	#ifdef DEBUG
	if ( getenv("ZEEK_DEBUG_STEM_STDERR") )
		// Essentially already emitted above.
		return;

	// Useful to also insert the error message into the debug log.
	LogDebug("%s", msg.data());
	#endif
	}

std::optional<Supervisor::SupervisedNode> Stem::Run()
	{
	for ( ; ; )
		{
		auto new_node = Poll();

		if ( new_node )
			return new_node;
		}

	return {};
	}

std::optional<Supervisor::SupervisedNode> Stem::Poll()
	{
	pollfd fds[2] = { { pipe->InFD(), POLLIN, 0 },
	                  { signal_flare->FD(), POLLIN, 0} };
	// Note: the poll timeout here is for periodically checking if the parent
	// process died (see below).
	constexpr auto poll_timeout_ms = 1000;
	auto res = poll(fds, 2, poll_timeout_ms);

	if ( res < 0 )
		{
		if ( errno != EINTR )
			{
			LogError("Stem poll() failed: %s", strerror(errno));
			return {};
			}
		}

	if ( last_signal >= 0 )
		{
		DBG_STEM("Stem received signal: %d", last_signal);
		last_signal = -1;
		}

	if ( getppid() != parent_pid )
		{
		// Note: only simple + portable way of detecting loss of parent
		// process seems to be polling for change in PPID.  There's platform
		// specific ways if we do end up needing something more responsive
		// and/or have to avoid overhead of polling, but maybe not worth
		// the additional complexity:
		//   Linux:   prctl(PR_SET_PDEATHSIG, ...)
		//   FreeBSD: procctl(PROC_PDEATHSIG_CTL)
		// Also note the similar polling methodology in ParentProcessCheckTimer.
		DBG_STEM("Stem suicide");
		Shutdown(13);
		}

	auto new_node = Revive();

	if ( new_node )
		return new_node;

	if ( res == 0 )
		return {};

	if ( signal_flare->Extinguish() )
		{
		if ( shutting_down )
			Shutdown(0);

		Reap();
		auto new_node = Revive();

		if ( new_node )
			return new_node;
		}

	if ( ! fds[0].revents )
		return {};

	char buf[256];
	int bytes_read = read(pipe->InFD(), buf, 256);

	if ( bytes_read == 0 )
		{
		// EOF, supervisor must have exited
		DBG_STEM("Stem EOF");
		Shutdown(14);
		}

	if ( bytes_read < 0 )
		{
		LogError("Stem read() failed: %s", strerror(errno));
		return {};
		}

	msg_buffer.append(buf, bytes_read);
	auto msgs = extract_messages(&msg_buffer);

	for ( auto& msg : msgs )
		{
		std::vector<std::string> msg_tokens;
		tokenize_string(std::move(msg), " ", &msg_tokens, 2);
		const auto& cmd = msg_tokens[0];
		const auto& node_name = msg_tokens[1];

		if ( cmd == "create" )
			{
			const auto& node_json = msg_tokens[2];
			assert(nodes.find(node_name) == nodes.end());
			auto node_config = Supervisor::NodeConfig::FromJSON(node_json);
			auto it = nodes.emplace(node_name, std::move(node_config)).first;
			auto& node = it->second;

			auto sn = Spawn(&node);

			if ( sn )
				return sn;

			DBG_STEM("Stem created node: %s (%d)", node.Name().data(), node.pid);
			ReportStatus(node);
			}
		else if ( cmd == "destroy" )
			{
			auto it = nodes.find(node_name);
			assert(it != nodes.end());
			auto& node = it->second;
			DBG_STEM("Stem destroying node: %s", node_name.data());
			Destroy(&node);
			nodes.erase(it);
			}
		else if ( cmd == "restart" )
			{
			auto it = nodes.find(node_name);
			assert(it != nodes.end());
			auto& node = it->second;
			DBG_STEM("Stem restarting node: %s", node_name.data());
			Destroy(&node);

			auto sn = Spawn(&node);

			if ( sn )
				 return sn;

			ReportStatus(node);
			}
		else
			LogError("Stem got unknown supervisor message: %s", cmd.data());
		}

	return {};
	}

std::optional<Supervisor::SupervisedNode> Supervisor::RunStem(std::unique_ptr<bro::PipePair> pipe, pid_t parent_pid)
	{
	Stem s(std::move(pipe), parent_pid);
	return s.Run();
	}

static BifEnum::Supervisor::ClusterRole role_str_to_enum(const std::string& r)
	{
	if ( r == "Supervisor::LOGGER" )
		return BifEnum::Supervisor::LOGGER;
	if ( r == "Supervisor::MANAGER" )
		return BifEnum::Supervisor::MANAGER;
	if ( r == "Supervisor::PROXY" )
		return BifEnum::Supervisor::PROXY;
	if ( r == "Supervisor::WORKER" )
		return BifEnum::Supervisor::WORKER;

	return BifEnum::Supervisor::NONE;
	}

Supervisor::NodeConfig Supervisor::NodeConfig::FromRecord(const RecordVal* node)
	{
	Supervisor::NodeConfig rval;
	rval.name = node->Lookup("name")->AsString()->CheckString();
	auto iface_val = node->Lookup("interface");

	if ( iface_val )
		rval.interface = iface_val->AsString()->CheckString();

	auto directory_val = node->Lookup("directory");

	if ( directory_val )
		rval.directory = directory_val->AsString()->CheckString();

	auto stdout_val = node->Lookup("stdout_file");

	if ( stdout_val )
		rval.stdout_file = stdout_val->AsString()->CheckString();

	auto stderr_val = node->Lookup("stderr_file");

	if ( stderr_val )
		rval.stderr_file = stderr_val->AsString()->CheckString();

	auto affinity_val = node->Lookup("cpu_affinity");

	if ( affinity_val )
		rval.cpu_affinity = affinity_val->AsInt();

	auto scripts_val = node->Lookup("scripts")->AsVectorVal();

	for ( auto i = 0; i < scripts_val->Size(); ++i )
		{
		auto script = scripts_val->Lookup(i)->AsStringVal()->ToStdString();
		rval.scripts.emplace_back(std::move(script));
		}

	auto cluster_table_val = node->Lookup("cluster")->AsTableVal();
	auto cluster_table = cluster_table_val->AsTable();
	auto c = cluster_table->InitForIteration();
	HashKey* k;
	TableEntryVal* v;

	while ( (v = cluster_table->NextEntry(k, c)) )
		{
		IntrusivePtr<ListVal> key{cluster_table_val->RecoverIndex(k), false};
		delete k;
		auto name = key->Index(0)->AsStringVal()->ToStdString();
		auto rv = v->Value()->AsRecordVal();

		Supervisor::ClusterEndpoint ep;
		ep.role = static_cast<BifEnum::Supervisor::ClusterRole>(rv->Lookup("role")->AsEnum());
		ep.host = rv->Lookup("host")->AsAddr().AsString();
		ep.port = rv->Lookup("p")->AsPortVal()->Port();

		auto iface = rv->Lookup("interface");

		if ( iface )
			ep.interface = iface->AsStringVal()->ToStdString();

		rval.cluster.emplace(name, std::move(ep));
		}

	return rval;
	}

Supervisor::NodeConfig Supervisor::NodeConfig::FromJSON(std::string_view json)
	{
	Supervisor::NodeConfig rval;
	auto j = nlohmann::json::parse(json);
	rval.name = j["name"];

	if ( auto it = j.find("interface"); it != j.end() )
		rval.interface = *it;

	if ( auto it = j.find("directory"); it != j.end() )
		rval.directory = *it;

	if ( auto it = j.find("stdout_file"); it != j.end() )
		rval.stdout_file= *it;

	if ( auto it = j.find("stderr_file"); it != j.end() )
		rval.stderr_file= *it;

	if ( auto it = j.find("cpu_affinity"); it != j.end() )
		rval.cpu_affinity = *it;

	auto scripts = j["scripts"];

	for ( auto& s : scripts )
		rval.scripts.emplace_back(std::move(s));

	auto cluster = j["cluster"];

	for ( const auto& e : cluster.items() )
		{
		Supervisor::ClusterEndpoint ep;

		auto& key = e.key();
		auto& val = e.value();

		auto role_str = val["role"];
		ep.role = role_str_to_enum(role_str);

		ep.host = val["host"];
		ep.port = val["p"]["port"];

		auto it = val.find("interface");

		if ( it != val.end() )
			ep.interface = *it;

		rval.cluster.emplace(key, std::move(ep));
		}

	return rval;
	}

std::string Supervisor::NodeConfig::ToJSON() const
	{
	auto re = std::make_unique<RE_Matcher>("^_");
	auto node_val = ToRecord();
	IntrusivePtr<StringVal> json_val{node_val->ToJSON(false, re.get()), false};
	auto rval = json_val->ToStdString();
	return rval;
	}

IntrusivePtr<RecordVal> Supervisor::NodeConfig::ToRecord() const
	{
	auto rt = BifType::Record::Supervisor::NodeConfig;
	auto rval = make_intrusive<RecordVal>(rt);
	rval->Assign(rt->FieldOffset("name"), new StringVal(name));

	if ( interface )
		rval->Assign(rt->FieldOffset("interface"), new StringVal(*interface));

	if ( directory )
		rval->Assign(rt->FieldOffset("directory"), new StringVal(*directory));

	if ( stdout_file )
		rval->Assign(rt->FieldOffset("stdout_file"), new StringVal(*stdout_file));

	if ( stderr_file )
		rval->Assign(rt->FieldOffset("stderr_file"), new StringVal(*stderr_file));

	if ( cpu_affinity )
		rval->Assign(rt->FieldOffset("cpu_affinity"), val_mgr->GetInt(*cpu_affinity));

	auto st = BifType::Record::Supervisor::NodeConfig->FieldType("scripts");
	auto scripts_val = new VectorVal(st->AsVectorType());
	rval->Assign(rt->FieldOffset("scripts"), scripts_val);

	for ( const auto& s : scripts )
		scripts_val->Assign(scripts_val->Size(), new StringVal(s));

	auto tt = BifType::Record::Supervisor::NodeConfig->FieldType("cluster");
	auto cluster_val = new TableVal(tt->AsTableType());
	rval->Assign(rt->FieldOffset("cluster"), cluster_val);

	for ( const auto& e : cluster )
		{
		auto& name = e.first;
		auto& ep = e.second;
		auto key = make_intrusive<StringVal>(name);
		auto ept = BifType::Record::Supervisor::ClusterEndpoint;
		auto val = make_intrusive<RecordVal>(ept);

		val->Assign(ept->FieldOffset("role"), BifType::Enum::Supervisor::ClusterRole->GetVal(ep.role));
		val->Assign(ept->FieldOffset("host"), new AddrVal(ep.host));
		val->Assign(ept->FieldOffset("p"), val_mgr->GetPort(ep.port, TRANSPORT_TCP));

		if ( ep.interface )
			val->Assign(ept->FieldOffset("interface"), new StringVal(*ep.interface));

		cluster_val->Assign(key.get(), val.detach());
		}

	return rval;
	}

IntrusivePtr<RecordVal> Supervisor::Node::ToRecord() const
	{
	auto rt = BifType::Record::Supervisor::NodeStatus;
	auto rval = make_intrusive<RecordVal>(rt);

	rval->Assign(rt->FieldOffset("node"), config.ToRecord().detach());

	if ( pid )
		rval->Assign(rt->FieldOffset("pid"), val_mgr->GetCount(pid));

	return rval;
	}


static Val* supervisor_role_to_cluster_node_type(BifEnum::Supervisor::ClusterRole role)
	{
	static auto node_type = global_scope()->Lookup("Cluster::NodeType")->AsType()->AsEnumType();

	switch ( role ) {
	case BifEnum::Supervisor::LOGGER:
		return node_type->GetVal(node_type->Lookup("Cluster", "LOGGER"));
	case BifEnum::Supervisor::MANAGER:
		return node_type->GetVal(node_type->Lookup("Cluster", "MANAGER"));
	case BifEnum::Supervisor::PROXY:
		return node_type->GetVal(node_type->Lookup("Cluster", "PROXY"));
	case BifEnum::Supervisor::WORKER:
		return node_type->GetVal(node_type->Lookup("Cluster", "WORKER"));
	default:
		return node_type->GetVal(node_type->Lookup("Cluster", "NONE"));
	}
	}

bool Supervisor::SupervisedNode::InitCluster()
	{
	if ( supervised_node->config.cluster.empty() )
		return false;

	auto cluster_node_type = global_scope()->Lookup("Cluster::Node")->AsType()->AsRecordType();
	auto cluster_nodes_id = global_scope()->Lookup("Cluster::nodes");
	auto cluster_manager_is_logger_id = global_scope()->Lookup("Cluster::manager_is_logger");
	auto cluster_nodes = cluster_nodes_id->ID_Val()->AsTableVal();
	auto has_logger = false;
	std::optional<std::string> manager_name;

	for ( const auto& e : supervised_node->config.cluster )
		{
		if ( e.second.role == BifEnum::Supervisor::MANAGER )
			manager_name = e.first;
		else if ( e.second.role == BifEnum::Supervisor::LOGGER )
			has_logger = true;
		}

	for ( const auto& e : supervised_node->config.cluster )
		{
		const auto& node_name = e.first;
		const auto& ep = e.second;
		auto key = make_intrusive<StringVal>(node_name);
		auto val = make_intrusive<RecordVal>(cluster_node_type);

		auto node_type = supervisor_role_to_cluster_node_type(ep.role);
		val->Assign(cluster_node_type->FieldOffset("node_type"), node_type);
		val->Assign(cluster_node_type->FieldOffset("ip"), new AddrVal(ep.host));
		val->Assign(cluster_node_type->FieldOffset("p"), val_mgr->GetPort(ep.port, TRANSPORT_TCP));

		if ( ep.interface )
			val->Assign(cluster_node_type->FieldOffset("interface"),
			            new StringVal(*ep.interface));

		if ( manager_name && ep.role != BifEnum::Supervisor::MANAGER )
			val->Assign(cluster_node_type->FieldOffset("manager"),
			            new StringVal(*manager_name));

		cluster_nodes->Assign(key.get(), val.detach());
		}

	cluster_manager_is_logger_id->SetVal(val_mgr->GetBool(! has_logger));
	return true;
	}

RecordVal* Supervisor::Status(std::string_view node_name)
	{
	auto rval = new RecordVal(BifType::Record::Supervisor::Status);
	auto tt = BifType::Record::Supervisor::Status->FieldType("nodes");
	auto node_table_val = new TableVal(tt->AsTableType());
	rval->Assign(0, node_table_val);

	if ( node_name.empty() )
		{
		for ( const auto& n : nodes )
			{
			const auto& name = n.first;
			const auto& node = n.second;
			auto key = make_intrusive<StringVal>(name);
			auto val = node.ToRecord();
			node_table_val->Assign(key.get(), val.detach());
			}
		}
	else
		{
		auto it = nodes.find(node_name);

		if ( it == nodes.end() )
			return rval;

		const auto& name = it->first;
		const auto& node = it->second;
		auto key = make_intrusive<StringVal>(name);
		auto val = node.ToRecord();
		node_table_val->Assign(key.get(), val.detach());
		}

	return rval;
	}

std::string Supervisor::Create(const RecordVal* node_val)
	{
	auto node = Supervisor::NodeConfig::FromRecord(node_val);
	return Create(node);
	}

std::string Supervisor::Create(const Supervisor::NodeConfig& node)
	{
	if ( node.name.empty() )
		return "node names must not be an empty string";

	if ( node.name.find(' ') != std::string::npos )
		return fmt("node names must not contain spaces: '%s'",
		           node.name.data());

	if ( nodes.find(node.name) != nodes.end() )
		return fmt("node with name '%s' already exists", node.name.data());

	if ( node.directory )
		{
		auto res = ensure_intermediate_dirs(node.directory->data());

		if ( ! res )
			return fmt("failed to create working directory %s\n",
			           node.directory->data());
		}

	auto msg = make_create_message(node);
	safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
	nodes.emplace(node.name, node);
	return "";
	}

bool Supervisor::Destroy(std::string_view node_name)
	{
	auto send_destroy_msg = [this](std::string_view name)
		{
		std::stringstream ss;
		ss << "destroy " << name;
		std::string msg = ss.str();
		safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
		};

	if ( node_name.empty() )
		{
		for ( const auto& n : nodes )
			send_destroy_msg(n.first);

		nodes.clear();
		return true;
		}

	auto it = nodes.find(node_name);

	if ( it == nodes.end() )
		return false;

	nodes.erase(it);
	send_destroy_msg(node_name);
	return true;
	}

bool Supervisor::Restart(std::string_view node_name)
	{
	auto send_restart_msg = [this](std::string_view name)
		{
		std::stringstream ss;
		ss << "restart " << name;
		std::string msg = ss.str();
		safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
		};

	if ( node_name.empty() )
		{
		for ( const auto& n : nodes )
			send_restart_msg(n.first);

		return true;
		}

	if ( nodes.find(node_name) == nodes.end() )
		return false;

	send_restart_msg(node_name);
	return true;
	}
