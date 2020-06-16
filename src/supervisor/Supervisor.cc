// See the file "COPYING" in the main distribution directory for copyright.

#include "Supervisor.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <csignal>
#include <cstdarg>
#include <sstream>

#include "iosource/Manager.h"
#include "ZeekString.h"
#include "Dict.h"
#include "RE.h"
#include "Reporter.h"
#include "Scope.h"
#include "DebugLogger.h"
#include "ID.h"
#include "Val.h"
#include "Net.h"
#include "NetVar.h"
#include "zeek-config.h"
#include "util.h"
#include "input.h"
#include "zeek-affinity.h"

#define RAPIDJSON_HAS_STDSTRING 1
#include "rapidjson/document.h"

extern "C" {
#include "setsignal.h"
}

#ifdef DEBUG
#define DBG_STEM(args...) stem->LogDebug(args);
#else
#define DBG_STEM
#endif

using namespace zeek;

std::optional<Supervisor::SupervisedNode> Supervisor::supervised_node;

namespace {

struct Stem {
	/**
	* State used to initalialize the Stem process.
	*/
	struct State {
		/**
		* Bidirectional pipes that allow the Supervisor and Stem to talk.
		*/
		std::unique_ptr<zeek::detail::PipePair> pipe;
		/**
		* The Stem's parent process ID (i.e. PID of the Supervisor).
		*/
		pid_t parent_pid = 0;
	};

	Stem(State stem_state);

	~Stem();

	Supervisor::SupervisedNode Run();

	std::optional<Supervisor::SupervisedNode> Poll();

	std::optional<Supervisor::SupervisedNode> Revive();

	void Reap();

	std::optional<Supervisor::SupervisedNode> Spawn(Supervisor::Node* node);

	int AliveNodeCount() const;

	void KillNodes(int signal);

	void KillNode(Supervisor::Node* node, int signal) const;

	void Destroy(Supervisor::Node* node) const;

	bool Wait(Supervisor::Node* node, int options) const;

	void Shutdown(int exit_code);

	void ReportStatus(const Supervisor::Node& node) const;

	void Log(std::string_view type, const char* format, va_list args) const;

	void LogDebug(const char* format, ...) const __attribute__((format(printf, 2, 3)));

	void LogError(const char* format, ...) const __attribute__((format(printf, 2, 3)));

	pid_t parent_pid;
	int last_signal = -1;
	std::unique_ptr<zeek::detail::Flare> signal_flare;
	std::unique_ptr<zeek::detail::PipePair> pipe;
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
	supervisor_mgr->ObserveChildSignal(signo);
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

zeek::detail::ParentProcessCheckTimer::ParentProcessCheckTimer(double t,
                                                               double arg_interval)
	: Timer(t, TIMER_PPID_CHECK), interval(arg_interval)
	{
	}

void zeek::detail::ParentProcessCheckTimer::Dispatch(double t, bool is_expire)
	{
	// Note: only simple + portable way of detecting loss of parent
	// process seems to be polling for change in PPID.  There's platform
	// specific ways if we do end up needing something more responsive
	// and/or have to avoid overhead of polling, but maybe not worth
	// the additional complexity:
	//   Linux:   prctl(PR_SET_PDEATHSIG, ...)
	//   FreeBSD: procctl(PROC_PDEATHSIG_CTL)
	// Also note the Stem process has its own polling loop with similar logic.
	if ( zeek::Supervisor::ThisNode()->parent_pid != getppid() )
		zeek_terminate_loop("supervised node was orphaned");

	if ( ! is_expire )
		timer_mgr->Add(new ParentProcessCheckTimer(network_time + interval,
		                                           interval));
	}

Supervisor::Supervisor(Supervisor::Config cfg, StemHandle sh)
	: config(std::move(cfg)), stem_pid(sh.pid), stem_pipe(std::move(sh.pipe))
	{
	DBG_LOG(DBG_SUPERVISOR, "forked stem process %d", stem_pid);
	setsignal(SIGCHLD, supervisor_signal_handler);

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
			fprintf(stderr, "Supervisor stem died early for unknown reason\n");
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

	iosource_mgr->UnregisterFd(signal_flare.FD(), this);
	iosource_mgr->UnregisterFd(stem_pipe->InFD(), this);

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

void Supervisor::InitPostScript()
	{
	iosource_mgr->Register(this);

	if ( ! iosource_mgr->RegisterFd(signal_flare.FD(), this) )
		reporter->FatalError("Failed registration for signal_flare with iosource_mgr");
	if ( ! iosource_mgr->RegisterFd(stem_pipe->InFD(), this) )
		reporter->FatalError("Failed registration for stem_pipe with iosource_mgr");
	}

double Supervisor::GetNextTimeout()
	{
	return -1;
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
		else if ( type == "error" )
			{
			msg_tokens.erase(msg_tokens.begin());
			auto err_msg = implode_string_vector(msg_tokens, " ");
			reporter->Error("%s", err_msg.data());
			}
		else
			reporter->Error("Supervisor got unknown msg: %s", msg.data());
		}

	return msgs.size();
	}

Stem::Stem(State ss)
	: parent_pid(ss.parent_pid), signal_flare(new zeek::detail::Flare()), pipe(std::move(ss.pipe))
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
	if ( node->pid <= 0 )
		{
		DBG_STEM("Stem skip waiting for node '%s' (PID %d) to terminate: already dead",
		         node->Name().data(), node->pid);
		return true;
		}

	int status;
	auto res = waitpid(node->pid, &status, options);

	if ( res == 0 )
		// It's still alive.
		return false;

	if ( res == -1 )
		{
		LogError("Stem failed to get node exit status '%s' (PID %d): %s",
		         node->Name().data(), node->pid, strerror(errno));
		return false;
		}

	if ( WIFEXITED(status) )
		{
		node->exit_status = WEXITSTATUS(status);
		DBG_STEM("node '%s' (PID %d) exited with status %d",
		         node->Name().data(), node->pid, node->exit_status);

		if ( ! node->killed )
			LogError("Supervised node '%s' (PID %d) exited prematurely with status %d",
			         node->Name().data(), node->pid, node->exit_status);
		}
	else if ( WIFSIGNALED(status) )
		{
		node->signal_number = WTERMSIG(status);
		DBG_STEM("node '%s' (PID %d) terminated by signal %d",
		         node->Name().data(), node->pid, node->signal_number);

		if ( ! node->killed )
			LogError("Supervised node '%s' (PID %d) terminated prematurely by signal %d",
			         node->Name().data(), node->pid, node->signal_number);
		}
	else
		LogError("Stem failed to get node exit status '%s' (PID %d)",
		         node->Name().data(), node->pid);

	node->pid = 0;
	return true;
	}

void Stem::KillNode(Supervisor::Node* node, int signal) const
	{
	if ( node->pid <= 0 )
		{
		DBG_STEM("Stem skip killing node '%s' (PID %d): already dead",
		         node->Name().data(), node->pid);
		return;
		}

	node->killed = true;
	auto kill_res = kill(node->pid, signal);

	if ( kill_res == -1 )
		LogError("Failed to send signal to node '%s' (PID %d): %s",
		         node->Name().data(), node->pid, strerror(errno));
	}

static int get_kill_signal(int attempts, int max_attempts)
	{
	if ( getenv("ZEEK_SUPERVISOR_NO_SIGKILL") )
		return SIGTERM;

	if ( attempts < max_attempts )
		return SIGTERM;

	return SIGKILL;
	}

void Stem::Destroy(Supervisor::Node* node) const
	{
	constexpr auto max_term_attempts = 13;
	constexpr auto kill_delay = 2;
	auto kill_attempts = 0;

	if ( node->pid <= 0 )
		{
		DBG_STEM("Stem skip killing/waiting node '%s' (PID %d): already dead",
		         node->Name().data(), node->pid);
		return;
		}

	for ( ; ; )
		{
		auto sig = get_kill_signal(kill_attempts++, max_term_attempts);
		KillNode(node, sig);
		usleep(10);

		if ( Wait(node, WNOHANG) )
			break;

		DBG_STEM("Stem waiting to destroy node: %s (PID %d)",
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

		LogError("Supervised node '%s' (PID %d) revived after premature exit",
		         node.Name().data(), node.pid);
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
	DBG_STEM("Stem spawned node: %s (PID %d)", node->Name().data(), node->pid);
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

void Stem::KillNodes(int signal)
	{
	for ( auto& n : nodes )
		KillNode(&n.second, signal);
	}

void Stem::Shutdown(int exit_code)
	{
	DBG_STEM("Stem shutting down with exit code %d", exit_code);
	shutting_down = true;
	constexpr auto max_term_attempts = 13;
	constexpr auto kill_delay = 2;
	auto kill_attempts = 0;

	for ( ; ; )
		{
		auto sig = get_kill_signal(kill_attempts++, max_term_attempts);

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

void Stem::Log(std::string_view type, const char* format, va_list args) const
	{
	auto raw_msg = vfmt(format, args);

	if ( getenv("ZEEK_DEBUG_STEM_STDERR") )
		{
		// Useful when debugging a breaking change to the IPC mechanism itself.
		fprintf(stderr, "%s\n", raw_msg);
		return;
		}

	std::string msg{type.data(), type.size()};
	msg += " ";
	msg += raw_msg;
	safe_write(pipe->OutFD(), msg.data(), msg.size() + 1);
	}

void Stem::LogDebug(const char* format, ...) const
	{
	va_list args;
	va_start(args, format);
	Log("debug", format, args);
	va_end(args);
	}

void Stem::LogError(const char* format, ...) const
	{
	va_list args;
	va_start(args, format);
	Log("error", format, args);
	va_end(args);
	}

Supervisor::SupervisedNode Stem::Run()
	{
	for ( ; ; )
		{
		auto new_node = Poll();

		if ( new_node )
			return *new_node;
		}

	// Shouldn't be reached.
	assert(false);
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

			DBG_STEM("Stem created node: %s (PID %d)", node.Name().data(), node.pid);
			ReportStatus(node);
			}
		else if ( cmd == "destroy" )
			{
			auto it = nodes.find(node_name);
			auto& node = it->second;
			DBG_STEM("Stem destroying node: %s (PID %d)", node_name.data(), node.pid);
			Destroy(&node);
			nodes.erase(it);
			}
		else if ( cmd == "restart" )
			{
			auto it = nodes.find(node_name);
			assert(it != nodes.end());
			auto& node = it->second;
			DBG_STEM("Stem restarting node: %s (PID %d)", node_name.data(), node.pid);
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

std::optional<Supervisor::StemHandle> Supervisor::CreateStem(bool supervisor_mode)
	{
	// If the Stem needs to be re-created via fork()/exec(), then the necessary
	// state information is communicated via ZEEK_STEM env. var.
	auto zeek_stem_env = getenv("ZEEK_STEM");

	if ( zeek_stem_env )
		{
		std::vector<std::string> zeek_stem_nums;
		tokenize_string(zeek_stem_env, ",", &zeek_stem_nums);

		if ( zeek_stem_nums.size() != 5 )
			{
			fprintf(stderr, "invalid ZEEK_STEM environment variable value: '%s'\n",
			        zeek_stem_env);
			exit(1);
			}

		pid_t stem_ppid = std::stoi(zeek_stem_nums[0]);
		int fds[4];

		for ( auto i = 0; i < 4; ++i )
			fds[i] = std::stoi(zeek_stem_nums[i + 1]);

		Stem::State ss;
		ss.pipe = std::make_unique<zeek::detail::PipePair>(FD_CLOEXEC, O_NONBLOCK, fds);
		ss.parent_pid = stem_ppid;

		Stem stem{std::move(ss)};
		supervised_node = stem.Run();
		return {};
		}

	if ( ! supervisor_mode )
		return {};

	Stem::State ss;
	ss.pipe = std::make_unique<zeek::detail::PipePair>(FD_CLOEXEC, O_NONBLOCK);
	ss.parent_pid = getpid();
	auto pid = fork();

	if ( pid == -1 )
		{
		fprintf(stderr, "failed to fork Zeek supervisor stem process: %s\n",
			    strerror(errno));
		exit(1);
		}

	if ( pid == 0 )
		{
		Stem stem{std::move(ss)};
		supervised_node = stem.Run();
		return {};
		}

	StemHandle sh;
	sh.pipe = std::move(ss.pipe);
	sh.pid = pid;
	return std::optional<Supervisor::StemHandle>(std::move(sh));
	}

static BifEnum::Supervisor::ClusterRole role_str_to_enum(std::string_view r)
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
	rval.name = node->GetField("name")->AsString()->CheckString();
	const auto& iface_val = node->GetField("interface");

	if ( iface_val )
		rval.interface = iface_val->AsString()->CheckString();

	const auto& directory_val = node->GetField("directory");

	if ( directory_val )
		rval.directory = directory_val->AsString()->CheckString();

	const auto& stdout_val = node->GetField("stdout_file");

	if ( stdout_val )
		rval.stdout_file = stdout_val->AsString()->CheckString();

	const auto& stderr_val = node->GetField("stderr_file");

	if ( stderr_val )
		rval.stderr_file = stderr_val->AsString()->CheckString();

	const auto& affinity_val = node->GetField("cpu_affinity");

	if ( affinity_val )
		rval.cpu_affinity = affinity_val->AsInt();

	auto scripts_val = node->GetField("scripts")->AsVectorVal();

	for ( auto i = 0u; i < scripts_val->Size(); ++i )
		{
		auto script = scripts_val->At(i)->AsStringVal()->ToStdString();
		rval.scripts.emplace_back(std::move(script));
		}

	auto cluster_table_val = node->GetField("cluster")->AsTableVal();
	auto cluster_table = cluster_table_val->AsTable();
	auto c = cluster_table->InitForIteration();
	HashKey* k;
	TableEntryVal* v;

	while ( (v = cluster_table->NextEntry(k, c)) )
		{
		auto key = cluster_table_val->RecreateIndex(*k);
		delete k;
		auto name = key->Idx(0)->AsStringVal()->ToStdString();
		auto rv = v->GetVal()->AsRecordVal();

		Supervisor::ClusterEndpoint ep;
		ep.role = static_cast<BifEnum::Supervisor::ClusterRole>(rv->GetField("role")->AsEnum());
		ep.host = rv->GetField("host")->AsAddr().AsString();
		ep.port = rv->GetField("p")->AsPortVal()->Port();

		const auto& iface = rv->GetField("interface");

		if ( iface )
			ep.interface = iface->AsStringVal()->ToStdString();

		rval.cluster.emplace(name, std::move(ep));
		}

	return rval;
	}

Supervisor::NodeConfig Supervisor::NodeConfig::FromJSON(std::string_view json)
	{
	Supervisor::NodeConfig rval;
	rapidjson::Document j;
	j.Parse(json.data(), json.size());
	rval.name = j["name"].GetString();

	if ( auto it = j.FindMember("interface"); it != j.MemberEnd() )
		rval.interface = it->value.GetString();

	if ( auto it = j.FindMember("directory"); it != j.MemberEnd() )
		rval.directory = it->value.GetString();

	if ( auto it = j.FindMember("stdout_file"); it != j.MemberEnd() )
		rval.stdout_file= it->value.GetString();

	if ( auto it = j.FindMember("stderr_file"); it != j.MemberEnd() )
		rval.stderr_file= it->value.GetString();

	if ( auto it = j.FindMember("cpu_affinity"); it != j.MemberEnd() )
		rval.cpu_affinity = it->value.GetInt();

	auto& scripts = j["scripts"];

	for ( auto it = scripts.Begin(); it != scripts.End(); ++it )
		rval.scripts.emplace_back(it->GetString());

	auto& cluster = j["cluster"];

	for ( auto it = cluster.MemberBegin(); it != cluster.MemberEnd(); ++it )
		{
		Supervisor::ClusterEndpoint ep;

		auto key = it->name.GetString();
		auto& val = it->value;

		auto& role_str = val["role"];
		ep.role = role_str_to_enum(role_str.GetString());

		ep.host = val["host"].GetString();
		ep.port = val["p"]["port"].GetInt();

		if ( auto it = val.FindMember("interface"); it != val.MemberEnd() )
			ep.interface = it->value.GetString();

		rval.cluster.emplace(key, std::move(ep));
		}

	return rval;
	}

std::string Supervisor::NodeConfig::ToJSON() const
	{
	auto re = std::make_unique<RE_Matcher>("^_");
	return ToRecord()->ToJSON(false, re.get())->ToStdString();
	}

RecordValPtr Supervisor::NodeConfig::ToRecord() const
	{
	const auto& rt = zeek::BifType::Record::Supervisor::NodeConfig;
	auto rval = zeek::make_intrusive<zeek::RecordVal>(rt);
	rval->Assign(rt->FieldOffset("name"), zeek::make_intrusive<zeek::StringVal>(name));

	if ( interface )
		rval->Assign(rt->FieldOffset("interface"), zeek::make_intrusive<zeek::StringVal>(*interface));

	if ( directory )
		rval->Assign(rt->FieldOffset("directory"), zeek::make_intrusive<zeek::StringVal>(*directory));

	if ( stdout_file )
		rval->Assign(rt->FieldOffset("stdout_file"), zeek::make_intrusive<zeek::StringVal>(*stdout_file));

	if ( stderr_file )
		rval->Assign(rt->FieldOffset("stderr_file"), zeek::make_intrusive<zeek::StringVal>(*stderr_file));

	if ( cpu_affinity )
		rval->Assign(rt->FieldOffset("cpu_affinity"), zeek::val_mgr->Int(*cpu_affinity));

	auto st = rt->GetFieldType<VectorType>("scripts");
	auto scripts_val = zeek::make_intrusive<zeek::VectorVal>(std::move(st));

	for ( const auto& s : scripts )
		scripts_val->Assign(scripts_val->Size(), zeek::make_intrusive<zeek::StringVal>(s));

	rval->Assign(rt->FieldOffset("scripts"), std::move(scripts_val));

	auto tt = rt->GetFieldType<TableType>("cluster");
	auto cluster_val = zeek::make_intrusive<zeek::TableVal>(std::move(tt));
	rval->Assign(rt->FieldOffset("cluster"), cluster_val);

	for ( const auto& e : cluster )
		{
		auto& name = e.first;
		auto& ep = e.second;
		auto key = zeek::make_intrusive<zeek::StringVal>(name);
		const auto& ept = zeek::BifType::Record::Supervisor::ClusterEndpoint;
		auto val = zeek::make_intrusive<zeek::RecordVal>(ept);

		val->Assign(ept->FieldOffset("role"), zeek::BifType::Enum::Supervisor::ClusterRole->GetVal(ep.role));
		val->Assign(ept->FieldOffset("host"), zeek::make_intrusive<zeek::AddrVal>(ep.host));
		val->Assign(ept->FieldOffset("p"), zeek::val_mgr->Port(ep.port, TRANSPORT_TCP));

		if ( ep.interface )
			val->Assign(ept->FieldOffset("interface"), zeek::make_intrusive<zeek::StringVal>(*ep.interface));

		cluster_val->Assign(std::move(key), std::move(val));
		}

	return rval;
	}

RecordValPtr Supervisor::Node::ToRecord() const
	{
	const auto& rt = zeek::BifType::Record::Supervisor::NodeStatus;
	auto rval = zeek::make_intrusive<zeek::RecordVal>(rt);

	rval->Assign(rt->FieldOffset("node"), config.ToRecord());

	if ( pid )
		rval->Assign(rt->FieldOffset("pid"), zeek::val_mgr->Int(pid));

	return rval;
	}


static ValPtr supervisor_role_to_cluster_node_type(BifEnum::Supervisor::ClusterRole role)
	{
	static auto node_type = zeek::id::find_type<zeek::EnumType>("Cluster::NodeType");

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

bool Supervisor::SupervisedNode::InitCluster() const
	{
	if ( config.cluster.empty() )
		return false;

	const auto& cluster_node_type = zeek::id::find_type<zeek::RecordType>("Cluster::Node");
	const auto& cluster_nodes_id = zeek::id::find("Cluster::nodes");
	const auto& cluster_manager_is_logger_id = zeek::id::find("Cluster::manager_is_logger");
	auto cluster_nodes = cluster_nodes_id->GetVal()->AsTableVal();
	auto has_logger = false;
	std::optional<std::string> manager_name;

	for ( const auto& e : config.cluster )
		{
		if ( e.second.role == BifEnum::Supervisor::MANAGER )
			manager_name = e.first;
		else if ( e.second.role == BifEnum::Supervisor::LOGGER )
			has_logger = true;
		}

	for ( const auto& e : config.cluster )
		{
		const auto& node_name = e.first;
		const auto& ep = e.second;
		auto key = zeek::make_intrusive<zeek::StringVal>(node_name);
		auto val = zeek::make_intrusive<zeek::RecordVal>(cluster_node_type);

		auto node_type = supervisor_role_to_cluster_node_type(ep.role);
		val->Assign(cluster_node_type->FieldOffset("node_type"), std::move(node_type));
		val->Assign(cluster_node_type->FieldOffset("ip"), zeek::make_intrusive<zeek::AddrVal>(ep.host));
		val->Assign(cluster_node_type->FieldOffset("p"), zeek::val_mgr->Port(ep.port, TRANSPORT_TCP));

		if ( ep.interface )
			val->Assign(cluster_node_type->FieldOffset("interface"),
			            zeek::make_intrusive<zeek::StringVal>(*ep.interface));

		if ( manager_name && ep.role != BifEnum::Supervisor::MANAGER )
			val->Assign(cluster_node_type->FieldOffset("manager"),
			            zeek::make_intrusive<zeek::StringVal>(*manager_name));

		cluster_nodes->Assign(std::move(key), std::move(val));
		}

	cluster_manager_is_logger_id->SetVal(zeek::val_mgr->Bool(! has_logger));
	return true;
	}

void Supervisor::SupervisedNode::Init(zeek::Options* options) const
	{
	const auto& node_name = config.name;

	if ( config.directory )
		{
		if ( chdir(config.directory->data()) )
			{
			fprintf(stderr, "node '%s' failed to chdir to %s: %s\n",
			        node_name.data(), config.directory->data(),
			        strerror(errno));
			exit(1);
			}
		}

	if ( config.stderr_file )
		{
		auto fd = open(config.stderr_file->data(),
			           O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC,
			           0600);

		if ( fd == -1 || dup2(fd, STDERR_FILENO) == -1 )
			{
			fprintf(stderr, "node '%s' failed to create stderr file %s: %s\n",
			        node_name.data(), config.stderr_file->data(),
			        strerror(errno));
			exit(1);
			}

		safe_close(fd);
		}

	if ( config.stdout_file )
		{
		auto fd = open(config.stdout_file->data(),
		               O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC,
		               0600);

		if ( fd == -1 || dup2(fd, STDOUT_FILENO) == -1 )
			{
			fprintf(stderr, "node '%s' failed to create stdout file %s: %s\n",
			        node_name.data(), config.stdout_file->data(),
			        strerror(errno));
			exit(1);
			}

		safe_close(fd);
		}

	if ( config.cpu_affinity )
		{
		auto res = zeek::set_affinity(*config.cpu_affinity);

		if ( ! res )
			fprintf(stderr, "node '%s' failed to set CPU affinity: %s\n",
			        node_name.data(), strerror(errno));
		}

	if ( ! config.cluster.empty() )
		{
		if ( setenv("CLUSTER_NODE", node_name.data(), true) == -1 )
			{
			fprintf(stderr, "node '%s' failed to setenv: %s\n",
			        node_name.data(), strerror(errno));
			exit(1);
			}
		}

	options->filter_supervised_node_options();

	if ( config.interface )
		options->interface = *config.interface;

	for ( const auto& s : config.scripts )
		options->scripts_to_load.emplace_back(s);
	}

RecordValPtr Supervisor::Status(std::string_view node_name)
	{
	auto rval = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Supervisor::Status);
	const auto& tt = zeek::BifType::Record::Supervisor::Status->GetFieldType("nodes");
	auto node_table_val = zeek::make_intrusive<zeek::TableVal>(zeek::cast_intrusive<TableType>(tt));
	rval->Assign(0, node_table_val);

	if ( node_name.empty() )
		{
		for ( const auto& n : nodes )
			{
			const auto& name = n.first;
			const auto& node = n.second;
			auto key = zeek::make_intrusive<zeek::StringVal>(name);
			auto val = node.ToRecord();
			node_table_val->Assign(std::move(key), std::move(val));
			}
		}
	else
		{
		auto it = nodes.find(node_name);

		if ( it == nodes.end() )
			return rval;

		const auto& name = it->first;
		const auto& node = it->second;
		auto key = zeek::make_intrusive<zeek::StringVal>(name);
		auto val = node.ToRecord();
		node_table_val->Assign(std::move(key), std::move(val));
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
