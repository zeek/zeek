// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/supervisor/Supervisor.h"

#include "zeek/zeek-config.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <sstream>
#include <utility>
#include <variant>

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>

extern "C"
	{
#include "zeek/3rdparty/setsignal.h"
	}

#include "zeek/DebugLogger.h"
#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/ID.h"
#include "zeek/NetVar.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/input.h"
#include "zeek/iosource/Manager.h"
#include "zeek/util.h"
#include "zeek/zeek-affinity.h"

#ifdef DEBUG
#define DBG_STEM(args...) stem->LogDebug(args);
#else
#define DBG_STEM
#endif

using namespace zeek;
using zeek::detail::SupervisedNode;
using zeek::detail::SupervisorNode;
using zeek::detail::SupervisorStemHandle;

std::optional<SupervisedNode> Supervisor::supervised_node;

namespace
	{

struct Stem
	{
	/**
	 * State used to initialize the Stem process.
	 */
	struct State
		{
		/**
		 * Bidirectional pipes that allow the Supervisor and Stem to talk.
		 */
		std::unique_ptr<detail::PipePair> pipe;
		/**
		 * The Stem's parent process ID (i.e. PID of the Supervisor).
		 */
		pid_t parent_pid = 0;
		};

	Stem(State stem_state);

	~Stem();

	SupervisedNode Run();

	std::optional<SupervisedNode> Poll();

	std::optional<SupervisedNode> Revive();

	void Reap();

	/**
	 * This performs fork() to initialize the supervised-node structure.
	 * There's three possible outcomes:
	 *   - return value is SupervisedNode: we are the child process
	 *   - return value is True: we are the parent and fork() succeeded
	 *   - return value is False: we are the parent and fork() failed
	 */
	std::variant<bool, SupervisedNode> Spawn(SupervisorNode* node);

	int AliveNodeCount() const;

	void KillNodes(int signal);

	void KillNode(SupervisorNode* node, int signal) const;

	void Destroy(SupervisorNode* node) const;

	bool Wait(SupervisorNode* node, int options) const;

	void Shutdown(int exit_code);

	void ReportStatus(const SupervisorNode& node) const;

	void Log(std::string_view type, const char* format, va_list args) const;

	void LogDebug(const char* format, ...) const __attribute__((format(printf, 2, 3)));

	void LogError(const char* format, ...) const __attribute__((format(printf, 2, 3)));

	pid_t parent_pid;
	int last_signal = -1;
	std::unique_ptr<detail::Flare> signal_flare;
	std::unique_ptr<detail::PipePair> pipe;
	std::map<std::string, SupervisorNode> nodes;
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

static std::vector<std::string> extract_msgs(std::string* buffer, char delim)
	{
	std::vector<std::string> rval;

	for ( ;; )
		{
		auto msg_end = buffer->find(delim);

		if ( msg_end == std::string::npos )
			// Don't have any full messages left
			break;

		auto msg = buffer->substr(0, msg_end);
		rval.emplace_back(std::move(msg));
		buffer->erase(0, msg_end + 1);
		}

	return rval;
	}

static std::pair<int, std::vector<std::string>> read_msgs(int fd, std::string* buffer, char delim)
	{
	constexpr auto buf_size = 256;
	char buf[buf_size];

	int bytes_read = read(fd, buf, buf_size);

	if ( bytes_read <= 0 )
		return {bytes_read, {}};

	buffer->append(buf, bytes_read);
	return {bytes_read, extract_msgs(buffer, delim)};
	}

static std::string make_create_message(const Supervisor::NodeConfig& node)
	{
	auto json_str = node.ToJSON();
	return util::fmt("create %s %s", node.name.data(), json_str.data());
	}

detail::ParentProcessCheckTimer::ParentProcessCheckTimer(double t, double arg_interval)
	: Timer(t, TIMER_PPID_CHECK), interval(arg_interval)
	{
	}

void detail::ParentProcessCheckTimer::Dispatch(double t, bool is_expire)
	{
	// Note: only simple + portable way of detecting loss of parent
	// process seems to be polling for change in PPID.  There's platform
	// specific ways if we do end up needing something more responsive
	// and/or have to avoid overhead of polling, but maybe not worth
	// the additional complexity:
	//   Linux:   prctl(PR_SET_PDEATHSIG, ...)
	//   FreeBSD: procctl(PROC_PDEATHSIG_CTL)
	// Also note the Stem process has its own polling loop with similar logic.
	if ( Supervisor::ThisNode()->parent_pid != getppid() )
		run_state::detail::zeek_terminate_loop("supervised node was orphaned");

	if ( ! is_expire )
		timer_mgr->Add(new ParentProcessCheckTimer(run_state::network_time + interval, interval));
	}

Supervisor::Supervisor(Supervisor::Config cfg, SupervisorStemHandle sh)
	: config(std::move(cfg)), stem_pid(sh.pid), stem_pipe(std::move(sh.pipe))
	{
	stem_stdout.pipe = std::move(sh.stdout_pipe);
	stem_stdout.prefix = "[supervisor:STDOUT] ";
	stem_stdout.stream = stdout;
	stem_stderr.pipe = std::move(sh.stderr_pipe);
	stem_stderr.prefix = "[supervisor:STDERR] ";
	stem_stderr.stream = stderr;

	DBG_LOG(DBG_SUPERVISOR, "forked stem process %d", stem_pid);
	setsignal(SIGCHLD, supervisor_signal_handler);

	int status;
	auto res = waitpid(stem_pid, &status, WNOHANG);

	if ( res == 0 )
		// Good, stem process is alive and the SIGCHLD handler will keep it so.
		return;

	if ( res == -1 )
		fprintf(stderr, "Supervisor failed to get status of stem process: %s\n", strerror(errno));
	else
		{
		if ( WIFEXITED(status) )
			fprintf(stderr, "Supervisor stem died early with exit code %d\n", WEXITSTATUS(status));
		else if ( WIFSIGNALED(status) )
			fprintf(stderr, "Supervisor stem died early by signal %d\n", WTERMSIG(status));
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
		util::zeek_strerror_r(errno, tmp, sizeof(tmp));
		reporter->Error("Failed to send SIGTERM to stem process: %s", tmp);
		}
	else
		{
		int status;
		auto wait_res = waitpid(stem_pid, &status, 0);

		if ( wait_res == -1 )
			{
			char tmp[256];
			util::zeek_strerror_r(errno, tmp, sizeof(tmp));
			reporter->Error("Failed to wait for stem process to exit: %s", tmp);
			}
		}

	stem_stdout.Drain();
	stem_stderr.Drain();

	while ( ProcessMessages() != 0 )
		;
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
		util::zeek_strerror_r(errno, tmp, sizeof(tmp));
		reporter->Error("Supervisor failed to get exit status"
		                " of stem process: %s",
		                tmp);
		return;
		}

	stem_pid = 0;

	if ( WIFEXITED(status) )
		{
		DBG_LOG(DBG_SUPERVISOR, "stem process exited with status %d", WEXITSTATUS(status));
		}
	else if ( WIFSIGNALED(status) )
		{
		DBG_LOG(DBG_SUPERVISOR, "stem process terminated by signal %d", WTERMSIG(status));
		}
	else
		reporter->Error("Supervisor failed to get exit status"
		                " of stem process for unknown reason");
	}

struct ForkResult
	{
	pid_t pid;
	std::unique_ptr<detail::Pipe> stdout_pipe;
	std::unique_ptr<detail::Pipe> stderr_pipe;
	};

static ForkResult fork_with_stdio_redirect(const char* where)
	{
	auto out = std::make_unique<detail::Pipe>(FD_CLOEXEC, FD_CLOEXEC, O_NONBLOCK, O_NONBLOCK);
	auto err = std::make_unique<detail::Pipe>(FD_CLOEXEC, FD_CLOEXEC, O_NONBLOCK, O_NONBLOCK);
	auto pid = fork();

	if ( pid == 0 )
		{
		while ( dup2(out->WriteFD(), STDOUT_FILENO) == -1 )
			{
			if ( errno == EINTR )
				continue;

			fprintf(stderr, "Supervisor %s fork() stdout redirect failed: %s\n", where,
			        strerror(errno));
			}

		while ( dup2(err->WriteFD(), STDERR_FILENO) == -1 )
			{
			if ( errno == EINTR )
				continue;

			fprintf(stderr, "Supervisor %s fork() stderr redirect failed: %s\n", where,
			        strerror(errno));
			}

		// Default buffering for stdout may be fully-buffered if not a TTY,
		// so set line-buffering since the Supervisor/Stem has to emit
		// only line-buffered messages anyway.
		setlinebuf(stdout);
		// Default buffering for stderr may be unbuffered, but since
		// Supervisor/Stem has to emit line-buffered messages, just set
		// it to line-buffered as well.
		setlinebuf(stderr);
		}

	return {pid, std::move(out), std::move(err)};
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
	auto fork_res = fork_with_stdio_redirect("stem revival");
	stem_pid = fork_res.pid;

	if ( stem_pid == -1 )
		{
		stem_pid = 0;
		char tmp[256];
		util::zeek_strerror_r(errno, tmp, sizeof(tmp));
		reporter->Error("failed to fork Zeek supervisor stem process: %s\n", tmp);
		signal_flare.Fire();
		// Sleep to avoid spinning too fast in a revival-fail loop.
		sleep(1);
		return;
		}

	if ( stem_pid == 0 )
		{
		// Child stem process needs to exec()
		auto stem_env = util::fmt("%d,%d,%d,%d,%d", stem_ppid, stem_pipe->In().ReadFD(),
		                          stem_pipe->In().WriteFD(), stem_pipe->Out().ReadFD(),
		                          stem_pipe->Out().WriteFD());

		if ( setenv("ZEEK_STEM", stem_env, true) == -1 )
			{
			fprintf(stderr, "setenv(ZEEK_STEM) failed: %s\n", strerror(errno));
			exit(1);
			}

		stem_pipe->In().UnsetFlags(FD_CLOEXEC);
		stem_pipe->Out().UnsetFlags(FD_CLOEXEC);

		char** args = new char*[detail::zeek_argc + 1];
		args[0] = config.zeek_exe_path.data();
		args[detail::zeek_argc] = nullptr;

		for ( auto i = 1; i < detail::zeek_argc; ++i )
			args[i] = detail::zeek_argv[i];

		auto res = execv(config.zeek_exe_path.data(), args);
		fprintf(stderr, "failed to exec Zeek supervisor stem process: %s\n", strerror(errno));
		exit(1);
		}
	else
		{
		if ( ! iosource_mgr->UnregisterFd(stem_stdout.pipe->ReadFD(), this) )
			reporter->FatalError("Revived supervisor stem failed to unregister "
			                     "redirected stdout pipe");

		if ( ! iosource_mgr->UnregisterFd(stem_stderr.pipe->ReadFD(), this) )
			reporter->FatalError("Revived supervisor stem failed to unregister "
			                     "redirected stderr pipe");

		stem_stdout.Drain();
		stem_stderr.Drain();
		stem_stdout.pipe = std::move(fork_res.stdout_pipe);
		stem_stderr.pipe = std::move(fork_res.stderr_pipe);

		if ( ! iosource_mgr->RegisterFd(stem_stdout.pipe->ReadFD(), this) )
			reporter->FatalError("Revived supervisor stem failed to register "
			                     "redirected stdout pipe");

		if ( ! iosource_mgr->RegisterFd(stem_stderr.pipe->ReadFD(), this) )
			reporter->FatalError("Revived supervisor stem failed to register "
			                     "redirected stderr pipe");
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
		util::safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
		}
	}

void Supervisor::InitPostScript()
	{
	node_status = event_registry->Register("Supervisor::node_status");

	stem_stdout.hook = id::find_func("Supervisor::stdout_hook");
	stem_stderr.hook = id::find_func("Supervisor::stderr_hook");

	iosource_mgr->Register(this);

	if ( ! iosource_mgr->RegisterFd(signal_flare.FD(), this) )
		reporter->FatalError("Supervisor stem failed to register signal_flare");

	if ( ! iosource_mgr->RegisterFd(stem_pipe->InFD(), this) )
		reporter->FatalError("Supervisor stem failed to register stem_pipe");

	if ( ! iosource_mgr->RegisterFd(stem_stdout.pipe->ReadFD(), this) )
		reporter->FatalError("Supervisor stem failed to register stdout pipe");

	if ( ! iosource_mgr->RegisterFd(stem_stderr.pipe->ReadFD(), this) )
		reporter->FatalError("Supervisor stem failed to register stderr pipe");
	}

double Supervisor::GetNextTimeout()
	{
	return -1;
	}

void Supervisor::Process()
	{
	HandleChildSignal();
	stem_stdout.Process();
	stem_stderr.Process();
	ProcessMessages();
	}

void zeek::detail::LineBufferedPipe::Emit(const char* msg) const
	{
	if ( ! msg[0] )
		// Skip empty lines.
		return;

	auto msg_start = msg;
	auto do_print = true;

	if ( hook )
		{
		auto node = "";
		auto node_len = 0;

		if ( msg[0] == '[' )
			{
			auto end = strchr(msg, ']');

			if ( end )
				{
				node = msg + 1;
				node_len = end - node;
				msg = end + 1;

				if ( msg[0] == ' ' )
					++msg;
				}
			}

		auto res = hook->Invoke(make_intrusive<StringVal>(node_len, node),
		                        make_intrusive<StringVal>(msg));
		do_print = res->AsBool();
		}

	if ( do_print )
		fprintf(stream, "%s%s\n", prefix.data(), msg_start);
	}

void zeek::detail::LineBufferedPipe::Drain()
	{
	while ( Process() != 0 )
		;

	Emit(buffer.data());
	buffer.clear();
	pipe = nullptr;
	}

size_t zeek::detail::LineBufferedPipe::Process()
	{
	if ( ! pipe )
		return 0;

	auto [bytes_read, msgs] = read_msgs(pipe->ReadFD(), &buffer, '\n');

	if ( bytes_read <= 0 )
		return 0;

	for ( const auto& msg : msgs )
		Emit(msg.data());

	return bytes_read;
	}

size_t Supervisor::ProcessMessages()
	{
	auto [bytes_read, msgs] = read_msgs(stem_pipe->InFD(), &msg_buffer, '\0');

	for ( auto& msg : msgs )
		{
		DBG_LOG(DBG_SUPERVISOR, "read msg from Stem: %s", msg.data());
		std::vector<std::string> msg_tokens;
		util::tokenize_string(msg, " ", &msg_tokens);
		const auto& type = msg_tokens[0];

		if ( type == "status" )
			{
			const auto& name = msg_tokens[1];
			auto it = nodes.find(name);

			if ( it != nodes.end() )
				it->second.pid = std::stoi(msg_tokens[2]);

			if ( node_status )
				event_mgr.Enqueue(node_status, make_intrusive<StringVal>(name),
				                  val_mgr->Count(std::stoi(msg_tokens[2])));
			}
		else if ( type == "debug" )
			{
			// Already logged the unparsed message above.
			}
		else if ( type == "error" )
			{
			msg_tokens.erase(msg_tokens.begin());
			auto err_msg = util::implode_string_vector(msg_tokens, " ");
			reporter->Error("%s", err_msg.data());
			}
		else
			reporter->Error("Supervisor got unknown msg: %s", msg.data());
		}

	return msgs.size();
	}

Stem::Stem(State ss)
	: parent_pid(ss.parent_pid), signal_flare(new detail::Flare()), pipe(std::move(ss.pipe))
	{
	util::detail::set_thread_name("zeek.stem");
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

bool Stem::Wait(SupervisorNode* node, int options) const
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
		LogError("Stem failed to get node exit status '%s' (PID %d): %s", node->Name().data(),
		         node->pid, strerror(errno));
		return false;
		}

	if ( WIFEXITED(status) )
		{
		node->exit_status = WEXITSTATUS(status);
		DBG_STEM("node '%s' (PID %d) exited with status %d", node->Name().data(), node->pid,
		         node->exit_status);

		if ( ! node->killed )
			LogError("Supervised node '%s' (PID %d) exited prematurely with status %d",
			         node->Name().data(), node->pid, node->exit_status);
		}
	else if ( WIFSIGNALED(status) )
		{
		node->signal_number = WTERMSIG(status);
		DBG_STEM("node '%s' (PID %d) terminated by signal %d", node->Name().data(), node->pid,
		         node->signal_number);

		if ( ! node->killed )
			LogError("Supervised node '%s' (PID %d) terminated prematurely by signal %d",
			         node->Name().data(), node->pid, node->signal_number);
		}
	else
		LogError("Stem failed to get node exit status '%s' (PID %d)", node->Name().data(),
		         node->pid);

	node->pid = 0;
	node->stdout_pipe.Drain();
	node->stderr_pipe.Drain();
	return true;
	}

void Stem::KillNode(SupervisorNode* node, int signal) const
	{
	if ( node->pid <= 0 )
		{
		DBG_STEM("Stem skip killing node '%s' (PID %d): already dead", node->Name().data(),
		         node->pid);
		return;
		}

	node->killed = true;
	auto kill_res = kill(node->pid, signal);

	if ( kill_res == -1 )
		LogError("Failed to send signal to node '%s' (PID %d): %s", node->Name().data(), node->pid,
		         strerror(errno));
	}

static int get_kill_signal(int attempts, int max_attempts)
	{
	if ( getenv("ZEEK_SUPERVISOR_NO_SIGKILL") )
		return SIGTERM;

	if ( attempts < max_attempts )
		return SIGTERM;

	return SIGKILL;
	}

void Stem::Destroy(SupervisorNode* node) const
	{
	constexpr auto max_term_attempts = 13;
	constexpr auto kill_delay = 2;
	auto kill_attempts = 0;

	if ( node->pid <= 0 )
		{
		DBG_STEM("Stem skip killing/waiting node '%s' (PID %d): already dead", node->Name().data(),
		         node->pid);
		return;
		}

	for ( ;; )
		{
		auto sig = get_kill_signal(kill_attempts++, max_term_attempts);
		KillNode(node, sig);
		usleep(10);

		if ( Wait(node, WNOHANG) )
			{
			break;
			}

		DBG_STEM("Stem waiting to destroy node: %s (PID %d)", node->Name().data(), node->pid);
		sleep(kill_delay);
		}
	}

std::optional<SupervisedNode> Stem::Revive()
	{
	constexpr auto attempts_before_delay_increase = 3;
	constexpr auto delay_increase_factor = 2;
	constexpr auto reset_revival_state_after = 30;
	auto now = std::chrono::steady_clock::now();
	auto revival_reset = std::chrono::seconds(reset_revival_state_after);

	for ( auto& n : nodes )
		{
		auto& node = n.second;
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

		auto spawn_res = Spawn(&node);

		if ( std::holds_alternative<SupervisedNode>(spawn_res) )
			return std::get<SupervisedNode>(spawn_res);

		if ( std::get<bool>(spawn_res) )
			LogError("Supervised node '%s' (PID %d) revived after premature exit",
			         node.Name().data(), node.pid);

		ReportStatus(node);
		}

	return {};
	}

std::variant<bool, SupervisedNode> Stem::Spawn(SupervisorNode* node)
	{
	auto ppid = getpid();
	auto fork_res = fork_with_stdio_redirect(util::fmt("node %s", node->Name().data()));
	auto node_pid = fork_res.pid;

	if ( node_pid == -1 )
		{
		LogError("failed to fork Zeek node '%s': %s", node->Name().data(), strerror(errno));
		return false;
		}

	if ( node_pid == 0 )
		{
		setsignal(SIGCHLD, SIG_DFL);
		setsignal(SIGTERM, SIG_DFL);
		util::detail::set_thread_name(util::fmt("zeek.%s", node->Name().data()));
		SupervisedNode rval;
		rval.config = node->config;
		rval.parent_pid = ppid;
		return rval;
		}

	node->pid = node_pid;
	auto prefix = util::fmt("[%s] ", node->Name().data());
	node->stdout_pipe.pipe = std::move(fork_res.stdout_pipe);
	node->stdout_pipe.prefix = prefix;
	node->stdout_pipe.stream = stdout;
	node->stderr_pipe.pipe = std::move(fork_res.stderr_pipe);
	node->stderr_pipe.prefix = prefix;
	node->stderr_pipe.stream = stderr;
	node->spawn_time = std::chrono::steady_clock::now();
	DBG_STEM("Stem spawned node: %s (PID %d)", node->Name().data(), node->pid);
	return true;
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

	for ( ;; )
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
			{
			exit(exit_code);
			}

		DBG_STEM("Stem nodes still alive %d, sleeping for %d seconds", nodes_alive, kill_delay);

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

void Stem::ReportStatus(const SupervisorNode& node) const
	{
	std::string msg = util::fmt("status %s %d", node.Name().data(), node.pid);
	util::safe_write(pipe->OutFD(), msg.data(), msg.size() + 1);
	}

void Stem::Log(std::string_view type, const char* format, va_list args) const
	{
	auto raw_msg = util::vfmt(format, args);

	if ( getenv("ZEEK_DEBUG_STEM_STDERR") )
		{
		// Useful when debugging a breaking change to the IPC mechanism itself.
		fprintf(stderr, "%s\n", raw_msg);
		return;
		}

	std::string msg{type.data(), type.size()};
	msg += " ";
	msg += raw_msg;
	util::safe_write(pipe->OutFD(), msg.data(), msg.size() + 1);
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

SupervisedNode Stem::Run()
	{
	for ( ;; )
		{
		auto new_node = Poll();

		if ( new_node )
			return *new_node;
		}

	// Shouldn't be reached.
	assert(false);
	return {};
	}

std::optional<SupervisedNode> Stem::Poll()
	{
	std::map<std::string, int> node_pollfd_indices;
	constexpr auto fixed_fd_count = 2;
	const auto total_fd_count = fixed_fd_count + (nodes.size() * 2);
	auto pfds = std::make_unique<pollfd[]>(total_fd_count);
	int pfd_idx = 0;
	pfds[pfd_idx++] = {pipe->InFD(), POLLIN, 0};
	pfds[pfd_idx++] = {signal_flare->FD(), POLLIN, 0};

	for ( const auto& [name, node] : nodes )
		{
		node_pollfd_indices[name] = pfd_idx;

		if ( node.stdout_pipe.pipe )
			pfds[pfd_idx++] = {node.stdout_pipe.pipe->ReadFD(), POLLIN, 0};
		else
			pfds[pfd_idx++] = {-1, POLLIN, 0};

		if ( node.stderr_pipe.pipe )
			pfds[pfd_idx++] = {node.stderr_pipe.pipe->ReadFD(), POLLIN, 0};
		else
			pfds[pfd_idx++] = {-1, POLLIN, 0};
		}

	// Note: the poll timeout here is for periodically checking if the parent
	// process died (see below).
	constexpr auto poll_timeout_ms = 1000;
	auto res = poll(pfds.get(), total_fd_count, poll_timeout_ms);

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

	for ( auto& [name, node] : nodes )
		{
		auto idx = node_pollfd_indices[name];

		if ( pfds[idx].revents )
			node.stdout_pipe.Process();

		if ( pfds[idx + 1].revents )
			node.stderr_pipe.Process();
		}

	if ( ! pfds[0].revents )
		// No messages from supervisor to process, so return early.
		return {};

	auto [bytes_read, msgs] = read_msgs(pipe->InFD(), &msg_buffer, '\0');

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

	for ( auto& msg : msgs )
		{
		std::vector<std::string> msg_tokens;
		util::tokenize_string(std::move(msg), " ", &msg_tokens, 2);
		const auto& cmd = msg_tokens[0];
		const auto& node_name = msg_tokens[1];

		if ( cmd == "create" )
			{
			const auto& node_json = msg_tokens[2];
			assert(nodes.find(node_name) == nodes.end());
			auto node_config = Supervisor::NodeConfig::FromJSON(node_json);
			auto it = nodes.emplace(node_name, std::move(node_config)).first;
			auto& node = it->second;

			DBG_STEM("Stem creating node: %s (PID %d)", node.Name().data(), node.pid);
			auto spawn_res = Spawn(&node);

			if ( std::holds_alternative<SupervisedNode>(spawn_res) )
				return std::get<SupervisedNode>(spawn_res);

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

			auto spawn_res = Spawn(&node);

			if ( std::holds_alternative<SupervisedNode>(spawn_res) )
				return std::get<SupervisedNode>(spawn_res);

			ReportStatus(node);
			}
		else
			LogError("Stem got unknown supervisor message: %s", cmd.data());
		}

	return {};
	}

std::optional<SupervisorStemHandle> Supervisor::CreateStem(bool supervisor_mode)
	{
	// If the Stem needs to be re-created via fork()/exec(), then the necessary
	// state information is communicated via ZEEK_STEM env. var.
	auto zeek_stem_env = getenv("ZEEK_STEM");

	if ( zeek_stem_env )
		{
		// Supervisor emits line-buffered messages stdout/stderr redirects
		// so ensure they're at least not fully-buffered after doing exec()
		setlinebuf(stdout);
		setlinebuf(stderr);
		std::vector<std::string> zeek_stem_nums;
		util::tokenize_string(zeek_stem_env, ",", &zeek_stem_nums);

		if ( zeek_stem_nums.size() != 5 )
			{
			fprintf(stderr, "invalid ZEEK_STEM environment variable value: '%s'\n", zeek_stem_env);
			exit(1);
			}

		pid_t stem_ppid = std::stoi(zeek_stem_nums[0]);
		int fds[4];

		for ( auto i = 0; i < 4; ++i )
			fds[i] = std::stoi(zeek_stem_nums[i + 1]);

		Stem::State ss;
		ss.pipe = std::make_unique<detail::PipePair>(FD_CLOEXEC, O_NONBLOCK, fds);
		ss.parent_pid = stem_ppid;

		Stem stem{std::move(ss)};
		supervised_node = stem.Run();
		return {};
		}

	if ( ! supervisor_mode )
		return {};

	Stem::State ss;
	ss.pipe = std::make_unique<detail::PipePair>(FD_CLOEXEC, O_NONBLOCK);
	ss.parent_pid = getpid();
	auto fork_res = fork_with_stdio_redirect("stem");
	auto pid = fork_res.pid;

	if ( pid == -1 )
		{
		fprintf(stderr, "failed to fork Zeek supervisor stem process: %s\n", strerror(errno));
		exit(1);
		}

	if ( pid == 0 )
		{
		Stem stem{std::move(ss)};
		supervised_node = stem.Run();
		return {};
		}

	SupervisorStemHandle sh;
	sh.pipe = std::move(ss.pipe);
	sh.pid = pid;
	sh.stdout_pipe = std::move(fork_res.stdout_pipe);
	sh.stderr_pipe = std::move(fork_res.stderr_pipe);
	return std::optional<SupervisorStemHandle>(std::move(sh));
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
	rval.name = node->GetFieldAs<StringVal>("name")->CheckString();
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

	const auto& bare_mode_val = node->GetField("bare_mode");

	if ( bare_mode_val )
		rval.bare_mode = bare_mode_val->AsBool();

	auto addl_base_scripts_val = node->GetField("addl_base_scripts")->AsVectorVal();

	for ( auto i = 0u; i < addl_base_scripts_val->Size(); ++i )
		{
		auto script = addl_base_scripts_val->StringValAt(i)->ToStdString();
		rval.addl_base_scripts.emplace_back(std::move(script));
		}

	auto addl_user_scripts_val = node->GetField("addl_user_scripts")->AsVectorVal();

	for ( auto i = 0u; i < addl_user_scripts_val->Size(); ++i )
		{
		auto script = addl_user_scripts_val->StringValAt(i)->ToStdString();
		rval.addl_user_scripts.emplace_back(std::move(script));
		}

	auto scripts_val = node->GetField("scripts")->AsVectorVal();

	for ( auto i = 0u; i < scripts_val->Size(); ++i )
		{
		auto script = scripts_val->StringValAt(i)->ToStdString();
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		rval.scripts.emplace_back(std::move(script));
#pragma GCC diagnostic pop
		}

	auto env_table_val = node->GetField("env")->AsTableVal();
	auto env_table = env_table_val->AsTable();

	for ( const auto& ee : *env_table )
		{
		auto k = ee.GetHashKey();
		auto* v = ee.value;

		auto key = env_table_val->RecreateIndex(*k);
		auto name = key->Idx(0)->AsStringVal()->ToStdString();
		auto val = v->GetVal()->AsStringVal()->ToStdString();

		rval.env[name] = val;
		}

	auto cluster_table_val = node->GetField("cluster")->AsTableVal();
	auto cluster_table = cluster_table_val->AsTable();

	for ( const auto& cte : *cluster_table )
		{
		auto k = cte.GetHashKey();
		auto* v = cte.value;

		auto key = cluster_table_val->RecreateIndex(*k);
		auto name = key->Idx(0)->AsStringVal()->ToStdString();
		auto rv = v->GetVal()->AsRecordVal();

		Supervisor::ClusterEndpoint ep;
		ep.role = static_cast<BifEnum::Supervisor::ClusterRole>(rv->GetFieldAs<EnumVal>("role"));
		ep.host = rv->GetFieldAs<AddrVal>("host").AsString();
		ep.port = rv->GetFieldAs<PortVal>("p")->Port();

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
		rval.stdout_file = it->value.GetString();

	if ( auto it = j.FindMember("stderr_file"); it != j.MemberEnd() )
		rval.stderr_file = it->value.GetString();

	if ( auto it = j.FindMember("cpu_affinity"); it != j.MemberEnd() )
		rval.cpu_affinity = it->value.GetInt();

	if ( auto it = j.FindMember("bare_mode"); it != j.MemberEnd() )
		rval.bare_mode = it->value.GetBool();

	auto& addl_base_scripts = j["addl_base_scripts"];

	for ( auto it = addl_base_scripts.Begin(); it != addl_base_scripts.End(); ++it )
		rval.addl_base_scripts.emplace_back(it->GetString());

	auto& addl_user_scripts = j["addl_user_scripts"];

	for ( auto it = addl_user_scripts.Begin(); it != addl_user_scripts.End(); ++it )
		rval.addl_user_scripts.emplace_back(it->GetString());

	auto& scripts = j["scripts"];

	for ( auto it = scripts.Begin(); it != scripts.End(); ++it )
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		rval.scripts.emplace_back(it->GetString());
#pragma GCC diagnostic pop

	auto& env = j["env"];

	for ( auto it = env.MemberBegin(); it != env.MemberEnd(); ++it )
		rval.env[it->name.GetString()] = it->value.GetString();

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
	const auto& rt = BifType::Record::Supervisor::NodeConfig;
	auto rval = make_intrusive<RecordVal>(rt);
	rval->AssignField("name", name);

	if ( interface )
		rval->AssignField("interface", *interface);

	if ( directory )
		rval->AssignField("directory", *directory);

	if ( stdout_file )
		rval->AssignField("stdout_file", *stdout_file);

	if ( stderr_file )
		rval->AssignField("stderr_file", *stderr_file);

	if ( cpu_affinity )
		rval->AssignField("cpu_affinity", *cpu_affinity);

	if ( bare_mode )
		rval->AssignField("bare_mode", *bare_mode);

	auto abs_t = rt->GetFieldType<VectorType>("addl_base_scripts");
	auto addl_base_scripts_val = make_intrusive<VectorVal>(std::move(abs_t));

	for ( const auto& s : addl_base_scripts )
		addl_base_scripts_val->Assign(addl_base_scripts_val->Size(), make_intrusive<StringVal>(s));

	rval->AssignField("addl_base_scripts", std::move(addl_base_scripts_val));

	auto aus_t = rt->GetFieldType<VectorType>("addl_user_scripts");
	auto addl_user_scripts_val = make_intrusive<VectorVal>(std::move(aus_t));

	for ( const auto& s : addl_user_scripts )
		addl_user_scripts_val->Assign(addl_user_scripts_val->Size(), make_intrusive<StringVal>(s));

	rval->AssignField("addl_user_scripts", std::move(addl_user_scripts_val));

	auto st = rt->GetFieldType<VectorType>("scripts");
	auto scripts_val = make_intrusive<VectorVal>(std::move(st));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	for ( const auto& s : scripts )
#pragma GCC diagnostic pop
		scripts_val->Assign(scripts_val->Size(), make_intrusive<StringVal>(s));

	rval->AssignField("scripts", std::move(scripts_val));

	auto et = rt->GetFieldType<TableType>("env");
	auto env_val = make_intrusive<TableVal>(std::move(et));
	rval->AssignField("env", env_val);

	for ( const auto& e : env )
		{
		auto name = make_intrusive<StringVal>(e.first);
		auto val = make_intrusive<StringVal>(e.second);
		env_val->Assign(std::move(name), std::move(val));
		}

	auto tt = rt->GetFieldType<TableType>("cluster");
	auto cluster_val = make_intrusive<TableVal>(std::move(tt));
	rval->AssignField("cluster", cluster_val);

	for ( const auto& e : cluster )
		{
		auto& name = e.first;
		auto& ep = e.second;
		auto key = make_intrusive<StringVal>(name);
		const auto& ept = BifType::Record::Supervisor::ClusterEndpoint;
		auto val = make_intrusive<RecordVal>(ept);

		val->AssignField("role", BifType::Enum::Supervisor::ClusterRole->GetEnumVal(ep.role));
		val->AssignField("host", make_intrusive<AddrVal>(ep.host));
		val->AssignField("p", val_mgr->Port(ep.port, TRANSPORT_TCP));

		if ( ep.interface )
			val->AssignField("interface", *ep.interface);

		cluster_val->Assign(std::move(key), std::move(val));
		}

	return rval;
	}

RecordValPtr SupervisorNode::ToRecord() const
	{
	const auto& rt = BifType::Record::Supervisor::NodeStatus;
	auto rval = make_intrusive<RecordVal>(rt);

	rval->AssignField("node", config.ToRecord());

	if ( pid )
		rval->AssignField("pid", pid);

	return rval;
	}

static ValPtr supervisor_role_to_cluster_node_type(BifEnum::Supervisor::ClusterRole role)
	{
	static auto node_type = id::find_type<zeek::EnumType>("Cluster::NodeType");

	switch ( role )
		{
		case BifEnum::Supervisor::LOGGER:
			return node_type->GetEnumVal(node_type->Lookup("Cluster", "LOGGER"));
		case BifEnum::Supervisor::MANAGER:
			return node_type->GetEnumVal(node_type->Lookup("Cluster", "MANAGER"));
		case BifEnum::Supervisor::PROXY:
			return node_type->GetEnumVal(node_type->Lookup("Cluster", "PROXY"));
		case BifEnum::Supervisor::WORKER:
			return node_type->GetEnumVal(node_type->Lookup("Cluster", "WORKER"));
		default:
			return node_type->GetEnumVal(node_type->Lookup("Cluster", "NONE"));
		}
	}

bool SupervisedNode::InitCluster() const
	{
	if ( config.cluster.empty() )
		return false;

	const auto& cluster_node_type = id::find_type<RecordType>("Cluster::Node");
	const auto& cluster_nodes_id = id::find("Cluster::nodes");
	const auto& cluster_manager_is_logger_id = id::find("Cluster::manager_is_logger");
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

		auto key = make_intrusive<StringVal>(node_name);
		auto val = make_intrusive<RecordVal>(cluster_node_type);

		auto node_type = supervisor_role_to_cluster_node_type(ep.role);
		val->AssignField("node_type", std::move(node_type));
		val->AssignField("ip", make_intrusive<AddrVal>(ep.host));
		val->AssignField("p", val_mgr->Port(ep.port, TRANSPORT_TCP));

		if ( ep.interface )
			val->AssignField("interface", *ep.interface);

		if ( manager_name && ep.role != BifEnum::Supervisor::MANAGER )
			val->AssignField("manager", *manager_name);

		cluster_nodes->Assign(std::move(key), std::move(val));
		}

	cluster_manager_is_logger_id->SetVal(val_mgr->Bool(! has_logger));
	return true;
	}

void SupervisedNode::Init(Options* options) const
	{
	const auto& node_name = config.name;

	if ( config.directory )
		{
		if ( chdir(config.directory->data()) )
			{
			fprintf(stderr, "node '%s' failed to chdir to %s: %s\n", node_name.data(),
			        config.directory->data(), strerror(errno));
			exit(1);
			}
		}

	if ( config.stderr_file )
		{
		auto fd = open(config.stderr_file->data(),
		               O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC, 0600);

		if ( fd == -1 || dup2(fd, STDERR_FILENO) == -1 )
			{
			fprintf(stderr, "node '%s' failed to create stderr file %s: %s\n", node_name.data(),
			        config.stderr_file->data(), strerror(errno));
			exit(1);
			}

		util::safe_close(fd);
		}

	if ( config.stdout_file )
		{
		auto fd = open(config.stdout_file->data(),
		               O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC, 0600);

		if ( fd == -1 || dup2(fd, STDOUT_FILENO) == -1 )
			{
			fprintf(stderr, "node '%s' failed to create stdout file %s: %s\n", node_name.data(),
			        config.stdout_file->data(), strerror(errno));
			exit(1);
			}

		util::safe_close(fd);
		}

	if ( config.cpu_affinity )
		{
		auto res = set_affinity(*config.cpu_affinity);

		if ( ! res )
			fprintf(stderr, "node '%s' failed to set CPU affinity: %s\n", node_name.data(),
			        strerror(errno));
		}

	if ( ! config.env.empty() )
		{
		for ( const auto& e : config.env )
			{
			if ( setenv(e.first.c_str(), e.second.c_str(), true) == -1 )
				{
				fprintf(stderr, "node '%s' failed to setenv: %s\n", node_name.data(),
				        strerror(errno));
				exit(1);
				}
			}
		}

	if ( ! config.cluster.empty() )
		{
		if ( setenv("CLUSTER_NODE", node_name.data(), true) == -1 )
			{
			fprintf(stderr, "node '%s' failed to setenv: %s\n", node_name.data(), strerror(errno));
			exit(1);
			}
		}

	options->filter_supervised_node_options();

	if ( config.bare_mode )
		options->bare_mode = *config.bare_mode;

	if ( config.interface )
		options->interface = *config.interface;

	auto& stl = options->scripts_to_load;

	stl.insert(stl.begin(), config.addl_base_scripts.begin(), config.addl_base_scripts.end());
	stl.insert(stl.end(), config.addl_user_scripts.begin(), config.addl_user_scripts.end());
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	stl.insert(stl.end(), config.scripts.begin(), config.scripts.end());
#pragma GCC diagnostic pop
	}

RecordValPtr Supervisor::Status(std::string_view node_name)
	{
	auto rval = make_intrusive<RecordVal>(BifType::Record::Supervisor::Status);
	const auto& tt = BifType::Record::Supervisor::Status->GetFieldType("nodes");
	auto node_table_val = make_intrusive<TableVal>(cast_intrusive<TableType>(tt));
	rval->Assign(0, node_table_val);

	if ( node_name.empty() )
		{
		for ( const auto& n : nodes )
			{
			const auto& name = n.first;
			const auto& node = n.second;
			auto key = make_intrusive<StringVal>(name);
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
		auto key = make_intrusive<StringVal>(name);
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
		return util::fmt("node names must not contain spaces: '%s'", node.name.data());

	if ( nodes.find(node.name) != nodes.end() )
		return util::fmt("node with name '%s' already exists", node.name.data());

	if ( node.directory )
		{
		auto res = util::detail::ensure_intermediate_dirs(node.directory->data());

		if ( ! res )
			return util::fmt("failed to create working directory %s\n", node.directory->data());
		}

	auto msg = make_create_message(node);
	util::safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
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
		util::safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
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
		util::safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
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
