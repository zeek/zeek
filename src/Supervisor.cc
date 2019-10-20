
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>

#include "Supervisor.h"
#include "Reporter.h"
#include "DebugLogger.h"
#include "Val.h"
#include "NetVar.h"
#include "zeek-config.h"
#include "util.h"

extern "C" {
#include "setsignal.h"
}

namespace {
struct Stem {
	Stem(std::unique_ptr<bro::PipePair> p);

	~Stem();

	std::string Run();

	std::string Poll();

	void Reap();

	std::string Revive();

	bool Spawn(zeek::Supervisor::Node* node);

	int AliveNodeCount() const;

	void KillNodes(int signal) const;

	void KillNode(const zeek::Supervisor::Node& node, int signal) const;

	void Destroy(zeek::Supervisor::Node* node) const;

	bool Wait(zeek::Supervisor::Node* node, int options) const;

	void Shutdown(int exit_code);

	void ReportStatus(const zeek::Supervisor::Node& node) const;

	std::unique_ptr<bro::Flare> signal_flare;
	std::unique_ptr<bro::PipePair> pipe;
	std::map<std::string, zeek::Supervisor::Node> nodes;
	std::string msg_buffer;
	bool shutting_down = false;
};
}

static Stem* stem = nullptr;

static RETSIGTYPE stem_sig_handler(int signo)
	{
	printf("Stem received signal: %d\n", signo);

	if ( stem->shutting_down )
		return RETSIGVAL;

	stem->signal_flare->Fire();

	if ( signo == SIGTERM )
		stem->shutting_down = true;

	return RETSIGVAL;
	}

static RETSIGTYPE supervisor_sig_handler(int signo)
	{
	DBG_LOG(DBG_SUPERVISOR, "received signal: %d", signo);
	zeek::supervisor->ObserveChildSignal();
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

zeek::Supervisor::Supervisor(zeek::Supervisor::Config cfg,
							 std::unique_ptr<bro::PipePair> pipe,
                             pid_t arg_stem_pid)
	: config(std::move(cfg)), stem_pid(arg_stem_pid), stem_pipe(std::move(pipe))
	{
	DBG_LOG(DBG_SUPERVISOR, "forked stem process %d", stem_pid);
	DBG_LOG(DBG_SUPERVISOR, "using %d workers", config.num_workers);
	setsignal(SIGCHLD, supervisor_sig_handler);
	SetIdle(true);
	}

zeek::Supervisor::~Supervisor()
	{
	setsignal(SIGCHLD, SIG_DFL);

	if ( ! stem_pid )
		{
		DBG_LOG(DBG_SUPERVISOR, "shutdown, stem process already exited");
		return;
		}

	DBG_LOG(DBG_SUPERVISOR, "shutdown, killing stem process %d", stem_pid);

	// TODO: is signal the best way to trigger shutdown of decendent processes?
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
	}

void zeek::Supervisor::ObserveChildSignal()
	{
	signal_flare.Fire();
	}

void zeek::Supervisor::ReapStem()
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

void zeek::Supervisor::HandleChildSignal()
	{
	signal_flare.Extinguish();
	ReapStem();

	if ( stem_pid )
		return;

	// Revive the Stem process
	// TODO: Stem process needs a way to inform Supervisor not to revive
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
		char stem_env[256];
		safe_snprintf(stem_env, sizeof(stem_env), "ZEEK_STEM=%d,%d,%d,%d",
		              stem_pipe->In().ReadFD(), stem_pipe->In().WriteFD(),
		              stem_pipe->Out().ReadFD(), stem_pipe->Out().WriteFD());
		char* env[] = { stem_env, (char*)0 };
		stem_pipe->In().UnsetFlags(FD_CLOEXEC);
		stem_pipe->Out().UnsetFlags(FD_CLOEXEC);
		auto res = execle(config.zeek_exe_path.data(),
		                  config.zeek_exe_path.data(),
		                  (char*)0, env);

		char tmp[256];
		bro_strerror_r(errno, tmp, sizeof(tmp));
		fprintf(stderr, "failed to exec Zeek supervisor stem process: %s\n", tmp);
		exit(1);
		}

	// Parent supervisor process resends node configurations to recreate
	// the desired process hierarchy
	DBG_LOG(DBG_SUPERVISOR, "stem process revived, new pid: %d", stem_pid);

	// TODO: probably a preferred order in which to create nodes
	// e.g. logger, manager, proxy, worker
	for ( const auto& n : nodes )
		{
		const auto& node = n.second;
		std::string msg = fmt("create %s", node.name.data());
		safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
		}
	}


void zeek::Supervisor::GetFds(iosource::FD_Set* read, iosource::FD_Set* write,
                              iosource::FD_Set* except)
	{
	read->Insert(signal_flare.FD());
	read->Insert(stem_pipe->InFD());
	}

double zeek::Supervisor::NextTimestamp(double* local_network_time)
	{
	return timer_mgr->Time();
	}

void zeek::Supervisor::Process()
	{
	HandleChildSignal();

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
		else
			reporter->Error("Supervisor got unknown msg: %s", msg.data());
		}
	}

Stem::Stem(std::unique_ptr<bro::PipePair> p)
	: signal_flare(new bro::Flare()), pipe(std::move(p))
	{
	zeek::set_thread_name("zeek.stem");
	pipe->Swap();
	stem = this;
	setsignal(SIGCHLD, stem_sig_handler);
	setsignal(SIGTERM, stem_sig_handler);

	// TODO: changing the process group here so that SIGINT to the
	// supervisor doesn't also get passed to the children.  i.e. supervisor
	// should be in charge of initiating orderly shutdown.  But calling
	// just setpgid() like this is technically a race-condition -- need
	// to do more work of blocking SIGINT before fork(), unblocking after,
	// then also calling setpgid() from parent.  And just not doing that
	// until more is known whether that's the right SIGINT behavior in
	// the first place.
	auto res = setpgid(0, 0);

	if ( res == -1 )
		fprintf(stderr, "failed to set stem process group: %s\n",
				strerror(errno));
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

bool Stem::Wait(zeek::Supervisor::Node* node, int options) const
	{
	int status;
	auto res = waitpid(node->pid, &status, options);

	if ( res == 0 )
		// It's still alive.
		return false;

	if ( res == -1 )
		{
		fprintf(stderr, "Stem failed to get node exit status %s (%d): %s\n",
			    node->name.data(), node->pid, strerror(errno));
		return false;
		}

	if ( WIFEXITED(status) )
		{
		node->exit_status = WEXITSTATUS(status);
		// TODO: may be some cases where the node is intended to exit
		printf("node '%s' exited with status %d\n",
			   node->name.data(), node->exit_status);
		}
	else if ( WIFSIGNALED(status) )
		{
		node->signal_number = WTERMSIG(status);
		printf("node '%s' terminated by signal %d\n",
			   node->name.data(), node->signal_number);
		}
	else
		fprintf(stderr, "Stem failed to get node exit status %s (%d)\n",
			    node->name.data(), node->pid);

	node->pid = 0;
	return true;
	}

void Stem::KillNode(const zeek::Supervisor::Node& node, int signal) const
	{
	auto kill_res = kill(node.pid, signal);

	if ( kill_res == -1 )
		fprintf(stderr, "Failed to send signal to node %s: %s",
		        node.name.data(), strerror(errno));
	}

void Stem::Destroy(zeek::Supervisor::Node* node) const
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

		printf("Stem waiting to destroy node: %s (%d)\n",
		       node->name.data(), node->pid);
		sleep(kill_delay);
		}
	}

std::string Stem::Revive()
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

		if ( Spawn(&node) )
			return node.name;

		ReportStatus(node);
		}

	return "";
	}

bool Stem::Spawn(zeek::Supervisor::Node* node)
	{
	auto node_pid = fork();

	if ( node_pid == -1 )
		{
		fprintf(stderr, "failed to fork Zeek node '%s': %s\n",
		        node->name.data(), strerror(errno));
		return false;
		}

	if ( node_pid == 0 )
		{
		zeek::set_thread_name(fmt("zeek.%s", node->name.data()));
		return true;
		}

	node->pid = node_pid;
	node->spawn_time = std::chrono::steady_clock::now();
	printf("Stem spawned node: %s (%d)\n", node->name.data(), node->pid);
	return false;
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
		printf("Stem killed nodes with signal %d\n", sig);
		KillNodes(sig);
		usleep(10);
		Reap();
		auto nodes_alive = AliveNodeCount();

		if ( nodes_alive == 0 )
			exit(exit_code);

		printf("Stem nodes still alive %d, sleeping for %d seconds\n",
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

void Stem::ReportStatus(const zeek::Supervisor::Node& node) const
	{
	std::string msg = fmt("status %s %d", node.name.data(), node.pid);
	safe_write(pipe->OutFD(), msg.data(), msg.size() + 1);
	}

std::string Stem::Run()
	{
	for ( ; ; )
		{
		auto new_node_name = Poll();

		if ( ! new_node_name.empty() )
			return new_node_name;
		}

	return "";
	}

std::string Stem::Poll()
	{
	pollfd fds[2] = { { pipe->InFD(), POLLIN, 0 },
	                  { signal_flare->FD(), POLLIN, 0} };
	constexpr auto poll_timeout_ms = 1000;
	auto res = poll(fds, 2, poll_timeout_ms);

	if ( res < 0 )
		{
		if ( errno != EINTR )
			{
			fprintf(stderr, "Stem poll() failed: %s\n", strerror(errno));
			return {};
			}
		}

	if ( getppid() == 1 )
		{
		// TODO: better way to detect loss of parent than polling ?
		// e.g. prctl(PR_SET_PDEATHSIG, ...) on Linux
		// or procctl(PROC_PDEATHSIG_CTL) on FreeBSD
		printf("Stem suicide\n");
		Shutdown(13);
		}

	auto new_node_name = Revive();

	if ( ! new_node_name.empty() )
		return new_node_name;

	if ( res == 0 )
		return {};

	if ( signal_flare->Extinguish() )
		{
		if ( shutting_down )
			Shutdown(0);

		Reap();
		auto new_node_name = Revive();

		if ( ! new_node_name.empty() )
			return new_node_name;
		}

	if ( ! fds[0].revents )
		return {};

	char buf[256];
	int bytes_read = read(pipe->InFD(), buf, 256);

	if ( bytes_read == 0 )
		{
		// EOF, supervisor must have exited
		printf("Stem EOF\n");
		Shutdown(14);
		}

	if ( bytes_read < 0 )
		{
		fprintf(stderr, "Stem read() failed: %s\n", strerror(errno));
		return {};
		}

	msg_buffer.append(buf, bytes_read);
	auto msgs = extract_messages(&msg_buffer);

	for ( auto& msg : msgs )
		{
		// TODO: improve message format ...
		std::vector<std::string> msg_tokens;
		tokenize_string(std::move(msg), " ", &msg_tokens);
		const auto& cmd = msg_tokens[0];
		const auto& node_name = msg_tokens[1];

		if ( cmd == "create" )
			{
			assert(nodes.find(node_name) == nodes.end());
			zeek::Supervisor::Node node;
			node.name = node_name;

			if ( Spawn(&node) )
				// TODO: probably want to return the full configuration the
				// new node ought to use
				return node.name;

			// TODO: get stem printfs going through standard Zeek debug.log
			printf("Stem created node: %s (%d)\n", node.name.data(), node.pid);
			auto it = nodes.emplace(node_name, std::move(node)).first;
			ReportStatus(it->second);
			}
		else if ( cmd == "destroy" )
			{
			auto it = nodes.find(node_name);
			assert(it != nodes.end());
			auto& node = it->second;
			printf("Stem destroying node: %s\n", node_name.data());
			Destroy(&node);
			nodes.erase(it);
			}
		else if ( cmd == "restart" )
			{
			auto it = nodes.find(node_name);
			assert(it != nodes.end());
			auto& node = it->second;
			printf("Stem restarting node: %s\n", node_name.data());
			Destroy(&node);

			if ( Spawn(&node) )
				return node.name;

			ReportStatus(node);
			}
		else
			fprintf(stderr, "unknown supervisor message: %s", cmd.data());
		}

	return {};
	}

std::string zeek::Supervisor::RunStem(std::unique_ptr<bro::PipePair> pipe)
	{
	Stem s(std::move(pipe));
	return s.Run();
	}

static zeek::Supervisor::Node node_val_to_struct(const RecordVal* node)
	{
	zeek::Supervisor::Node rval;
	rval.name = node->Lookup("name")->AsString()->CheckString();
	return rval;
	}

static RecordVal* node_struct_to_val(const zeek::Supervisor::Node& node)
	{
	auto rval = new RecordVal(BifType::Record::Supervisor::Node);
	rval->Assign(0, new StringVal(node.name));

	if ( node.pid )
		rval->Assign(1, val_mgr->GetCount(node.pid));

	return rval;
	}

RecordVal* zeek::Supervisor::Status(const std::string& node_name)
	{
	// TODO: handle node classes
	auto rval = new RecordVal(BifType::Record::Supervisor::Status);
	auto tt = BifType::Record::Supervisor::Status->FieldType("nodes");
	auto node_table_val = new TableVal(tt->AsTableType());
	rval->Assign(0, node_table_val);

	for ( const auto& n : nodes )
		{
		const auto& node = n.second;
		auto key = new StringVal(node.name);
		auto val = node_struct_to_val(node);
		node_table_val->Assign(key, val);
		Unref(key);
		}

	return rval;
	}

std::string zeek::Supervisor::Create(const RecordVal* node_val)
	{
	auto node = node_val_to_struct(node_val);

	if ( node.name.find(' ') != std::string::npos )
		return fmt("node names must not contain spaces: '%s'",
		           node.name.data());

	if ( nodes.find(node.name) != nodes.end() )
		return fmt("node with name '%s' already exists", node.name.data());

	std::string msg = fmt("create %s", node.name.data());
	safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
	nodes.emplace(node.name, node);
	return "";
	}

bool zeek::Supervisor::Destroy(const std::string& node_name)
	{
	// TODO: handle node classes

	if ( ! nodes.erase(node_name) )
		return false;

	std::string msg = fmt("destroy %s", node_name.data());
	safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
	return true;
	}

bool zeek::Supervisor::Restart(const std::string& node_name)
	{
	// TODO: handle node classes

	if ( nodes.find(node_name) == nodes.end() )
		return false;

	std::string msg = fmt("restart %s", node_name.data());
	safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
	return true;
	}
