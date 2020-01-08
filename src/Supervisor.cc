
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <csignal>
#include <sstream>

#include "Supervisor.h"
#include "Reporter.h"
#include "DebugLogger.h"
#include "Val.h"
#include "NetVar.h"
#include "zeek-config.h"
#include "util.h"

#include "3rdparty/json.hpp"

extern "C" {
#include "setsignal.h"
}

using namespace zeek;

namespace {
struct Stem {
	Stem(std::unique_ptr<bro::PipePair> p);

	~Stem();

	Supervisor::Node* Run();

	Supervisor::Node* Poll();

	Supervisor::Node* Revive();

	void Reap();

	bool Spawn(Supervisor::Node* node);

	int AliveNodeCount() const;

	void KillNodes(int signal) const;

	void KillNode(const Supervisor::Node& node, int signal) const;

	void Destroy(Supervisor::Node* node) const;

	bool Wait(Supervisor::Node* node, int options) const;

	void Shutdown(int exit_code);

	void ReportStatus(const Supervisor::Node& node) const;

	std::unique_ptr<bro::Flare> signal_flare;
	std::unique_ptr<bro::PipePair> pipe;
	std::map<std::string, Supervisor::Node> nodes;
	std::string msg_buffer;
	bool shutting_down = false;
};
}

static Stem* stem = nullptr;

static RETSIGTYPE stem_sig_handler(int signo)
	{
	// TODO: signal safety
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
	// TODO: signal safety
	DBG_LOG(DBG_SUPERVISOR, "received signal: %d", signo);
	supervisor->ObserveChildSignal();
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

static std::string make_create_message(const Supervisor::Node& node)
	{
	auto json_str = node.ToJSON();
	return fmt("create %s %s", node.name.data(), json_str.data());
	}

Supervisor::Supervisor(Supervisor::Config cfg,
							 std::unique_ptr<bro::PipePair> pipe,
                             pid_t arg_stem_pid)
	: config(std::move(cfg)), stem_pid(arg_stem_pid), stem_pipe(std::move(pipe))
	{
	DBG_LOG(DBG_SUPERVISOR, "forked stem process %d", stem_pid);
	DBG_LOG(DBG_SUPERVISOR, "using %d workers", config.num_workers);
	setsignal(SIGCHLD, supervisor_sig_handler);
	SetIdle(true);
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

void Supervisor::ObserveChildSignal()
	{
	signal_flare.Fire();
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
	bool had_child_signal = signal_flare.Extinguish();

	if ( had_child_signal )
		{
		ReapStem();

		DBG_LOG(DBG_SUPERVISOR, "processed SIGCHLD %s",
		        stem_pid ? "(spurious)" : "");
		}

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
		auto stem_env = fmt("%d,%d,%d,%d",
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
	// the desired process hierarchy

	// TODO: probably a preferred order in which to create nodes
	// e.g. logger, manager, proxy, worker
	for ( const auto& n : nodes )
		{
		const auto& node = n.second;
		auto msg = make_create_message(node);
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

bool Stem::Wait(Supervisor::Node* node, int options) const
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

void Stem::KillNode(const Supervisor::Node& node, int signal) const
	{
	auto kill_res = kill(node.pid, signal);

	if ( kill_res == -1 )
		fprintf(stderr, "Failed to send signal to node %s: %s",
		        node.name.data(), strerror(errno));
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

		printf("Stem waiting to destroy node: %s (%d)\n",
		       node->name.data(), node->pid);
		sleep(kill_delay);
		}
	}

Supervisor::Node* Stem::Revive()
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
			return new Supervisor::Node(node);

		ReportStatus(node);
		}

	return {};
	}

bool Stem::Spawn(Supervisor::Node* node)
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

		if ( ! nodes.empty() )
			{
			KillNodes(sig);
			printf("Stem killed nodes with signal %d\n", sig);
			usleep(10);
			Reap();
			}

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

void Stem::ReportStatus(const Supervisor::Node& node) const
	{
	std::string msg = fmt("status %s %d", node.name.data(), node.pid);
	safe_write(pipe->OutFD(), msg.data(), msg.size() + 1);
	}

Supervisor::Node* Stem::Run()
	{
	for ( ; ; )
		{
		auto new_node = Poll();

		if ( new_node )
			return new_node;
		}

	return {};
	}

Supervisor::Node* Stem::Poll()
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
		tokenize_string(std::move(msg), " ", &msg_tokens, 2);
		const auto& cmd = msg_tokens[0];
		const auto& node_name = msg_tokens[1];

		if ( cmd == "create" )
			{
			const auto& node_json = msg_tokens[2];
			assert(nodes.find(node_name) == nodes.end());
			auto node = Supervisor::Node::FromJSON(node_json);

			if ( Spawn(&node) )
				return new Supervisor::Node(node);

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
				return new Supervisor::Node(node);

			ReportStatus(node);
			}
		else
			fprintf(stderr, "unknown supervisor message: %s", cmd.data());
		}

	return {};
	}

Supervisor::Node* Supervisor::RunStem(std::unique_ptr<bro::PipePair> pipe)
	{
	Stem s(std::move(pipe));
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

Supervisor::Node Supervisor::Node::FromRecord(const RecordVal* node)
	{
	Supervisor::Node rval;
	rval.name = node->Lookup("name")->AsString()->CheckString();
	auto iface_val = node->Lookup("interface");

	if ( iface_val )
		rval.interface = iface_val->AsString()->CheckString();

	auto directory_val = node->Lookup("directory");

	if ( directory_val )
		rval.directory = directory_val->AsString()->CheckString();

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

Supervisor::Node Supervisor::Node::FromJSON(std::string_view json)
	{
	Supervisor::Node rval;
	auto j = nlohmann::json::parse(json);
	rval.name = j["name"];

	if ( auto it = j.find("interface"); it != j.end() )
		rval.interface = *it;

	if ( auto it = j.find("directory"); it != j.end() )
		rval.directory= *it;

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

std::string Supervisor::Node::ToJSON() const
	{
	auto re = std::make_unique<RE_Matcher>("^_");
	auto node_val = ToRecord();
	IntrusivePtr<StringVal> json_val{node_val->ToJSON(false, re.get()), false};
	auto rval = json_val->ToStdString();
	return rval;
	}

IntrusivePtr<RecordVal> Supervisor::Node::ToRecord() const
	{
	auto rt = BifType::Record::Supervisor::Node;
	auto rval = make_intrusive<RecordVal>(rt);
	rval->Assign(rt->FieldOffset("name"), new StringVal(name));

	if ( interface )
		rval->Assign(rt->FieldOffset("interface"), new StringVal(*interface));

	if ( directory )
		rval->Assign(rt->FieldOffset("directory"), new StringVal(*directory));

	auto tt = BifType::Record::Supervisor::Node->FieldType("cluster");
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

void Supervisor::Node::InitCluster()
	{
	auto cluster_node_type = global_scope()->Lookup("Cluster::Node")->AsType()->AsRecordType();
	auto cluster_nodes_id = global_scope()->Lookup("Cluster::nodes");
	auto cluster_manager_is_logger_id = global_scope()->Lookup("Cluster::manager_is_logger");
	auto cluster_nodes = cluster_nodes_id->ID_Val()->AsTableVal();
	auto has_logger = false;
	std::optional<std::string> manager_name;

	for ( const auto& e : supervised_node->cluster )
		{
		if ( e.second.role == BifEnum::Supervisor::MANAGER )
			manager_name = e.first;
		else if ( e.second.role == BifEnum::Supervisor::LOGGER )
			has_logger = true;
		}

	for ( const auto& e : supervised_node->cluster )
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
	}

RecordVal* Supervisor::Status(std::string_view node_name)
	{
	// TODO: handle node classes
	auto rval = new RecordVal(BifType::Record::Supervisor::Status);
	auto tt = BifType::Record::Supervisor::Status->FieldType("nodes");
	auto node_table_val = new TableVal(tt->AsTableType());
	rval->Assign(0, node_table_val);

	for ( const auto& n : nodes )
		{
		const auto& node = n.second;
		auto key = make_intrusive<StringVal>(node.name);
		auto val = node.ToRecord();
		node_table_val->Assign(key.get(), val.detach());
		}

	return rval;
	}

std::string Supervisor::Create(const RecordVal* node_val)
	{
	auto node = Supervisor::Node::FromRecord(node_val);
	return Create(node);
	}

std::string Supervisor::Create(const Supervisor::Node& node)
	{
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
	// TODO: handle node classes

	auto it = nodes.find(node_name);

	if ( it == nodes.end() )
		return false;

	nodes.erase(it);

	std::stringstream ss;
	ss << "destroy " << node_name;
	std::string msg = ss.str();
	safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
	return true;
	}

bool Supervisor::Restart(std::string_view node_name)
	{
	// TODO: handle node classes

	if ( nodes.find(node_name) == nodes.end() )
		return false;

	std::stringstream ss;
	ss << "restart " << node_name;
	std::string msg = ss.str();
	safe_write(stem_pipe->OutFD(), msg.data(), msg.size() + 1);
	return true;
	}
