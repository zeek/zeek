// See the file "COPYING" in the main distribution directory for copyright.

#include <caf/test/unit_test_impl.hpp>

#include "zeek-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <list>

#ifdef USE_IDMEF
extern "C" {
#include <libidmef/idmefxml.h>
}
#endif

#include "input.h"
#include "DNS_Mgr.h"
#include "Frame.h"
#include "Scope.h"
#include "Event.h"
#include "File.h"
#include "Reporter.h"
#include "Net.h"
#include "NetVar.h"
#include "Var.h"
#include "Timer.h"
#include "Stmt.h"
#include "Debug.h"
#include "DFA.h"
#include "RuleMatcher.h"
#include "Anon.h"
#include "EventRegistry.h"
#include "Stats.h"
#include "Brofiler.h"
#include "Traverse.h"

#include "threading/Manager.h"
#include "input/Manager.h"
#include "logging/Manager.h"
#include "logging/writers/ascii/Ascii.h"
#include "input/readers/raw/Raw.h"
#include "analyzer/Manager.h"
#include "analyzer/Tag.h"
#include "plugin/Manager.h"
#include "file_analysis/Manager.h"
#include "zeekygen/Manager.h"
#include "iosource/Manager.h"
#include "broker/Manager.h"

#include "binpac_bro.h"

Brofiler brofiler;

extern "C" {
#include "setsignal.h"
};

#ifdef USE_PERFTOOLS_DEBUG
HeapLeakChecker* heap_checker = 0;
int perftools_leaks = 0;
int perftools_profile = 0;
#endif

DNS_Mgr* dns_mgr;
TimerMgr* timer_mgr;
ValManager* val_mgr = 0;
PortManager* port_mgr = 0;
logging::Manager* log_mgr = 0;
threading::Manager* thread_mgr = 0;
input::Manager* input_mgr = 0;
plugin::Manager* plugin_mgr = 0;
analyzer::Manager* analyzer_mgr = 0;
file_analysis::Manager* file_mgr = 0;
zeekygen::Manager* zeekygen_mgr = 0;
iosource::Manager* iosource_mgr = 0;
bro_broker::Manager* broker_mgr = 0;

const char* prog;
char* writefile = 0;
name_list prefixes;
Stmt* stmts;
EventHandlerPtr net_done = 0;
RuleMatcher* rule_matcher = 0;
EventRegistry* event_registry = 0;
ProfileLogger* profiling_logger = 0;
ProfileLogger* segment_logger = 0;
SampleLogger* sample_logger = 0;
int signal_val = 0;
extern char version[];
char* command_line_policy = 0;
vector<string> params;
set<string> requested_plugins;
char* proc_status_file = 0;

OpaqueType* md5_type = 0;
OpaqueType* sha1_type = 0;
OpaqueType* sha256_type = 0;
OpaqueType* entropy_type = 0;
OpaqueType* cardinality_type = 0;
OpaqueType* topk_type = 0;
OpaqueType* bloomfilter_type = 0;
OpaqueType* x509_opaque_type = 0;
OpaqueType* ocsp_resp_opaque_type = 0;
OpaqueType* paraglob_type = 0;

int bro_argc;
char** bro_argv;

const char* zeek_version()
	{
	return version;
	}

bool bro_dns_fake()
	{
	return zeekenv("ZEEK_DNS_FAKE");
	}

bool show_plugins(int level)
	{
	return false;
	}

void done_with_network()
	{
	}

void termination_signal()
	{
	exit(0);
	}

RETSIGTYPE sig_handler(int signo)
	{
	return RETSIGVAL;
	}

static void atexit_handler()
	{
	set_processing_status("TERMINATED", "atexit");
	}

