// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Stats.h"

#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#include "zeek/Conn.h"
#include "zeek/DNS_Mgr.h"
#include "zeek/Dict.h"
#include "zeek/Event.h"
#include "zeek/File.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/NetVar.h"
#include "zeek/RuleMatcher.h"
#include "zeek/RunState.h"
#include "zeek/Scope.h"
#include "zeek/Trigger.h"
#include "zeek/broker/Manager.h"
#include "zeek/input.h"
#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/session/Manager.h"
#include "zeek/threading/Manager.h"

uint64_t zeek::detail::killed_by_inactivity = 0;
uint64_t& killed_by_inactivity = zeek::detail::killed_by_inactivity;

uint64_t zeek::detail::tot_ack_events = 0;
uint64_t& tot_ack_events = zeek::detail::tot_ack_events;
uint64_t zeek::detail::tot_ack_bytes = 0;
uint64_t& tot_ack_bytes = zeek::detail::tot_ack_bytes;
uint64_t zeek::detail::tot_gap_events = 0;
uint64_t& tot_gap_events = zeek::detail::tot_gap_events;
uint64_t zeek::detail::tot_gap_bytes = 0;
uint64_t& tot_gap_bytes = zeek::detail::tot_gap_bytes;

namespace zeek::detail {

class ProfileTimer final : public Timer {
public:
    ProfileTimer(double t, ProfileLogger* l, double i) : Timer(t, TIMER_PROFILE) {
        logger = l;
        interval = i;
    }

    void Dispatch(double t, bool is_expire) override;

protected:
    double interval;
    ProfileLogger* logger;
};

void ProfileTimer::Dispatch(double t, bool is_expire) {
    logger->Log();

    // Reinstall timer.
    if ( ! is_expire )
        timer_mgr->Add(new ProfileTimer(run_state::network_time + interval, logger, interval));
}

ProfileLogger::ProfileLogger(zeek::File* arg_file, double interval) {
    file = arg_file;
    log_count = 0;
    timer_mgr->Add(new ProfileTimer(1, this, interval));
}

ProfileLogger::~ProfileLogger() { file->Close(); }

void ProfileLogger::Log() {
    if ( run_state::terminating )
        // Connections have been flushed already.
        return;

    file->Write(util::fmt("%.06f ------------------------\n", run_state::network_time));

    // Do expensive profiling only occasionally.
    bool expensive = false;

    if ( expensive_profiling_multiple )
        expensive = (++log_count) % expensive_profiling_multiple == 0;

    // Memory information.
    struct rusage r;
    getrusage(RUSAGE_SELF, &r);
    struct timeval tv_utime = r.ru_utime;
    struct timeval tv_stime = r.ru_stime;

    uint64_t total;
    uint64_t malloced;
    util::get_memory_usage(&total, &malloced);

    static unsigned int first_total = 0;
    static double first_rtime = 0;
    static double first_utime = 0;
    static double first_stime = 0;

    double rtime = util::current_time();
    double utime = static_cast<double>(tv_utime.tv_sec) + static_cast<double>(tv_utime.tv_usec) / 1e6;
    double stime = static_cast<double>(tv_stime.tv_sec) + static_cast<double>(tv_stime.tv_usec) / 1e6;

    if ( first_total == 0 ) {
        first_total = total;
        first_rtime = rtime;
        first_utime = utime;
        first_stime = stime;

        file->Write(util::fmt("%.06f Command line: ", run_state::network_time));
        for ( int i = 0; i < zeek_argc; i++ ) {
            file->Write(zeek_argv[i]);
            file->Write(" ");
        }
        file->Write(util::fmt("\n%.06f ------------------------\n", run_state::network_time));
    }

    file->Write(util::fmt("%.06f Memory: total=%" PRId64 "K total_adj=%" PRId64 "K malloced: %" PRId64 "K\n",
                          run_state::network_time, total / 1024, (total - first_total) / 1024, malloced / 1024));

    file->Write(util::fmt("%.06f Run-time: user+sys=%.1f user=%.1f sys=%.1f real=%.1f\n", run_state::network_time,
                          (utime + stime) - (first_utime + first_stime), utime - first_utime, stime - first_stime,
                          rtime - first_rtime));

    // TODO: This previously output the number of connections, but now that we're storing
    // sessions as well as connections, this might need to be renamed.
    file->Write(util::fmt("%.06f Conns: total=%" PRIu64 " current=%" PRIu64 "/%zu\n", run_state::network_time,
                          Connection::TotalConnections(), Connection::CurrentConnections(),
                          session_mgr->CurrentSessions()));

    session::Stats s;
    session_mgr->GetStats(s);

    file->Write(util::fmt("%.06f Conns: tcp=%zu/%zu udp=%zu/%zu icmp=%zu/%zu\n", run_state::network_time,
                          s.num_TCP_conns, s.max_TCP_conns, s.num_UDP_conns, s.max_UDP_conns, s.num_ICMP_conns,
                          s.max_ICMP_conns));

    packet_analysis::TCP::TCPAnalyzer::GetStats().PrintStats(file,
                                                             util::fmt("%.06f TCP-States:", run_state::network_time));

    // Alternatively, if you prefer more compact output...
    /*
    file->Write(util::fmt("%.8f TCP-States: I=%d S=%d SA=%d SR=%d E=%d EF=%d ER=%d F=%d P=%d\n",
               run_state::network_time,
               session_mgr->tcp_stats.StateInactive(),
               session_mgr->tcp_stats.StateRequest(),
               session_mgr->tcp_stats.StateSuccRequest(),
               session_mgr->tcp_stats.StateRstRequest(),
               session_mgr->tcp_stats.StateEstablished(),
               session_mgr->tcp_stats.StateHalfClose(),
               session_mgr->tcp_stats.StateHalfRst(),
               session_mgr->tcp_stats.StateClosed(),
               session_mgr->tcp_stats.StatePartial()
               ));
    */

    file->Write(util::fmt("%.06f Connections expired due to inactivity: %" PRIu64 "\n", run_state::network_time,
                          killed_by_inactivity));

    // Signature engine.
    if ( expensive && rule_matcher ) {
        RuleMatcher::Stats stats;
        rule_matcher->GetStats(&stats);

        file->Write(
            util::fmt("%06f RuleMatcher: matchers=%d nfa_states=%d dfa_states=%d "
                      "ncomputed=%d mem=%dK\n",
                      run_state::network_time, stats.matchers, stats.nfa_states, stats.dfa_states, stats.computed,
                      stats.mem / 1024));
    }
    file->Write(util::fmt("%.06f Timers: current=%zu max=%zu lag=%.2fs\n", run_state::network_time, timer_mgr->Size(),
                          timer_mgr->PeakSize(), run_state::network_time - timer_mgr->LastTimestamp()));

    DNS_Mgr::Stats dstats;
    dns_mgr->GetStats(&dstats);

    file->Write(
        util::fmt("%.06f DNS_Mgr: requests=%lu successful=%lu failed=%lu pending=%lu "
                  "cached_hosts=%lu cached_addrs=%lu\n",
                  run_state::network_time, dstats.requests, dstats.successful, dstats.failed, dstats.pending,
                  dstats.cached.hosts, dstats.cached.addresses));

    trigger::Manager::Stats tstats;
    trigger_mgr->GetStats(&tstats);

    file->Write(
        util::fmt("%.06f Triggers: total=%lu pending=%lu\n", run_state::network_time, tstats.total, tstats.pending));

    unsigned int* current_timers = TimerMgr::CurrentTimers();
    for ( int i = 0; i < NUM_TIMER_TYPES; ++i ) {
        if ( current_timers[i] )
            file->Write(util::fmt("%.06f         %s = %d\n", run_state::network_time,
                                  timer_type_to_string(static_cast<TimerType>(i)), current_timers[i]));
    }

    file->Write(util::fmt("%0.6f Threads: current=%zu\n", run_state::network_time, thread_mgr->NumThreads()));

    const threading::Manager::msg_stats_list& thread_stats = thread_mgr->GetMsgThreadStats();
    for ( const auto& [name, s] : thread_stats ) {
        file->Write(util::fmt("%0.6f   %-25s in=%" PRIu64 " out=%" PRIu64 " pending=%" PRIu64 "/%" PRIu64
                              " (#queue r/w: in=%" PRIu64 "/%" PRIu64 " out=%" PRIu64 "/%" PRIu64 ")"
                              "\n",
                              run_state::network_time, name.c_str(), s.sent_in, s.sent_out, s.pending_in, s.pending_out,
                              s.queue_in_stats.num_reads, s.queue_in_stats.num_writes, s.queue_out_stats.num_reads,
                              s.queue_out_stats.num_writes));
    }

    auto cs = broker_mgr->GetStatistics();

    file->Write(
        util::fmt("%0.6f Comm: peers=%zu stores=%zu "
                  "pending_queries=%zu "
                  "events_in=%zu events_out=%zu "
                  "logs_in=%zu logs_out=%zu "
                  "ids_in=%zu ids_out=%zu ",
                  run_state::network_time, cs.num_peers, cs.num_stores, cs.num_pending_queries, cs.num_events_incoming,
                  cs.num_events_outgoing, cs.num_logs_incoming, cs.num_logs_outgoing, cs.num_ids_incoming,
                  cs.num_ids_outgoing));

    if ( expensive ) {
        // Script-level state.
        int total_table_entries = 0;
        int total_table_rentries = 0;

        for ( const auto& global : global_scope()->Vars() ) {
            auto& id = global.second;

            // We don't show/count internal globals as they are always
            // contained in some other global user-visible container.
            if ( id->HasVal() ) {
                const auto& v = id->GetVal();

                bool print = false;
                int entries = -1;
                int rentries = -1;

                if ( v->GetType()->Tag() == TYPE_TABLE ) {
                    entries = v->AsTable()->Length();
                    total_table_entries += entries;

                    // ### 100 shouldn't be hardwired
                    // in here.
                    if ( entries >= 100 )
                        print = true;

                    rentries = v->AsTableVal()->RecursiveSize();
                    total_table_rentries += rentries;
                    if ( rentries >= 100 ) // ### or here
                        print = true;
                }

                if ( print && entries >= 0 ) {
                    file->Write(
                        util::fmt("%.06f                %d/%d entries\n", run_state::network_time, entries, rentries));
                }
            }
        }

        file->Write(util::fmt("%.06f Total number of table entries: %d/%d\n", run_state::network_time,
                              total_table_entries, total_table_rentries));
    }

    // Create an event so that scripts can log their information, too.
    // (and for consistency we dispatch it *now*). Don't propagate this
    // event to remote clients.
    if ( profiling_update ) {
        zeek::Args args{make_intrusive<FileVal>(IntrusivePtr{NewRef{}, file}), val_mgr->Bool(expensive)};
        event_mgr.Dispatch(profiling_update, std::move(args));
    }
}

PacketProfiler::PacketProfiler(unsigned int mode, double freq, File* arg_file) {
    update_mode = mode;
    update_freq = freq;
    file = arg_file;

    last_Utime = last_Stime = last_Rtime = 0.0;
    last_timestamp = time = 0.0;
    pkt_cnt = byte_cnt = 0;
    last_mem = 0;

    file->Write("time dt npkts nbytes dRtime dUtime dStime dmem\n");
}

PacketProfiler::~PacketProfiler() { file->Close(); }

void PacketProfiler::ProfilePkt(double t, unsigned int bytes) {
    if ( last_timestamp == 0.0 ) {
        struct rusage res;
        struct timeval ptimestamp;
        getrusage(RUSAGE_SELF, &res);
        gettimeofday(&ptimestamp, nullptr);

        util::get_memory_usage(&last_mem, nullptr);
        last_Utime = res.ru_utime.tv_sec + res.ru_utime.tv_usec / 1e6;
        last_Stime = res.ru_stime.tv_sec + res.ru_stime.tv_usec / 1e6;
        last_Rtime = ptimestamp.tv_sec + ptimestamp.tv_usec / 1e6;
        last_timestamp = t;
    }

    if ( (update_mode == MODE_TIME && t > last_timestamp + update_freq) ||
         (update_mode == MODE_PACKET && static_cast<double>(pkt_cnt) > update_freq) ||
         (update_mode == MODE_VOLUME && static_cast<double>(pkt_cnt) > update_freq) ) {
        struct rusage res;
        struct timeval ptimestamp;
        getrusage(RUSAGE_SELF, &res);
        gettimeofday(&ptimestamp, nullptr);

        double curr_Utime = res.ru_utime.tv_sec + res.ru_utime.tv_usec / 1e6;
        double curr_Stime = res.ru_stime.tv_sec + res.ru_stime.tv_usec / 1e6;
        double curr_Rtime = ptimestamp.tv_sec + ptimestamp.tv_usec / 1e6;

        uint64_t curr_mem;
        util::get_memory_usage(&curr_mem, nullptr);

        file->Write(util::fmt("%.06f %.03f %" PRIu64 " %" PRIu64 " %.03f %.03f %.03f %" PRIu64 "\n", t,
                              time - last_timestamp, pkt_cnt, byte_cnt, curr_Rtime - last_Rtime,
                              curr_Utime - last_Utime, curr_Stime - last_Stime, curr_mem - last_mem));

        last_Utime = curr_Utime;
        last_Stime = curr_Stime;
        last_Rtime = curr_Rtime;
        last_mem = curr_mem;
        last_timestamp = t;
        pkt_cnt = 0;
        byte_cnt = 0;
    }

    ++pkt_cnt;
    byte_cnt += bytes;
    time = t;
}

} // namespace zeek::detail
