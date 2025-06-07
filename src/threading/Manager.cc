// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/threading/Manager.h"

#include <sys/socket.h>
#include <unistd.h>
#include <cstdint>
#include <limits>

#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/RunState.h"
#include "zeek/telemetry/Manager.h"

namespace zeek::threading {
namespace detail {

void HeartbeatTimer::Dispatch(double t, bool is_expire) {
    if ( is_expire )
        return;

    thread_mgr->SendHeartbeats();
    thread_mgr->StartHeartbeatTimer();
}

} // namespace detail

static std::vector<uint64_t> pending_bucket_brackets = {1, 10, 100, 1000, 10000, std::numeric_limits<uint64_t>::max()};

Manager::Manager() {
    DBG_LOG(DBG_THREADING, "Creating thread manager ...");

    did_process = true;
    next_beat = 0;
    terminating = false;
    terminated = false;
}

Manager::~Manager() {
    if ( all_threads.size() )
        Terminate();
}

void Manager::InitPostScript() {
    static auto get_message_thread_stats = []() -> const BucketedMessages* {
        if ( ! thread_mgr->terminating ) {
            double now = util::current_time();
            if ( thread_mgr->bucketed_messages_last_updated < now - 1 ) {
                thread_mgr->current_bucketed_messages.pending_in_total = 0;
                thread_mgr->current_bucketed_messages.pending_out_total = 0;
                for ( auto& m : thread_mgr->current_bucketed_messages.pending_in )
                    m.second = 0;
                for ( auto& m : thread_mgr->current_bucketed_messages.pending_out )
                    m.second = 0;

                MsgThread::Stats thread_stats;
                for ( auto* t : thread_mgr->msg_threads ) {
                    t->GetStats(&thread_stats);

                    thread_mgr->current_bucketed_messages.pending_in_total += thread_stats.pending_in;
                    thread_mgr->current_bucketed_messages.pending_out_total += thread_stats.pending_out;

                    for ( auto upper_limit : pending_bucket_brackets ) {
                        if ( thread_stats.pending_in <= upper_limit )
                            thread_mgr->current_bucketed_messages.pending_in[upper_limit]++;

                        if ( thread_stats.pending_out <= upper_limit )
                            thread_mgr->current_bucketed_messages.pending_out[upper_limit]++;
                    }
                }

                thread_mgr->bucketed_messages_last_updated = now;
            }
        }

        return &thread_mgr->current_bucketed_messages;
    };

    num_threads_metric =
        telemetry_mgr->GaugeInstance("zeek", "msgthread_active_threads", {}, "Number of active threads", "", []() {
            return thread_mgr ? static_cast<double>(thread_mgr->all_threads.size()) : 0.0;
        });

    total_threads_metric = telemetry_mgr->CounterInstance("zeek", "msgthread_threads", {}, "Total number of threads");
    total_messages_in_metric =
        telemetry_mgr->CounterInstance("zeek", "msgthread_in_messages", {}, "Number of inbound messages received", "");

    total_messages_out_metric =
        telemetry_mgr->CounterInstance("zeek", "msgthread_out_messages", {}, "Number of outbound messages sent", "");

    pending_messages_in_metric = telemetry_mgr->GaugeInstance("zeek", "msgthread_pending_in_messages", {},
                                                              "Pending number of inbound messages", "", []() {
                                                                  auto* s = get_message_thread_stats();
                                                                  return static_cast<double>(s->pending_in_total);
                                                              });
    pending_messages_out_metric = telemetry_mgr->GaugeInstance("zeek", "msgthread_pending_out_messages", {},
                                                               "Pending number of outbound messages", "", []() {
                                                                   auto* s = get_message_thread_stats();
                                                                   return static_cast<double>(s->pending_out_total);
                                                               });

    pending_message_in_buckets_fam =
        telemetry_mgr->GaugeFamily("zeek", "msgthread_pending_messages_in_buckets", {"le"},
                                   "Number of threads with pending inbound messages split into buckets");
    pending_message_out_buckets_fam =
        telemetry_mgr->GaugeFamily("zeek", "msgthread_pending_messages_out_buckets", {"le"},
                                   "Number of threads with pending outbound messages split into buckets");

    for ( auto upper_limit : pending_bucket_brackets ) {
        std::string upper_limit_str;
        if ( upper_limit == std::numeric_limits<uint64_t>::max() )
            upper_limit_str = "inf";
        else
            upper_limit_str = std::to_string(upper_limit);

        current_bucketed_messages.pending_in[upper_limit] = 0;
        current_bucketed_messages.pending_out[upper_limit] = 0;

        pending_message_in_buckets[upper_limit] =
            pending_message_in_buckets_fam->GetOrAdd({{"le", upper_limit_str}}, [upper_limit]() {
                auto* s = get_message_thread_stats();
                return static_cast<double>(s->pending_in.at(upper_limit));
            });
        pending_message_out_buckets[upper_limit] =
            pending_message_out_buckets_fam->GetOrAdd({{"le", upper_limit_str}}, [upper_limit]() {
                auto* s = get_message_thread_stats();
                return static_cast<double>(s->pending_out.at(upper_limit));
            });
    }
}

void Manager::Terminate() {
    DBG_LOG(DBG_THREADING, "Terminating thread manager ...");
    terminating = true;

    // First process remaining thread output for the message threads.
    do
        Flush();
    while ( did_process );

    // Signal all to stop.

    for ( auto* t : all_threads )
        t->SignalStop();

    for ( auto* t : all_threads )
        t->WaitForStop();

    // Then join them all.
    for ( auto* t : all_threads ) {
        t->Join();
        delete t;
    }

    all_threads.clear();
    msg_threads.clear();
    terminating = false;
    terminated = true;
}

void Manager::AddThread(BasicThread* thread) {
    DBG_LOG(DBG_THREADING, "Adding thread %s ...", thread->Name());

    // This can happen when log writers or other threads are
    // created during the shutdown phase and results in unclean
    // shutdowns.
    if ( terminated )
        reporter->Warning("Thread %s added after threading manager terminated", thread->Name());

    all_threads.push_back(thread);

    if ( ! heartbeat_timer_running )
        StartHeartbeatTimer();

    total_threads_metric->Inc();
}

void Manager::AddMsgThread(MsgThread* thread) {
    DBG_LOG(DBG_THREADING, "%s is a MsgThread ...", thread->Name());
    msg_threads.push_back(thread);
}

void Manager::KillThreads() {
    DBG_LOG(DBG_THREADING, "Killing threads ...");

    for ( auto* t : all_threads )
        t->Kill();
}

void Manager::KillThread(BasicThread* thread) {
    DBG_LOG(DBG_THREADING, "Killing thread %s ...", thread->Name());
    thread->Kill();
}

void Manager::SendHeartbeats() {
    for ( MsgThread* thread : msg_threads )
        thread->Heartbeat();

    // Since this is a regular timer, this is also an ideal place to check whether we have
    // and dead threads and to delete them.
    all_thread_list to_delete;
    for ( auto* t : all_threads ) {
        if ( t->Killed() )
            to_delete.push_back(t);
    }

    for ( auto* t : to_delete ) {
        t->WaitForStop();

        all_threads.remove(t);

        MsgThread* mt = dynamic_cast<MsgThread*>(t);

        if ( mt )
            msg_threads.remove(mt);

        t->Join();
        delete t;
    }
}

void Manager::StartHeartbeatTimer() {
    heartbeat_timer_running = true;
    zeek::detail::timer_mgr->Add(
        new detail::HeartbeatTimer(run_state::network_time + BifConst::Threading::heartbeat_interval));
}

void Manager::MessageIn() { total_messages_in_metric->Inc(); }

void Manager::MessageOut() { total_messages_out_metric->Inc(); }

// Raise everything in here as warnings so it is passed to scriptland without
// looking "fatal". In addition to these warnings, ReaderBackend will queue
// one reporter message.
bool Manager::SendEvent(MsgThread* thread, const std::string& name, const int num_vals, Value** vals) const {
    EventHandler* handler = event_registry->Lookup(name);
    if ( handler == nullptr ) {
        reporter->Warning("Thread %s: Event %s not found", thread->Name(), name.c_str());
        Value::delete_value_ptr_array(vals, num_vals);
        return false;
    }

#ifdef DEBUG
    DBG_LOG(DBG_INPUT, "Thread %s: SendEvent for event %s with %d vals", thread->Name(), name.c_str(), num_vals);
#endif

    const auto& type = handler->GetType()->Params();
    int num_event_vals = type->NumFields();
    if ( num_vals != num_event_vals ) {
        reporter->Warning("Thread %s: Wrong number of values for event %s", thread->Name(), name.c_str());
        Value::delete_value_ptr_array(vals, num_vals);
        return false;
    }

    bool convert_error = false;

    Args vl;
    vl.reserve(num_vals);

    for ( int j = 0; j < num_vals; j++ ) {
        Val* v = Value::ValueToVal(std::string("thread ") + thread->Name(), vals[j], convert_error);
        vl.emplace_back(AdoptRef{}, v);

        if ( v && ! convert_error && ! same_type(type->GetFieldType(j), v->GetType()) ) {
            convert_error = true;
            type->GetFieldType(j)->Error("SendEvent types do not match", v->GetType().get());
        }
    }

    Value::delete_value_ptr_array(vals, num_vals);

    if ( convert_error )
        return false;
    else if ( handler )
        event_mgr.Enqueue(handler, std::move(vl), util::detail::SOURCE_LOCAL);

    return true;
}

void Manager::Flush() {
    bool do_beat = false;

    if ( run_state::network_time && (run_state::network_time > next_beat || ! next_beat) ) {
        do_beat = true;
        next_beat = run_state::network_time + BifConst::Threading::heartbeat_interval;
    }

    did_process = false;

    for ( auto* t : msg_threads ) {
        if ( do_beat )
            t->Heartbeat();

        while ( t->HasOut() ) {
            Message* msg = t->RetrieveOut();
            assert(msg);

            if ( msg->Process() ) {
                if ( run_state::network_time )
                    did_process = true;
            }

            else {
                reporter->Error("%s failed, terminating thread", msg->Name());
                t->SignalStop();
            }

            delete msg;
        }
    }

    all_thread_list to_delete;

    for ( auto* t : all_threads ) {
        if ( t->Killed() )
            to_delete.push_back(t);
    }

    for ( auto* t : to_delete ) {
        t->WaitForStop();

        all_threads.remove(t);

        MsgThread* mt = dynamic_cast<MsgThread*>(t);

        if ( mt )
            msg_threads.remove(mt);

        t->Join();
        delete t;
    }

    // fprintf(stderr, "P %.6f %.6f do_beat=%d did_process=%d next_next=%.6f\n",
    // run_state::network_time,
    //         detail::timer_mgr->Time(), do_beat, (int)did_process, next_beat);
}

const threading::Manager::msg_stats_list& threading::Manager::GetMsgThreadStats() {
    stats.clear();

    for ( auto* t : msg_threads ) {
        MsgThread::Stats s;
        t->GetStats(&s);

        stats.emplace_back(t->Name(), s);
    }

    return stats;
}

} // namespace zeek::threading
