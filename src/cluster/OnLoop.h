// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <list>
#include <mutex>
#include <thread>

#include "zeek/Flare.h"
#include "zeek/Reporter.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/iosource/Manager.h"

namespace zeek::detail {


/**
 * Template class allowing work items to be queued by threads and processed
 * in Zeek's main thread.
 *
 * This is similar to MsgThread::SendOut(), but doesn't require usage of BasicThread
 * or MsgThread instances. Some libraries spawn their own threads or invoke callbacks
 * from arbitrary threads. OnLoopProcess::QueueForProcessing() can be used to transfer
 * work from such callbacks onto Zeek's main thread.
 *
 * There's currently no explicit way to transfer a result back. If this is needed,
 * have the queueing thread block on a semaphore or condition variable and update
 * it from Process().
 *
 * Note that QueueForProcessing() puts the queueing thread to sleep if there's
 * too many items in the queue.
 */
template<class Proc, class Work>
class OnLoopProcess : public zeek::iosource::IOSource {
public:
    /**
     * Constructor.
     *
     * @param proc The instance processing.
     * @param tag The tag to use as the IOSource's tag.
     * @param max_queue_size How many messages to queue before blocking the producing thread.
     * @param cond_timeout If a producer is blocked for more than that many microseconds, report a warning.
     * @param main_thread_id The ID of the main thread for usage checks.
     */
    OnLoopProcess(Proc* proc, std::string tag, size_t max_queue_size = 250,
                  std::chrono::microseconds cond_timeout = std::chrono::microseconds(100000),
                  std::thread::id main_thread_id = std::this_thread::get_id())
        : cond_timeout(cond_timeout),
          max_queue_size(max_queue_size),
          proc(proc),
          tag(std::move(tag)),
          main_thread_id(main_thread_id) {}

    /**
     * Register this instance with the IO loop.
     *
     * The IO loop will manage the lifetime of this
     * IO source instance.
     *
     * @param dont_count If false, prevents Zeek from terminating as long as the IO source is open.
     */
    void Register(bool dont_count = true) {
        zeek::iosource_mgr->Register(this, dont_count, /*manage_lifetime=*/true);

        if ( ! zeek::iosource_mgr->RegisterFd(flare.FD(), this) )
            zeek::reporter->InternalError("Failed to register IO source FD %d for OnLoopProcess %s", flare.FD(),
                                          tag.c_str());
    }

    /**
     * Close the IO source.
     */
    void Close() {
        zeek::iosource_mgr->UnregisterFd(flare.FD(), this);

        {
            // Close under lock to guarantee visibility for
            // any pending queuers QueueForProcessing() calls.
            std::scoped_lock lock(mtx);
            SetClosed(true);

            // Wake a process stuck in queueing.
            cond.notify_one();

            // Don't attempt to Process anymore.
            proc = nullptr;
        }

        // Wait for any active queuers to vanish, should be quick.
        while ( queuers > 0 )
            std::this_thread::sleep_for(std::chrono::microseconds(10));
    }

    /**
     * Implements IOSource::Process()
     *
     * Runs in Zeek's main thread, invoked by the IO loop.
     */
    void Process() override {
        std::list<Work> to_process;
        bool notify = false;
        {
            std::scoped_lock lock(mtx);
            if ( queue.size() >= max_queue_size )
                notify = true;

            to_process.splice(to_process.end(), queue);
            flare.Extinguish();
        }

        // The queue was full before and is now empty,
        // wake up any pending thread.
        if ( notify )
            cond.notify_one();

        // We've been closed, so proc will most likely
        // be invalid at this point and we'll discard
        // whatever was left to do.
        if ( ! IsOpen() )
            return;

        for ( auto& work : to_process )
            proc->Process(std::move(work));
    }

    /**
     * Implements IOSource::Tag()
     */
    const char* Tag() override { return tag.c_str(); }

    /**
     * Implements IOSource::GetNextTimeout()
     */
    double GetNextTimeout() override { return -1; };

    /**
     * Queue the given Work item to be processed on Zeek's main thread.
     *
     * If there's too many items in the queue, this method sleeps using
     * std::this_thread::sleep() for the *block_duration* passed to the
     * constructor.
     *
     * Calling this method from the main thread will result in an abort().
     */
    void QueueForProcessing(Work&& work) {
        ++queuers;
        std::list<Work> to_queue{std::move(work)};

        if ( std::this_thread::get_id() == main_thread_id ) {
            fprintf(stderr, "OnLoopProcess::QueueForProcessing() called by main thread!");
            abort();
        }

        bool fire = false;
        size_t qs = 0;

        int timeouts = 0;

        {
            std::unique_lock lock(mtx);

            // Wait for room in the queue.
            while ( IsOpen() && queue.size() >= max_queue_size ) {
                auto status = cond.wait_for(lock, cond_timeout);
                if ( status == std::cv_status::timeout && IsOpen() )
                    ++timeouts;
            }

            if ( IsOpen() ) {
                assert(queue.size() < max_queue_size);
                assert(to_queue.size() == 1);
                queue.splice(queue.end(), to_queue);
                fire = queue.size() == 1; // first element in queue triggers processing.
            }
            else {
                // IO Source is being or was removed.
                fire = false;
            }
        }


        if ( fire )
            flare.Fire();

        if ( timeouts > 0 ) {
            // XXX: Should this invoke some callback or change the return value
            // so users can react on this?
            //
            // We could also do suicidal snail pattern here. If the event
            // loop is unable to process, we may as well knock ourselves out.
            std::fprintf(stderr, "timeouts %d!\n", timeouts);
        }

        --queuers;
    }

private:
    // Flare to notify Zeek's IO loop.
    zeek::detail::Flare flare;

    // Mutex, condition and timeout protecting access to queue.
    std::mutex mtx;
    std::condition_variable cond;
    std::chrono::microseconds cond_timeout;

    std::list<Work> queue;
    size_t max_queue_size;

    Proc* proc;
    std::string tag;
    std::atomic<int> queuers = 0;
    std::thread::id main_thread_id;
};


} // namespace zeek::detail
