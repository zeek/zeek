// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/backend/zeromq/ZeroMQ-Proxy.h"

#include <zmq.hpp>

#include "zeek/Reporter.h"
#include "zeek/util.h"


using namespace zeek::cluster::zeromq;

namespace {

/**
 * Function that runs zmq_proxy() that provides a central XPUB/XSUB
 * broker for other Zeek nodes to connect and exchange subscription
 * information.
 */
void thread_fun(ProxyThread::Args* args) {
    zeek::util::detail::set_thread_name("zmq-proxy-thread");

    bool done = false;

    while ( ! done ) {
        try {
            zmq::proxy_steerable(args->xsub, args->xpub, zmq::socket_ref{}, args->rep /*capture*/);
        } catch ( zmq::error_t& err ) {
            if ( err.num() == EINTR )
                continue;

            done = true;
            args->xsub.close();
            args->xpub.close();
            args->rep.close();

            if ( err.num() != ETERM ) {
                std::fprintf(stderr, "[zeromq] unexpected zmq_proxy() error: %s (%d)", err.what(), err.num());
                throw;
            }
        }
    }
}

} // namespace

bool ProxyThread::Start() {
    ctx.set(zmq::ctxopt::io_threads, io_threads);

    // Enable IPv6 support for all subsequently created sockets, if configured.
    ctx.set(zmq::ctxopt::ipv6, ipv6);

    zmq::socket_t xpub(ctx, zmq::socket_type::xpub);
    zmq::socket_t xsub(ctx, zmq::socket_type::xsub);
    zmq::socket_t rep(ctx, zmq::socket_type::rep);

    // Enable XPUB_VERBOSER unconditional to enforce nodes receiving
    // notifications about any new and removed subscriptions, even if
    // they have seen them before. This is needed for the subscribe
    // callback and shared subscription removal notification to work
    // reliably.
    xpub.set(zmq::sockopt::xpub_verboser, 1);

    xpub.set(zmq::sockopt::xpub_nodrop, xpub_nodrop);

    try {
        xpub.bind(xpub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to bind xpub socket %s: %s (%d)", xpub_endpoint.c_str(), err.what(),
                              err.num());
        return false;
    }

    try {
        xsub.bind(xsub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to bind xsub socket %s: %s (%d)", xsub_endpoint.c_str(), err.what(),
                              err.num());
        return false;
    }

    try {
        rep.bind(rep_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("ZeroMQ: Failed to bind rep socket %s: %s (%d)", rep_endpoint.c_str(), err.what(),
                              err.num());
        return false;
    }

    args = {.xpub = std::move(xpub), .xsub = std::move(xsub), .rep = std::move(rep)};

    thread = std::thread(thread_fun, &args);

    return true;
}

void ProxyThread::Shutdown() {
    ctx.shutdown();

    if ( thread.joinable() )
        thread.join();

    ctx.close();
}
