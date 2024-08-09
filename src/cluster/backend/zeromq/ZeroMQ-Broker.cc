#include "ZeroMQ-Broker.h"

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
void thread_fun(BrokerThread::Args* args) {
    zeek::util::detail::set_thread_name("zeromq-broker");

    try {
        std::fprintf(stderr, "[zeromq] broker thread running\n");
        zmq::proxy(args->xsub, args->xpub, zmq::socket_ref{} /*capture*/);
    } catch ( zmq::error_t& err ) {
        args->xsub.close();
        args->xpub.close();

        if ( err.num() != ETERM ) {
            std::fprintf(stderr, "[zeromq] unexpected zmq_proxy() error: %s (%d)", err.what(), err.num());
            throw;
        }
    }

    std::fprintf(stderr, "[zeromq] broker thread done\n");
}

} // namespace

bool BrokerThread::Start() {
    zmq::socket_t xpub(ctx, zmq::socket_type::xpub);
    zmq::socket_t xsub(ctx, zmq::socket_type::xsub);

    try {
        xpub.bind(xpub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("Failed to bind xpub socket %s: %s (%d)", xpub_endpoint.c_str(), err.what(), err.num());
        return false;
    }

    try {
        xsub.bind(xsub_endpoint);
    } catch ( zmq::error_t& err ) {
        zeek::reporter->Error("Failed to bind xsub socket %s: %s (%d)", xpub_endpoint.c_str(), err.what(), err.num());
        return false;
    }

    args = {.xpub = std::move(xpub), .xsub = std::move(xsub)};

    thread = std::thread(thread_fun, &args);

    return true;
}

void BrokerThread::Shutdown() {
    ctx.shutdown();
    if ( thread.joinable() ) {
        thread.join();
    }
    ctx.close();
}
