// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <thread>
#include <zmq.hpp>


// Central XPUB/XSUB proxy.
//
// Spawns a thread that runs zmq_proxy() for a XPUB/XSUB pair.
namespace zeek::cluster::zeromq {

class ProxyThread {
public:
    /**
     * Constructor.
     *
     * @param xpub_endpoint - the XPUB socket address to listen on.
     * @param xsub_endpoint - the XSUB socket address to listen on.
     */
    ProxyThread(std::string xpub_endpoint, std::string xsub_endpoint)
        : xpub_endpoint(std::move(xpub_endpoint)), xsub_endpoint(std::move(xsub_endpoint)) {}


    ~ProxyThread() { Shutdown(); }

    /**
     * Data kept in object and passed to thread.
     */
    struct Args {
        zmq::socket_t xpub;
        zmq::socket_t xsub;
    };

    /**
     * Bind the sockets and spawn the thread.
     */
    bool Start();

    /**
     * Shutdown the ZeroMQ context and join the thread.
     */
    void Shutdown();

private:
    zmq::context_t ctx;
    std::thread thread;
    Args args;
    std::string xpub_endpoint;
    std::string xsub_endpoint;
};
} // namespace zeek::cluster::zeromq
