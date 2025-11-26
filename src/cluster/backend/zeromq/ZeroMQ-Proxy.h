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
     * @param xpub_endpoint the XPUB socket address to listen on.
     * @param xsub_endpoint the XSUB socket address to listen on.
     * @param xpub_nodrop the xpub_nodrop option to use on the XPUB socket.
     */
    ProxyThread(std::string xpub_endpoint, std::string xsub_endpoint, std::string rep_endpoint, int ipv6, int xpub_nodrop, int io_threads)
        : xpub_endpoint(std::move(xpub_endpoint)),
          xsub_endpoint(std::move(xsub_endpoint)),
          rep_endpoint(std::move(rep_endpoint)),
          ipv6(ipv6),
          xpub_nodrop(xpub_nodrop),
          io_threads(io_threads) {}


    ~ProxyThread() { Shutdown(); }

    /**
     * Data kept in object and passed to thread.
     */
    struct Args {
        zmq::socket_t xpub;
        zmq::socket_t xsub;
        zmq::socket_t rep;
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
    std::string rep_endpoint;
    int ipv6 = 1;
    int xpub_nodrop = 1;
    int io_threads = 2;
};
} // namespace zeek::cluster::zeromq
