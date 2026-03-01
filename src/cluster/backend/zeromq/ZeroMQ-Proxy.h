// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <thread>
#include <zmq.hpp>

#include "zeek/cluster/backend/zeromq/ZeroMQ-ZAP.h"
#include "zeek/cluster/backend/zeromq/ZeroMQ.h"

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
     * @param control A ZeroMQ REP socket for the zmq::proxy_steerable() control parameter. This socket can be used to
     * send commands to the proxy (https://libzmq.readthedocs.io/en/latest/zmq_proxy_steerable.html).
     * @param xpub_nodrop the xpub_nodrop option to use on the XPUB socket.
     * @param io_threads The number of IO threads to configure with the ZeroMQ context.
     * @param curve_config Optional curve config to enable encryption.
     */
    ProxyThread(std::string xpub_endpoint, std::string xsub_endpoint, zmq::socket_t&& control, int ipv6,
                int xpub_nodrop, int io_threads, CurveConfig curve_config)
        : xpub_endpoint(std::move(xpub_endpoint)),
          xsub_endpoint(std::move(xsub_endpoint)),
          control(std::move(control)),
          ipv6(ipv6),
          xpub_nodrop(xpub_nodrop),
          io_threads(io_threads),
          curve_config(std::move(curve_config)) {}


    ~ProxyThread() { Shutdown(); }

    /**
     * Data kept in object and passed to thread.
     */
    struct Args {
        zmq::socket_t xpub;
        zmq::socket_t xsub;
        zmq::socket_t control;
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
    std::thread zap_thread;
    ZapArgs zap_args;
    std::string xpub_endpoint;
    std::string xsub_endpoint;
    zmq::socket_t control;
    int ipv6 = 1;
    int xpub_nodrop = 1;
    int io_threads = 2;
    CurveConfig curve_config;
};
} // namespace zeek::cluster::zeromq
