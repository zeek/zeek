// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <set>
#include <string>
#include <zmq.hpp>
#include <zmq_addon.hpp>

namespace zeek::cluster::zeromq {

/**
 * The ZAP (ZeroMQ Authentication Protocol) is an RPC mechanism
 * within libzmq for authentication purposes.
 *
 * The existence of a REP socket that's bound to zeromq.zap.01 in
 * a ZeroMQ context is automatically used for authentication purposes
 * by an internal REQ socket sending a multipart message to the REP
 * socket. See the `27/ZAP ZeroMQ Authentication Protocol <https://rfc.zeromq.org/spec/27/>`_
 * RFC for more details.
 *
 * Zeek creates and binds the REP socket if keys are configured. This is
 * done in the ZeroMQ context in which the central XPUB/XSUB sockets exist.
 * Also ZeroMQ contexts used by loggers to create PULL sockets have the
 * REP socket instantiated. See initZap() in the ZeroMQ.cc file.
 *
 * The zap_thread_fun() function runs in a separate thread to handle the
 * multipart messages originating form libzmq when a new client connects.
 * It takes the ZapArgs struct below. The thread terminates by closing the
 * ZeroMQ context which was used to create the zap_rep member.
 */

/**
 * Data used by the zap_thread_fun.
 */
struct ZapArgs {
    // Socket bound to well-known inproc ZAP endpoint.
    zmq::socket_t zap_rep;

    // Allowed CURVE public keys. These are raw decoded keys
    // that should all have a size of 32. Not the z85 encoded
    // version of size 40.bytes.
    std::set<std::string> allowed_publickeys;
};

/**
 * Function for a thread running a ZAP handler.
 */
void zap_thread_fun(ZapArgs* zap_args);

} // namespace zeek::cluster::zeromq
