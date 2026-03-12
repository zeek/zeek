// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <set>
#include <string>
#include <zmq.hpp>
#include <zmq_addon.hpp>

namespace zeek::cluster::zeromq {

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
