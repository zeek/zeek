// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/backend/zeromq/ZeroMQ-ZAP.h"

#include "zeek/util.h"

namespace zeek::cluster::zeromq {

// Implements a ZAP handler for Zeek's XPUB/XSUB proxy.
//
// https://rfc.zeromq.org/spec/27/#formal-specification
//
// zap_args contains the allowed client public keys.
void zap_thread_fun(ZapArgs* zap_args) {
    zeek::util::detail::set_thread_name("zmq-zap-thread");

    bool done = false;

    // Process ZAP requests.

    while ( ! done ) {
        std::string status_code = "400";
        std::string status_text = "Invalid ZAP request";
        std::string user_id = "";
        std::vector<zmq::message_t> request_frames;
        request_frames.reserve(8);

        try {
            zmq::recv_result_t r = zmq::recv_multipart(zap_args->zap_rep, std::back_inserter(request_frames));


            if ( r && *r >= 7 ) {
                auto mech = request_frames[5].to_string_view();
                if ( mech == "CURVE" ) {
                    std::string client_publickey = {request_frames[6].data<const char>(), request_frames[6].size()};

                    if ( zap_args->allowed_publickeys.contains(client_publickey) ) {
                        status_code = "200";
                        status_text = "OK";
                        user_id = "0";
                    }
                }
            }
            else {
                std::fprintf(stderr, "[zeromq/zap] invalid request (has_value=%d value=%zu)\n", r.has_value(),
                             r.value_or(0));
            }

            std::vector<zmq::message_t> response_frames;
            response_frames.reserve(6);
            response_frames.emplace_back(request_frames[0].data(), request_frames[0].size());
            response_frames.emplace_back(request_frames[1].data(), request_frames[1].size());
            response_frames.emplace_back(status_code.data(), status_code.size());
            response_frames.emplace_back(status_text.data(), status_text.size());
            response_frames.emplace_back("0", 1); // user id
            response_frames.emplace_back("", 0);  // metadata

            zmq::send_multipart(zap_args->zap_rep, response_frames);

        } catch ( zmq::error_t& err ) {
            if ( err.num() == EINTR )
                continue;

            done = true;
            zap_args->zap_rep.close();

            if ( err.num() != ETERM ) {
                std::fprintf(stderr, "[zeromq/zap] unexpected recv() error: %s (%d)", err.what(), err.num());
                throw;
            }
        }
    }
}
} // namespace zeek::cluster::zeromq
