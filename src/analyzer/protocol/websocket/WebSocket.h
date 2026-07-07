// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/analyzer/protocol/websocket/websocket_pac.h"
#include "zeek/analyzer/Analyzer.h"

namespace zeek::analyzer::websocket {

/**
 * A WebSocket analyzer to be used directly on top of HTTP.
 */
class WebSocket_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    WebSocket_Analyzer(zeek::Connection* conn);

    /**
     * Allows script land to configure the WebSocket analyzer before analysis.
     *
     * @param config Zeek value of type WebSocket::AnalyzerConfig
     */
    bool Configure(zeek::RecordValPtr config);

    void Init() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EnablePerMessageCompression() 
        { 
        permessage_deflate = true; 
        
        if ( interp ) {
            fprintf(stderr, "DEBUG: C++ EnablePerMessageCompression called. Calling interp->Enable()...\n");
            interp->EnablePerMessageCompression(); 
        } else {
            fprintf(stderr, "DEBUG: C++ EnablePerMessageCompression called, but INTERP IS NULL!\n");
        }
        }
    static zeek::analyzer::Analyzer* Instantiate(Connection* conn) { return new WebSocket_Analyzer(conn); }
private:
    std::unique_ptr<binpac::WebSocket::WebSocket_Conn> interp;
    bool had_gap = false;
    bool permessage_deflate = false;
};

} // namespace zeek::analyzer::websocket
