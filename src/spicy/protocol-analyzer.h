// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <optional>
#include <string>
#include <utility>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/driver.h>
#include <spicy/rt/parser.h>

#include "zeek/spicy/cookie.h"

namespace zeek::spicy::rt {

/** Parsing state for one endpoint of the connection. */
class EndpointState : public ::spicy::rt::driver::ParsingState {
public:
    /**
     * Constructor.
     *
     * @param cookie cookie to associated with the endpoint
     * @param type type of parsing, depending on whether it's a stream- or
     * packet-based protocol
     */
    EndpointState(Cookie cookie, ::spicy::rt::driver::ParsingType type)
        : ParsingState(type), _cookie(std::move(cookie)) {}

    /** Returns the protocol-specific cookie state associated with the endpoint. */
    auto& protocol() {
        assert(_cookie.protocol);
        return *_cookie.protocol;
    }

    /** Returns the cookie pointer to use with the runtime library during analysis. */
    auto* cookie() { return &_cookie; }

    /**
     * Records a debug message pertaining to this specific endpoint.
     *
     * @param msg message to record
     */
    void DebugMsg(const std::string& msg) { debug(msg); }

protected:
    // Overridden from driver::ParsingState.
    void debug(const std::string& msg) override;

private:
    Cookie _cookie;
};

/** Base clase for Spicy protocol analyzers. */
class ProtocolAnalyzer {
public:
    ProtocolAnalyzer(analyzer::Analyzer* analyzer, ::spicy::rt::driver::ParsingType type);
    virtual ~ProtocolAnalyzer();

    /** Returns the originator-side parsing state. */
    auto& originator() { return _originator; }

    /** Returns the responder-side parsing state. */
    auto& responder() { return _responder; }

protected:
    /** Initialize analyzer.  */
    void Init();

    /** Shutdown analyzer. */
    void Done();

    /**
     * Signal that Zeek has flipped the direction of the connection, meaning
     * that originator and responder state need to be swapped.
     */
    void FlipRoles();

    /**
     * Feeds a chunk of data into one side's parsing.
     *
     * @param is_orig true to use originator-side endpoint state, false for responder
     * @param len number of bytes valid in *data*
     * @param data pointer to data
     */
    void Process(bool is_orig, int len, const u_char* data);

    /**
     * Finalizes parsing. After calling this, no more data must be passed
     * into Process() for the corresponding side.
     *
     * @param is_orig true to finish originator-side parsing, false for responder
     */
    void Finish(bool is_orig);

    /**
     * Helper returning the protocol analyzer cookie for the requested side.
     *
     * @param is_orig tru to return the originator's state, false for the
     * responder.
     * @return protocol analyzer cookie for the requested side
     */
    cookie::ProtocolAnalyzer& cookie(bool is_orig);

    /**
     * Records a debug message. This forwards to `DebugMsg()` for the
     * corresponding `EndpointState`.
     */
    void DebugMsg(bool is_orig, const std::string& msg);

private:
    EndpointState _originator; /**< Originator-side state. */
    EndpointState _responder;  /**< Responder-side state. */
    std::optional<::spicy::rt::UnitContext> _context;
};

/**
 * Spicy analyzer for TCP application-layer protocols. Implements the
 * standard Zeek API.
 */
class TCP_Analyzer : public ProtocolAnalyzer, public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    TCP_Analyzer(Connection* conn);
    virtual ~TCP_Analyzer();

    // Overridden from Spicy's Analyzer.
    void Init() override;
    void Done() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndOfData(bool is_orig) override;
    void FlipRoles() override;

    // Overridden from Zeek's TCP_ApplicationAnalyzer.
    void EndpointEOF(bool is_orig) override;
    void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
                          bool gen_event) override;
    void ConnectionFinished(bool half_finished) override;
    void ConnectionReset() override;
    void PacketWithRST() override;

    static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn);
};

/**
 * Spicy analyzer for UDP application-layer protocols. Implements the
 * standard Zeek API.
 */
class UDP_Analyzer : public ProtocolAnalyzer, public analyzer::Analyzer {
public:
    UDP_Analyzer(Connection* conn);
    virtual ~UDP_Analyzer();

    // Overridden from Spicy's Analyzer.
    void Init() override;
    void Done() override;
    void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq, const IP_Hdr* ip, int caplen) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndOfData(bool is_orig) override;
    void FlipRoles() override;

    static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn);
};

} // namespace zeek::spicy::rt
