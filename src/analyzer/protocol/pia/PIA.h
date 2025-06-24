// See the file "COPYING" in the main distribution directory for copyright.

// An analyzer for application-layer protocol-detection.

#pragma once

#include "zeek/RuleMatcher.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::detail {
class RuleEndpointState;
}

namespace zeek::analyzer::pia {

// Abstract PIA class providing common functionality for both TCP and UDP.
// Accepts only packet input.
//
// Note that the PIA provides our main interface to the signature engine and
// also keeps the matching state.  This is because (i) it needs to match
// itself, and (ii) in case of tunnel-decapsulation we may have multiple
// PIAs and then each needs its own matching-state.
class PIA : public zeek::detail::RuleMatcherState {
public:
    explicit PIA(analyzer::Analyzer* as_analyzer);
    virtual ~PIA();

    // Called when PIA wants to put an Analyzer in charge.  rule is the
    // signature that triggered the activation, if any.
    virtual void ActivateAnalyzer(zeek::Tag tag, const zeek::detail::Rule* rule = nullptr) = 0;

    // Called when PIA wants to remove an Analyzer.
    virtual void DeactivateAnalyzer(zeek::Tag tag) = 0;

    void Match(zeek::detail::Rule::PatternType type, const u_char* data, int len, bool is_orig, bool bol, bool eol,
               bool clear_state);

    void ReplayPacketBuffer(analyzer::Analyzer* analyzer);

    // The first packet for each direction of a connection is passed
    // in here. This initializes the signature engine state for DPD.
    //
    // This version of the method should be used preferably, assuming an IP
    // header is available.
    //
    // (This API is a bit crude as it doesn't really fit nicely into the
    // analyzer interface. Yet we need it for initializing the packet matcher
    // in the case that we already get reassembled input; and making it part of
    // the general analyzer interface seems to be unnecessary overhead.)
    void FirstPacket(bool is_orig, const IP_Hdr* ip);

    // The first packet for each direction of a connection is passed
    // in here. This initializes the signature engine state for DPD.
    //
    // This version of the method should be used if no actual IP header is
    // available. In that case a fake one will be created internally just for
    // initializing the signature engine. The fake header's transport-layer
    // protocol will be `proto`. Only TCP or UDP are supported.
    //
    // (Similar to the other variant of this method, this API is a bit crude as
    // it doesn't really fit nicely into the analyzer interface. This version
    // we need for feeding data into the matcher that's not directly top-level
    // IP payload, but decapsulated out of other layers.)
    void FirstPacket(bool is_orig, TransportProto proto);

    // Children are also derived from Analyzer. Return this object
    // as pointer to an Analyzer.
    analyzer::Analyzer* AsAnalyzer() { return as_analyzer; }

protected:
    void PIA_Done();
    void PIA_DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen,
                           bool clear_state);

    enum State : uint8_t { INIT, BUFFERING, MATCHING_ONLY, SKIPPING };
    State state = INIT;

    // Buffers one chunk of data.  Used both for packet payload (incl.
    // sequence numbers for TCP) and chunks of a reassembled stream.
    struct DataBlock {
        IP_Hdr* ip = nullptr;
        const u_char* data = nullptr;
        bool is_orig = false;
        size_t len = 0;
        size_t cap_len = 0;
        uint64_t seq = 0;
        DataBlock* next = nullptr;
    };

    struct Buffer {
        DataBlock* head = nullptr;
        DataBlock* tail = nullptr;
        int64_t size = 0;
        int64_t chunks = 0;
        State state = INIT;
    };

    void AddToBuffer(Buffer* buffer, uint64_t seq, int len, const u_char* data, bool is_orig,
                     const IP_Hdr* ip = nullptr);
    void AddToBuffer(Buffer* buffer, int len, const u_char* data, bool is_orig, const IP_Hdr* ip = nullptr);
    void ClearBuffer(Buffer* buffer);

    DataBlock* CurrentPacket() { return &current_packet; }

    void DoMatch(const u_char* data, int len, bool is_orig, bool bol, bool eol, bool clear_state,
                 const IP_Hdr* ip = nullptr);

    auto Conn() const { return conn; }
    void SetConn(Connection* c) { conn = c; }

    Buffer pkt_buffer;

private:
    // Joint backend for the two public FirstPacket() methods.
    void FirstPacket(bool is_orig, const std::optional<TransportProto>& proto, const IP_Hdr* ip);

    analyzer::Analyzer* as_analyzer = nullptr;
    Connection* conn = nullptr;
    DataBlock current_packet;
};

// PIA for UDP.
class PIA_UDP : public PIA, public analyzer::Analyzer {
public:
    explicit PIA_UDP(Connection* conn) : PIA(this), Analyzer("PIA_UDP", conn) { SetConn(conn); }
    ~PIA_UDP() override {}

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new PIA_UDP(conn); }

protected:
    void Done() override {
        Analyzer::Done();
        PIA_Done();
    }

    void DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen) override {
        Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);
        PIA_DeliverPacket(len, data, is_orig, seq, ip, caplen, true);
    }

    void ActivateAnalyzer(zeek::Tag tag, const zeek::detail::Rule* rule) override;
    void DeactivateAnalyzer(zeek::Tag tag) override;
};

// PIA for TCP.  Accepts both packet and stream input (and reassembles
// packets before passing payload on to children).
class PIA_TCP : public PIA, public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit PIA_TCP(Connection* conn) : PIA(this), analyzer::tcp::TCP_ApplicationAnalyzer("PIA_TCP", conn) {
        stream_mode = false;
        SetConn(conn);
    }

    ~PIA_TCP() override;

    void Init() override;

    void ReplayStreamBuffer(analyzer::Analyzer* analyzer);

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new PIA_TCP(conn); }

protected:
    void Done() override {
        Analyzer::Done();
        PIA_Done();
    }

    void DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen) override {
        TCP_ApplicationAnalyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);
        PIA_DeliverPacket(len, data, is_orig, seq, ip, caplen, false);
    }

    void DeliverStream(int len, const u_char* data, bool is_orig) override;
    void Undelivered(uint64_t seq, int len, bool is_orig) override;

    void ActivateAnalyzer(zeek::Tag tag, const zeek::detail::Rule* rule = nullptr) override;
    void DeactivateAnalyzer(zeek::Tag tag) override;

private:
    // FIXME: Not sure yet whether we need both pkt_buffer and stream_buffer.
    // In any case, it's easier this way...
    Buffer stream_buffer;

    bool stream_mode;
};

} // namespace zeek::analyzer::pia
