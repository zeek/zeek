// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/analyzer/Analyzer.h"
#include "zeek/iosource/Packet.h"

namespace zeek::analyzer::pia {
class PIA;
}

namespace zeek::packet_analysis::IP {

class IPBasedAnalyzer;

namespace detail {

/**
 * Reason why a packet was skipped instead of forwarded to the root protocol analyzer.
 *
 * Passed into TapAnalyzer::SkippedBacked().
 */
enum class SkipReason : uint8_t {
    BadProtoHeader,
    BadChecksum,
};

/**
 * An interface for a lightweight analyzer that receives all packets forwarded (or not)
 * to child protocol analyzers of session adapters.
 *
 * A use case of tap analyzers is to attach them during HookSetupAnalyzerTree() to
 * observe all raw packets of a session, including those that are invalid or corrupt
 * and aren't delivered to child protocol analyzers.
 *
 * The Packet class has an *is_orig* field if directionality is required. Additionally,
 * the Connection instance available during HookSetupAnalyzerTree() can be stored into
 * a custom TapAnalyzer, allowing to associate packets with a given Connection. However,
 * the TapAnalyzer interface itself does not provide provisions for this use case.
 */
class TapAnalyzer {
public:
    virtual ~TapAnalyzer() = default;

    virtual void DeliverPacket(const Packet& pkt) = 0;

    virtual void SkippedPacket(const Packet& pkt, SkipReason skip_reason) = 0;

    virtual void Done() {};
};

using TapAnalyzerPtr = std::unique_ptr<TapAnalyzer>;

} // namespace detail

/**
 * This class represents the interface between the packet analysis framework and
 * the session analysis framework. One of these should be implemented for each
 * packet analyzer that intends to forward into the session analysis.
 */
class SessionAdapter : public analyzer::Analyzer {
public:
    SessionAdapter(const char* name, Connection* conn) : analyzer::Analyzer(name, conn) {}

    /**
     * Overridden from parent class.
     */
    void Done() override;

    /**
     * Sets the parent packet analyzer for this session adapter. This can't be passed to
     * the constructor due to the way that SessionAdapter gets instantiated.
     *
     * @param p The parent packet analyzer to store
     */
    void SetParent(IPBasedAnalyzer* p) { parent = p; }

    /**
     * Returns true if the analyzer determines that in fact a new connection has started
     * without the connection statement having terminated the previous one, i.e., the new
     * data is arriving at what's the analyzer for the previous instance. This is used only
     * for TCP.
     */
    virtual bool IsReuse(double t, const u_char* pkt);

    /**
     * Pure virtual method to allow extra session analyzers to be added to this analyzer's
     * tree of children. This is used by analyzer::Manager when creating the session analyzer
     * tree.
     */
    virtual void AddExtraAnalyzers(Connection* conn) = 0;

    /**
     * Associates a file with the analyzer in which to record all
     * analyzed input. This must only be called with derived classes that
     * override the method; the default implementation will abort.
     *
     * @param direction One of the CONTENTS_* constants indicating which
     * direction of the input stream is to be recorded.
     *
     * @param f The file to record to.
     *
     */
    virtual void SetContentsFile(unsigned int direction, FilePtr f);

    /**
     * Returns an associated contents file, if any.  This must only be
     * called with derived classes that override the method; the default
     * implementation will abort.
     *
     * @param direction One of the CONTENTS_* constants indicating which
     * direction the query is for.
     */
    virtual FilePtr GetContentsFile(unsigned int direction) const;

    /**
     * Associates a PIA with this analyzer. A PIA takes the
     * transport-layer input and determine which protocol analyzer(s) to
     * use for parsing it.
     */
    void SetPIA(analyzer::pia::PIA* arg_PIA) { pia = arg_PIA; }

    /**
     * Returns the associated PIA, or null of none. Does not take
     * ownership.
     */
    analyzer::pia::PIA* GetPIA() const { return pia; }

    /**
     * Helper to raise a \c packet_contents event.
     *
     * @param data The data to pass to the event.
     *
     * @param len The length of \a data.
     */
    void PacketContents(const u_char* data, int len);

    void AddTapAnalyzer(detail::TapAnalyzerPtr ta);

    // Remove the tap analyzer with the given raw pointer.
    //
    // This will call Done() and delete the analyzer. Callers
    // should throw away their ta pointer immediately afterwards.
    bool RemoveTapAnalyzer(const detail::TapAnalyzer* ta);

    void TapPacket(const Packet* pkt);

    void TapSkippedPacket(const Packet* pkt, detail::SkipReason skip_reason);

protected:
    IPBasedAnalyzer* parent = nullptr;
    analyzer::pia::PIA* pia = nullptr;
    std::list<detail::TapAnalyzerPtr> tap_analyzers;
};

} // namespace zeek::packet_analysis::IP
