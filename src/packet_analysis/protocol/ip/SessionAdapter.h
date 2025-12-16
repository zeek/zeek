// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/analyzer/Analyzer.h"
#include "zeek/iosource/Packet.h"

namespace zeek::analyzer::pia {
class PIA;
}

namespace zeek::packet_analysis {

/**
 * Indicator for a TapAnalyzer to determine what will happen to a packet.
 */
enum class PacketAction : uint8_t {
    Deliver, ///< Packet will be delivered to child protocol analyzers.
    Skip,    ///< Processing of this packet will be skipped.
};

/**
 * Reason why delivery of a packet would be skipped.
 */
enum class SkipReason : uint8_t {
    None,           ///< None is used when the action is Deliver.
    Unknown,        ///< Placeholder if no other value fits.
    BadChecksum,    ///< The packet's checksum is invalid and ignore_checksums is false.
    BadProtoHeader, ///< Something was off with the lengths or offsets in the protocol header.
    SkipProcessing, ///< The session adapter's connection had skip_further_processing called on it.
};

/**
 * A lightweight analyzer that receives all packets passing through session adapters.
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

    /**
     * Hook of a tap analyzer for receiving packet data.
     *
     * @param pkt The packet being processed.
     * @param action Either Deliver or Skip as determined by session analyzers.
     * @param skip_reason If action is Skip, an indication why this packet is skipped, otherwise None.
     */
    virtual void TapPacket(const Packet& pkt, PacketAction action, SkipReason skip_reason) = 0;

    /**
     * Hook for initialization before tapping begins.
     *
     * This method is invoked after a tap analyzer has been added to a SessionAdapter.
     */
    virtual void Init() {};

    /**
     * Hook for when this analyzer is about to be removed and destructed.
     *
     * This is invoked when the session's Done() method is invoked, just before
     * the TapAnalyzer instance is destroyed.
     */
    virtual void Done() {};
};

using TapAnalyzerPtr = std::unique_ptr<TapAnalyzer>;

namespace IP {

class IPBasedAnalyzer;
class SessionAdapter;

/**
 * Helper class embedded in the SessionAdapter to assign callbacks for
 * for size and state fields within the endpoint records of connection.
 *
 * SessonAdapter implementations are required to implement
 * GetEndpointSize(bool is_orig) and GetEndpointState(bool is_orig) to
 * query the most recent values.
 */
class EndpointRecordValCallback : zeek::detail::RecordFieldCallback {
public:
    EndpointRecordValCallback() = default;

    // Avoid copying or assigning instances.
    EndpointRecordValCallback(EndpointRecordValCallback&& o) = delete;
    EndpointRecordValCallback(EndpointRecordValCallback& o) = delete;
    EndpointRecordValCallback& operator=(EndpointRecordValCallback& o) = delete;

    void Init(RecordVal& conn_val, const SessionAdapter* arg_adapter);

    void Done();

    ZVal Invoke(const RecordVal& val, int field) const override;

    /**
     * Flip originator and responder endpoint if we have them.
     */
    void FlipRoles() { std::swap(orig_endp, resp_endp); }

    static void InitPostScript();

private:
    const SessionAdapter* adapter = nullptr;
    // Pointers to the endpoint records within connection.
    //
    // These are owned and kept alive by a Connection's record_val.
    // Just before the Connection is freed, the Done() method will
    // clear these raw pointers after uninstalling the field callbacks.
    RecordVal* orig_endp = nullptr;
    RecordVal* resp_endp = nullptr;

    // Cached offsets.
    static int orig_endp_offset;
    static int resp_endp_offset;
    static int size_offset;
    static int state_offset;
};

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

    /**
     * Adds a TapAnalyzer instance to this session adapter.
     *
     * @param ta The TapAnalyzer instance to attach.
     */
    void AddTapAnalyzer(TapAnalyzerPtr ta);

    /**
     * Remove a TapAnalyzer instance by raw pointer.
     *
     * Note that the TapAnalyzer instance \a ta is pointing at will be destroyed
     * during the call to RemoveTapAnalyzer() and should be discarded by the caller
     * immediately. If you call RemoveTapAnalyzer() from within a TapAnalyzer's member
     * function, ensure not accessing \a this afterwards.
     *
     * @param ta The raw pointer to the TapAnalyzer instance to remove.
     */
    bool RemoveTapAnalyzer(const TapAnalyzer* ta);

    /**
     * Helper to forward a packet to all attached TapAnalyzer instances.
     *
     * @param pkt The packet.
     * @param action Whether the packet will be delivered or skipped.
     * @param skip_reason If action is Skip, should be an indication why this packet is skipped.
     */
    void TapPacket(const Packet* pkt, PacketAction action = PacketAction::Deliver,
                   SkipReason skip_reason = SkipReason::None) const;

    /**
     * SessionAdapter implements InitConnVal() to install callbacks
     * for endpoint's state, num_pkts and num_bytes_ip fields.
     *
     * If you derive from SessionAdapter and need additional functionality
     * other than GetEndpointSize() and GetEndpointState(), override this
     * method, but do call SessionAdapter::InitConnVal().
     */
    void InitConnVal(RecordVal& conn_val) override;

    /**
     * @return The most recent value for endpoint$size.
     */
    virtual zeek_uint_t GetEndpointSize(bool is_orig) const = 0;

    /**
     * @return The most recent value value for endpoint$state.
     */
    virtual zeek_uint_t GetEndpointState(bool is_orig) const = 0;

    /**
     * Overridden from parent class to flip endpoint callback.
     */
    void FlipRoles() override;

    static void InitPostScript();

protected:
    IPBasedAnalyzer* parent = nullptr;
    analyzer::pia::PIA* pia = nullptr;
    std::vector<TapAnalyzerPtr> tap_analyzers;
    EndpointRecordValCallback endp_cb;
};

} // namespace IP
} // namespace zeek::packet_analysis
