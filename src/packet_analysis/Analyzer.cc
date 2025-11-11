// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/Analyzer.h"

#include <cinttypes>

#include "zeek/DebugLogger.h"
#include "zeek/Event.h"
#include "zeek/RunState.h"
#include "zeek/session/Manager.h"
#include "zeek/util.h"

namespace zeek::packet_analysis {

Analyzer::Analyzer(std::string name, bool report_unknown_protocols)
    : report_unknown_protocols(report_unknown_protocols) {
    Tag t = packet_mgr->GetComponentTag(name);

    if ( ! t )
        reporter->InternalError("unknown packet_analysis name %s", name.c_str());

    Init(t);
}

Analyzer::Analyzer(const Tag& tag) { Init(tag); }

void Analyzer::Init(const Tag& _tag) { tag = _tag; }

void Analyzer::Initialize() { default_analyzer = LoadAnalyzer("default_analyzer"); }

zeek::packet_analysis::AnalyzerPtr Analyzer::LoadAnalyzer(const std::string& name) {
    auto& analyzer = zeek::id::find(GetModuleName() + name);
    if ( ! analyzer )
        return nullptr;

    auto& analyzer_val = analyzer->GetVal();
    if ( ! analyzer_val )
        return nullptr;

    return packet_mgr->GetAnalyzer(analyzer_val->AsEnumVal());
}

Tag Analyzer::GetAnalyzerTag() const {
    assert(tag);
    return tag;
}

const char* Analyzer::GetAnalyzerName() const {
    assert(tag);
    return packet_mgr->GetComponentName(tag).c_str();
}

bool Analyzer::IsAnalyzer(const char* name) {
    assert(tag);
    return packet_mgr->GetComponentName(tag) == name;
}

const AnalyzerPtr& Analyzer::Lookup(uint64_t identifier) const { return dispatcher.Lookup(identifier); }

// Find the next inner analyzer using identifier or via DetectProtocol(),
// otherwise return the default analyzer.
const AnalyzerPtr& Analyzer::FindInnerAnalyzer(size_t len, const uint8_t* data, Packet* packet,
                                               uint64_t identifier) const {
    const auto& identifier_based_analyzer = Lookup(identifier);
    if ( identifier_based_analyzer )
        return identifier_based_analyzer;

    const auto& detect_based_analyzer = DetectInnerAnalyzer(len, data, packet);
    if ( detect_based_analyzer )
        return detect_based_analyzer;

    return default_analyzer;
}

// Find the next inner analyzer via DetectProtocol(), otherwise the default analyzer.
const AnalyzerPtr& Analyzer::FindInnerAnalyzer(size_t len, const uint8_t* data, Packet* packet) const {
    const auto& detect_based_analyzer = DetectInnerAnalyzer(len, data, packet);
    if ( detect_based_analyzer )
        return detect_based_analyzer;

    return default_analyzer;
}

// Return an analyzer found via DetectProtocol() for the given data, else nil.
const AnalyzerPtr& Analyzer::DetectInnerAnalyzer(size_t len, const uint8_t* data, Packet* packet) const {
    for ( const auto& child : analyzers_to_detect ) {
        if ( child->IsEnabled() && child->DetectProtocol(len, data, packet) ) {
            DBG_LOG(DBG_PACKET_ANALYSIS, "Protocol detection in %s succeeded, next layer analyzer is %s",
                    GetAnalyzerName(), child->GetAnalyzerName());
            return child;
        }
    }

    return nil;
}

bool Analyzer::ForwardPacket(size_t len, const uint8_t* data, Packet* packet, uint64_t identifier) const {
    const auto& inner_analyzer = FindInnerAnalyzer(len, data, packet, identifier);

    if ( ! inner_analyzer ) {
        DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s failed, could not find analyzer for identifier %#" PRIx64 ".",
                GetAnalyzerName(), identifier);

        if ( report_unknown_protocols )
            packet_mgr->ReportUnknownProtocol(GetAnalyzerName(), identifier, data, len);

        return false;
    }

    if ( ! inner_analyzer->IsEnabled() ) {
        DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s found disabled next layer analyzer %s for identifier %#" PRIx64,
                GetAnalyzerName(), inner_analyzer->GetAnalyzerName(), identifier);
        return false;
    }

    DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s succeeded, next layer identifier is %#" PRIx64 ".", GetAnalyzerName(),
            identifier);

    packet_mgr->TrackAnalyzer(inner_analyzer.get(), len, data);
    return inner_analyzer->AnalyzePacket(len, data, packet);
}

bool Analyzer::ForwardPacket(size_t len, const uint8_t* data, Packet* packet) const {
    const auto& inner_analyzer = FindInnerAnalyzer(len, data, packet);

    if ( ! inner_analyzer ) {
        DBG_LOG(DBG_PACKET_ANALYSIS, "Analysis in %s stopped, no default analyzer available.", GetAnalyzerName());

        if ( report_unknown_protocols )
            Weird("no_suitable_analyzer_found", packet);

        return false;
    }

    packet_mgr->TrackAnalyzer(inner_analyzer.get(), len, data);
    return inner_analyzer->AnalyzePacket(len, data, packet);
}

void Analyzer::DumpDebug() const {
#ifdef DEBUG
    DBG_LOG(DBG_PACKET_ANALYSIS, "Dispatcher for %s", this->GetAnalyzerName());
    dispatcher.DumpDebug();
#endif
}

void Analyzer::RegisterProtocol(uint64_t identifier, AnalyzerPtr child) {
    if ( run_state::detail::zeek_init_done )
        reporter->FatalError("Packet protocols cannot be registered after zeek_init has finished.");

    dispatcher.Register(identifier, std::move(child));
}

void Analyzer::Weird(const char* name, Packet* packet, const char* addl) const {
    session_mgr->Weird(name, packet, addl, GetAnalyzerName());
}

void Analyzer::EnqueueAnalyzerConfirmationInfo(session::Session* session, const zeek::Tag& arg_tag) {
    static auto info_type = zeek::id::find_type<RecordType>("AnalyzerConfirmationInfo");
    static auto info_c_idx = info_type->FieldOffset("c");

    auto info = make_intrusive<RecordVal>(info_type);
    info->Assign(info_c_idx, session->GetVal());

    event_mgr.Enqueue(analyzer_confirmation_info, arg_tag.AsVal(), info);
}

void Analyzer::AnalyzerConfirmation(session::Session* session, zeek::Tag arg_tag) {
    const auto& effective_tag = arg_tag ? arg_tag : GetAnalyzerTag();

    if ( ! session )
        return;

    if ( session->AnalyzerState(effective_tag) == session::AnalyzerConfirmationState::CONFIRMED )
        return;

    // If this session violated previously, we don't allow through a confirmation.
    if ( session->AnalyzerState(effective_tag) == session::AnalyzerConfirmationState::VIOLATED )
        return;

    session->SetAnalyzerState(effective_tag, session::AnalyzerConfirmationState::CONFIRMED);

    if ( analyzer_confirmation_info )
        EnqueueAnalyzerConfirmationInfo(session, effective_tag);
}

void Analyzer::EnqueueAnalyzerViolationInfo(session::Session* session, const char* reason, const char* data, int len,
                                            const zeek::Tag& arg_tag) {
    static auto info_type = zeek::id::find_type<RecordType>("AnalyzerViolationInfo");
    static auto info_reason_idx = info_type->FieldOffset("reason");
    static auto info_c_idx = info_type->FieldOffset("c");
    static auto info_data_idx = info_type->FieldOffset("data");

    auto info = zeek::make_intrusive<RecordVal>(info_type);
    info->Assign(info_reason_idx, make_intrusive<StringVal>(reason));
    info->Assign(info_c_idx, session->GetVal());
    if ( data && len )
        info->Assign(info_data_idx, make_intrusive<StringVal>(len, data));

    event_mgr.Enqueue(analyzer_violation_info, arg_tag.AsVal(), info);
}

void Analyzer::AnalyzerViolation(const char* reason, session::Session* session, const char* data, int len,
                                 zeek::Tag arg_tag) {
    const auto& effective_tag = arg_tag ? arg_tag : GetAnalyzerTag();

    if ( ! session )
        return;

    if ( session->AnalyzerState(effective_tag) == session::AnalyzerConfirmationState::VIOLATED )
        return;

    session->SetAnalyzerState(effective_tag, session::AnalyzerConfirmationState::VIOLATED);

    if ( analyzer_violation_info )
        EnqueueAnalyzerViolationInfo(session, reason, data, len, effective_tag);
}

} // namespace zeek::packet_analysis
