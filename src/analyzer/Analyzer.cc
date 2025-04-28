// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/Analyzer.h"

#include <binpac.h>
#include <algorithm>

#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"

#include "zeek/3rdparty/doctest.h"

namespace zeek::analyzer {

class AnalyzerTimer final : public zeek::detail::Timer {
public:
    AnalyzerTimer(Analyzer* arg_analyzer, analyzer_timer_func arg_timer, double arg_t, int arg_do_expire,
                  zeek::detail::TimerType arg_type);

    ~AnalyzerTimer() override;

    void Dispatch(double t, bool is_expire) override;

protected:
    void Init(Analyzer* analyzer, analyzer_timer_func timer, int do_expire);

    Analyzer* analyzer = nullptr;
    analyzer_timer_func timer;
    int do_expire = 0;
};

AnalyzerTimer::AnalyzerTimer(Analyzer* arg_analyzer, analyzer_timer_func arg_timer, double arg_t, int arg_do_expire,
                             zeek::detail::TimerType arg_type)
    : Timer(arg_t, arg_type) {
    Init(arg_analyzer, arg_timer, arg_do_expire);
}

AnalyzerTimer::~AnalyzerTimer() {
    analyzer->RemoveTimer(this);
    Unref(analyzer->Conn());
}

void AnalyzerTimer::Dispatch(double t, bool is_expire) {
    if ( is_expire && ! do_expire )
        return;

    // Remove ourselves from the connection's set of timers so
    // it doesn't try to cancel us.
    analyzer->RemoveTimer(this);

    (analyzer->*timer)(t);
}

void AnalyzerTimer::Init(Analyzer* arg_analyzer, analyzer_timer_func arg_timer, int arg_do_expire) {
    analyzer = arg_analyzer;
    timer = arg_timer;
    do_expire = arg_do_expire;

    // We need to Ref the connection as the analyzer doesn't do it and
    // we need to have it around until we expire.
    Ref(analyzer->Conn());
}

analyzer::ID Analyzer::id_counter = 0;

const char* Analyzer::GetAnalyzerName() const {
    assert(tag);
    return analyzer_mgr->GetComponentName(tag).c_str();
}

void Analyzer::SetAnalyzerTag(const zeek::Tag& arg_tag) {
    assert(! tag || tag == arg_tag);
    tag = arg_tag;
}

bool Analyzer::IsAnalyzer(const char* name) {
    assert(tag);
    return strcmp(analyzer_mgr->GetComponentName(tag).c_str(), name) == 0;
}

Analyzer::Analyzer(const char* name, Connection* conn) {
    zeek::Tag tag = analyzer_mgr->GetComponentTag(name);

    if ( ! tag )
        reporter->InternalError("unknown analyzer name %s; mismatch with tag analyzer::Component?", name);

    CtorInit(tag, conn);
}

Analyzer::Analyzer(const zeek::Tag& tag, Connection* conn) { CtorInit(tag, conn); }

Analyzer::Analyzer(Connection* conn) { CtorInit(zeek::Tag(), conn); }

void Analyzer::CtorInit(const zeek::Tag& arg_tag, Connection* arg_conn) {
    // Don't Ref conn here to avoid circular ref'ing. It can't be deleted
    // before us.
    conn = arg_conn;
    tag = arg_tag;
    id = ++id_counter;
    protocol_confirmed = false;
    analyzer_confirmed = false;
    timers_canceled = false;
    skip = false;
    finished = false;
    removing = false;
    parent = nullptr;
    orig_supporters = nullptr;
    resp_supporters = nullptr;
    signature = nullptr;
    output_handler = nullptr;
}

Analyzer::~Analyzer() {
    assert(finished);
    assert(new_children.empty());

    LOOP_OVER_CHILDREN(i)
    delete *i;

    SupportAnalyzer* next = nullptr;

    for ( SupportAnalyzer* a = orig_supporters; a; a = next ) {
        next = a->sibling;
        delete a;
    }

    for ( SupportAnalyzer* a = resp_supporters; a; a = next ) {
        next = a->sibling;
        delete a;
    }

    delete output_handler;
}

void Analyzer::Init() {}

void Analyzer::InitChildren() {
    AppendNewChildren();

    LOOP_OVER_CHILDREN(i) {
        (*i)->Init();
        (*i)->InitChildren();
    }
}

void Analyzer::Done() {
    assert(! finished);

    if ( ! skip ) {
        EndOfData(true);
        EndOfData(false);
    }

    CancelTimers();

    AppendNewChildren();

    LOOP_OVER_CHILDREN(i)
    if ( ! (*i)->finished )
        (*i)->Done();

    for ( SupportAnalyzer* a = orig_supporters; a; a = a->sibling )
        if ( ! a->finished )
            a->Done();

    for ( SupportAnalyzer* a = resp_supporters; a; a = a->sibling )
        if ( ! a->finished )
            a->Done();

    finished = true;
}

void Analyzer::NextPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen) {
    if ( skip )
        return;

    SupportAnalyzer* next_sibling = FirstSupportAnalyzer(is_orig);

    if ( next_sibling )
        next_sibling->NextPacket(len, data, is_orig, seq, ip, caplen);

    else {
        try {
            DeliverPacket(len, data, is_orig, seq, ip, caplen);
        } catch ( binpac::Exception const& e ) {
            AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
        }
    }
}

void Analyzer::NextStream(int len, const u_char* data, bool is_orig) {
    if ( skip )
        return;

    SupportAnalyzer* next_sibling = FirstSupportAnalyzer(is_orig);

    if ( next_sibling )
        next_sibling->NextStream(len, data, is_orig);

    else {
        try {
            DeliverStream(len, data, is_orig);
        } catch ( binpac::Exception const& e ) {
            AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
        }
    }
}

void Analyzer::NextUndelivered(uint64_t seq, int len, bool is_orig) {
    if ( skip )
        return;

    SupportAnalyzer* next_sibling = FirstSupportAnalyzer(is_orig);

    if ( next_sibling )
        next_sibling->NextUndelivered(seq, len, is_orig);

    else {
        try {
            Undelivered(seq, len, is_orig);
        } catch ( binpac::Exception const& e ) {
            AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
        }
    }
}

void Analyzer::NextEndOfData(bool is_orig) {
    if ( skip )
        return;

    SupportAnalyzer* next_sibling = FirstSupportAnalyzer(is_orig);

    if ( next_sibling )
        next_sibling->NextEndOfData(is_orig);
    else
        EndOfData(is_orig);
}

void Analyzer::ForwardPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen) {
    if ( output_handler )
        output_handler->DeliverPacket(len, data, is_orig, seq, ip, caplen);

    AppendNewChildren();

    // Pass to all children.
    for ( auto i = children.begin(); i != children.end(); ) {
        Analyzer* current = *i;

        if ( ! (current->finished || current->removing) ) {
            current->NextPacket(len, data, is_orig, seq, ip, caplen);
            ++i;
        }
        else
            i = DeleteChild(i);
    }

    AppendNewChildren();
}

void Analyzer::ForwardStream(int len, const u_char* data, bool is_orig) {
    if ( output_handler )
        output_handler->DeliverStream(len, data, is_orig);

    AppendNewChildren();

    for ( auto i = children.begin(); i != children.end(); ) {
        Analyzer* current = *i;

        if ( ! (current->finished || current->removing) ) {
            current->NextStream(len, data, is_orig);
            ++i;
        }
        else
            i = DeleteChild(i);
    }

    AppendNewChildren();
}

void Analyzer::ForwardUndelivered(uint64_t seq, int len, bool is_orig) {
    if ( output_handler )
        output_handler->Undelivered(seq, len, is_orig);

    AppendNewChildren();

    for ( auto i = children.begin(); i != children.end(); ) {
        Analyzer* current = *i;

        if ( ! (current->finished || current->removing) ) {
            current->NextUndelivered(seq, len, is_orig);
            ++i;
        }
        else
            i = DeleteChild(i);
    }

    AppendNewChildren();
}

void Analyzer::ForwardEndOfData(bool orig) {
    AppendNewChildren();

    for ( auto i = children.begin(); i != children.end(); ) {
        Analyzer* current = *i;

        if ( ! (current->finished || current->removing) ) {
            current->NextEndOfData(orig);
            ++i;
        }
        else
            i = DeleteChild(i);
    }

    AppendNewChildren();
}

bool Analyzer::AddChildAnalyzer(Analyzer* analyzer, bool init) {
    auto t = analyzer->GetAnalyzerTag();

    // Prevent attaching child analyzers to analyzer subtrees where
    // either the parent has finished or is being removed. Further,
    // don't attach analyzers when the connection has finished or is
    // currently being finished (executing Done()).
    //
    // Scenarios in which analyzers have been observed that late in
    // analyzer / connection lifetime are:
    //
    // * A DPD signature match on undelivered TCP data that is flushed
    //   during Connection::Done(). The PIA analyzer activates a new
    //   analyzer adding it to the TCP analyzer.
    //
    // * Analyzers flushing buffered state during Done(), resulting
    //   in new analyzers being created.
    //
    // Analyzers added during Done() are problematic as calling Done()
    // within the parent's destructor isn't safe, so we prevent these
    // situations.
    if ( Removing() || IsFinished() || Conn()->IsFinished() ) {
        analyzer->Done();
        delete analyzer;
        return false;
    }

    if ( HasChildAnalyzer(t) || IsPreventedChildAnalyzer(t) ) {
        analyzer->Done();
        delete analyzer;
        return false;
    }

    // We add new children to new_children first.  They are then
    // later copied to the "real" child list.  This is necessary
    // because this method may be called while somebody is iterating
    // over the children and we might confuse the caller by modifying
    // the list.

    analyzer->parent = this;
    new_children.push_back(analyzer);

    if ( init )
        analyzer->Init();

    DBG_LOG(DBG_ANALYZER, "%s added child %s", fmt_analyzer(this).c_str(), fmt_analyzer(analyzer).c_str());
    return true;
}

Analyzer* Analyzer::AddChildAnalyzer(const zeek::Tag& analyzer) {
    if ( HasChildAnalyzer(analyzer) )
        return nullptr;

    if ( IsPreventedChildAnalyzer(tag) )
        return nullptr;

    Analyzer* a = analyzer_mgr->InstantiateAnalyzer(analyzer, conn);

    if ( a && AddChildAnalyzer(a) )
        return a;

    return nullptr;
}

bool Analyzer::RemoveChild(const analyzer_list& children, ID id) {
    for ( const auto& i : children ) {
        if ( i->id != id )
            continue;

        if ( i->finished || i->removing )
            return false;

        DBG_LOG(DBG_ANALYZER, "%s disabling child %s", fmt_analyzer(this).c_str(), fmt_analyzer(i).c_str());
        // We just flag it as being removed here but postpone
        // actually doing that to later. Otherwise, we'd need
        // to call Done() here, which then in turn might
        // cause further code to be executed that may assume
        // something not true because of a violation that
        // triggered the removal in the first place.
        i->removing = true;
        return true;
    }

    return false;
}

bool Analyzer::RemoveChildAnalyzer(ID id) { return RemoveChild(children, id) || RemoveChild(new_children, id); }

bool Analyzer::Remove() {
    assert(parent);
    parent->RemoveChildAnalyzer(this);
    return removing;
}

void Analyzer::PreventChildren(const zeek::Tag& tag) {
    if ( IsPreventedChildAnalyzer(tag) )
        return;

    prevented.emplace_back(tag);
}

bool Analyzer::IsPreventedChildAnalyzer(const zeek::Tag& tag) const {
    return std::find(prevented.begin(), prevented.end(), tag) != prevented.end();
}

bool Analyzer::HasChildAnalyzer(const zeek::Tag& tag) const { return GetChildAnalyzer(tag) != nullptr; }

Analyzer* Analyzer::GetChildAnalyzer(const zeek::Tag& tag) const {
    LOOP_OVER_CHILDREN(i)
    if ( (*i)->tag == tag && ! ((*i)->removing || (*i)->finished) )
        return *i;

    LOOP_OVER_GIVEN_CHILDREN(i, new_children)
    if ( (*i)->tag == tag && ! ((*i)->removing || (*i)->finished) )
        return *i;

    return nullptr;
}

Analyzer* Analyzer::GetChildAnalyzer(const std::string& name) const {
    LOOP_OVER_CHILDREN(i)
    if ( (*i)->GetAnalyzerName() == name && ! ((*i)->removing || (*i)->finished) )
        return *i;

    LOOP_OVER_GIVEN_CHILDREN(i, new_children)
    if ( (*i)->GetAnalyzerName() == name && ! ((*i)->removing || (*i)->finished) )
        return *i;

    return nullptr;
}

Analyzer* Analyzer::FindChild(ID arg_id) {
    if ( id == arg_id && ! (removing || finished) )
        return this;

    LOOP_OVER_CHILDREN(i) {
        Analyzer* child = (*i)->FindChild(arg_id);
        if ( child )
            return child;
    }

    LOOP_OVER_GIVEN_CHILDREN(i, new_children) {
        Analyzer* child = (*i)->FindChild(arg_id);
        if ( child )
            return child;
    }

    return nullptr;
}

Analyzer* Analyzer::FindChild(zeek::Tag arg_tag) {
    if ( tag == arg_tag && ! (removing || finished) )
        return this;

    LOOP_OVER_CHILDREN(i) {
        Analyzer* child = (*i)->FindChild(arg_tag);
        if ( child )
            return child;
    }

    LOOP_OVER_GIVEN_CHILDREN(i, new_children) {
        Analyzer* child = (*i)->FindChild(arg_tag);
        if ( child )
            return child;
    }

    return nullptr;
}

Analyzer* Analyzer::FindChild(const char* name) {
    zeek::Tag tag = analyzer_mgr->GetComponentTag(name);
    return tag ? FindChild(tag) : nullptr;
}

void Analyzer::CleanupChildren() {
    AppendNewChildren();

    for ( auto i = children.begin(); i != children.end(); ) {
        if ( ! ((*i)->finished || (*i)->removing) )
            ++i;
        else
            i = DeleteChild(i);
    }
}

analyzer_list::iterator Analyzer::DeleteChild(analyzer_list::iterator i) {
    Analyzer* child = *i;

    // Analyzer must have already been finished or marked for removal.
    assert(child->finished || child->removing);

    if ( child->removing ) {
        child->Done();
        child->removing = false;
    }

    DBG_LOG(DBG_ANALYZER, "%s deleted child %s 3", fmt_analyzer(this).c_str(), fmt_analyzer(child).c_str());

    auto next = children.erase(i);
    delete child;
    return next;
}

void Analyzer::AddSupportAnalyzer(SupportAnalyzer* analyzer) {
    if ( HasSupportAnalyzer(analyzer->GetAnalyzerTag(), analyzer->IsOrig()) ) {
        DBG_LOG(DBG_ANALYZER, "%s already has %s %s", fmt_analyzer(this).c_str(),
                analyzer->IsOrig() ? "originator" : "responder", fmt_analyzer(analyzer).c_str());

        analyzer->Done();
        delete analyzer;
        return;
    }

    SupportAnalyzer** head = analyzer->IsOrig() ? &orig_supporters : &resp_supporters;

    // Find end of the list.
    SupportAnalyzer* prev = nullptr;
    SupportAnalyzer* s;
    for ( s = *head; s; prev = s, s = s->sibling )
        ;

    if ( prev )
        prev->sibling = analyzer;
    else
        *head = analyzer;

    analyzer->parent = this;

    analyzer->Init();

    DBG_LOG(DBG_ANALYZER, "%s added %s support %s", fmt_analyzer(this).c_str(),
            analyzer->IsOrig() ? "originator" : "responder", fmt_analyzer(analyzer).c_str());
}

void Analyzer::RemoveSupportAnalyzer(SupportAnalyzer* analyzer) {
    DBG_LOG(DBG_ANALYZER, "%s disabled %s support analyzer %s", fmt_analyzer(this).c_str(),
            analyzer->IsOrig() ? "originator" : "responder", fmt_analyzer(analyzer).c_str());

    // We mark the analyzer as being removed here, which will prevent it
    // from being used further. However, we don't actually delete it
    // before the parent gets destroyed. While we could do that, it's a
    // bit tricky to do at the right time and it doesn't seem worth the
    // trouble.
    analyzer->removing = true;
    return;
}

bool Analyzer::HasSupportAnalyzer(const zeek::Tag& tag, bool orig) {
    SupportAnalyzer* s = orig ? orig_supporters : resp_supporters;
    for ( ; s; s = s->sibling )
        if ( s->tag == tag )
            return true;

    return false;
}

SupportAnalyzer* Analyzer::FirstSupportAnalyzer(bool orig) {
    SupportAnalyzer* sa = orig ? orig_supporters : resp_supporters;

    if ( ! sa )
        return nullptr;

    if ( ! sa->Removing() )
        return sa;

    return sa->Sibling(true);
}

void Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen) {
    DBG_LOG(DBG_ANALYZER, "%s DeliverPacket(%d, %s, %" PRIu64 ", %p, %d) [%s%s]", fmt_analyzer(this).c_str(), len,
            is_orig ? "T" : "F", seq, ip, caplen, util::fmt_bytes((const char*)data, min(40, len)),
            len > 40 ? "..." : "");
}

void Analyzer::DeliverStream(int len, const u_char* data, bool is_orig) {
    DBG_LOG(DBG_ANALYZER, "%s DeliverStream(%d, %s) [%s%s]", fmt_analyzer(this).c_str(), len, is_orig ? "T" : "F",
            util::fmt_bytes((const char*)data, min(40, len)), len > 40 ? "..." : "");
}

void Analyzer::Undelivered(uint64_t seq, int len, bool is_orig) {
    DBG_LOG(DBG_ANALYZER, "%s Undelivered(%" PRIu64 ", %d, %s)", fmt_analyzer(this).c_str(), seq, len,
            is_orig ? "T" : "F");
}

void Analyzer::EndOfData(bool is_orig) {
    DBG_LOG(DBG_ANALYZER, "%s EndOfData(%s)", fmt_analyzer(this).c_str(), is_orig ? "T" : "F");
}

void Analyzer::FlipRoles() {
    DBG_LOG(DBG_ANALYZER, "%s FlipRoles()", fmt_analyzer(this).c_str());

    LOOP_OVER_CHILDREN(i)
    (*i)->FlipRoles();

    LOOP_OVER_GIVEN_CHILDREN(i, new_children)
    (*i)->FlipRoles();

    for ( SupportAnalyzer* a = orig_supporters; a; a = a->sibling )
        a->FlipRoles();

    for ( SupportAnalyzer* a = resp_supporters; a; a = a->sibling )
        a->FlipRoles();

    SupportAnalyzer* tmp = orig_supporters;
    orig_supporters = resp_supporters;
    resp_supporters = tmp;
}

void Analyzer::EnqueueAnalyzerConfirmationInfo(const zeek::Tag& arg_tag) {
    static auto info_type = zeek::id::find_type<RecordType>("AnalyzerConfirmationInfo");
    static auto info_c_idx = info_type->FieldOffset("c");
    static auto info_aid_idx = info_type->FieldOffset("aid");

    auto info = make_intrusive<RecordVal>(info_type);
    info->Assign(info_c_idx, ConnVal());
    info->Assign(info_aid_idx, val_mgr->Count(id));

    event_mgr.Enqueue(analyzer_confirmation_info, arg_tag.AsVal(), info);
}

void Analyzer::AnalyzerConfirmation(zeek::Tag arg_tag) {
    if ( analyzer_confirmed )
        return;

    analyzer_confirmed = true;

    const auto& effective_tag = arg_tag ? arg_tag : tag;

    if ( analyzer_confirmation_info )
        EnqueueAnalyzerConfirmationInfo(effective_tag);
}

void Analyzer::EnqueueAnalyzerViolationInfo(const char* reason, const char* data, int len, const zeek::Tag& arg_tag) {
    static auto info_type = zeek::id::find_type<RecordType>("AnalyzerViolationInfo");
    static auto info_reason_idx = info_type->FieldOffset("reason");
    static auto info_c_idx = info_type->FieldOffset("c");
    static auto info_aid_idx = info_type->FieldOffset("aid");
    static auto info_data_idx = info_type->FieldOffset("data");

    auto info = zeek::make_intrusive<RecordVal>(info_type);
    info->Assign(info_reason_idx, make_intrusive<StringVal>(reason));
    info->Assign(info_c_idx, ConnVal());
    info->Assign(info_aid_idx, val_mgr->Count(id));
    if ( data && len )
        info->Assign(info_data_idx, make_intrusive<StringVal>(len, data));

    event_mgr.Enqueue(analyzer_violation_info, arg_tag.AsVal(), info);
}

void Analyzer::AnalyzerViolation(const char* reason, const char* data, int len, zeek::Tag arg_tag) {
    const auto& effective_tag = arg_tag ? arg_tag : tag;

    ++analyzer_violations;

    if ( analyzer_violations > BifConst::max_analyzer_violations ) {
        if ( analyzer_violations == BifConst::max_analyzer_violations + 1 )
            Weird("too_many_analyzer_violations");

        return;
    }

    if ( analyzer_violation_info )
        EnqueueAnalyzerViolationInfo(reason, data, len, effective_tag);
}

void Analyzer::AddTimer(analyzer_timer_func timer, double t, bool do_expire, zeek::detail::TimerType type) {
    zeek::detail::Timer* analyzer_timer = new AnalyzerTimer(this, timer, t, do_expire, type);

    zeek::detail::timer_mgr->Add(analyzer_timer);
    timers.push_back(analyzer_timer);
}

void Analyzer::RemoveTimer(zeek::detail::Timer* t) { timers.remove(t); }

void Analyzer::CancelTimers() {
    // We are going to cancel our timers which, in turn, may cause them to
    // call RemoveTimer(), which would then modify the list we're just
    // traversing.  Thus, we first make a copy of the list which we then
    // iterate through.
    TimerPList tmp(timers.length());
    std::copy(timers.begin(), timers.end(), back_inserter(tmp));

    // TODO: could be a for_each
    for ( auto timer : tmp )
        zeek::detail::timer_mgr->Cancel(timer);

    timers_canceled = true;
    timers.clear();
}

void Analyzer::AppendNewChildren() {
    LOOP_OVER_GIVEN_CHILDREN(i, new_children)
    children.push_back(*i);
    new_children.clear();
}

void Analyzer::UpdateConnVal(RecordVal* conn_val) {
    LOOP_OVER_CHILDREN(i)
    (*i)->UpdateConnVal(conn_val);
}

const RecordValPtr& Analyzer::ConnVal() { return conn->GetVal(); }

void Analyzer::Event(EventHandlerPtr f, const char* name) { conn->Event(f, this, name); }

void Analyzer::EnqueueConnEvent(EventHandlerPtr f, Args args) { conn->EnqueueEvent(f, this, std::move(args)); }

void Analyzer::Weird(const char* name, const char* addl) { conn->Weird(name, addl, GetAnalyzerName()); }

SupportAnalyzer* SupportAnalyzer::Sibling(bool only_active) const {
    if ( ! only_active )
        return sibling;

    SupportAnalyzer* next = sibling;
    while ( next && next->Removing() )
        next = next->sibling;

    return next;
}

void SupportAnalyzer::ForwardPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip,
                                    int caplen) {
    // We do not call parent's method, as we're replacing the functionality.

    if ( GetOutputHandler() ) {
        GetOutputHandler()->DeliverPacket(len, data, is_orig, seq, ip, caplen);
        return;
    }

    // If the parent is being removed or has finished, there's little point
    // for a support analyzers to move packets forward.
    if ( Parent()->Removing() || Parent()->IsFinished() )
        return;

    SupportAnalyzer* next_sibling = Sibling(true);

    if ( next_sibling )
        // Pass to next in chain.
        next_sibling->NextPacket(len, data, is_orig, seq, ip, caplen);
    else
        // Finished with preprocessing - now it's the parent's turn.
        Parent()->DeliverPacket(len, data, is_orig, seq, ip, caplen);
}

void SupportAnalyzer::ForwardStream(int len, const u_char* data, bool is_orig) {
    // We do not call parent's method, as we're replacing the functionality.

    if ( GetOutputHandler() ) {
        GetOutputHandler()->DeliverStream(len, data, is_orig);
        return;
    }

    // If the parent is being removed or has finished, there's little point
    // for a support analyzers to move stream data forward.
    if ( Parent()->Removing() || Parent()->IsFinished() )
        return;

    SupportAnalyzer* next_sibling = Sibling(true);

    if ( next_sibling )
        // Pass to next in chain.
        next_sibling->NextStream(len, data, is_orig);
    else
        // Finished with preprocessing - now it's the parent's turn.
        Parent()->DeliverStream(len, data, is_orig);
}

void SupportAnalyzer::ForwardUndelivered(uint64_t seq, int len, bool is_orig) {
    // We do not call parent's method, as we're replacing the functionality.

    if ( GetOutputHandler() ) {
        GetOutputHandler()->Undelivered(seq, len, is_orig);
        return;
    }

    SupportAnalyzer* next_sibling = Sibling(true);

    if ( next_sibling )
        // Pass to next in chain.
        next_sibling->NextUndelivered(seq, len, is_orig);
    else
        // Finished with preprocessing - now it's the parent's turn.
        Parent()->Undelivered(seq, len, is_orig);
}

} // namespace zeek::analyzer

TEST_SUITE("Analyzer management") {
    TEST_CASE("Re-add analyzer after removal") {
        // This test tries to reactivate an analyzer which was previously removed.
        // It's a regression test for #2801.
        REQUIRE(zeek::analyzer_mgr);

        zeek::Packet p;
        zeek::ConnTuple t;
        auto conn = std::make_unique<zeek::Connection>(zeek::detail::ConnKey(t), 0, &t, 0, &p);
        auto* tcp = new zeek::packet_analysis::TCP::TCPSessionAdapter(conn.get());
        conn->SetSessionAdapter(tcp, nullptr);

        auto a = zeek::analyzer_mgr->InstantiateAnalyzer("SSH", conn.get());
        REQUIRE(a);
        auto b1 = zeek::analyzer_mgr->InstantiateAnalyzer("IMAP", a->Conn());
        REQUIRE(b1);

        CHECK(tcp->AddChildAnalyzer(a));
        CHECK(a->AddChildAnalyzer(b1));

        CHECK(conn->FindAnalyzer("SSH"));
        CHECK(conn->FindAnalyzer("IMAP"));

        CHECK(a->RemoveChildAnalyzer(b1));

        CHECK(! conn->FindAnalyzer("IMAP"));

        auto b2 = zeek::analyzer_mgr->InstantiateAnalyzer("IMAP", a->Conn());
        REQUIRE(b2);

        REQUIRE(a->AddChildAnalyzer(b2));
        CHECK(conn->FindAnalyzer("IMAP"));
        conn->Done();
    }

    TEST_CASE("Analyzer mapping") {
        REQUIRE(zeek::analyzer_mgr);

        zeek::Packet p;
        zeek::ConnTuple t;
        auto conn = std::make_unique<zeek::Connection>(zeek::detail::ConnKey(t), 0, &t, 0, &p);

        auto ssh = zeek::analyzer_mgr->InstantiateAnalyzer("SSH", conn.get());
        REQUIRE(ssh);
        auto imap = zeek::analyzer_mgr->InstantiateAnalyzer("IMAP", conn.get());
        REQUIRE(imap);

        zeek::analyzer_mgr->AddComponentMapping(ssh->GetAnalyzerTag(), imap->GetAnalyzerTag());
        zeek::analyzer_mgr->DisableAnalyzer(ssh->GetAnalyzerTag()); // needs to be disabled for mapping to take effect
        auto ssh_is_imap = zeek::analyzer_mgr->InstantiateAnalyzer("SSH", conn.get());
        CHECK_EQ(ssh_is_imap->GetAnalyzerTag(), imap->GetAnalyzerTag()); // SSH is now IMAP

        // orderly cleanup through connection
        auto* tcp = new zeek::packet_analysis::TCP::TCPSessionAdapter(conn.get());
        conn->SetSessionAdapter(tcp, nullptr);
        tcp->AddChildAnalyzer(ssh);
        tcp->AddChildAnalyzer(imap);
        tcp->AddChildAnalyzer(ssh_is_imap);
        conn->Done();
    }
}
