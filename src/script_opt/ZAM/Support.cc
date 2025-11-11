// See the file "COPYING" in the main distribution directory for copyright.

// Low-level support utilities/globals for ZAM compilation.

#include "zeek/script_opt/ZAM/Support.h"

#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/ScriptValidation.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"
#include "zeek/broker/Manager.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/file_analysis/file_analysis.bif.h"
#include "zeek/logging/Manager.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/session/Manager.h"

namespace zeek::detail {

namespace ZAM {
std::string curr_func;
std::shared_ptr<ZAMLocInfo> curr_loc;
TypePtr log_ID_enum_type;
TypePtr any_base_type = base_type(TYPE_ANY);

bool log_mgr_write(zeek::EnumVal* v, zeek::RecordVal* r) { return zeek::log_mgr->Write(v, r); }

size_t broker_mgr_flush_log_buffers() { return zeek::broker_mgr->FlushLogBuffers(); }

zeek::Connection* session_mgr_find_connection(zeek::Val* cid) { return zeek::session_mgr->FindConnection(cid); }

zeek::StringVal* analyzer_name(zeek::EnumVal* val) {
    plugin::Component* component = zeek::analyzer_mgr->Lookup(val, false);

    if ( ! component )
        component = zeek::packet_mgr->Lookup(val, false);

    if ( ! component )
        component = zeek::file_mgr->Lookup(val, false);

    if ( component )
        return new StringVal(component->CanonicalName());
    return new StringVal("<error>");
}

zeek::plugin::Component* analyzer_mgr_lookup(zeek::EnumVal* v) { return zeek::analyzer_mgr->Lookup(v); }

zeek_uint_t conn_size_get_bytes_threshold(Val* cid, bool is_orig) {
    if ( auto* a = analyzer::conn_size::GetConnsizeAnalyzer(cid) )
        return static_cast<analyzer::conn_size::ConnSize_Analyzer*>(a)->GetByteAndPacketThreshold(true, is_orig);

    return 0;
}

bool conn_size_set_bytes_threshold(zeek_uint_t threshold, Val* cid, bool is_orig) {
    if ( auto* a = analyzer::conn_size::GetConnsizeAnalyzer(cid) ) {
        static_cast<analyzer::conn_size::ConnSize_Analyzer*>(a)->SetByteAndPacketThreshold(threshold, true, is_orig);
        return true;
    }

    return false;
}

// File analysis wrappers
void file_mgr_set_handle(StringVal* h) { zeek::file_mgr->SetHandle(h->ToStdString()); }

bool file_mgr_add_analyzer(StringVal* file_id, EnumVal* tag, RecordVal* args) {
    const auto& tag_ = zeek::file_mgr->GetComponentTag(tag);
    if ( ! tag_ )
        return false;

    using zeek::BifType::Record::Files::AnalyzerArgs;
    auto rv = args->CoerceTo(AnalyzerArgs);
    return zeek::file_mgr->AddAnalyzer(file_id->CheckString(), tag_, std::move(rv));
}

bool file_mgr_remove_analyzer(StringVal* file_id, EnumVal* tag, RecordVal* args) {
    const auto& tag_ = zeek::file_mgr->GetComponentTag(tag);
    if ( ! tag_ )
        return false;

    using zeek::BifType::Record::Files::AnalyzerArgs;
    auto rv = args->CoerceTo(AnalyzerArgs);
    return zeek::file_mgr->RemoveAnalyzer(file_id->CheckString(), tag_, std::move(rv));
}

bool file_mgr_analyzer_enabled(zeek::EnumVal* v) {
    auto c = zeek::file_mgr->Lookup(v->AsEnumVal());
    return c && c->Enabled();
}

zeek::StringVal* file_mgr_analyzer_name(EnumVal* v) {
    // to be placed into a ZVal
    return file_mgr->GetComponentNameVal({NewRef{}, v}).release();
}

bool file_mgr_enable_reassembly(StringVal* file_id) {
    std::string fid = file_id->CheckString();
    return zeek::file_mgr->EnableReassembly(fid);
}

bool file_mgr_disable_reassembly(StringVal* file_id) {
    std::string fid = file_id->CheckString();
    return zeek::file_mgr->DisableReassembly(fid);
}

bool file_mgr_set_reassembly_buffer(StringVal* file_id, uint64_t max) {
    std::string fid = file_id->CheckString();
    return zeek::file_mgr->SetReassemblyBuffer(fid, max);
}

} // namespace ZAM

bool ZAM_error = false;

bool is_ZAM_compilable(const ProfileFunc* pf, const char** reason) {
    auto func = pf->ProfiledFunc(); // can be nil for lambdas

    if ( func ) {
        auto& scope_id = pf->ProfiledScope()->GetID();
        if ( scope_id && scope_id->GetAttr(ATTR_NO_ZAM_OPT) ) {
            if ( reason )
                *reason = "&no_ZAM_opt attribute";
            return false;
        }
    }

    if ( has_AST_node_unknown_to_script_opt(pf, true) ) {
        if ( reason )
            *reason = "unknown AST node type";
        return false;
    }

    auto b = pf->ProfiledBody();
    auto is_hook = pf->ProfiledFunc()->Flavor() == FUNC_FLAVOR_HOOK;
    if ( b && ! script_is_valid(b, is_hook) ) {
        if ( reason )
            *reason = "invalid script body";
        return false;
    }

    return true;
}

bool IsAny(const Type* t) { return t->Tag() == TYPE_ANY; }

bool CheckAnyType(const TypePtr& any_type, const TypePtr& expected_type, const std::shared_ptr<ZAMLocInfo>& loc) {
    if ( IsAny(expected_type) )
        return true;

    if ( ! same_type(any_type, expected_type, false, false) ) {
        auto at = any_type->Tag();
        auto et = expected_type->Tag();

        if ( at == TYPE_RECORD && et == TYPE_RECORD ) {
            auto at_r = any_type->AsRecordType();
            auto et_r = expected_type->AsRecordType();

            if ( record_promotion_compatible(et_r, at_r) )
                return true;
        }

        char buf[8192];
        snprintf(buf, sizeof buf, "run-time type clash (%s/%s)", type_name(at), type_name(et));

        reporter->RuntimeError(loc->Loc(), "%s", buf);
        return false;
    }

    return true;
}

StringVal* ZAM_to_lower(const StringVal* sv) {
    auto bs = sv->AsString();
    const u_char* s = bs->Bytes();
    int n = bs->Len();
    u_char* lower_s = new u_char[n + 1];
    u_char* ls = lower_s;

    for ( int i = 0; i < n; ++i ) {
        if ( isascii(s[i]) && isupper(s[i]) )
            *ls++ = tolower(s[i]);
        else
            *ls++ = s[i];
    }

    *ls++ = '\0';

    return new StringVal(new String(true, lower_s, n));
}

StringVal* ZAM_sub_bytes(const StringVal* s, zeek_uint_t start, zeek_int_t n) {
    if ( start > 0 )
        --start; // make it 0-based

    auto ss = s->AsString()->GetSubstring(start, n);

    return new StringVal(ss ? ss : new String(""));
}

StringValPtr ZAM_val_cat(const ValPtr& v) {
    // Quite similar to cat(), but for only one value.
    zeek::ODesc d;
    d.SetStyle(RAW_STYLE);

    v->Describe(&d);

    String* s = new String(true, d.TakeBytes(), d.Size());
    s->SetUseFreeToDelete(true);

    return make_intrusive<StringVal>(s);
}

void ZAM_run_time_error(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    ZAM_error = true;
}

void ZAM_run_time_error(const std::shared_ptr<ZAMLocInfo>& loc, const char* msg) {
    if ( loc )
        reporter->RuntimeError(loc->Loc(), "%s", msg);
    else
        fprintf(stderr, "<no location in optimized code>: %s\n", msg);
    ZAM_error = true;
}

void ZAM_run_time_error(const char* msg, const Obj* o) {
    fprintf(stderr, "%s: %s\n", msg, obj_desc(o).c_str());
    ZAM_error = true;
}

void ZAM_run_time_error(const std::shared_ptr<ZAMLocInfo>& loc, const char* msg, const Obj* o) {
    if ( loc )
        reporter->RuntimeError(loc->Loc(), "%s (%s)", msg, obj_desc(o).c_str());
    else
        ZAM_run_time_error(msg, o);
    ZAM_error = true;
}

void ZAM_run_time_warning(const std::shared_ptr<ZAMLocInfo>& loc, const char* msg) {
    ODesc d;
    loc->Loc()->Describe(&d);

    reporter->Warning("%s: %s", d.Description(), msg);
}

} // namespace zeek::detail
