// See the file "COPYING" in the main distribution directory for copyright.

// Low-level support utilities/globals for ZAM compilation.

#include "zeek/script_opt/ZAM/Support.h"

#include "zeek/Desc.h"
#include "zeek/Reporter.h"
#include "zeek/ScriptValidation.h"
#include "zeek/ZeekString.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

namespace ZAM {
std::string curr_func;
std::shared_ptr<ZAMLocInfo> curr_loc;
TypePtr log_ID_enum_type;
TypePtr any_base_type;
} // namespace ZAM

bool ZAM_error = false;

bool is_ZAM_compilable(const ProfileFunc* pf, const char** reason) {
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

    String* s = new String(true, d.TakeBytes(), d.Len());
    s->SetUseFreeToDelete(true);

    return make_intrusive<StringVal>(s);
}

void ZAM_run_time_error(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    ZAM_error = true;
}

void ZAM_run_time_error(std::shared_ptr<ZAMLocInfo> loc, const char* msg) {
    reporter->RuntimeError(loc->Loc(), "%s", msg);
    ZAM_error = true;
}

void ZAM_run_time_error(const char* msg, const Obj* o) {
    fprintf(stderr, "%s: %s\n", msg, obj_desc(o).c_str());
    ZAM_error = true;
}

void ZAM_run_time_error(std::shared_ptr<ZAMLocInfo> loc, const char* msg, const Obj* o) {
    reporter->RuntimeError(loc->Loc(), "%s (%s)", msg, obj_desc(o).c_str());
    ZAM_error = true;
}

void ZAM_run_time_warning(std::shared_ptr<ZAMLocInfo> loc, const char* msg) {
    ODesc d;
    loc->Loc()->Describe(&d);

    reporter->Warning("%s: %s", d.Description(), msg);
}

} // namespace zeek::detail
