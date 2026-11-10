// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ZAM/BodyCache.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "zeek/Attr.h"
#include "zeek/Desc.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/IPAddr.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/module_util.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/ZAM/Profile.h"
#include "zeek/script_opt/ZAM/Support.h"
#include "zeek/script_opt/ZAM/ZBody.h"
#include "zeek/script_opt/ZAM/ZInst.h"
#include "zeek/script_opt/ZAM/ZInstAux.h"
#include "zeek/script_opt/ZAM/ZOp.h"

namespace zeek {
extern const char* zeek_version();
}

namespace zeek::detail {

ZAMBodyCache::ZAMBodyCache() {
    const char* d = getenv("ZEEK_ZAM_CACHE_DIR");
    if ( ! d || ! *d )
        return;

    dir = d;
    enabled = true;

    ComputeBuildId();
    ComputeOptionsHash();
}

// ---- Compile-environment fingerprint --------------------------------------
//
// A function's profile hash covers its own source, but its compiled ZAM body
// also depends on the environment it was compiled in, which differs between
// processes that load different scripts:
//   - record layouts: the profile type-hash covers only a record's original
//     fields, while ZAM hardwires field offsets and fields added via
//     "redef record ... +=" land at load-order-dependent offsets;
//   - enum values: redef-extensible enums (e.g. Log::ID) get load-order-dependent
//     integers, and instructions embed those integers;
//   - field/type attributes (&optional, &default, ...), which affect codegen;
//   - values of redef'able global constants, which the optimizer may fold.
// The fingerprint below captures all of these so that two processes only share
// a cache entry when the body would compile identically in both.

namespace {

p_hash_type env_type_hash(const Type* t, std::unordered_map<const Type*, p_hash_type>& memo,
                          std::unordered_set<const Type*>& active, bool& saw_cycle);

// A stable hash of an attribute expression. Plain Describe() is not stable for
// lambdas (e.g. "&default=function(n: count): string {...}"): their names are
// randomized per process, and their bodies render differently once compiled to
// ZAM, which happens partway through the very compile loop computing keys. So
// any expression whose rendering involves a lambda or compiled code is instead
// identified by its source location, type, and tag. (A caller's compiled body
// doesn't embed such expressions; they're evaluated at run time from the
// loading process's own attributes.)
p_hash_type env_attr_expr_hash(const Expr* e) {
    ODesc d;
    e->Describe(&d);
    std::string_view desc(d.Description());
    if ( desc.find("lambda_<") == std::string_view::npos && desc.find("ZAM-code") == std::string_view::npos )
        return p_hash(desc);

    auto l = e->GetLocationInfo();
    p_hash_type h = p_hash(static_cast<int>(e->Tag()));
    h = merge_p_hashes(h, p_hash(std::string_view(l && l->FileName() ? l->FileName() : "")));
    h = merge_p_hashes(h, p_hash(l ? l->FirstLine() : 0));
    h = merge_p_hashes(h, p_hash(l ? l->LastLine() : 0));
    if ( const auto& t = e->GetType() ) {
        ODesc td;
        t->Describe(&td);
        h = merge_p_hashes(h, p_hash(std::string_view(td.Description())));
    }
    return h;
}

p_hash_type env_attrs_hash(const Attributes* attrs) {
    if ( ! attrs )
        return 0;
    p_hash_type h = p_hash("attrs");
    for ( const auto& a : attrs->GetAttrs() ) {
        h = merge_p_hashes(h, p_hash(static_cast<int>(a->Tag())));
        if ( const auto& e = a->GetExpr() )
            h = merge_p_hashes(h, env_attr_expr_hash(e.get()));
    }
    return h;
}

p_hash_type env_type_hash(const Type* t, std::unordered_map<const Type*, p_hash_type>& memo,
                          std::unordered_set<const Type*>& active, bool& saw_cycle) {
    // Hashes of types whose traversal never reached an in-progress type depend
    // only on the type itself, so they are shared across all roots. Hashes
    // computed under a cycle depend on where the cycle was entered, so they are
    // only memoized within the current root's walk ('memo').
    static std::unordered_map<const Type*, p_hash_type> acyclic_memo;

    if ( ! t )
        return 0;
    if ( auto it = acyclic_memo.find(t); it != acyclic_memo.end() )
        return it->second;
    if ( auto it = memo.find(t); it != memo.end() ) {
        saw_cycle = true; // conservatively: this entry may be cycle-dependent
        return it->second;
    }

    p_hash_type h = merge_p_hashes(p_hash(static_cast<int>(t->Tag())), p_hash(std::string_view(t->GetName())));

    // Recursive types: within an in-progress traversal, refer to the type by
    // tag + name only (its full structure is accounted for by the outer visit).
    if ( ! active.insert(t).second ) {
        saw_cycle = true;
        return h;
    }

    bool local_cycle = false;
    auto sub = [&](const Type* st) { h = merge_p_hashes(h, env_type_hash(st, memo, active, local_cycle)); };

    switch ( t->Tag() ) {
        case TYPE_RECORD: {
            auto rt = t->AsRecordType();
            h = merge_p_hashes(h, p_hash(rt->NumFields()));
            for ( int i = 0; i < rt->NumFields(); ++i ) {
                auto fd = rt->FieldDecl(i);
                h = merge_p_hashes(h, p_hash(std::string_view(fd->id)));
                sub(fd->type.get());
                h = merge_p_hashes(h, env_attrs_hash(fd->attrs.get()));
            }
        } break;
        case TYPE_ENUM:
            for ( auto& [name, val] : t->AsEnumType()->Names() ) {
                h = merge_p_hashes(h, p_hash(std::string_view(name)));
                h = merge_p_hashes(h, p_hash(static_cast<int>(val)));
            }
            break;
        case TYPE_TABLE:
            sub(t->AsTableType()->GetIndices().get());
            sub(t->AsTableType()->Yield().get());
            break;
        case TYPE_FUNC: {
            auto ft = t->AsFuncType();
            h = merge_p_hashes(h, p_hash(static_cast<int>(ft->Flavor())));
            sub(ft->Params().get());
            sub(ft->Yield().get());
        } break;
        case TYPE_LIST:
            for ( auto& lt : t->AsTypeList()->GetTypes() )
                sub(lt.get());
            break;
        case TYPE_VECTOR:
            // Yield() reports "any" for unspecified vectors too; keep them distinct.
            h = merge_p_hashes(h, p_hash(t->AsVectorType()->IsUnspecifiedVector() ? 1 : 0));
            sub(t->AsVectorType()->Yield().get());
            break;
        case TYPE_FILE: sub(t->AsFileType()->Yield().get()); break;
        case TYPE_TYPE: sub(t->AsTypeType()->GetType().get()); break;
        default: break;
    }

    active.erase(t);
    if ( local_cycle ) {
        memo[t] = h;
        saw_cycle = true;
    }
    else
        acyclic_memo[t] = h;
    return h;
}

// Hash of a type's full structure, as a function of the type alone. Recursive
// types make a nested hash depend on which types are already being visited, so
// a memo freely shared across different roots would make results depend on
// traversal order (which, via unordered sets of pointers, can vary between
// processes). So each root is hashed by a deterministic depth-first walk; only
// root results and acyclic subtrees (see env_type_hash) are cached across walks.
p_hash_type env_type_hash_root(const Type* t) {
    static std::unordered_map<const Type*, p_hash_type> root_memo;
    if ( auto it = root_memo.find(t); it != root_memo.end() )
        return it->second;

    std::unordered_map<const Type*, p_hash_type> memo;
    std::unordered_set<const Type*> active;
    bool saw_cycle = false;
    auto h = env_type_hash(t, memo, active, saw_cycle);
    root_memo[t] = h;
    return h;
}

// Hash of a (global constant's) value that is stable across processes. Plain
// Describe() is not: table iteration order depends on the per-process hash
// seed, and lambda names are randomized. So containers are hashed structurally,
// with table/set entries combined order-independently.
p_hash_type env_value_hash(const Val* v, int depth = 0) {
    if ( ! v )
        return 0;

    auto tag = v->GetType()->Tag();
    p_hash_type h = p_hash(static_cast<int>(tag));

    if ( depth > 64 )
        return h; // pathological nesting; tag-only is still a valid (coarser) key

    switch ( tag ) {
        case TYPE_TABLE: {
            std::multiset<p_hash_type> entries;
            for ( auto& [k, val] : v->AsTableVal()->ToMap() )
                entries.insert(
                    merge_p_hashes(env_value_hash(k.get(), depth + 1), env_value_hash(val.get(), depth + 1)));
            for ( auto e : entries )
                h = merge_p_hashes(h, e);
        } break;
        case TYPE_RECORD: {
            auto rv = v->AsRecordVal();
            for ( int i = 0; i < rv->NumFields(); ++i )
                h = merge_p_hashes(h, env_value_hash(rv->GetField(i).get(), depth + 1));
        } break;
        case TYPE_VECTOR: {
            auto vv = v->AsVectorVal();
            for ( unsigned int i = 0; i < vv->Size(); ++i )
                h = merge_p_hashes(h, env_value_hash(vv->ValAt(i).get(), depth + 1));
        } break;
        case TYPE_LIST:
            for ( auto& e : v->AsListVal()->Vals() )
                h = merge_p_hashes(h, env_value_hash(e.get(), depth + 1));
            break;
        case TYPE_FUNC: {
            const auto& name = v->AsFunc()->GetName();
            if ( ! name.starts_with("lambda_") )
                h = merge_p_hashes(h, p_hash(std::string_view(name)));
        } break;
        case TYPE_OPAQUE:
        case TYPE_FILE:
        case TYPE_ANY: break;
        default: {
            ODesc d;
            v->Describe(&d);
            h = merge_p_hashes(h, p_hash(std::string_view(d.Description())));
        } break;
    }

    return h;
}

// Fingerprint of the environment a single profiled body compiles against.
p_hash_type env_fingerprint_uncached(const ProfileFunc* pf) {
    // Memoized across calls within a run; types and global values are fixed
    // by the time ZAM compilation happens.
    static std::unordered_map<const ID*, p_hash_type> global_memo;

    std::set<p_hash_type> parts;
    for ( auto t : pf->OrderedTypes() )
        parts.insert(env_type_hash_root(t));

    for ( auto& g : pf->AllGlobals() ) {
        auto [it, inserted] = global_memo.emplace(g.get(), 0);
        if ( inserted ) {
            p_hash_type gh = merge_p_hashes(p_hash(std::string_view(g->Name())), p_hash(g->IsConst() ? 1 : 0));
            gh = merge_p_hashes(gh, env_type_hash_root(g->GetType().get()));
            gh = merge_p_hashes(gh, env_attrs_hash(g->GetAttrs().get()));
            if ( g->IsConst() && g->GetVal() )
                gh = merge_p_hashes(gh, env_value_hash(g->GetVal().get()));
            it->second = gh;
        }
        parts.insert(it->second);
    }

    // Source locations are observable at run time (error messages, backtraces,
    // profiles) but are not part of the profile hash, so textually identical
    // bodies at different lines or in different files would otherwise collide.
    // Fold in every statement's and expression's location, in traversal order.
    auto loc_hash = [](const Obj* o) {
        auto l = o->GetLocationInfo();
        p_hash_type lh = p_hash(std::string_view(l && l->FileName() ? l->FileName() : ""));
        lh = merge_p_hashes(lh, p_hash(l ? l->FirstLine() : 0));
        return merge_p_hashes(lh, p_hash(l ? l->LastLine() : 0));
    };
    p_hash_type locs = p_hash("locs");
    for ( auto& st : pf->Stmts() )
        locs = merge_p_hashes(locs, loc_hash(st.get()));
    for ( auto& e : pf->Exprs() )
        locs = merge_p_hashes(locs, loc_hash(e.get()));
    parts.insert(locs);

    p_hash_type h = p_hash("env");
    for ( auto x : parts )
        h = merge_p_hashes(h, x);
    return h;
}

// The fingerprint is a pure function of the profile within a run, and the
// same callees recur in many functions' keys, so memoize it.
p_hash_type env_fingerprint(const ProfileFunc* pf) {
    static std::unordered_map<const ProfileFunc*, p_hash_type> memo;
    if ( auto it = memo.find(pf); it != memo.end() )
        return it->second;
    auto h = env_fingerprint_uncached(pf);
    memo[pf] = h;
    return h;
}
} // namespace

p_hash_type ZAMBodyCache::EffectiveKey(const ProfileFunc* pf, const ProfileFuncs& pfs) {
    // Keys are needed for a function and, via coalesced handlers, for its
    // constituents; memoize per profile (fixed for the run).
    static std::unordered_map<const ProfileFunc*, p_hash_type> memo;
    if ( auto it = memo.find(pf); it != memo.end() )
        return it->second;
    auto k = EffectiveKeyUncached(pf, pfs);
    memo[pf] = k;
    return k;
}

p_hash_type ZAMBodyCache::EffectiveKeyUncached(const ProfileFunc* pf, const ProfileFuncs& pfs) {
    // Returns 0 ("no usable key") if any reachable body lacks a computed hash,
    // so the caller treats the function as non-cacheable rather than keying on
    // an incomplete fingerprint.
    if ( ! pf->HasHashVal() )
        return 0;

    std::set<p_hash_type> hashes; // sorted + deduplicated -> order-independent
    hashes.insert(pf->HashVal());
    hashes.insert(env_fingerprint(pf));

    std::unordered_set<const ScriptFunc*> seen;
    std::vector<const ProfileFunc*> work{pf};

    while ( ! work.empty() ) {
        auto cur = work.back();
        work.pop_back();

        for ( auto sf : cur->ScriptCalls() ) {
            if ( ! seen.insert(sf).second )
                continue;
            auto it = pfs.FuncProfs().find(sf);
            if ( it == pfs.FuncProfs().end() )
                continue; // e.g. a BiF or otherwise unprofiled; covered by BuildId
            if ( ! it->second->HasHashVal() )
                return 0; // can't form a complete key -> non-cacheable
            hashes.insert(it->second->HashVal());
            hashes.insert(env_fingerprint(it->second.get()));
            work.push_back(it->second.get());
        }
    }

    p_hash_type h = 0;
    for ( auto x : hashes )
        h = merge_p_hashes(h, x);
    return h;
}

void ZAMBodyCache::ComputeBuildId() {
    // The build identity must change whenever the compiled ZAM output could
    // change across zeek binaries (opcode numbering, codegen, runtime support).
    //
    // TODO(prototype): this uses the version string plus the format version,
    // which does NOT change between local rebuilds of the same version. Before
    // this cache is enabled by default it must incorporate a true binary
    // fingerprint (e.g. the executable's mtime/size or a content hash) so a
    // rebuilt zeek never loads bytecode produced by a previous build.
    build_id = std::string(zeek::zeek_version()) + ";zam-cache-v" + std::to_string(ZAM_CACHE_FORMAT_VERSION);
}

void ZAMBodyCache::ComputeOptionsHash() {
    // Fold in every analysis option that changes the compiled ZAM output.
    const auto& o = analysis_options;
    p_hash_type h = p_hash(static_cast<int>(ZAM_CACHE_FORMAT_VERSION));

    auto add_bool = [&](bool b) { h = merge_p_hashes(h, p_hash(b ? 1 : 0)); };
    add_bool(o.compile_all);
    add_bool(o.optimize_AST);
    add_bool(o.inliner);
    add_bool(o.no_inliner);
    add_bool(o.no_eh_coalescence);
    add_bool(o.keep_asserts);
    add_bool(o.no_ZAM_opt);
    add_bool(o.no_ZAM_control_flow_opt);

    options_hash = h;
}

// ---- ZBody serialization ------------------------------------------------
//
// This is an incremental implementation. It serializes bodies whose
// instruction stream and body-level structure fall within the currently
// supported subset; Serialize() returns false for anything else so the caller
// falls back to normal compilation (the cache never produces a wrong body).
// Coverage grows per the roadmap in ZAM-CACHING-FINDINGS.md.

namespace {

// Owns interned filenames so Location's const char* stays valid for the life
// of the process (Locations don't copy their filename).
std::set<std::string>& filename_pool() {
    static std::set<std::string> pool;
    return pool;
}

// Resolve a global identifier by its (fully qualified) name directly in the
// global scope. Deliberately not lookup_ID(), which searches the active scope
// stack innermost-first and so could bind to a same-named local if a body is
// deserialized while a function scope is pushed.
IDPtr resolve_global(const std::string& name) {
    return global_scope()->Find(make_full_var_name(GLOBAL_MODULE_NAME, name.c_str()));
}

// Little binary writer appending to a std::string.
class W {
public:
    explicit W(std::string& b) : buf(b) {}
    void u8(uint8_t v) { buf.append(1, static_cast<char>(v)); }
    void u32(uint32_t v) { buf.append(reinterpret_cast<const char*>(&v), sizeof v); }
    void i32(int32_t v) { buf.append(reinterpret_cast<const char*>(&v), sizeof v); }
    void u64(uint64_t v) { buf.append(reinterpret_cast<const char*>(&v), sizeof v); }
    void i64(int64_t v) { buf.append(reinterpret_cast<const char*>(&v), sizeof v); }
    void dbl(double v) { buf.append(reinterpret_cast<const char*>(&v), sizeof v); }
    void str(std::string_view s) {
        u32(static_cast<uint32_t>(s.size()));
        buf.append(s.data(), s.size());
    }

private:
    std::string& buf;
};

// Little binary reader with bounds checking; any underrun sets ok=false and all
// subsequent reads return zero/empty so callers can check ok once at the end.
class R {
public:
    R(const char* p, size_t n) : cur(p), end(p + n) {}
    bool Ok() const { return ok; }
    bool AtEnd() const { return cur == end; }

    // The unread remainder, consuming it. Used to take the body bytes that
    // follow a cache-file header.
    std::string rest() {
        std::string s(cur, end - cur);
        cur = end;
        return s;
    }

    uint8_t u8() { return read<uint8_t>(); }
    uint32_t u32() { return read<uint32_t>(); }
    int32_t i32() { return read<int32_t>(); }
    uint64_t u64() { return read<uint64_t>(); }
    int64_t i64() { return read<int64_t>(); }
    double dbl() { return read<double>(); }
    std::string str() {
        auto n = u32();
        if ( ! ok || static_cast<size_t>(end - cur) < n ) {
            ok = false;
            return {};
        }
        std::string s(cur, n);
        cur += n;
        return s;
    }

private:
    template<typename T>
    T read() {
        T v{};
        if ( static_cast<size_t>(end - cur) < sizeof(T) ) {
            ok = false;
            return v;
        }
        std::memcpy(&v, cur, sizeof(T));
        cur += sizeof(T);
        return v;
    }

    const char* cur;
    const char* end;
    bool ok = true;
};

// Atomic Val tags we can serialize. Anything else makes a body non-cacheable.
bool supported_const_type(TypeTag tag) {
    switch ( tag ) {
        case TYPE_BOOL:
        case TYPE_INT:
        case TYPE_COUNT:
        case TYPE_DOUBLE:
        case TYPE_TIME:
        case TYPE_INTERVAL:
        case TYPE_STRING:
        case TYPE_ADDR:
        case TYPE_SUBNET:
        case TYPE_PORT:
        case TYPE_ENUM: return true;
        default: return false;
    }
}

bool supported_const(const ValPtr& v) { return supported_const_type(v->GetType()->Tag()); }

// Types are encoded as their profile type-hash and resolved on load to the
// live representative type for that hash. The profile hash doesn't distinguish
// an unspecified vector ("vector()", internally yield void) from "vector of
// any" (VectorType::Yield() reports any for both), so that flag is carried
// alongside and must match.
bool is_unspecified_vector(const Type* t) {
    return t && t->Tag() == TYPE_VECTOR && t->AsVectorType()->IsUnspecifiedVector();
}

void encode_type(W& w, ProfileFuncs& pfs, const Type* t) {
    w.u64(t ? pfs.HashType(t) : 0);
    w.u8(is_unspecified_vector(t) ? 1 : 0);
}

// Returns null for "no type". A non-null type that can't be resolved exactly
// sets ok=false (so the body is a cache miss) rather than being dropped.
TypePtr decode_type(R& r, ProfileFuncs& pfs, bool& ok) {
    auto h = r.u64();
    bool unspecified = r.u8() != 0;
    if ( h == 0 )
        return nullptr;
    auto rep = pfs.TypeForHash(h);
    if ( ! rep || is_unspecified_vector(rep) != unspecified ) {
        ok = false;
        return nullptr;
    }
    return {NewRef{}, const_cast<Type*>(rep)};
}

void encode_val(W& w, ProfileFuncs& pfs, const ValPtr& v) {
    auto t = v->GetType();
    encode_type(w, pfs, t.get());
    w.u32(static_cast<uint32_t>(t->Tag()));

    switch ( t->Tag() ) {
        case TYPE_BOOL:
        case TYPE_INT: w.i64(v->AsInt()); break;
        case TYPE_COUNT: w.u64(v->AsCount()); break;
        case TYPE_DOUBLE: w.dbl(v->AsDouble()); break;
        case TYPE_TIME: w.dbl(v->AsTime()); break;
        case TYPE_INTERVAL: w.dbl(v->AsInterval()); break;
        case TYPE_STRING: {
            auto s = v->AsString();
            w.str(std::string_view(reinterpret_cast<const char*>(s->Bytes()), s->Len()));
        } break;
        case TYPE_ADDR: w.str(v->AsAddr().AsString()); break;
        case TYPE_SUBNET: w.str(v->AsSubNet().AsString()); break;
        case TYPE_PORT: {
            auto pv = v->AsPortVal();
            w.u32(pv->Port());
            w.u32(static_cast<uint32_t>(pv->PortType()));
        } break;
        case TYPE_ENUM: w.i64(v->AsEnum()); break;
        default: break; // gated out by supported_const()
    }
}

ValPtr decode_val(R& r, ProfileFuncs& pfs, bool& ok) {
    auto type = decode_type(r, pfs, ok);
    auto tag = static_cast<TypeTag>(r.u32());
    if ( ! r.Ok() || ! type ) {
        ok = false;
        return nullptr;
    }

    switch ( tag ) {
        case TYPE_BOOL: return val_mgr->Bool(r.i64() != 0);
        case TYPE_INT: return val_mgr->Int(r.i64());
        case TYPE_COUNT: return val_mgr->Count(r.u64());
        case TYPE_DOUBLE: return make_intrusive<DoubleVal>(r.dbl());
        case TYPE_TIME: return make_intrusive<TimeVal>(r.dbl());
        case TYPE_INTERVAL: return make_intrusive<IntervalVal>(r.dbl());
        case TYPE_STRING: return make_intrusive<StringVal>(r.str());
        case TYPE_ADDR: return make_intrusive<AddrVal>(r.str());
        case TYPE_SUBNET: {
            auto s = r.str();
            return make_intrusive<SubNetVal>(s.c_str());
        }
        case TYPE_PORT: {
            auto num = r.u32();
            auto proto = static_cast<TransportProto>(r.u32());
            return val_mgr->Port(num, proto);
        }
        case TYPE_ENUM: {
            auto i = r.i64();
            return type->AsEnumType()->GetEnumVal(i);
        }
        default: ok = false; return nullptr;
    }
}

// Whether an op reads its instruction's constant slot 'c' at run time. An
// instruction's op_type doesn't reliably say so: optimized built-ins construct
// the instruction with a slot-only op_type and then assign 'c' directly. So
// consult the op's generated description: a 'C' in its declared operand class,
// or a reference to z.c in its evaluation code. Unknown ops are treated as
// possibly reading it.
bool op_reads_constant(ZOp op) {
    auto it = zam_inst_desc.find(op);
    if ( it == zam_inst_desc.end() )
        return true;
    return it->second.op_class.find('C') != std::string::npos || it->second.op_eval.find("z.c") != std::string::npos;
}

// Reinterpret an instruction's raw constant slot as a value, using the
// instruction's type (which is how the compiler builds it: ZVal(v, t) followed
// by SetType(t)). Since ZVal is an untyped union, validate the result rather
// than trust the type: it must be a supported atomic value whose dynamic type
// matches, and for unmanaged types re-encoding it must reproduce 'c' exactly.
// Returns nullptr if any check fails.
ValPtr constant_slot_value(const ZInst& in) {
    const auto& t = in.GetType();
    if ( ! t || ! supported_const_type(t->Tag()) )
        return nullptr;
    auto v = in.c.ToVal(t);
    if ( ! v || v->GetType()->Tag() != t->Tag() )
        return nullptr;
    if ( ! ZVal::IsManagedType(t) ) {
        ZVal re(v, t);
        if ( std::memcmp(&re, &in.c, sizeof(ZVal)) != 0 )
            return nullptr;
    }
    return v;
}

// Whether an instruction's auxiliary info is within the currently supported
// serialization subset. Gates the AST-heavy members (handled in later roadmap
// steps) and record/vector construction (whose runtime scratch, e.g. zvec, is
// sized outside the serialized fields).
// Returns nullptr if serializable, otherwise a short reason naming the gate.
const char* aux_unserializable_reason(const ZInstAux* aux) {
    if ( aux->call_expr )
        return "aux:call-expr";
    if ( aux->lambda )
        return "aux:lambda";
    if ( aux->wi )
        return "aux:when-info";
    if ( aux->cat_args )
        return "aux:cat-args";
    if ( aux->attrs )
        return "aux:attrs";
    if ( aux->field_inits )
        return "aux:field-inits";
    if ( ! aux->map.empty() || ! aux->rhs_map.empty() || ! aux->lhs_map.empty() )
        return "aux:maps";
    for ( int i = 0; i < aux->n; ++i )
        if ( const auto& c = aux->elems[i].Constant() )
            if ( ! supported_const(c) )
                return "aux:const";
    return nullptr;
}

void encode_int_vec(W& w, const std::vector<int>& v) {
    w.u32(static_cast<uint32_t>(v.size()));
    for ( auto x : v )
        w.i32(x);
}

void encode_aux(W& w, ProfileFuncs& pfs, const ZInstAux* aux) {
    w.u32(static_cast<uint32_t>(aux->n));
    w.u8(aux->elems_has_slots ? 1 : 0);

    for ( int i = 0; i < aux->n; ++i ) {
        const auto& e = aux->elems[i];
        if ( const auto& c = e.Constant() ) {
            w.u8(2); // constant
            encode_val(w, pfs, c);
        }
        else if ( e.GetType() ) {
            w.u8(1); // frame slot with type
            w.i32(e.Slot());
            encode_type(w, pfs, e.GetType().get());
        }
        else {
            w.u8(0); // plain integer
            w.i32(e.IntVal());
        }
    }

    encode_int_vec(w, aux->map);
    encode_int_vec(w, aux->rhs_map);
    encode_int_vec(w, aux->lhs_map);
    encode_int_vec(w, aux->loop_vars);

    w.u32(static_cast<uint32_t>(aux->types.size()));
    for ( auto& t : aux->types )
        encode_type(w, pfs, t.get());

    w.u32(static_cast<uint32_t>(aux->is_managed.size()));
    for ( bool b : aux->is_managed )
        w.u8(b ? 1 : 0);

    encode_type(w, pfs, aux->value_var_type.get());

    w.u8(aux->is_BiF_call ? 1 : 0);
    w.u8(aux->can_change_non_locals ? 1 : 0);

    w.u32(static_cast<uint32_t>(aux->cft.size()));
    for ( auto& [k, v] : aux->cft ) {
        w.u8(static_cast<uint8_t>(k));
        w.i32(v);
    }

    // By-name references, re-resolved against the running process at load.
    if ( aux->id_val ) {
        w.u8(1);
        w.str(aux->id_val->Name());
    }
    else
        w.u8(0);

    if ( aux->func ) {
        w.u8(1);
        w.str(aux->func->GetName());
    }
    else
        w.u8(0);

    if ( aux->event_handler ) {
        w.u8(1);
        w.str(aux->event_handler->Name());
    }
    else
        w.u8(0);

    // The zvec runtime-scratch vector is pre-sized by the compiler (e.g. to a
    // record's field count for record constructors) and indexed during Exec;
    // its size is part of the body's state, so serialize it faithfully. Its
    // contents are filled at run time and need not be stored.
    w.u32(static_cast<uint32_t>(aux->zvec.size()));
}

ZInstAux* decode_aux(R& r, ProfileFuncs& pfs, bool& ok) {
    auto n = r.u32();
    if ( ! r.Ok() ) {
        ok = false;
        return nullptr;
    }

    auto aux = new ZInstAux(static_cast<int>(n));
    aux->elems_has_slots = r.u8() != 0;

    for ( int i = 0; i < static_cast<int>(n) && r.Ok() && ok; ++i ) {
        auto kind = r.u8();
        if ( kind == 2 ) {
            auto cv = decode_val(r, pfs, ok);
            if ( ok && cv )
                aux->Add(i, cv);
        }
        else if ( kind == 1 ) {
            auto slot = r.i32();
            auto t = decode_type(r, pfs, ok);
            if ( ! t )
                ok = false;
            else
                aux->Add(i, slot, t);
        }
        else
            aux->Add(i, r.i32());
    }

    auto read_int_vec = [&](std::vector<int>& v) {
        auto cnt = r.u32();
        for ( uint32_t j = 0; j < cnt && r.Ok(); ++j )
            v.push_back(r.i32());
    };
    read_int_vec(aux->map);
    read_int_vec(aux->rhs_map);
    read_int_vec(aux->lhs_map);
    read_int_vec(aux->loop_vars);

    auto n_types = r.u32();
    for ( uint32_t j = 0; j < n_types && r.Ok() && ok; ++j ) {
        auto t = decode_type(r, pfs, ok);
        if ( ! t )
            ok = false;
        else
            aux->types.push_back(t);
    }

    auto n_managed = r.u32();
    for ( uint32_t j = 0; j < n_managed && r.Ok(); ++j )
        aux->is_managed.push_back(r.u8() != 0);

    aux->value_var_type = decode_type(r, pfs, ok);

    aux->is_BiF_call = r.u8() != 0;
    aux->can_change_non_locals = r.u8() != 0;

    auto n_cft = r.u32();
    for ( uint32_t j = 0; j < n_cft && r.Ok(); ++j ) {
        auto k = static_cast<ControlFlowType>(r.u8());
        aux->cft[k] = r.i32();
    }

    if ( r.u8() == 1 ) {
        auto name = r.str();
        auto id = resolve_global(name);
        if ( ! id )
            ok = false;
        else
            aux->id_val = id;
    }
    if ( r.u8() == 1 ) {
        auto name = r.str();
        auto f = id::find_func(name);
        if ( ! f )
            ok = false;
        else
            aux->func = f.get();
    }
    if ( r.u8() == 1 ) {
        auto name = r.str();
        auto eh = event_registry->Lookup(name);
        if ( ! eh )
            ok = false;
        else
            aux->event_handler = eh;
    }

    // Restore the compiler-set size of the zvec runtime-scratch vector.
    aux->zvec.resize(r.u32());

    if ( ! r.Ok() || ! ok ) {
        delete aux;
        return nullptr;
    }
    return aux;
}

} // namespace

bool ZBodySerializer::Serialize(const ZBody& body, ProfileFuncs& pfs, std::string& out, const char** why) {
    auto refuse = [why](const char* reason) {
        if ( why )
            *why = reason;
        return false;
    };

    // Capability gate: refuse bodies with structure we don't yet serialize.
    if ( ! body.int_cases.empty() || ! body.uint_cases.empty() || ! body.double_cases.empty() ||
         ! body.str_cases.empty() )
        return refuse("switch-cases");
    if ( ! body.table_iters.empty() )
        return refuse("table-iters");
    if ( body.num_step_iters != 0 )
        return refuse("step-iters");

    for ( unsigned i = 0; i < body.end_pc; ++i )
        if ( auto aux = body.insts[i].aux ) {
            if ( auto reason = aux_unserializable_reason(aux) )
                return refuse(reason);
        }

    W w(out);
    w.str(body.func_name);
    w.i32(body.frame_size);
    w.u8(body.fixed_frame ? 1 : 0); // non-recursive -> pre-allocated fixed frame

    w.u32(static_cast<uint32_t>(body.managed_slots.size()));
    for ( auto s : body.managed_slots )
        w.i32(s);

    w.u32(static_cast<uint32_t>(body.frame_denizens.size()));
    for ( auto& fd : body.frame_denizens ) {
        w.u32(static_cast<uint32_t>(fd.names.size()));
        for ( auto n : fd.names )
            w.str(n);
        w.u32(static_cast<uint32_t>(fd.id_start.size()));
        for ( auto s : fd.id_start )
            w.u64(s);
        w.i32(fd.scope_end);
        w.u8(fd.is_managed ? 1 : 0);
    }

    w.u32(static_cast<uint32_t>(body.modules.size()));
    for ( auto& m : body.modules )
        w.str(m);

    // Globals: serialized by name, re-resolved against global scope at load.
    w.u32(static_cast<uint32_t>(body.globals.size()));
    for ( auto& g : body.globals ) {
        w.str(g.id->Name());
        w.i32(g.slot);
    }

    w.u32(body.end_pc);
    for ( unsigned i = 0; i < body.end_pc; ++i ) {
        auto& in = body.insts[i];

        auto cv = in.ConstVal();
        if ( ! cv && op_reads_constant(in.op) ) {
            // Some ops (notably optimized built-ins) keep a constant in 'c'
            // without an op_type that says so; capture it explicitly.
            cv = constant_slot_value(in);
            if ( ! cv )
                return refuse("const-slot");
        }
        if ( cv && ! supported_const(cv) )
            return refuse("const");

        w.u32(static_cast<uint32_t>(in.op));
        w.u32(static_cast<uint32_t>(in.op_type));
        w.i32(in.v1);
        w.i32(in.v2);
        w.i32(in.v3);
        w.i32(in.v4);
        encode_type(w, pfs, in.GetType().get());
        encode_type(w, pfs, in.GetType2().get());

        // is_managed: 0 = unset, 1 = false, 2 = true.
        w.u8(! in.is_managed ? 0 : (*in.is_managed ? 2 : 1));

        if ( cv ) {
            w.u8(1);
            encode_val(w, pfs, cv);
        }
        else
            w.u8(0);

        // Location (flattened: no inlining parent chain yet).
        auto l = in.loc ? in.loc->Loc() : nullptr;
        w.str(l && l->FileName() ? l->FileName() : "");
        w.i32(l ? l->FirstLine() : 0);
        w.i32(l ? l->LastLine() : 0);

        if ( in.aux ) {
            w.u8(1);
            encode_aux(w, pfs, in.aux);
        }
        else
            w.u8(0);
    }

    return true;
}

ZBodyPtr ZBodySerializer::Deserialize(const std::string& in, ProfileFuncs& pfs) {
    R r(in.data(), in.size());

    auto func_name = r.str();
    // ZBody's deserialization constructor is private; ZBodySerializer is a
    // friend, so construct directly and adopt the reference.
    ZBodyPtr zb{AdoptRef{}, new ZBody(func_name)};

    zb->frame_size = r.i32();
    bool non_recursive = r.u8() != 0;

    auto n_managed = r.u32();
    for ( uint32_t i = 0; i < n_managed && r.Ok(); ++i )
        zb->managed_slots.push_back(r.i32());

    auto n_fd = r.u32();
    for ( uint32_t i = 0; i < n_fd && r.Ok(); ++i ) {
        FrameSharingInfo fd;
        auto n_names = r.u32();
        for ( uint32_t j = 0; j < n_names && r.Ok(); ++j ) {
            auto interned = filename_pool().insert(r.str()).first;
            fd.names.push_back(interned->c_str());
        }
        auto n_starts = r.u32();
        for ( uint32_t j = 0; j < n_starts && r.Ok(); ++j )
            fd.id_start.push_back(r.u64());
        fd.scope_end = r.i32();
        fd.is_managed = r.u8() != 0;
        zb->frame_denizens.push_back(std::move(fd));
    }

    auto n_mod = r.u32();
    for ( uint32_t i = 0; i < n_mod && r.Ok(); ++i )
        zb->modules.insert(r.str());

    auto n_glob = r.u32();
    for ( uint32_t i = 0; i < n_glob && r.Ok(); ++i ) {
        auto name = r.str();
        auto slot = r.i32();
        if ( ! r.Ok() )
            break;
        auto id = resolve_global(name);
        if ( ! id )
            return nullptr; // global no longer present -> safe miss
        zb->globals.push_back(GlobalInfo{id, slot});
    }

    auto end_pc = r.u32();
    if ( ! r.Ok() )
        return nullptr;

    // A placeholder current-location satisfies the ZInst constructor's
    // assertion while we build instructions; each gets its real loc below.
    // The Location must carry a non-null filename: ZAMLocInfo's constructor
    // feeds it to func_name_at_loc(), which strlen()s it.
    auto empty_fn = filename_pool().insert("").first->c_str();
    auto prev_curr_loc = ZAM::curr_loc;
    ZAM::curr_loc = std::make_shared<ZAMLocInfo>(func_name, std::make_shared<Location>(empty_fn, 0, 0), nullptr);

    auto insts = new ZInst[end_pc];
    bool ok = true;

    for ( uint32_t i = 0; i < end_pc && r.Ok() && ok; ++i ) {
        auto op = static_cast<ZOp>(r.u32());
        auto op_type = static_cast<ZAMOpType>(r.u32());

        // Note: not "ZInstI zi(op, op_type)", which would resolve to the
        // ZInstI(ZOp, int v1) constructor and silently set op_type to OP_V.
        ZInstI zi(op);
        zi.op_type = op_type;
        zi.v1 = r.i32();
        zi.v2 = r.i32();
        zi.v3 = r.i32();
        zi.v4 = r.i32();

        auto t = decode_type(r, pfs, ok);
        auto t2 = decode_type(r, pfs, ok);
        if ( t )
            zi.SetType(t);
        if ( t2 )
            zi.SetType2(t2);

        auto managed_flag = r.u8();
        if ( managed_flag == 1 )
            zi.is_managed = false;
        else if ( managed_flag == 2 )
            zi.is_managed = true;

        if ( r.u8() == 1 ) {
            auto cv = decode_val(r, pfs, ok);
            if ( ok && cv )
                zi.c = ZVal(cv, cv->GetType());
        }

        auto fname = r.str();
        auto line_f = r.i32();
        auto line_l = r.i32();
        auto interned = filename_pool().insert(fname).first;
        zi.loc = std::make_shared<ZAMLocInfo>(func_name, std::make_shared<Location>(interned->c_str(), line_f, line_l),
                                              nullptr);

        if ( r.u8() == 1 )
            zi.aux = decode_aux(r, pfs, ok);

        insts[i] = zi; // slice-copy base ZInst (final form; branches already concrete)
    }

    ZAM::curr_loc = prev_curr_loc;

    if ( ! r.Ok() || ! ok ) {
        delete[] insts;
        return nullptr;
    }

    // Several ZBody members have no in-class default initializer and are
    // normally set by the ZAMCompiler-driven constructor. The capability gate
    // guarantees these are empty/zero for serialized bodies, but they must be
    // set explicitly here since ZInst::Exec() reads them (e.g. num_step_iters
    // sizes a stack vector).
    zb->num_step_iters = 0;
    zb->num_globals = static_cast<int>(zb->globals.size());

    zb->insts = insts;
    zb->end_pc = end_pc;
    zb->inst_cnt = new uint64_t[end_pc];
    for ( uint32_t i = 0; i < end_pc; ++i )
        zb->inst_cnt[i] = 0;
    zb->default_prof_vec = zb->BuildProfVec();
    zb->curr_prof_vec = zb->default_prof_vec.get();

    if ( non_recursive ) {
        zb->fixed_frame = new ZVal[zb->frame_size];
        for ( auto ms : zb->managed_slots )
            zb->fixed_frame[ms].ClearManagedVal();
    }

    return zb;
}

// Structural self-check for round-trip verification (ZEEK_ZAM_CACHE_VERIFY_LOG):
// compares every field of a compiled body against its reconstruction and
// appends any difference to the named file. This is independent of whether a
// test happens to exercise the affected code, so it catches reconstruction
// errors that btest baselines can miss. Types may legitimately differ by
// identity (they resolve to the representative for their hash), so only
// non-equivalent types are reported.
void ZBodySerializer::VerifyStructure(const ZBody& a, const ZBody& b) {
    static FILE* log = [] {
        auto path = getenv("ZEEK_ZAM_CACHE_VERIFY_LOG");
        return path ? fopen(path, "a") : nullptr;
    }();
    if ( ! log )
        return;

    auto report = [&](const char* what, int i) { fprintf(log, "%s inst=%d %s\n", a.func_name.c_str(), i, what); };

    auto equiv_type = [](const TypePtr& x, const TypePtr& y) {
        if ( x == y )
            return true;
        if ( ! x || ! y )
            return false;
        return x->GetName() == y->GetName() && is_unspecified_vector(x.get()) == is_unspecified_vector(y.get()) &&
               same_type(*x, *y, false, true);
    };

    auto val_desc = [](const ValPtr& v) -> std::string {
        if ( ! v )
            return "<nil>";
        ODesc d;
        v->Describe(&d);
        return d.Description();
    };

    if ( a.frame_size != b.frame_size )
        report("frame_size", -1);
    if ( (a.fixed_frame != nullptr) != (b.fixed_frame != nullptr) )
        report("fixed_frame", -1);
    if ( a.managed_slots != b.managed_slots )
        report("managed_slots", -1);
    if ( a.globals.size() != b.globals.size() || a.num_globals != b.num_globals )
        report("globals", -1);
    else
        for ( size_t g = 0; g < a.globals.size(); ++g )
            if ( a.globals[g].id != b.globals[g].id || a.globals[g].slot != b.globals[g].slot )
                report("globals", static_cast<int>(g));
    if ( a.table_iters.size() != b.table_iters.size() || a.num_step_iters != b.num_step_iters )
        report("iterators", -1);
    if ( a.int_cases != b.int_cases || a.uint_cases != b.uint_cases || a.double_cases != b.double_cases ||
         a.str_cases != b.str_cases )
        report("case-maps", -1);
    if ( a.end_pc != b.end_pc ) {
        report("end_pc", -1);
        return;
    }

    for ( unsigned i = 0; i < a.end_pc; ++i ) {
        const auto& x = a.insts[i];
        const auto& y = b.insts[i];
        int n = static_cast<int>(i);

        if ( x.op != y.op || x.op_type != y.op_type )
            report("op", n);
        if ( x.v1 != y.v1 || x.v2 != y.v2 || x.v3 != y.v3 || x.v4 != y.v4 )
            report("operands", n);
        if ( ! equiv_type(x.GetType(), y.GetType()) || ! equiv_type(x.GetType2(), y.GetType2()) )
            report("type", n);
        if ( x.is_managed != y.is_managed )
            report("is_managed", n);
        if ( val_desc(x.ConstVal()) != val_desc(y.ConstVal()) )
            report("constant", n);
        if ( op_reads_constant(x.op) && x.GetType() && ! ZVal::IsManagedType(x.GetType()) &&
             std::memcmp(&x.c, &y.c, sizeof(ZVal)) != 0 )
            report("constant-slot", n);

        if ( (x.aux != nullptr) != (y.aux != nullptr) ) {
            report("aux", n);
            continue;
        }
        if ( ! x.aux )
            continue;

        auto xa = x.aux;
        auto ya = y.aux;
        if ( xa->n != ya->n ) {
            report("aux.n", n);
            continue;
        }
        for ( int e = 0; e < xa->n; ++e ) {
            const auto& ex = xa->elems[e];
            const auto& ey = ya->elems[e];
            if ( ex.Slot() != ey.Slot() || ex.IsManaged() != ey.IsManaged() ||
                 ! equiv_type(ex.GetType(), ey.GetType()) || val_desc(ex.Constant()) != val_desc(ey.Constant()) )
                report("aux.elem", n);
        }
        if ( xa->elems_has_slots != ya->elems_has_slots || xa->map != ya->map || xa->rhs_map != ya->rhs_map ||
             xa->lhs_map != ya->lhs_map || xa->loop_vars != ya->loop_vars || xa->is_managed != ya->is_managed ||
             xa->zvec.size() != ya->zvec.size() )
            report("aux.vectors", n);
        if ( xa->types.size() != ya->types.size() )
            report("aux.types", n);
        else
            for ( size_t k = 0; k < xa->types.size(); ++k )
                if ( ! equiv_type(xa->types[k], ya->types[k]) )
                    report("aux.types", n);
        if ( ! equiv_type(xa->value_var_type, ya->value_var_type) )
            report("aux.value_var_type", n);
        if ( xa->is_BiF_call != ya->is_BiF_call || xa->can_change_non_locals != ya->can_change_non_locals ||
             xa->cft != ya->cft )
            report("aux.flags", n);
        if ( xa->id_val != ya->id_val || xa->func != ya->func || xa->event_handler != ya->event_handler )
            report("aux.refs", n);
        if ( (xa->field_inits != nullptr) != (ya->field_inits != nullptr) ||
             (xa->field_inits && *xa->field_inits != *ya->field_inits) )
            report("aux.field_inits", n);
        if ( (xa->cat_args != nullptr) != (ya->cat_args != nullptr) )
            report("aux.cat_args", n);
        if ( (xa->call_expr != nullptr) != (ya->call_expr != nullptr) )
            report("aux.call_expr", n);
        else if ( xa->call_expr ) {
            ODesc dx, dy;
            xa->call_expr->Describe(&dx);
            ya->call_expr->Describe(&dy);
            if ( std::string(dx.Description()) != dy.Description() )
                fprintf(log, "%s inst=%d aux.call_expr orig=[%s] reconstructed=[%s]\n", a.func_name.c_str(), n,
                        dx.Description(), dy.Description());
        }
    }

    fflush(log);
}

bool zam_cache_verify_active() {
    static const bool active = getenv("ZEEK_ZAM_CACHE_VERIFY") != nullptr;
    return active;
}

static uint64_t rt_ok = 0;    // bodies serialized + reconstructed
static uint64_t rt_gated = 0; // bodies the gate declined

ZBodyPtr zam_cache_roundtrip(const ZBody* orig, ProfileFuncs& pfs) {
    std::string buf;
    if ( ! ZBodySerializer::Serialize(*orig, pfs, buf) ) {
        ++rt_gated;
        return nullptr;
    }
    auto zb = ZBodySerializer::Deserialize(buf, pfs);
    if ( zb )
        ZBodySerializer::VerifyStructure(*orig, *zb);
    if ( zb )
        ++rt_ok;
    else
        ++rt_gated;
    return zb;
}

void zam_cache_verify_report() {
    // Only emit when explicitly debugging: verify mode runs during the btest
    // suite, and many tests diff stderr, so it must stay silent by default.
    if ( ! zam_cache_verify_active() || ! getenv("ZEEK_ZAM_CACHE_DEBUG") )
        return;
    auto total = rt_ok + rt_gated;
    fprintf(stderr, "# ZAM cache round-trip verify: %llu/%llu bodies serialized (%.1f%%), %llu gated\n",
            (unsigned long long)rt_ok, (unsigned long long)total,
            total ? 100.0 * static_cast<double>(rt_ok) / total : 0.0, (unsigned long long)rt_gated);
}

// ---- On-disk cache files ------------------------------------------------

namespace {
// Identifies a ZAM body cache file; bumped with ZAM_CACHE_FORMAT_VERSION below.
constexpr uint32_t ZAM_CACHE_MAGIC = 0x5A42'4331; // "ZBC1"
} // namespace

std::string ZAMBodyCache::PathFor(p_hash_type key) const {
    // Include the configuration (build identity + analysis options) in the
    // name, not just the header, so that differently configured runs sharing a
    // cache directory keep separate entries rather than overwriting each other.
    auto config = merge_p_hashes(p_hash(std::string_view(build_id)), options_hash);
    char name[64];
    snprintf(name, sizeof name, "zam-%016llx-%016llx.zbc", static_cast<unsigned long long>(config),
             static_cast<unsigned long long>(key));
    return dir + "/" + name;
}

void ZAMBodyCache::Store(p_hash_type key, const std::string& body, int frame_size) const {
    if ( ! enabled )
        return;

    std::string buf;
    W w(buf);
    w.u32(ZAM_CACHE_MAGIC);
    w.u32(ZAM_CACHE_FORMAT_VERSION);
    w.u64(options_hash);
    w.str(build_id);
    w.u64(key);
    w.i32(frame_size);
    buf += body; // the serialized body occupies the remainder of the file

    // Write to a unique temp file, then atomically rename into place so a
    // concurrent reader never sees a partial file. Same-key writes carry
    // identical content, so a last-writer-wins rename is harmless.
    auto final_path = PathFor(key);
    auto tmp_path = final_path + ".tmp." + std::to_string(static_cast<long long>(getpid()));

    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if ( ! out )
            return;
        out.write(buf.data(), static_cast<std::streamsize>(buf.size()));
        if ( ! out )
            return;
    }

    if ( std::rename(tmp_path.c_str(), final_path.c_str()) != 0 )
        std::remove(tmp_path.c_str());
}

std::optional<ZAMBodyCache::Entry> ZAMBodyCache::TryLoad(p_hash_type key) const {
    if ( ! enabled )
        return std::nullopt;

    std::ifstream in(PathFor(key), std::ios::binary);
    if ( ! in )
        return std::nullopt;

    std::string buf((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    R r(buf.data(), buf.size());
    if ( r.u32() != ZAM_CACHE_MAGIC || r.u32() != ZAM_CACHE_FORMAT_VERSION || r.u64() != options_hash )
        return std::nullopt;
    if ( r.str() != build_id || r.u64() != key )
        return std::nullopt;
    auto frame_size = r.i32();
    if ( ! r.Ok() || frame_size < 0 )
        return std::nullopt;

    return Entry{r.rest(), frame_size};
}

} // namespace zeek::detail
