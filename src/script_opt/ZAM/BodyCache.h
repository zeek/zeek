// See the file "COPYING" in the main distribution directory for copyright.

// On-disk cache of compiled ZAM function bodies.
//
// ZAM compilation recomputes the full optimize+compile pipeline on every
// process start. For workloads that repeatedly compile the same scripts (most
// notably the `-a zam` btest suite, where ~1900 processes each recompile the
// identical base-script corpus), this is almost entirely redundant work. This
// cache serializes fully-compiled bodies to disk, keyed by an inlining-safe
// per-body key plus the build identity and analysis options, and installs them
// on a subsequent run instead of recompiling.
//
// Correctness invariant: the cache can only ever skip recompilation of a body
// whose serialized form matches the current build, the active analysis options,
// and the body's (inlining-safe) effective key. On any mismatch, corruption, or
// not-yet-supported feature it falls back to normal compilation. It can
// therefore never cause an incorrect execution -- at worst a cache miss.
//
// The cache is opt-in: it is active only when the environment variable
// ZEEK_ZAM_CACHE_DIR names a directory. Otherwise every method is inert and ZAM
// behaves exactly as before.

#pragma once

#include <optional>
#include <string>

#include "zeek/IntrusivePtr.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

class ZBody;
using ZBodyPtr = IntrusivePtr<ZBody>;

// Bump whenever the on-disk format or any ZAM encoding detail changes, so old
// cache files are rejected rather than misread.
constexpr uint32_t ZAM_CACHE_FORMAT_VERSION = 1;

class ZAMBodyCache {
public:
    // Reads ZEEK_ZAM_CACHE_DIR; if set and usable, computes the build-identity
    // and analysis-options fingerprints that scope every cache entry.
    ZAMBodyCache();

    bool Enabled() const { return enabled; }
    const std::string& Dir() const { return dir; }

    // The inlining-safe effective key for a function: its own profile HashVal()
    // merged with the HashVal() of every script function transitively reachable
    // through its call graph. Inlined callees are a subset of called functions,
    // so this is a safe over-approximation -- the key changes whenever the body
    // or any transitively called body changes. Combination is over a sorted set
    // (order-independent, cycle-safe). This is build/options independent; the
    // cache separately scopes entries by BuildId()/OptionsHash().
    static p_hash_type EffectiveKey(const ProfileFunc* pf, const ProfileFuncs& pfs);


    // Fingerprints that must match for a cache entry to be reused. BuildId
    // captures anything that can change ZAM output across binaries; OptionsHash
    // captures the ZAM-affecting analysis options.
    const std::string& BuildId() const { return build_id; }
    p_hash_type OptionsHash() const { return options_hash; }

    // A cache entry: the serialized body plus the interpreter frame size the
    // function requires (compilation can enlarge it for reducer temporaries,
    // and a cache hit skips compilation, so it must be restored explicitly).
    struct Entry {
        std::string body;
        int frame_size = 0;
    };

    // Return the entry stored for 'key', or nullopt if there is no entry or its
    // header does not match this build and options. Never throws.
    std::optional<Entry> TryLoad(p_hash_type key) const;

    // Store serialized 'body' bytes for 'key', scoped by this build and
    // options. Best-effort: write failures are silently ignored (a later run
    // just recompiles). Uses a temp file + atomic rename so concurrent btest
    // processes sharing a cache directory never observe a partial file.
    void Store(p_hash_type key, const std::string& body, int frame_size) const;

private:
    static p_hash_type EffectiveKeyUncached(const ProfileFunc* pf, const ProfileFuncs& pfs);

    void ComputeBuildId();
    void ComputeOptionsHash();
    std::string PathFor(p_hash_type key) const;

    bool enabled = false;
    std::string dir;
    std::string build_id;
    p_hash_type options_hash = 0;
};

// Serializes a compiled ZBody to a byte string and reconstructs it. Used both
// by the on-disk cache and by the round-trip self-verification mode.
class ZBodySerializer {
public:
    // Serialize 'body' into 'out'. Returns false (leaving 'out' unspecified) if
    // the body uses a feature not yet supported by the serializer, in which
    // case the caller must not cache it.
    static bool Serialize(const ZBody& body, ProfileFuncs& pfs, std::string& out);

    // Reconstruct a ZBody from bytes produced by Serialize(), using 'pfs' (over
    // the same scripts) to resolve types by hash. Returns nullptr on any
    // malformed input or unresolvable reference.
    static ZBodyPtr Deserialize(const std::string& in, ProfileFuncs& pfs);

    // Round-trip self-check: with ZEEK_ZAM_CACHE_VERIFY_LOG naming a file,
    // append any non-equivalent difference between a compiled body and its
    // reconstruction to that file. See BodyCache.cc.
    static void VerifyStructure(const ZBody& orig, const ZBody& reconstructed);
};

// Round-trip self-verification (env-gated by ZEEK_ZAM_CACHE_VERIFY): if 'orig'
// is serializable, serialize then immediately deserialize it and return the
// reconstructed body (which the caller installs in place of the original), so
// the existing btest baselines validate serialization faithfulness. Returns
// nullptr if the body is not serializable or the round trip fails, in which
// case the caller keeps the freshly compiled body.
extern bool zam_cache_verify_active();
extern ZBodyPtr zam_cache_roundtrip(const ZBody* orig, ProfileFuncs& pfs);

// Reports round-trip verification coverage (how many bodies were serialized vs
// gated) to stderr. Called at the end of analyze_scripts(). No-op unless
// verification is active.
extern void zam_cache_verify_report();

} // namespace zeek::detail
