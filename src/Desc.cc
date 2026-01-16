// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Desc.h"

#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdlib>
#include <cstring>

#include "zeek/File.h"
#include "zeek/IPAddr.h"
#include "zeek/Reporter.h"

constexpr size_t DEFAULT_SIZE = 128;
constexpr size_t SLOP = 10;

namespace zeek {

ODesc::ODesc(DescType t, File* arg_f) {
    type = t;
    style = STANDARD_STYLE;
    f = arg_f;

    if ( f == nullptr ) {
        size = DEFAULT_SIZE;
        base = util::safe_malloc(size);
        (reinterpret_cast<char*>(base))[0] = '\0';
        offset = 0;
    }
    else {
        offset = size = 0;
        base = nullptr;
    }

    indent_level = 0;
    is_short = false;
    want_quotes = false;
    want_determinism = false;
    do_flush = true;
    include_stats = false;
    indent_with_spaces = 0;
    escape = false;
    utf8 = false;
}

ODesc::~ODesc() {
    if ( f ) {
        if ( do_flush )
            f->Flush();
    }
    else if ( base )
        free(base);
}

void ODesc::EnableEscaping() { escape = true; }

void ODesc::EnableUTF8() { utf8 = true; }

void ODesc::PushIndent() {
    ++indent_level;
    NL();
}

void ODesc::PopIndent() {
    if ( --indent_level < 0 )
        reporter->InternalError("ODesc::PopIndent underflow");

    NL();
}

void ODesc::PopIndentNoNL() {
    if ( --indent_level < 0 )
        reporter->InternalError("ODesc::PopIndent underflow");
}

void ODesc::Add(const char* s, int do_indent) {
    size_t n = strlen(s);

    if ( do_indent && n > 0 && IsReadable() && offset > 0 && (reinterpret_cast<const char*>(base))[offset - 1] == '\n' )
        Indent();

    if ( IsBinary() )
        AddBytes(s, n + 1);
    else
        AddBytes(s, n);
}

void ODesc::Add(int i) {
    if ( IsBinary() )
        AddBytes(&i, sizeof(i));
    else {
        char tmp[256];
        auto res = std::to_chars(tmp, tmp + sizeof(tmp), i);
        size_t len = res.ptr - tmp;
        if ( len > 255 )
            len = 255;
        tmp[len] = '\0';
        Add(tmp);
    }
}

void ODesc::Add(uint32_t u) {
    if ( IsBinary() )
        AddBytes(&u, sizeof(u));
    else {
        char tmp[256];
        auto res = std::to_chars(tmp, tmp + sizeof(tmp), u);
        size_t len = res.ptr - tmp;
        if ( len > 255 )
            len = 255;
        tmp[len] = '\0';
        Add(tmp);
    }
}

void ODesc::Add(int64_t i) {
    if ( IsBinary() )
        AddBytes(&i, sizeof(i));
    else {
        char tmp[256];
        auto res = std::to_chars(tmp, tmp + sizeof(tmp), i);
        size_t len = res.ptr - tmp;
        if ( len > 255 )
            len = 255;
        tmp[len] = '\0';
        Add(tmp);
    }
}

void ODesc::Add(uint64_t u) {
    if ( IsBinary() )
        AddBytes(&u, sizeof(u));
    else {
        char tmp[256];
        auto res = std::to_chars(tmp, tmp + sizeof(tmp), u);
        size_t len = res.ptr - tmp;
        if ( len > 255 )
            len = 255;
        tmp[len] = '\0';
        Add(tmp);
    }
}

void ODesc::Add(double d, bool no_exp) {
    if ( IsBinary() )
        AddBytes(&d, sizeof(d));
    else {
        char tmp[350];
        auto res = util::double_to_str(d, tmp, sizeof(tmp), IsReadable() ? 6 : 8, no_exp);
        if ( res == 0 )
            return;

        AddBytes(tmp, res);

        if ( util::approx_equal(d, nearbyint(d), 1e-9) && std::isfinite(d) && (strchr(tmp, 'e') == nullptr) )
            // disambiguate from integer
            Add(".0");
    }
}

void ODesc::Add(const IPAddr& addr) { Add(addr.AsString()); }

void ODesc::Add(const IPPrefix& prefix) { Add(prefix.AsString()); }

void ODesc::AddCS(const char* s) {
    int n = strlen(s);
    Add(n);
    if ( ! IsBinary() )
        Add(" ");
    Add(s);
}

void ODesc::AddBytes(const String* s) {
    if ( IsReadable() ) {
        if ( Style() == RAW_STYLE )
            AddBytes(reinterpret_cast<const char*>(s->Bytes()), s->Len());
        else {
            const char* str = s->Render(String::EXPANDED_STRING);
            Add(str);
            delete[] str;
        }
    }
    else {
        Add(s->Len());
        if ( ! IsBinary() )
            Add(" ");
        AddBytes(s->Bytes(), s->Len());
    }
}

void ODesc::Indent() {
    if ( indent_with_spaces > 0 ) {
        for ( int i = 0; i < indent_level; ++i )
            for ( int j = 0; j < indent_with_spaces; ++j )
                Add(" ", 0);
    }
    else {
        for ( int i = 0; i < indent_level; ++i )
            Add("\t", 0);
    }
}

static bool starts_with(const char* str1, const char* str2, size_t len) {
    for ( size_t i = 0; i < len; ++i )
        if ( str1[i] != str2[i] )
            return false;

    return true;
}

size_t ODesc::StartsWithEscapeSequence(const char* start, const char* end) {
    if ( escape_sequences.empty() )
        return 0;

    for ( const auto& esc_str : escape_sequences ) {
        size_t esc_len = esc_str.length();

        if ( start + esc_len > end )
            continue;

        if ( starts_with(start, esc_str.c_str(), esc_len) )
            return esc_len;
    }

    return 0;
}

std::pair<const char*, size_t> ODesc::FirstEscapeLoc(const char* bytes, size_t n) {
    if ( IsBinary() )
        return {nullptr, 0};

    for ( size_t i = 0; i < n; ++i ) {
        auto printable = isprint(bytes[i]);

        if ( ! printable && ! utf8 )
            return {bytes + i, 1};

        if ( bytes[i] == '\\' )
            return {bytes + i, 1};

        size_t len = StartsWithEscapeSequence(bytes + i, bytes + n);

        if ( len )
            return {bytes + i, len};
    }

    return {nullptr, 0};
}

void ODesc::AddBytes(const void* bytes, size_t n) {
    if ( ! escape ) {
        AddBytesRaw(bytes, n);
        return;
    }

    const char* s = reinterpret_cast<const char*>(bytes);
    const char* e = reinterpret_cast<const char*>(bytes) + n;

    while ( s < e ) {
        auto [esc_start, esc_len] = FirstEscapeLoc(s, e - s);

        if ( esc_start != nullptr ) {
            if ( utf8 ) {
                assert(esc_start >= s);
                std::string result =
                    util::escape_utf8({s, static_cast<size_t>(esc_start - s)},
                                      util::ESCAPE_PRINTABLE_CONTROLS | util::ESCAPE_UNPRINTABLE_CONTROLS);
                AddBytesRaw(result.c_str(), result.size());
            }
            else
                AddBytesRaw(s, esc_start - s);

            util::get_escaped_string(this, esc_start, esc_len, true);
            s = esc_start + esc_len;
        }
        else {
            if ( utf8 ) {
                assert(e >= s);
                std::string result =
                    util::escape_utf8({s, static_cast<size_t>(e - s)},
                                      util::ESCAPE_PRINTABLE_CONTROLS | util::ESCAPE_UNPRINTABLE_CONTROLS);
                AddBytesRaw(result.c_str(), result.size());
            }
            else
                AddBytesRaw(s, e - s);

            break;
        }
    }
}

void ODesc::AddBytesRaw(const void* bytes, size_t n) {
    if ( n == 0 )
        return;

    if ( f ) {
        static bool write_failed = false;

        if ( ! f->Write(reinterpret_cast<const char*>(bytes), n) ) {
            if ( ! write_failed )
                // Most likely it's a "disk full" so report
                // subsequent failures only once.
                reporter->Error("error writing to %s: %s", f->Name(), strerror(errno));

            write_failed = true;
            return;
        }

        write_failed = false;
    }

    else {
        Grow(n);

        // The following casting contortions are necessary because
        // simply using &base[offset] generates complaints about
        // using a void* for pointer arithmetic.
        memcpy((void*)&(reinterpret_cast<char*>(base))[offset], bytes, n);
        offset += n;

        (reinterpret_cast<char*>(base))[offset] = '\0'; // ensure that always NUL-term.
    }
}

void ODesc::Grow(size_t n) {
    bool size_changed = false;
    while ( offset + n + SLOP >= size ) {
        size *= 2;
        size_changed = true;
    }

    if ( size_changed )
        base = util::safe_realloc(base, size);
}

void ODesc::Clear() {
    offset = 0;

    // If we've allocated an exceedingly large amount of space, free it.
    constexpr size_t too_large = 10l * 1024 * 1024;
    if ( size > too_large ) {
        free(base);
        size = DEFAULT_SIZE;
        base = util::safe_malloc(size);
        (reinterpret_cast<char*>(base))[0] = '\0';
    }
}

bool ODesc::PushType(const Type* type) {
    auto res = encountered_types.insert(type);
    return std::get<1>(res);
}

bool ODesc::PopType(const Type* type) {
    size_t res = encountered_types.erase(type);
    return (res == 1);
}

bool ODesc::FindType(const Type* type) {
    auto res = encountered_types.find(type);

    if ( res != encountered_types.end() )
        return true;

    return false;
}

std::string obj_desc(const Obj* o) {
    static ODesc d;

    d.Clear();
    o->Describe(&d);
    d.SP();
    o->GetLocationInfo()->Describe(&d);

    return d.Description();
}

std::string obj_desc_short(const Obj* o) {
    static ODesc d;

    d.SetShort(true);
    d.Clear();
    o->Describe(&d);

    return d.Description();
}

} // namespace zeek
