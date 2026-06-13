// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>

// printf-style append into a std::string. Aborts via exit(1) if the formatted
// output would exceed the internal 4 KB buffer; that should be well past
// anything bifcl currently deals with.
void appendf(std::string& out, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
void vappendf(std::string& out, const char* fmt, va_list ap);

enum builtin_func_arg_type : uint8_t {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DEFINE_BIF_TYPE(id, bif_type, bro_type, c_type, c_type_smart, accessor, accessor_smart, cast_smart,            \
                        constructor, ctor_smart, native_return_type, native_to_val)                                    \
    id,
#include "bif_type.def"
#undef DEFINE_BIF_TYPE
};

// Per-Zeek-type code-generation info, populated from bif_type.def. Indexed
// by the builtin_func_arg_type enum above, plus a TYPE_OTHER terminator row
// (with empty bif_type / zeek_type) used as a sentinel by lookup loops.
struct bif_type_info {
    const char* type_enum;          // stringified enumerator name, e.g. "TYPE_BOOL"
    const char* bif_type;           // .bif source spelling, e.g. "bool"
    const char* zeek_type;          // Zeek-script-level spelling, often == bif_type
    const char* c_type;             // raw C++ type (e.g. "zeek::StringVal*")
    const char* c_type_smart;       // owning IntrusivePtr-flavored C++ type
    const char* accessor;           // fmt extracting a value via raw c_type
    const char* accessor_smart;     // fmt extracting via c_type_smart
    const char* cast_smart;         // template-arg suffix for find_const<...>
    const char* constructor;        // fmt wrapping a raw C++ value into a ValPtr
    const char* ctor_smart;         // same, for the smart-pointer flavor
    const char* native_return_type; // C++ return type
    const char* native_to_val;      // fmt wrapping a native return to a ValPtr
};

extern const bif_type_info bif_types[];

// Returns the builtin_func_arg_type index whose bif_type matches `name`,
// or TYPE_OTHER if none match.
int get_type_index(const char* name);

class BuiltinFuncArg final {
public:
    BuiltinFuncArg(const char* arg_name, int arg_type);
    BuiltinFuncArg(const char* arg_name, const char* arg_type_str, const char* arg_attr_str = "");

    void SetAttrStr(const char* arg_attr_str) { attr_str = arg_attr_str; };

    const char* Name() const { return name; }
    int Type() const { return type; }

    // For BiF return types that have a native primitive form, returns the
    // C++ type to use as the native function's return type.  Returns an empty
    // string if this Zeek type has no native C++ return form (a ValPtr is
    // used instead).
    const char* NativeReturnType() const;

    // printf-style template (with one %s) that wraps a primitive value into
    // the corresponding ValPtr for the shim's return path.
    const char* NativeToVal() const;

    void PrintZeek(std::string& out);
    void PrintCDef(std::string& out, int n, bool runtime_type_check);
    void PrintCArg(std::string& out, int n);
    void PrintValConstructor(std::string& out);

    // Native helpers: print "c_type name" for a parameter list, and the bare
    // name for a call-site argument list.
    void PrintCImplParam(std::string& out);
    void PrintCImplCallArg(std::string& out);

    // Convenience FILE* overloads: format into a std::string and write
    // the result via fputs. Avoid inside a func body (use the std::string&
    // forms above).
    void PrintZeek(FILE* fp);
    void PrintCDef(FILE* fp, int n, bool runtime_type_check);
    void PrintCArg(FILE* fp, int n);
    void PrintValConstructor(FILE* fp);
    void PrintCImplParam(FILE* fp);
    void PrintCImplCallArg(FILE* fp);

private:
    const char* name;
    int type;
    const char* type_str;
    const char* attr_str;
};
