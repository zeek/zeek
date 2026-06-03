// See the file "COPYING" in the main distribution directory for copyright.

#include "include/bif_arg.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

const bif_type_info bif_types[] = {
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DEFINE_BIF_TYPE(id, bif_type, zeek_type, c_type, c_type_smart, accessor, accessor_smart, cast_smart,           \
                        constructor, ctor_smart, native_return_type, native_to_val)                                    \
    {#id,         bif_type,   zeek_type,          c_type,       c_type_smart, accessor, accessor_smart, cast_smart,    \
     constructor, ctor_smart, native_return_type, native_to_val},
#include "bif_type.def"
#undef DEFINE_BIF_TYPE
};

int get_type_index(const char* name) {
    for ( int i = 0; bif_types[i].bif_type[0] != '\0'; ++i )
        if ( strcmp(bif_types[i].bif_type, name) == 0 )
            return i;
    return TYPE_OTHER;
}

extern const char* arg_list_name;

void vappendf(std::string& out, const char* fmt, va_list ap) {
    char buf[4096];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if ( n >= (int)sizeof(buf) ) {
        fprintf(stderr, "bifcl: appendf output exceeded %zu bytes (format \"%s\")\n", sizeof(buf), fmt);
        exit(1);
    }
    out.append(buf, n);
}

void appendf(std::string& out, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vappendf(out, fmt, ap);
    va_end(ap);
}

BuiltinFuncArg::BuiltinFuncArg(const char* arg_name, int arg_type) {
    name = arg_name;
    type = arg_type;
    type_str = "";
    attr_str = "";
}

BuiltinFuncArg::BuiltinFuncArg(const char* arg_name, const char* arg_type_str, const char* arg_attr_str) {
    name = arg_name;
    attr_str = arg_attr_str;
    type = get_type_index(arg_type_str);
    type_str = (type == TYPE_OTHER) ? arg_type_str : "";
}

void BuiltinFuncArg::PrintZeek(std::string& out) {
    appendf(out, "%s: %s%s %s", name, bif_types[type].zeek_type, type_str, attr_str);
}

void BuiltinFuncArg::PrintCDef(std::string& out, int n, bool runtime_type_check) {
    // For most BiFs, script-level type-checking already guarantees that the
    // argument types match the declared signature, so the generated code does
    // a typed cast without re-checking. Variadic BiFs are the exception:
    // their fixed-position arguments aren't type-checked, so invoking these
    // requires runtime tag-checking on those. TYPE_OTHER and TYPE_ANY don't
    // have a single fixed TypeTag.
    if ( runtime_type_check && type != TYPE_OTHER && type != TYPE_ANY ) {
        appendf(out, "\t\t{\n");
        appendf(out, "\t\t// Runtime type check for %s argument\n", name);
        appendf(out, "\t\tzeek::TypeTag __tag = (*%s)[%d]->GetType()->Tag();\n", arg_list_name, n);
        appendf(out, "\t\tif ( __tag != %s )\n", bif_types[type].type_enum);
        appendf(out, "\t\t\t{\n");
        appendf(out,
                "\t\t\tzeek::emit_builtin_error(zeek::util::fmt(\"expected type %s for %s, got "
                "%%s\", zeek::type_name(__tag)));\n",
                bif_types[type].zeek_type, name);
        appendf(out, "\t\t\treturn nullptr;\n");
        appendf(out, "\t\t\t}\n");
        appendf(out, "\t\t}\n");
    }
    appendf(out, "\t%s %s = (%s) (", bif_types[type].c_type, name, bif_types[type].c_type);

    char buf[1024];
    snprintf(buf, sizeof(buf), "(*%s)[%d].get()", arg_list_name, n);
    // Print the accessor expression.
    appendf(out, bif_types[type].accessor, buf);

    appendf(out, "); // NOLINT(cppcoreguidelines-pro-type-cstyle-cast,modernize-avoid-c-style-cast)\n");
}

void BuiltinFuncArg::PrintCArg(std::string& out, int n) { appendf(out, "%s %s", bif_types[type].c_type_smart, name); }

void BuiltinFuncArg::PrintValConstructor(std::string& out) { appendf(out, bif_types[type].ctor_smart, name); }

void BuiltinFuncArg::PrintCImplParam(std::string& out) { appendf(out, "%s %s", bif_types[type].c_type, name); }

void BuiltinFuncArg::PrintCImplCallArg(std::string& out) { appendf(out, "%s", name); }

const char* BuiltinFuncArg::NativeReturnType() const { return bif_types[type].native_return_type; }
const char* BuiltinFuncArg::NativeToVal() const { return bif_types[type].native_to_val; }

// FILE* convenience overloads: format into a std::string, then fputs.
// to_file resolves the std::string& overload at the lambda call site,
// avoiding the ambiguity that a direct &PrintZeek member-pointer would have.

template<typename F>
static void to_file(FILE* fp, F&& fn) {
    std::string s;
    fn(s);
    fputs(s.c_str(), fp);
}

void BuiltinFuncArg::PrintZeek(FILE* fp) {
    to_file(fp, [&](std::string& s) { PrintZeek(s); });
}

void BuiltinFuncArg::PrintCDef(FILE* fp, int n, bool runtime_type_check) {
    to_file(fp, [&](std::string& s) { PrintCDef(s, n, runtime_type_check); });
}

void BuiltinFuncArg::PrintCArg(FILE* fp, int n) {
    to_file(fp, [&](std::string& s) { PrintCArg(s, n); });
}

void BuiltinFuncArg::PrintValConstructor(FILE* fp) {
    to_file(fp, [&](std::string& s) { PrintValConstructor(s); });
}

void BuiltinFuncArg::PrintCImplParam(FILE* fp) {
    to_file(fp, [&](std::string& s) { PrintCImplParam(s); });
}

void BuiltinFuncArg::PrintCImplCallArg(FILE* fp) {
    to_file(fp, [&](std::string& s) { PrintCImplCallArg(s); });
}
