// See the file "COPYING" in the main distribution directory for copyright.

#ifndef pac_number_h
#define pac_number_h

#include "pac_common.h"
#include "pac_exception.h"

class Number : public Object {
public:
    Number(int arg_n) : s(strfmt("%d", arg_n)), n(arg_n) {}
    Number(unsigned int arg_u) : s(strfmt("%uu", arg_u)), is_unsigned(true), u(arg_u) {}
    Number(const char* arg_s, int arg_n) : s(arg_s), n(arg_n) {}
    const char* Str() const { return s.c_str(); }
    int Num() const {
        if ( is_unsigned )
            throw Exception(this, "Num() called for unsigned number");
        return n;
    }
    unsigned int Unsigned() const {
        if ( ! is_unsigned )
            throw Exception(this, "Unsigned() called for signed number");
        return u;
    }
    bool IsUnsigned() const { return is_unsigned; }

protected:
    const string s;
    bool is_unsigned = false;
    union {
        const int n;
        const unsigned int u;
    };
};

#endif // pac_number_h
