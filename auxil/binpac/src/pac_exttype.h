// See the file "COPYING" in the main distribution directory for copyright.

#ifndef pac_exttype_h
#define pac_exttype_h

#include "pac_type.h"

// ExternType represent external C++ types that are not defined in
// PAC specification (therefore they cannot appear in data layout
// specification, e.g., in a record field). The type name is copied
// literally to the compiled code.

class ExternType : public Type {
public:
    enum EXTType { PLAIN, NUMBER, POINTER, BOOLEAN };
    ExternType(const ID* id, EXTType ext_type) : Type(EXTERN), id_(id), ext_type_(ext_type) {}

    bool DefineValueVar() const override;
    string DataTypeStr() const override;
    int StaticSize(Env* env) const override;
    bool ByteOrderSensitive() const override;

    string EvalMember(const ID* member_id) const override;
    bool IsNumericType() const override { return ext_type_ == NUMBER; }
    bool IsPointerType() const override { return ext_type_ == POINTER; }
    bool IsBooleanType() const override { return ext_type_ == BOOLEAN; }

    void GenInitCode(Output* out_cc, Env* env) override;

protected:
    void DoGenParseCode(Output* out, Env* env, const DataPtr& data, int flags) override;
    void GenDynamicSize(Output* out, Env* env, const DataPtr& data) override;

    Type* DoClone() const override;

private:
    const ID* id_;
    EXTType ext_type_;

public:
    static void static_init();
};

#define EXTERNTYPE(name, ctype, exttype) extern ExternType* extern_type_##name;
#include "pac_externtype.def"
#undef EXTERNTYPE

#endif // pac_exttype_h
