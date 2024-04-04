// See the file "COPYING" in the main distribution directory for copyright.

// ZAM classes for built-in functions.

#pragma once

#include "zeek/Expr.h"
#include "zeek/script_opt/ZAM/Compile.h"

namespace zeek::detail {

class ZAMBuiltIn {
public:
    ZAMBuiltIn(std::string name, bool _ret_val_matters);
    virtual ~ZAMBuiltIn() = default;

    bool ReturnValMatters() const { return ret_val_matters; }
    bool HaveBothReturnValAndNon() const { return have_both; }

    virtual bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const = 0;
    virtual bool BuildCond(ZAMCompiler* zam, const ExprPList& args, int& branch_v) const { return false; };

protected:
    bool ret_val_matters = true;
    bool have_both = false;
};

class DirectBuiltIn : public ZAMBuiltIn {
public:
    DirectBuiltIn(std::string name, ZOp _op, int _nargs, bool _ret_val_matters = true, ZOp _cond_op = OP_NOP);

    DirectBuiltIn(std::string name, ZOp _const_op, ZOp _op, int _nargs, bool _ret_val_matters = true);

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;
    bool BuildCond(ZAMCompiler* zam, const ExprPList& args, int& branch_v) const override;

protected:
    ZOp op;
    ZOp const_op = OP_NOP;
    ZOp cond_op = OP_NOP;
    int nargs;
};

class DirectBuiltInOptAssign : public DirectBuiltIn {
public:
    // Second argument is assignment flavor, third is assignment-less flavor.
    DirectBuiltInOptAssign(std::string name, ZOp _op, ZOp _op2, int _nargs);

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

protected:
    ZOp op2;
};

class CatBiF : public ZAMBuiltIn {
public:
    CatBiF() : ZAMBuiltIn("cat", true) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

private:
    ZInstAux* BuildCatAux(ZAMCompiler* zam, const ExprPList& args) const;
};

class SortBiF : public DirectBuiltInOptAssign {
public:
    SortBiF() : DirectBuiltInOptAssign("sort", OP_SORT_VV, OP_SORT_V, 1) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;
};

class LogWriteBiF : public ZAMBuiltIn {
public:
    LogWriteBiF(std::string name) : ZAMBuiltIn(std::move(name), false) { have_both = true; }

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;
};

enum BIFArgsType {
    VV = 0x0,
    VC = 0x1,
    CV = 0x2,
    CC = 0x3,

    VVV = 0x0,
    VVC = 0x1,
    VCV = 0x2,
    VCC = 0x3,
    CVV = 0x4,
    CVC = 0x5,
    CCV = 0x6,
    CCC = 0x7,
};

struct BIFArgInfo {
    ZOp op;
    ZAMOpType op_type;
};

using BifArgsInfo = std::map<BIFArgsType, BIFArgInfo>;

class MultiArgBuiltIn : public ZAMBuiltIn {
public:
    MultiArgBuiltIn(std::string name, bool _ret_val_matters, BifArgsInfo _args_info, int _type_arg = -1);

    MultiArgBuiltIn(std::string name, BifArgsInfo _args_info, BifArgsInfo _assign_args_info, int _type_arg = -1);

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

private:
    // Returns a bit mask of which of the arguments in the given list
    // correspond to constants, with the high-ordered bit being the first
    // argument (argument "0" in the list) and the low-ordered bit being
    // the last. These correspond to the ArgsType enum integer values.
    BIFArgsType ComputeArgsType(const ExprPList& args) const;

    BifArgsInfo args_info;
    BifArgsInfo assign_args_info;
    int type_arg;
};

// If the given expression corresponds to a call to a ZAM built-in,
// then compiles the call and returns true.  Otherwise, returns false.
extern bool IsZAM_BuiltIn(ZAMCompiler* zam, const Expr* e);

// If the given expression corresponds to a call to a ZAM built-in
// that has a conditional version, compiles the conditional and returns
// true, and updates branch_v to reflect the branch slot.
// Otherwise, returns false.
extern bool IsZAM_BuiltInCond(ZAMCompiler* zam, const CallExpr* c, int& branch_v);

} // namespace zeek::detail
