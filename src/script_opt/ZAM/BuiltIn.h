// See the file "COPYING" in the main distribution directory for copyright.

// ZAM classes for built-in functions. We refer to the script-level notion
// as a BiF, and the (potential) ZAM-level replacement as a ZBI = ZAM built-in.

#pragma once

#include "zeek/Expr.h"
#include "zeek/script_opt/ZAM/ZOp.h"

namespace zeek::detail {

class ZInstAux;

// Base class for analyzing function calls to BiFs to see if they can
// be replaced with ZBIs.
class ZAMBuiltIn {
public:
    // Constructed using the name of the BiF and a flag that if true means
    // that the point of calling the BiF is to do something with its return
    // value (in particular, the BiF does not have side-effects).
    ZAMBuiltIn(std::string name, bool _ret_val_matters);
    virtual ~ZAMBuiltIn() = default;

    bool ReturnValMatters() const { return ret_val_matters; }
    bool HaveBothReturnValAndNon() const { return have_both; }

    // Called to compile, if appropriate, a call to the BiF into the
    // corresponding specialized instruction. "n", if non-nil, provides
    // the assignment target for the return value. "args" are the (reduced)
    // arguments in the call, all either names or constants.
    //
    // Returns true if the replacement was successful, false if it's not
    // appropriate.
    virtual bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const = 0;

    // Similar to Build(), but done in the context of a conditional. If
    // successful, "branch_v" is updated with the slot in the newly added
    // instruction where the branch target lives.
    //
    // If "zam" is nil then does the true/false checking but not the actual
    // compilation. In this case, "branch_v" is unchanged.
    virtual bool BuildCond(ZAMCompiler* zam, const ExprPList& args, int& branch_v) const { return false; };

protected:
    bool ret_val_matters = true;

    // If true, then there are two versions of the ZBI, one for returning
    // a value and one for when the value is ignored.
    bool have_both = false;
};

// Class for dealing with simple 0- or 1-argument ZBIs that don't have
// any special considerations for applicability or compiling. These are
// quite common.
class SimpleZBI : public ZAMBuiltIn {
public:
    // This constructor is for ZBIs that either take no arguments, or always
    // take a single variable as their argument.
    SimpleZBI(std::string name, ZOp _op, int _nargs, bool _ret_val_matters = true);

    // A version for supporting a single argument that can be either a
    // constant (first operand) or a variable (second operand).
    SimpleZBI(std::string name, ZOp _const_op, ZOp _op, bool _ret_val_matters = true);

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

protected:
    // Operand used for the 0-argument or 1-argument-that's-a-variable case.
    ZOp op;

    // Operand used for the 1-argument-that's-a-constant case.
    ZOp const_op = OP_NOP;

    int nargs;
};

// A form of simple ZBIs that also support calling the BiF in a conditional.
class CondZBI : public SimpleZBI {
public:
    CondZBI(std::string name, ZOp _op, ZOp _cond_op, int _nargs);

    bool BuildCond(ZAMCompiler* zam, const ExprPList& args, int& branch_v) const override;

protected:
    ZOp cond_op;
};

// A form of simple ZBIs that support assignment but do not require it.
class OptAssignZBI : public SimpleZBI {
public:
    // Second argument is assignment flavor, third is assignment-less flavor.
    OptAssignZBI(std::string name, ZOp _op, ZOp _op2, int _nargs);

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

protected:
    ZOp op2;
};

// The cat() ZBI has an involved build process that can employ a number
// of different ZAM operations.
class CatZBI : public ZAMBuiltIn {
public:
    CatZBI() : ZAMBuiltIn("cat", true) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

private:
    // cat() ZBIs can have complex auxiliary information capturing the various
    // transformations (and fixed strings) to compute for each call.
    ZInstAux* BuildCatAux(ZAMCompiler* zam, const ExprPList& args) const;
};

// The sort() ZBI needs to refrain from replacing the BiF call if the
// arguments will generate an error (which can be determined at compile-time).
// Doing so enables us to streamline the corresponding ZAM operations.
class SortZBI : public OptAssignZBI {
public:
    SortZBI() : OptAssignZBI("sort", OP_SORT_VV, OP_SORT_V, 1) {}

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;
};


// The last form of ZBI is for more complex BiFs that take multiple arguments,
// which vary in whether some of them can be constants or have to be variables.
// Currently, 2- and 3-argument BiFs are supported.

// The following encodes the possible patterns of 2- and 3-argument calls
// to BiFs. V = Variable argument, C = Constant argument. The enums have
// values assigned to them reflecting the bit-pattern of the arguments from
// left (most significant) to right (least), with a 1-bit encoding Constant,
// 0-bit for Variable.
enum BiFArgsType : uint8_t {
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

// The following captures a ZAM operation and its associated operand type.
struct BiFArgInfo {
    ZOp op;
    ZAMOpType op_type;
};

// A map that associates ZAM operations (and types) with particular
// argument patterns.
using BiFArgsInfo = std::map<BiFArgsType, BiFArgInfo>;

// Class for supporting ZBIs that take multiple (i.e., > 1) arguments.
class MultiZBI : public ZAMBuiltIn {
public:
    // This first constructor is for ZBIs that either always have return
    // values or never do, and thus need just one BiFArgsInfo map.
    // If "_type_arg" is non-negative, then it specifies which argument
    // (numbered left-to-right, starting at 0) should be used to set the
    // Zeek type associated with the generated ZAM instruction.
    MultiZBI(std::string name, bool _ret_val_matters, BiFArgsInfo _args_info, int _type_arg = -1);

    // Alternative constructor for ZBIs that have optional return values.
    // The first map is for the non-assignment case, the second for the
    // assignment case.
    MultiZBI(std::string name, BiFArgsInfo _args_info, BiFArgsInfo _assign_args_info, int _type_arg = -1);

    bool Build(ZAMCompiler* zam, const NameExpr* n, const ExprPList& args) const override;

private:
    // Returns an enum describing the pattern of Constants/Variables in the
    // given argument list.
    BiFArgsType ComputeArgsType(const ExprPList& args) const;

    BiFArgsInfo args_info;
    BiFArgsInfo assign_args_info;
    int type_arg;
};

// If the given expression corresponds to a call to a ZAM built-in, then
// compiles the call and returns true.  Otherwise, returns false.
extern bool IsZAM_BuiltIn(ZAMCompiler* zam, const Expr* e);

// If the given expression corresponds to a call to a ZAM built-in that has
// a conditional version, compiles the conditional and returns true, and
// updates branch_v to reflect the branch slot. Otherwise, returns false.
extern bool IsZAM_BuiltInCond(ZAMCompiler* zam, const CallExpr* c, int& branch_v);

} // namespace zeek::detail
