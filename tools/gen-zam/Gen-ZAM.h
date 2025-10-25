// See the file "COPYING" in the main distribution directory for copyright.

// Gen-ZAM is a standalone program that takes as input a file specifying
// ZAM operations and from them generates a (large) set of C++ include
// files used to instantiate those operations as low-level ZAM instructions.
// (Those files are described in the EmitTarget enumeration below.)
//
// See Ops.in for documentation regarding the format of the ZAM templates.

#pragma once

#include <cassert>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using std::string;
using std::vector;

// An instruction can have one of four basic classes.
enum ZAM_InstClass {
    ZIC_REGULAR, // a non-complicated instruction
    ZIC_COND,    // a conditional branch
    ZIC_VEC,     // a vector operation
    ZIC_FIELD,   // a record field assignment
};

// For a given instruction operand, its general class.
enum ZAM_OperandClass {
    ZAM_OC_CONSTANT,      // uses the instruction's associated constant
    ZAM_OC_EVENT_HANDLER, // uses the associated event handler
    ZAM_OC_INT,           // directly specified integer
    ZAM_OC_VAR,           // frame slot associated with a variable

    ZAM_OC_ASSIGN_FIELD, // record field offset to assign to
    ZAM_OC_RECORD_FIELD, // record field offset to access

    // The following wind up the same in the ultimate instruction,
    // but they differ in the calling sequences used to generate
    // the instruction.
    ZAM_OC_AUX,  // uses the instruction's "aux" field
    ZAM_OC_LIST, // a list, managed via the "aux" field

    // Internal types: branches, tracking globals, step-wise iterations
    // (vectors and strings), table iterations.
    ZAM_OC_BRANCH,
    ZAM_OC_GLOBAL,
    ZAM_OC_STEP_ITER,
    ZAM_OC_TBL_ITER,

    ZAM_OC_NONE, // instruction has no direct operands
};

using OCVec = vector<ZAM_OperandClass>;

// For instructions corresponding to evaluating expressions, the type
// of a given operand.  The generator uses these to transform the operand's
// low-level ZVal into a higher-level type expected by the associated
// evaluation code.
enum ZAM_Type {
    ZAM_TYPE_ADDR,
    ZAM_TYPE_ANY,
    ZAM_TYPE_DOUBLE,
    ZAM_TYPE_FUNC,
    ZAM_TYPE_INT,
    ZAM_TYPE_PATTERN,
    ZAM_TYPE_RECORD,
    ZAM_TYPE_STRING,
    ZAM_TYPE_SUBNET,
    ZAM_TYPE_TABLE,
    ZAM_TYPE_UINT,
    ZAM_TYPE_VECTOR,
    ZAM_TYPE_FILE,
    ZAM_TYPE_OPAQUE,
    ZAM_TYPE_LIST,
    ZAM_TYPE_TYPE,

    // Used to specify "apart from the explicitly specified operand
    // types, do this action for any other types".
    ZAM_TYPE_DEFAULT,

    // Used for expressions where the evaluation code for the
    // expression deals directly with the operand's ZVal, rather
    // than the generator providing a higher-level version.
    ZAM_TYPE_NONE,
};

// We only use the following in the context where the vector's elements
// are individual words from the same line.  We don't use it in other
// contexts where we're tracking a bunch of strings.
using Words = vector<string>;

// Used for error-reporting.
struct InputLoc {
    const char* file_name;
    int line_num = 0;
};

// An EmitTarget is a generated file to which code will be emitted.
// The different values are used to instruct the generator which target
// is currently of interest.
enum EmitTarget {
    // Indicates that no generated file has yet been specified.
    None,

    // Declares/defines methods that take AST nodes and generate
    // corresponding ZAM instructions.
    MethodDecl,
    MethodDef,

    // Switch cases for expressions that are compiled directly, using
    // custom methods rather than methods produced by the generator.
    DirectDef,

    // Switch cases for invoking various flavors of methods produced
    // by the generator for generating ZAM instructions for AST
    // expressions.  C1/C2/C3 refer to the first/second/third operand
    // being a constant.  V refers to none of the operands being
    // a constant.
    C1Def,
    C2Def,
    C3Def,
    VDef,

    // The same, but for when the expression is being assigned to
    // a record field rather than a variable.  There's no "C3" option
    // because of how we reduce AST ternary operations.
    C1FieldDef,
    C2FieldDef,
    VFieldDef,

    // Switch cases for compiling relational operations used in
    // conditionals.
    Cond,

    // Descriptions of final ZAM operations, used for validation.
    OpDesc,

    // The same, for macros.
    MacroDesc,

    // Switch cases that provide the C++ code for executing specific
    // individual ZAM instructions.
    Eval,

    // #define's used to provide the templator's macro functionality.
    EvalMacros,

    // Switch cases the provide the C++ code for executing unary
    // and binary vector operations.
    Vec1Eval,
    Vec2Eval,

    // A set of instructions to dynamically generate maps that
    // translate a generic ZAM operation (e.g., OP_LOAD_GLOBAL_VV)
    // to a specific ZAM instruction, given a specific type
    // (e.g., for OP_LOAD_GLOBAL_VV plus TYPE_ADDR, the map yields
    // OP_LOAD_GLOBAL_VV_A).
    AssignFlavor,

    // A list of values, one per ZAM instruction, that indicate whether
    // that instruction writes to its first operand (the most common
    // case), reads the operand but doesn't write to it, both reads it
    // and writes to it, or none of these apply because the first
    // operand isn't a frame variable.  See the ZAMOp1Flavor enum
    // defined in ZOp.h.
    Op1Flavor,

    // A list of boolean values, one per ZAM instruction, that indicate
    // whether the instruction has side effects, and thus should not
    // be deleted even if its associated assignment is to a dead value
    // (one not subsequently used).
    OpSideEffects,

    // A list of names enumerating each ZAM instruction.  These
    // are ZAM opcodes.
    OpDef,

    // A list of cases, indexed by ZAM opcode, that return a
    // human-readable string of naming the opcode, for use in debugging
    // output.  For example, for OP_NEGATE_VV_I the corresponding
    // string is "negate-VV-I".
    OpName,
};

// A helper class for managing the (ordered) collection of ZAM_OperandClass's
// associated with an instruction in order to generate C++ calling sequences
// (both parameters for declarations, and arguments for invocations).
class ArgsManager {
public:
    // Constructed by providing the various ZAM_OperandClass's along
    // with the instruction's class.
    ArgsManager(const OCVec& oc, ZAM_InstClass ic);

    // Returns a string defining the parameters for a declaration;
    // these have full C++ type information along with the parameter
    // name.
    string Decls() const { return full_decl; }

    // Returns a string for passing the parameters in a function
    // call.  This is a comma-separated list of the parameter names,
    // with no associated C++ types.
    string Params() const { return full_params; }

    // Returns the name of the given parameter, indexed starting with 0.
    const string& NthParam(int n) const { return params[n]; }

    // Returns how many parameters the manager has.
    int NumParams() const { return static_cast<int>(args.size()); }

private:
    // Makes sure that each parameter has a unique name.  For any
    // parameter 'x' that occurs more than once, renames the instances
    // "x1", "x2", etc.
    void Differentiate();

    // Maps ZAM_OperandClass's to their associated C++ type and
    // canonical parameter name.
    static std::unordered_map<ZAM_OperandClass, std::pair<const char*, const char*>> oc_to_args;

    // For a single argument/parameter, tracks its declaration name,
    // C++ type, and the name to use when providing it as a parameter.
    // We have two names because in some contexts record fields have
    // different names in declarations vs. in parameter lists.
    struct Arg {
        string decl_name;
        string decl_type;
        string param_name;
    };

    // All of the argument/parameters associated with the collection
    // of ZAM_OperandClass's.
    vector<Arg> args;

    // Each of the individual parameters.
    vector<string> params;

    // See Decls() and Params() above.
    string full_decl;
    string full_params;
};

// There are two mutually interacting classes: ZAMGen is the overall driver
// for the ZAM generator, while ZAM_OpTemplate represents a single operation
// template, with subclasses for specific types of operations.
class ZAMGen;

class ZAM_OpTemplate {
public:
    // Instantiated by passing in the ZAMGen driver and the generic
    // name for the operation.
    ZAM_OpTemplate(ZAMGen* _g, string _base_name);
    virtual ~ZAM_OpTemplate() {}

    // Constructs the template's data structures by parsing its
    // description (beyond the initial description of the type of
    // operation).
    void Build();

    // Tells the object to generate the code/files necessary for
    // each of its underlying instructions.
    virtual void Instantiate();

    // Returns the generic name for the operation.
    const string& BaseName() const { return base_name; }

    // Returns the canonical name for the operation.  This is a
    // version of the name that, for expression-based operations,
    // can be concatenated with "EXPR_" to get the name of the
    // corresponding AST node.
    const string& CanonicalName() const { return cname; }

    // Returns a string version of the ZAMOp1Flavor associated
    // with this operation.
    const string& GetOp1Flavor() const { return op1_flavor; }

    // True if this operation has side effects (see OpSideEffects above).
    bool HasSideEffects() const { return has_side_effects; }

    // True if this operation has a predicate form (i.e., yields a
    // boolean value that can be used in conditionals).
    void SetIsPredicate() { is_predicate = true; }
    bool IsPredicate() const { return is_predicate; }

    // The number of operands the operation takes (not including its
    // assignment target).  A value of 0 is used for operations that
    // require special handling.
    virtual int Arity() const { return 0; }

protected:
    // Do instantiation for predicate operations.
    void InstantiatePredicate();

    // Retrieve the list of operand classes associated with this operation.
    const OCVec& OperandClasses() const { return op_classes; }

    // Specify the ZAMOp1Flavor associated with this operation.  See
    // GetOp1Flavor() above for the corresponding accessor.
    void SetOp1Flavor(string fl) { op1_flavor = fl; }

    // Specify/fetch the parameter (operand) from which to take the
    // primary type of this operation.
    void SetTypeParam(int param) { type_param = param; }
    const auto& GetTypeParam() const { return type_param; }

    // Specify/fetch the parameter (operand) from which to take the
    // secondary type of this operation.
    void SetType2Param(int param) { type2_param = param; }
    const auto& GetType2Param() const { return type2_param; }

    // Tracking of assignment values (C++ variables that hold the
    // value that should be assigned to usual frame slot).
    void SetAssignVal(string _av) { av = _av; }
    bool HasAssignVal() const { return ! av.empty(); }
    const string& GetAssignVal() const { return av; }

    // Management of C++ evaluation blocks.  These are built up
    // line-by-line.
    void AddEval(string line) { eval += line; }
    bool HasEval() const { return ! eval.empty(); }
    const string& GetEval() const { return eval; }

    // Management of custom methods to be used rather than generating
    // a method.
    void SetCustomMethod(string cm) { custom_method = SkipWS(cm); }
    bool HasCustomMethod() const { return ! custom_method.empty(); }
    const string& GetCustomMethod() const { return custom_method; }

    // Management of code to execute at the end of a generated method.
    void SetPostMethod(string cm) { post_method = SkipWS(cm); }
    bool HasPostMethod() const { return ! post_method.empty(); }
    const string& GetPostMethod() const { return post_method; }

    // Predicates indicating whether a subclass supports a given
    // property.  These are whether the operation: (1) should include
    // a version that assigns to a record field as well as the normal
    // assigning to a frame slot, (2) is a conditional branch, (3) does
    // not have a corresponding AST node, (4) is a direct assignment
    // (not an assignment to an expression), (5) is a direct assignment
    // to a record field.
    virtual bool IncludesFieldOp() const { return false; }
    virtual bool IsConditionalOp() const { return false; }
    virtual bool IsInternalOp() const { return false; }
    virtual bool IsAssignOp() const { return false; }
    virtual bool IsFieldOp() const { return false; }

    // Whether this operation does not have any C++ evaluation associated
    // with it.  Used for custom methods that compile into internal
    // ZAM operations.
    bool NoEval() const { return no_eval; }
    void SetNoEval() { no_eval = true; }

    // Whether this operation does not have a version where one of
    // its operands is a constant.
    bool NoConst() const { return no_const; }
    void SetNoConst() { no_const = true; }

    // Whether this operation also has a vectorized form.
    bool IncludesVectorOp() const { return includes_vector_op; }
    void SetIncludesVectorOp() { includes_vector_op = true; }

    // Whether this operation has side effects, and thus should
    // not be elided even if its result is used in a dead assignment.
    void SetHasSideEffects() { has_side_effects = true; }

    // An "assignment-less" operation is one that, if its result
    // is used in a dead assignment, should be converted to a different
    // operation that explicitly omits any assignment.
    bool HasAssignmentLess() const { return ! assignment_less_op.empty(); }
    void SetAssignmentLess(string op, string op_class) {
        assignment_less_op = std::move(op);
        assignment_less_op_class = std::move(op_class);
    }
    const string& AssignmentLessOp() const { return assignment_less_op; }
    const string& AssignmentLessOpClass() const { return assignment_less_op_class; }

    // Builds the instructions associated with this operation, assuming
    // a single operand.
    void UnaryInstantiate();

    // Parses the next line in an operation template.  "attr" is
    // the first word on the line, which often specifies the
    // attribute specified by the line.  "line" is the entire line,
    // for parsing when that's necessary, and for error reporting.
    // "words" is "line" split into a vector of whitespace-delimited
    // words.
    virtual void Parse(const string& attr, const string& line, const Words& words);

    // Helper function that parses "class" specifications.
    OCVec ParseClass(const string& spec) const;

    // Scans in a C++ evaluation block, which continues until encountering
    // a line that does not start with whitespace, or that's empty.
    string GatherEval();

    // Parses a $-specifier of which operand to use to associate
    // a Zeek scripting type with ZAM instructions.
    int ExtractTypeParam(const string& arg);

    // Generates instructions for each of the different flavors of the
    // given operation. "oc" specifies the classes of operands for the
    // instruction, and "do_vec" whether to generate a vector version.
    void InstantiateOp(const OCVec& oc, bool do_vec);

    // Generates one specific flavor ("zc") of the given operation,
    // using a method named 'm', the given operand classes, and the
    // instruction class.
    void InstantiateOp(const string& m, const OCVec& oc, ZAM_InstClass zc);

    // Generates the "assignment-less" version of the given op-code.
    void GenAssignmentlessVersion(const string& op);

    // Generates the method 'm' for an operation, where "suffix" is
    // a (potentially empty) string differentiating the method from
    // others for that operation, and "oc" and "zc" are the same
    // as above.
    void InstantiateMethod(const string& m, const string& suffix, const OCVec& oc, ZAM_InstClass zc);

    // Generates the main logic of an operation's method, given the
    // specific operand classes, an associated suffix for differentiating
    // ZAM instructions, and the instruction class.
    void InstantiateMethodCore(const OCVec& oc, const string& suffix, ZAM_InstClass zc);

    // Generates the specific code to create a ZInst for the given
    // operation, operands, parameters to "GenInst", and suffix and
    // class per the above.
    virtual void BuildInstruction(const OCVec& oc, const string& params, const string& suffix, ZAM_InstClass zc);

    // Expands $-parameters into their direct representations given the
    // operand classes and associated accessors.
    string ExpandParams(const OCVec& oc, string eval, const vector<string>& accessors) const;
    string ExpandParams(const OCVec& oc, string eval) const {
        vector<string> no_accessors;
        return ExpandParams(oc, std::move(eval), no_accessors);
    }

    // Top-level driver for generating the C++ evaluation code for
    // a given flavor of operation.
    virtual void InstantiateEval(const OCVec& oc, const string& suffix, ZAM_InstClass zc);

    // Generates the C++ case statement for evaluating the given flavor
    // of operation.
    void GenEval(EmitTarget et, const string& oc_str, const string& op_suffix, const string& eval, ZAM_InstClass zc);

    // Generates a description of the ZAM operation suitable for
    // reflection.
    void GenDesc(const string& op_code, const string& oc_str, const string& eval);

    // Generates the first part of a description, up to (but not including)
    // the evaluation.
    void StartDesc(const string& op_code, const string& oc_str);

    // Finishes a description, once the evaluation is done.
    void EndDesc();

    // Generates a set of assignment C++ evaluations, one per each
    // possible Zeek scripting type of operand.
    void InstantiateAssignOp(const OCVec& oc, const string& suffix);

    // Generates a C++ evaluation for an assignment of the type
    // corresponding to "accessor".  If "is_managed" is true then
    // generates the associated memory management, too.
    void GenAssignOpCore(const OCVec& oc, const string& eval, const string& accessor, bool is_managed);

    // The same, but for when there's an explicit assignment value.
    void GenAssignOpValCore(const OCVec& oc, const string& eval, const string& accessor, bool is_managed);

    // Returns the name of the method associated with the particular
    // list of operand classes.
    string MethodName(const OCVec& oc) const;

    // Returns the parameter declarations to use in declaring a method.
    string MethodDeclare(const OCVec& oc, ZAM_InstClass zc);

    // Returns a suffix that differentiates an operation name for
    // a specific list of operand classes.
    string OpSuffix(const OCVec& oc) const;

    // Returns a copy of the given string with leading whitespace
    // removed.
    string SkipWS(const string& s) const;

    // Set the target to use for subsequent code emission.
    void EmitTo(EmitTarget et) { curr_et = et; }

    // Emit the given string to the currently selected EmitTarget.
    void Emit(const string& s);

    // Same, but temporarily indented up.
    void EmitUp(const string& s) {
        IndentUp();
        Emit(s);
        IndentDown();
    }

    // Same, but reframe from inserting a newline.
    void EmitNoNL(const string& s);

    // Emit a newline.  Implementation doesn't actually include a
    // newline since that's implicit in a call to Emit().
    void NL() { Emit(""); }

    // Increase/decrease the indentation level, with the last two
    // being used for brace-delimited code blocks.
    void IndentUp();
    void IndentDown();
    void BeginBlock() {
        IndentUp();
        Emit("{");
    }
    void EndBlock() {
        Emit("}");
        IndentDown();
    }

    // Start/finish emitting a (likely multi-line) string literal -
    // see corresponding ZAMGen methods.
    void StartString();
    void EndString();

    // Exit with an error, mainly for consistency-checking.
    void Gripe(const char* msg) const;
    void Gripe(string msg, string addl) const;

    // Maps an operand class to a character mnemonic used to distinguish
    // it from others.
    static std::unordered_map<ZAM_OperandClass, char> oc_to_char;

    // The associated driver object.
    ZAMGen* g;

    // See BaseName() and CanonicalName() above.
    string base_name;
    string cname;

    // Tracks the beginning of this operation template's definition,
    // for error reporting.
    InputLoc op_loc;

    // The current emission target.
    EmitTarget curr_et = None;

    // The operand classes for operations that have a single fixed list.
    // Some operations (like those evaluating expressions) instead have
    // dynamically generated range of possible operand classes.
    OCVec op_classes;

    // For operations that have several fixed operand sets to work through.
    vector<OCVec> op_classes_vec;

    // If non-empty, the ZAM types associated with each operand,
    // left-to-right mirroring the order of the op_classes.
    vector<ZAM_Type> op_types;

    // The following is usually empty, but can be instantiated when
    // iterating across "types" that in some instances include ZAM_OC_INT,
    // in which case those will have ".int_val" accessors associated
    // with those slots.
    vector<string> accessors;

    // See the description of Op1Flavor above.
    string op1_flavor = "OP1_WRITE";

    // Tracks the result of ExtractTypeParam() used for "type" and
    // "type2" attributes.
    std::optional<int> type_param;
    std::optional<int> type2_param;

    // If non-empty, the value to assign to the target in an assignment
    // operation.
    string av;

    // The C++ evaluation; may span multiple lines.
    string eval;

    // Postlog C++ code (currently only used in support of profiling).
    string post_eval;

    // Any associated custom method.
    string custom_method;

    // Any associated additional code to add at the end of a
    // generated method.
    string post_method;

    // If true, then this operation does not have C++ evaluation
    // associated with it.
    bool no_eval = false;

    // If true, then this operation should not include a version
    // supporting operands of constant type.
    bool no_const = false;

    // If true, then this operation includes a vectorized version.
    bool includes_vector_op = false;

    // If true, then this operation has side effects.
    bool has_side_effects = false;

    // Whether to instantiate this operation as a predicate, which
    // results in three versions: (1) assignment of the evaluation to
    // a (integer-typed) target, (2) branch if the evaluation *is not*
    // the case, (3) branch if the evaluation *is* the case.
    bool is_predicate = false;

    // If non-empty, then specifies the associated operation that
    // is a version of this operation but without assigning the result;
    // and the operand class (like "OP_V") of that associated operation.
    string assignment_less_op;
    string assignment_less_op_class;
};

// A subclass used for "unary-op" templates.
class ZAM_UnaryOpTemplate : public ZAM_OpTemplate {
public:
    ZAM_UnaryOpTemplate(ZAMGen* _g, string _base_name) : ZAM_OpTemplate(_g, _base_name) {}

protected:
    void Instantiate() override;
};

// A subclass for unary operations that are directly instantiated using
// custom methods.
class ZAM_DirectUnaryOpTemplate : public ZAM_OpTemplate {
public:
    ZAM_DirectUnaryOpTemplate(ZAMGen* _g, string _base_name, string _direct)
        : ZAM_OpTemplate(_g, _base_name), direct(_direct) {}

protected:
    void Instantiate() override;

private:
    // The ZAMCompiler method to call to compile the operation.
    string direct;
};

// A helper class for the ZAM_ExprOpTemplate class (which follows).
// This class tracks a single instance of creating an evaluation for
// an AST expression.
class EvalInstance {
public:
    // Initialized using the types of the LHS (result) and the
    // first and second operand.  Often all three types are the
    // same, but they can differ for some particular expressions,
    // and for relationals.  "eval" provides the C++ evaluation code.
    // "is_def" is true if this instance is for the default catch-all
    // where the operand types don't match any of the explicitly
    // specified evaluations;
    EvalInstance(ZAM_Type lhs_et, ZAM_Type op1_et, ZAM_Type op2_et, string eval, bool is_def);

    // Returns the accessor to use for assigning to the LHS.  "is_ptr"
    // indicates whether the value to which we're applying the
    // accessor is a pointer, rather than a ZVal.
    string LHSAccessor(bool is_ptr = false) const;

    // Same but for access to the first or second operand.
    string Op1Accessor(bool is_ptr = false) const { return Accessor(op1_et, is_ptr); }
    string Op2Accessor(bool is_ptr = false) const { return Accessor(op2_et, is_ptr); }

    // Provides an accessor for an operand of the given type.
    string Accessor(ZAM_Type zt, bool is_ptr = false) const;

    // Returns the "marker" use to make unique the opcode for this
    // flavor of expression-evaluation instruction.
    string OpMarker() const;

    const string& Eval() const { return eval; }
    bool IsDefault() const { return is_def; }

    ZAM_Type LHS_ET() const { return lhs_et; }
    ZAM_Type Op1_ET() const { return op1_et; }
    ZAM_Type Op2_ET() const { return op2_et; }

private:
    ZAM_Type lhs_et;
    ZAM_Type op1_et;
    ZAM_Type op2_et;
    string eval;
    bool is_def;
};

// A subclass for AST "Expr" nodes in reduced form.
class ZAM_ExprOpTemplate : public ZAM_OpTemplate {
public:
    ZAM_ExprOpTemplate(ZAMGen* _g, string _base_name);

    int HasExplicitResultType() const { return explicit_res_type; }
    void SetHasExplicitResultType() { explicit_res_type = true; }

    void AddExprType(ZAM_Type zt) { expr_types.insert(zt); }
    const std::unordered_set<ZAM_Type>& ExprTypes() const { return expr_types; }

    void AddEvalSet(ZAM_Type zt, string ev) { eval_set[zt] += ev; }
    void AddEvalSet(ZAM_Type et1, ZAM_Type et2, string ev) { eval_mixed_set[et1][et2] += ev; }

    bool IncludesFieldOp() const override { return includes_field_op; }
    void SetIncludesFieldOp() { includes_field_op = true; }

    bool HasPreCheck() const { return ! pre_check.empty(); }
    void SetPreCheck(string pe) { pre_check = SkipWS(pe); }
    const string& GetPreCheck() const { return pre_check; }

    bool HasPreCheckAction() const { return ! pre_check_action.empty(); }
    void SetPreCheckAction(string pe) { pre_check_action = SkipWS(pe); }
    const string& GetPreCheckAction() const { return pre_check_action; }

protected:
    // Returns a regular expression used to access the value of the
    // expression suitable for assignment in a loop across the elements
    // of a Zeek "vector" type.  "have_target" is true if the template
    // has an explicit "$$" assignment target.
    virtual const char* VecEvalRE(bool have_target) const { return have_target ? "$$$$ = ZVal($1)" : "ZVal($&)"; }

    void Parse(const string& attr, const string& line, const Words& words) override;
    void Instantiate() override;

    // Instantiates versions of the operation that have a constant
    // as the first, second, or third operand ...
    void InstantiateC1(const OCVec& ocs, size_t arity);
    void InstantiateC2(const OCVec& ocs, size_t arity);
    void InstantiateC3(const OCVec& ocs);

    // ... or if all of the operands are non-constant.
    void InstantiateV(const OCVec& ocs);

    // Generates code that instantiates either the vectorized version
    // of an operation, or the non-vector one, depending on whether
    // the RHS of the reduced expression/assignment is a vector.
    void DoVectorCase(const string& m, const string& args);

    // Iterates over the different Zeek types specified for an expression's
    // operands and generates instructions for each.
    void BuildInstructionCore(const string& params, const string& suffix, ZAM_InstClass zc);

    // Generates an if-else cascade element that matches one of the
    // specific Zeek types associated with the instruction.
    void GenMethodTest(ZAM_Type et1, ZAM_Type et2, const string& params, const string& suffix, bool do_else,
                       ZAM_InstClass zc);

    void InstantiateEval(const OCVec& oc, const string& suffix, ZAM_InstClass zc) override;

private:
    // The Zeek types that can appear as operands for the expression.
    std::unordered_set<ZAM_Type> expr_types;

    // The C++ evaluation template for a given operand type.
    std::unordered_map<ZAM_Type, string> eval_set;

    // Some expressions take two operands of different types.  This
    // holds their C++ evaluation template.
    std::unordered_map<ZAM_Type, std::unordered_map<ZAM_Type, string>> eval_mixed_set;

    // Whether this expression's operand is a field access (and thus
    // needs both the record as an operand and an additional constant
    // offset into the record to get to the field).
    bool includes_field_op = false;

    // If non-empty, a check to conduct before evaluating the expression ...
    string pre_check;

    // ... and the action to take if the check is true, *instead* of
    // evaluating the expression.
    string pre_check_action;

    // If true, then the evaluations will take care of ensuring
    // proper result types when assigning to $$.
    bool explicit_res_type = false;
};

// A version of ZAM_ExprOpTemplate for unary expressions.
class ZAM_UnaryExprOpTemplate : public ZAM_ExprOpTemplate {
public:
    ZAM_UnaryExprOpTemplate(ZAMGen* _g, string _base_name) : ZAM_ExprOpTemplate(_g, _base_name) {}

    bool IncludesFieldOp() const override { return ExprTypes().count(ZAM_TYPE_NONE) == 0; }

    int Arity() const override { return 1; }

protected:
    void Parse(const string& attr, const string& line, const Words& words) override;
    void Instantiate() override;

    void BuildInstruction(const OCVec& oc, const string& params, const string& suffix, ZAM_InstClass zc) override;
};

// A version of ZAM_UnaryExprOpTemplate where the point of the expression
// is to capture a direct assignment operation.
class ZAM_AssignOpTemplate : public ZAM_UnaryExprOpTemplate {
public:
    ZAM_AssignOpTemplate(ZAMGen* _g, string _base_name);

    bool IsAssignOp() const override { return true; }
    bool IncludesFieldOp() const override { return false; }
    bool IsFieldOp() const override { return field_op; }
    void SetFieldOp() { field_op = true; }

protected:
    void Parse(const string& attr, const string& line, const Words& words) override;
    void Instantiate() override;

private:
    bool field_op = false;
};

// A version of ZAM_ExprOpTemplate for binary expressions.
class ZAM_BinaryExprOpTemplate : public ZAM_ExprOpTemplate {
public:
    ZAM_BinaryExprOpTemplate(ZAMGen* _g, string _base_name) : ZAM_ExprOpTemplate(_g, _base_name) {}

    bool IncludesFieldOp() const override { return true; }

    int Arity() const override { return 2; }

protected:
    void Instantiate() override;

    void BuildInstruction(const OCVec& oc, const string& params, const string& suffix, ZAM_InstClass zc) override;

    void GenerateSecondTypeVars(const OCVec& oc, ZAM_InstClass zc);
};

// A version of ZAM_BinaryExprOpTemplate for relationals.
class ZAM_RelationalExprOpTemplate : public ZAM_BinaryExprOpTemplate {
public:
    ZAM_RelationalExprOpTemplate(ZAMGen* _g, string _base_name) : ZAM_BinaryExprOpTemplate(_g, _base_name) {}

    bool IncludesFieldOp() const override { return false; }
    bool IsConditionalOp() const override { return true; }

protected:
    const char* VecEvalRE(bool have_target) const override {
        if ( have_target )
            return "$$$$ = ZVal(zeek_int_t($1))";
        else
            return "ZVal(zeek_int_t($&))";
    }

    void Instantiate() override;

    void BuildInstruction(const OCVec& oc, const string& params, const string& suffix, ZAM_InstClass zc) override;
};

// A version of ZAM_OpTemplate for operations used internally (and not
// corresponding to AST elements).
class ZAM_InternalOpTemplate : public ZAM_OpTemplate {
public:
    ZAM_InternalOpTemplate(ZAMGen* _g, string _base_name) : ZAM_OpTemplate(_g, _base_name) {}

    bool IsInternalOp() const override { return true; }

protected:
    void Parse(const string& attr, const string& line, const Words& words) override;

private:
    void ParseCall(const string& line, const Words& words);

    // True if the internal operation corresponds to an indirect call,
    // i.e., one through a variable rather than one directly specified.
    bool is_indirect_call = false;

    // Refinement of is_indirect_call, when it's also via a local variable.
    bool is_local_indirect_call = false;
};

// An internal operation that assigns a result to a frame element.
class ZAM_InternalAssignOpTemplate : public ZAM_InternalOpTemplate {
public:
    ZAM_InternalAssignOpTemplate(ZAMGen* _g, string _base_name) : ZAM_InternalOpTemplate(_g, _base_name) {}

    bool IsAssignOp() const override { return true; }
};

// Helper classes for managing input from the template file, including
// low-level scanning.

class TemplateInput {
public:
    // Program name and file name are for generating error messages.
    TemplateInput(FILE* _f, const char* _prog_name, const char* _file_name) : f(_f), prog_name(_prog_name) {
        loc.file_name = _file_name;
    }

    const InputLoc& CurrLoc() const { return loc; }

    // Fetch the next line of input, including trailing newline.
    // Returns true on success, false on EOF or error.  Skips over
    // comments.
    bool ScanLine(string& line);

    // Takes a line and splits it into white-space delimited words,
    // returned in a vector.  Removes trailing whitespace.
    Words SplitIntoWords(const string& line) const;

    // Returns the line with the given number of initial words skipped.
    string SkipWords(const string& line, int n) const;

    // Puts back the given line so that the next call to ScanLine will
    // return it.  Does not nest.
    void PutBack(const string& line) { put_back = line; }

    // Report an error and exit.
    [[noreturn]] void Gripe(const char* msg, const string& input) const;
    [[noreturn]] void Gripe(const char* msg, const InputLoc& loc) const;

private:
    string put_back; // if non-empty, use this for the next ScanLine

    FILE* f;
    const char* prog_name;
    InputLoc loc;
};

// Driver class for the ZAM instruction generator.

class ZAMGen {
public:
    ZAMGen(int argc, char** argv);

    // Reads in and records a macro definition, which ends upon
    // encountering a blank line or a line that does not begin
    // with whitespace.
    void ReadMacro(const string& line);

    // Emits C++ #define's to implement the recorded macros.
    void GenMacros();

    // Generates a ZAM op-code for the given template, suffix, and
    // instruction class.  Also creates auxiliary information associated
    // with the instruction.
    string GenOpCode(const ZAM_OpTemplate* op_templ, const string& suffix, ZAM_InstClass zc = ZIC_REGULAR);

    // These methods provide low-level parsing (and error-reporting)
    // access to ZAM_OpTemplate objects.
    const InputLoc& CurrLoc() const { return ti->CurrLoc(); }
    bool ScanLine(string& line) { return ti->ScanLine(line); }
    Words SplitIntoWords(const string& line) const { return ti->SplitIntoWords(line); }
    string SkipWords(const string& line, int n) const { return ti->SkipWords(line, n); }
    void PutBack(const string& line) { ti->PutBack(line); }

    // Methods made public to ZAM_OpTemplate objects for emitting code.
    void Emit(EmitTarget et, const string& s);

    void IndentUp() { ++indent_level; }
    void IndentDown() { --indent_level; }
    void StartString() { string_lit = true; }
    void EndString() { string_lit = false; }
    void SetNoNL(bool _no_NL) { no_NL = _no_NL; }

    [[noreturn]] void Gripe(const char* msg, const string& input) const { ti->Gripe(msg, input); }
    [[noreturn]] void Gripe(const char* msg, const InputLoc& loc) const { ti->Gripe(msg, loc); }

private:
    // Opens all of the code generation targets, and creates prologs
    // for those requiring them (such as for embedding into switch
    // statements).
    void InitEmitTargets();
    void InitSwitch(EmitTarget et, string desc);

    // Closes all of the code generation targets, and creates epilogs
    // for those requiring them.
    void CloseEmitTargets();
    void FinishSwitches();

    // Parses a single template, returning true on success and false
    // if we've reached the end of the input.  (Errors during parsing
    // result instead in exiting.)
    bool ParseTemplate();

    // Maps code generation targets with their corresponding FILE*.
    std::unordered_map<EmitTarget, FILE*> gen_files;

    // Maps code generation targets to strings used to describe any
    // associated switch (for error reporting).
    std::unordered_map<EmitTarget, string> switch_targets;

    // The low-level TemplateInput object used to manage input.
    std::unique_ptr<TemplateInput> ti;

    // Tracks all of the templates created so far.
    vector<std::unique_ptr<ZAM_OpTemplate>> templates;

    // Tracks the macros recorded so far.
    vector<vector<string>> macros;

    // Current indentation level.  Maintained globally rather than
    // per EmitTarget, so the caller needs to ensure it is managed
    // consistently.
    int indent_level = 0;

    // If true, we're generating a string literal.
    bool string_lit = false;

    // If true, refrain from appending a newline to any emitted lines.
    bool no_NL = false;
};
