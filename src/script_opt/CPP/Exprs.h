// See the file "COPYING" in the main distribution directory for copyright.

// Methods for generating code corresponding with Zeek expression AST nodes
// (Expr objects).
//
// This file is included by Compile.h to insert into the CPPCompiler class.

// These methods are all oriented around returning strings of C++ code;
// they do not directly emit the code, since often the caller will be embedding
// the result in some surrounding context.  No effort is made to reduce string
// copying; this isn't worth the hassle, as it takes just a few seconds for
// the compiler to generate 100K+ LOC that clang will then need 10s of seconds
// to compile, so speeding up the compiler has little practical advantage.

// The following enum's represent whether, for expressions yielding native
// values, the end goal is to have the value in (1) native form, (2) instead
// in ValPtr form, or (3) whichever is more convenient to generate (sometimes
// used when the caller knows that the value is non-native).

#include <cstdint>

enum GenType : uint8_t {
    GEN_NATIVE,
    GEN_VAL_PTR,
    GEN_DONT_CARE,
};

// Generate an expression for which we want the result embedded in {}
// initializers (generally to be used in calling a function where we want
// those values to be translated to a vector<ValPtr>).
std::string GenExprs(const Expr* e);

// Generate the value(s) associated with a ListExpr.  If true, the "nested"
// parameter indicates that this list is embedded within an outer list, in
// which case it's expanded to include {}'s.  It's false if the ListExpr is
// at the top level, such as when expanding the arguments in a CallExpr.
std::string GenListExpr(const Expr* e, GenType gt, bool nested);

// Per-Expr-subclass code generation.  The resulting code generally reflects
// the corresponding Eval() or Fold() methods.
std::string GenExpr(const ExprPtr& e, GenType gt, bool top_level = false) { return GenExpr(e.get(), gt, top_level); }
std::string GenExpr(const Expr* e, GenType gt, bool top_level = false);

std::string GenNameExpr(const NameExpr* ne, GenType gt);
std::string GenConstExpr(const ConstExpr* c, GenType gt);
std::string GenAggrAdd(const Expr* e);
std::string GenAggrDel(const Expr* e);
std::string GenIncrExpr(const Expr* e, GenType gt, bool is_incr, bool top_level);
std::string GenCondExpr(const Expr* e, GenType gt);
std::string GenCallExpr(const CallExpr* c, GenType gt, bool top_level);
std::string GenInExpr(const Expr* e, GenType gt);
std::string GenFieldExpr(const FieldExpr* fe, GenType gt);
std::string GenHasFieldExpr(const HasFieldExpr* hfe, GenType gt);
std::string GenIndexExpr(const Expr* e, GenType gt);
std::string GenAssignExpr(const Expr* e, GenType gt, bool top_level);
std::string GenAddToExpr(const Expr* e, GenType gt, bool top_level);
std::string GenRemoveFromExpr(const Expr* e, GenType gt, bool top_level);
std::string GenSizeExpr(const Expr* e, GenType gt);
std::string GenScheduleExpr(const Expr* e);
std::string GenLambdaExpr(const Expr* e);
std::string GenLambdaExpr(const Expr* e, std::string capture_args);
std::string GenIsExpr(const Expr* e, GenType gt);

std::string GenArithCoerceExpr(const Expr* e, GenType gt);
std::string GenRecordCoerceExpr(const Expr* e);
std::string GenTableCoerceExpr(const Expr* e);
std::string GenVectorCoerceExpr(const Expr* e);

std::string GenRecordConstructorExpr(const Expr* e);
std::string GenSetConstructorExpr(const Expr* e);
std::string GenTableConstructorExpr(const Expr* e);
std::string GenVectorConstructorExpr(const Expr* e);

// Generate code for constants that can be expressed directly as C++ constants.
std::string GenVal(const ValPtr& v);

// Helper functions for particular Expr subclasses / flavors.
std::string GenUnary(const Expr* e, GenType gt, const char* op, const char* vec_op = nullptr);
std::string GenBinary(const Expr* e, GenType gt, const char* op, const char* vec_op = nullptr);
std::string GenBinarySet(const Expr* e, GenType gt, const char* op);
std::string GenBinaryString(const Expr* e, GenType gt, const char* op);
std::string GenBinaryPattern(const Expr* e, GenType gt, const char* op);
std::string GenBinaryAddr(const Expr* e, GenType gt, const char* op);
std::string GenBinarySubNet(const Expr* e, GenType gt, const char* op);
std::string GenEQ(const Expr* e, GenType gt, const char* op, const char* vec_op);

std::string GenAssign(const ExprPtr& lhs, const ExprPtr& rhs, const std::string& rhs_native,
                      const std::string& rhs_val_ptr, GenType gt, bool top_level);
std::string GenDirectAssign(const ExprPtr& lhs, const std::string& rhs_native, const std::string& rhs_val_ptr,
                            GenType gt, bool top_level);
std::string GenIndexAssign(const ExprPtr& lhs, const ExprPtr& rhs, const std::string& rhs_val_ptr, GenType gt,
                           bool top_level);
std::string GenFieldAssign(const ExprPtr& lhs, const ExprPtr& rhs, const std::string& rhs_native,
                           const std::string& rhs_val_ptr, GenType gt, bool top_level);
std::string GenListAssign(const ExprPtr& lhs, const ExprPtr& rhs);

// Support for element-by-element vector operations.
std::string GenVectorOp(const Expr* e, std::string op, const char* vec_op);
std::string GenVectorOp(const Expr* e, std::string op1, std::string op2, const char* vec_op);

// If "all_deep" is true, it means make all of the captures deep copies,
// not just the ones that were explicitly marked as deep copies.  That
// functionality is used to support Clone() methods; it's not needed when
// creating a new lambda instance.
std::string GenLambdaClone(const LambdaExpr* l, bool all_deep);

// Returns an initializer list for a vector of integers.
std::string GenIntVector(const std::vector<int>& vec);

// The following are used to generate accesses to elements of extensible
// types.  They first check whether the type has been extended (for records,
// beyond the field of interest); if not, then the access is done directly.
// If the access is however to an extended element, then they indirect the
// access through a map that is generated dynamically when the compiled code.
// Doing so allows the compiled code to work in contexts where other extensions
// occur that would otherwise conflict with hardwired offsets/values.
std::string GenField(const ExprPtr& rec, int field);
std::string GenEnum(const TypePtr& et, const ValPtr& ev);

// Creates all the initializations needed to evaluate the given expression.
// Returns the maximum cohort associated with these.
friend class GlobalInitInfo;
int ReadyExpr(const ExprPtr& e);

// Creates all the initializations needed for the given profile.
int ReadyProfile(std::shared_ptr<ProfileFunc> pf);

// Tracks which globals we've readied and their associated init cohort.
std::unordered_map<IDPtr, int> readied_globals;

// For record that are extended via redef's, maps fields beyond the original
// definition to locations in the global (in the compiled code) "field_mapping"
// array.
//
// So for each such record, there's a second map of field-in-the-record to
// offset-in-field_mapping.
std::unordered_map<const RecordType*, std::unordered_map<int, int>> record_field_mappings;

// Total number of such mappings (i.e., entries in the inner maps, not the
// outer map).
int num_rf_mappings = 0;

// For each entry in "field_mapping", the record (as a global offset) and
// TypeDecl associated with the mapping.
std::vector<std::pair<int, const TypeDecl*>> field_decls;

// For enums that are extended via redef's, maps each distinct value (that
// the compiled scripts refer to) to locations in the global (in the compiled
// code) "enum_mapping" array.
//
// So for each such enum, there's a second map of value-during-compilation to
// offset-in-enum_mapping.
std::unordered_map<const EnumType*, std::unordered_map<int, int>> enum_val_mappings;

// Total number of such mappings (i.e., entries in the inner maps, not the
// outer map).
int num_ev_mappings = 0;

// Information captured for generating entries in "enum_mapping".
struct EnumMappingInfo {
    int enum_type; // as a global offset
    std::string enum_name;
    bool create_if_missing;
};

// For each entry in "enum_mapping", the EnumType (as a global offset) and
// name associated with the mapping.
std::vector<EnumMappingInfo> enum_names;
