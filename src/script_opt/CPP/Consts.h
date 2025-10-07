// See the file "COPYING" in the main distribution directory for copyright.

// Methods related to generating code for representing script constants
// as run-time values.  There's only one nontrivial one of these,
// RegisterConstant() (declared above, as it's public).  All the other
// work is done by secondary objects - see InitsInfo.{h,cc} for those.
//
// This file is included by Compile.h to insert into the CPPCompiler class.

public:
// Tracks a Zeek ValPtr used as a constant value.  These occur in two
// contexts: directly as constant expressions, and indirectly as elements
// within aggregate constants (such as in vector initializers).
//
// Returns the associated initialization info.  In addition, consts_offset
// returns an offset into an initialization-time global that tracks all
// constructed globals, providing general access to them for aggregate
// constants. The second form is for when this isn't needed.
std::shared_ptr<CPP_InitInfo> RegisterConstant(const ValPtr& vp, int& consts_offset);
std::shared_ptr<CPP_InitInfo> RegisterConstant(const ValPtr& vp) {
    [[maybe_unused]] int consts_offset; // ignored
    return RegisterConstant(vp, consts_offset);
}

private:
// Maps (non-native) constants to associated C++ globals.
std::unordered_map<const ConstExpr*, std::string> const_exprs;

// Maps the values of (non-native) constants to associated initializer
// information.
std::unordered_map<const Val*, std::shared_ptr<CPP_InitInfo>> const_vals;

// Same, but for the offset into the vector that tracks all constants
// collectively (to support initialization of compound constants).
std::unordered_map<const Val*, int> const_offsets;

// The same as the above pair, but indexed by the string representation
// rather than the Val*.  The reason for having both is to enable
// reusing common constants even though their Val*'s differ.
std::unordered_map<std::string, std::shared_ptr<CPP_InitInfo>> constants;
std::unordered_map<std::string, int> constants_offsets;

// Used for memory management associated with const_vals's index.
std::vector<ValPtr> cv_indices;

// For different types of constants (as indicated by TypeTag),
// provides the associated object that manages the initializers
// for those constants.
std::unordered_map<TypeTag, std::shared_ptr<CPP_InitsInfo>> const_info;

// Tracks entries for constructing the vector of all constants
// (regardless of type).  Each entry provides a TypeTag, used
// to identify the type-specific vector for a given constant,
// and the offset into that vector.
std::vector<std::pair<TypeTag, int>> consts;
