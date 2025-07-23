// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Most of these headers are needed for the block of #includes later
#include "zeek/Desc.h"
#include "zeek/script_opt/CPP/Func.h"
#include "zeek/script_opt/CPP/InitsInfo.h"
#include "zeek/script_opt/CPP/Tracker.h"
#include "zeek/script_opt/CPP/Util.h"
#include "zeek/script_opt/ScriptOpt.h"

// We structure the compiler for generating C++ versions of Zeek script
// bodies mainly as a single large class.  While we divide the compiler's
// functionality into a number of groups (see below), these interact with
// one another, and in particular with various member variables, enough
// so that it's not clear there's benefit to further splitting the
// functionality into multiple classes.  (Some splitting has already been done
// for more self-contained functionality, resulting in the CPPTracker class
// and initialization information in InitsInfo.{h,cc} and RuntimeInits.{h,cc}.)
//
// Most aspects of translating to C++ have a straightforward nature.
// We can turn many Zeek script statements directly into the C++ that's
// used by the interpreter for the corresponding Exec()/DoExec() methods.
// This often holds for Zeek expressions, too, though some of them require
// considerations (e.g., error handling) that require introducing helper
// functions to maintain the property that a Zeek script expression translates
// to a C++ expression.  That property (i.e., not needing to turn Zeek
// expressions into multiple C++ statements) simplifies code generation
// considerably.  It also means that the compiler should *not* run on
// transformed ASTs such as produced by the Reducer class.  We instead
// seek to let the C++ compiler (meaning clang or g++, for example)
// find optimization opportunities, including inlining.
//
// For some Zeek scripting types, we use their natural C++ counterparts,
// such as "zeek_uint_t" for "count" values.  In the source code these
// are referred to as "native" types.  Other types, like tables, keep
// their interpreter-equivalent type (e.g., TableVal).  These are dealt
// with almost entirely using IntrusivePtr's.  The few exceptions (i.e.,
// direct uses of "new") are in contexts where the memory management
// is clearly already addressed.
//
// The user specifies generation of C++ using "-O gen-C++", which produces
// C++ code for all of the loaded functions/hooks/event handlers.  Thus,
// for example, "zeek -b -O gen-C++ foo.zeek" will generate C++ code for
// all of the scripts loaded in "bare" mode, plus those for foo.zeek; and
// without the "-b" for all of the default scripts plus those in foo.zeek.
//
// "-O report-C++" reports on which compiled functions will/won't be used
// (including ones that are available but not relevant to the scripts loaded
// on the command line).  This can be useful when debugging to make sure
// that you're indeed running compiled code when you expect to be.
//
// We partition the methods of the compiler into a number of groups,
// the definitions of each having their own source file:
//
//	Driver		Drives the overall compilation process.
//
//	Vars		Management of C++ variables relating to local/global
//			script variables.
//
//	DeclFunc	Generating declarations of C++ subclasses and
//			functions.
//
//	GenFunc		Generating the bodies of script functions.
//
//	Consts		Dealing with Zeek script constants.  Depending
//			on their type, these are represented either
//			directly in C++, or using C++ variables that
//			are constructed at run-time.
//
//	Stmts		Generating code for Zeek statements.
//
//	Exprs		Generating code for Zeek expressions.
//
//	Types		Management of (1) C++ types used in generated code,
//			and (2) C++ variables that hold Zeek script types,
//			generated at run-time.
//
//	Attrs		Management of Zeek type attributes, some of which
//			must be generated at run-time.
//
//	Inits		Management of initializing the run-time
//			variables needed by the compiled code.
//
//	Emit		Low-level code generation.
//
// Of these, Inits is the most subtle and complex.  There are two major
// challenges in creating run-time values (such as Zeek types and constants).
//
// First, generating individual code for creating each of these winds up
// incurring unacceptable compile times (for example, clang compiling all
// of the base scripts with optimization takes many hours on a high-end
// laptop).  As a result, we employ a table-driven approach that compiles
// much faster (though still taking many minutes on the same high-end laptop,
// running about 40x faster however).
//
// Second, initializations frequently rely upon *other* initializations
// having occurred first.  For example, a global might need a record type
// to be defined; one of the record's fields is a table; that table contains
// another record; one of that other record's fields is the original record
// (recursion); another field has an &default expression that requires the
// compiler to generate a helper function to construct the expression
// dynamically; and that helper function might in turn refer to other types
// that require initialization.  What's required is a framework for ensuring
// that everything occurs in the proper order.
//
// The logic for dealing with these complexities is isolated into several
// sets of classes.  InitsInfo.{h,cc} provides the classes related to tracking
// how to generate initializations in the proper order.  RuntimeInits.{h,cc}
// provides the classes used when initialization generated code in order
// to instantiate all of the necessary values.  See those files for discussions
// on how they address the points framed above.
//
// In declaring the CPPCompiler class, we group methods in accordance with
// those listed above, locating member variables with the group most relevant
// for their usage.  However, keep in mind that many member variables are
// used by multiple groups, which is why we haven't created distinct
// per-group classes.  In addition, we make a number of methods public
// in order to avoid the need for numerous "friend" declarations to allow
// associated classes (like those for initialization) access to a the
// necessary compiler methods.

namespace zeek::detail {

class CPPCompile {
public:
    // Constructing a CPPCompile object does all of the compilation.
    CPPCompile(std::vector<FuncInfo>& _funcs, std::shared_ptr<ProfileFuncs> pfs, const std::string& gen_name,
               bool _standalone, bool report_uncompilable);
    ~CPPCompile();

    // Returns the hash associated with a given function body. It's a fatal
    // error to call this for a body that hasn't been compiled.
    p_hash_type BodyHash(const Stmt* body);

    // Returns true if at least one of the function bodies associated with
    // the function/hook/event handler of the given fname is not compilable.
    bool NotFullyCompilable(const std::string& fname) const { return not_fully_compilable.contains(fname); }

private:
#include "zeek/script_opt/CPP/Attrs.h"
#include "zeek/script_opt/CPP/Consts.h"
#include "zeek/script_opt/CPP/DeclFunc.h"
#include "zeek/script_opt/CPP/Driver.h"
#include "zeek/script_opt/CPP/Emit.h"
#include "zeek/script_opt/CPP/Exprs.h"
#include "zeek/script_opt/CPP/GenFunc.h"
#include "zeek/script_opt/CPP/Inits.h"
#include "zeek/script_opt/CPP/Stmts.h"
#include "zeek/script_opt/CPP/Types.h"
#include "zeek/script_opt/CPP/Vars.h"

    // Returns the object used to track indices (vectors of integers that
    // are used to index various other vectors, including other indices).
    // Only used by CPP_InitsInfo objects, but stored in the CPPCompile object
    // to make it available across different CPP_InitsInfo objects.

    friend class CPP_InitsInfo;
    IndicesManager& IndMgr() { return indices_mgr; }

    IndicesManager indices_mgr;

    // The following objects track initialization information for different
    // types of initializers: Zeek types, individual attributes, sets of
    // attributes, expressions that call script functions (for attribute
    // expressions), registering lambda bodies, and registering Zeek globals.

    std::shared_ptr<CPP_InitsInfo> type_info;
    std::shared_ptr<CPP_InitsInfo> attr_info;
    std::shared_ptr<CPP_InitsInfo> attrs_info;
    std::shared_ptr<CPP_InitsInfo> call_exprs_info;
    std::shared_ptr<CPP_InitsInfo> lambda_reg_info;
    std::shared_ptr<CPP_InitsInfo> global_id_info;

    // Tracks all of the above objects (as well as each entry in const_info),
    // to facilitate easy iterating over them.
    std::set<std::shared_ptr<CPP_InitsInfo>> all_global_info;

    // Tracks the attribute expressions for which we need to generate function
    // calls to evaluate them.
    std::unordered_map<std::string, std::shared_ptr<CallExprInitInfo>> init_infos;
};

} // namespace zeek::detail
