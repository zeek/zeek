// See the file "COPYING" in the main distribution directory for copyright.

// Methods for dealing with Zeek script types.
//
// This file is included by Compile.h to insert into the CPPCompiler class.

public:
// Tracks the given type (with support methods for ones that are complicated),
// recursively including its sub-types, and creating initializations for
// constructing C++ variables representing the types.
//
// Returns the initialization info associated with the type.
std::shared_ptr<CPP_InitInfo> RegisterType(const TypePtr& t);

private:
// "Native" types are those Zeek scripting types that we support using
// low-level C++ types (like "zeek_uint_t" for "count").  Types that we
// instead support using some form of ValPtr representation are "non-native".
bool IsNativeType(const TypePtr& t) const;

// Given an expression corresponding to a native type (and with the given
// script type 't'), converts it to the given GenType.
std::string NativeToGT(const std::string& expr, const TypePtr& t, GenType gt);

// Given an expression with a C++ type of generic "ValPtr", of the given script
// type 't', converts it as needed to the given GenType.
std::string GenericValPtrToGT(const std::string& expr, const TypePtr& t, GenType gt);

// Returns the name of a C++ variable that will hold a TypePtr of the
// appropriate flavor. 't' does not need to be a type representative.
std::string GenTypeName(const Type* t);
std::string GenTypeName(const TypePtr& t) { return GenTypeName(t.get()); }

// Returns the "representative" for a given type, used to ensure that we
// re-use the C++ variable corresponding to a type and don't instantiate
// redundant instances.
const Type* TypeRep(const Type* t) { return pfs->TypeRep(t); }
const Type* TypeRep(const TypePtr& t) { return TypeRep(t.get()); }

// Low-level C++ representations for types, of various flavors.
static const char* TypeTagName(TypeTag tag);
const char* TypeName(const TypePtr& t);
const char* FullTypeName(const TypePtr& t);
const char* TypeType(const TypePtr& t);

// Access to a type's underlying values.
const char* NativeAccessor(const TypePtr& t);

// The name for a type that should be used in declaring an IntrusivePtr to
// such a type.
const char* IntrusiveVal(const TypePtr& t);

// Maps types to indices in the global "CPP__Type__" array.
CPPTracker<Type> types = {"types", true};

// Used to prevent analysis of mutually-referring types from leading to
// infinite recursion.  Maps types to their global initialization information
// (or, initially, to nullptr, if they're in the process of being registered).
std::unordered_map<const Type*, std::shared_ptr<CPP_InitInfo>> processed_types;
