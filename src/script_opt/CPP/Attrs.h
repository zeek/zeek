// See the file "COPYING" in the main distribution directory for copyright.

// Methods for tracking attributes associated with Zeek variables/types.
// Attributes arise mainly in the context of constructing types.
//
// This file is included by Compile.h to insert into the CPPCompiler class.

public:
// Tracks a use of the given set of attributes, including
// initialization dependencies and the generation of any
// associated expressions.
//
// Returns the initialization info associated with the set of attributes.
// Returns nil if the attributes are empty.
std::shared_ptr<CPP_InitInfo> RegisterAttributes(const AttributesPtr& attrs);

// Convenient access to the global offset associated with
// a set of Attributes.
int AttributesOffset(const AttributesPtr& attrs) { return GI_Offset(RegisterAttributes(attrs)); }

// The same, for a single attribute.
std::shared_ptr<CPP_InitInfo> RegisterAttr(const AttrPtr& attr);

// Returns a mapping of from Attr objects to their associated
// initialization information.  The Attr must have previously
// been registered.
auto& ProcessedAttr() const { return processed_attr; }

private:
// Start of methods related to managing script type attributes.
// Attributes arise mainly in the context of constructing types.
// See Attrs.cc for definitions.
//

// Populates the 2nd and 3rd arguments with C++ representations
// of the tags and (optional) values/expressions associated with
// the set of attributes.
void BuildAttrs(const AttributesPtr& attrs, std::string& attr_tags, std::string& attr_vals);

// Returns a string representation of the name associated with
// different attribute tags (e.g., "ATTR_DEFAULT").
static const char* AttrName(AttrTag t);

// Similar for attributes, so we can reconstruct record types.
CPPTracker<Attributes> attributes = {"attrs", false};

// Maps Attributes and Attr's to their global initialization
// information.
std::unordered_map<const Attributes*, std::shared_ptr<CPP_InitInfo>> processed_attrs;
std::unordered_map<const Attr*, std::shared_ptr<CPP_InitInfo>> processed_attr;
