// See the file "COPYING" in the main distribution directory for copyright.

#ifndef pac_cclass_h
#define pac_cclass_h

#include <string>
#include <vector>

class CClass;
class CClassMember;
class CClassMethod;
class CType;
class CVariable;

using CClassMemberList = std::vector<CClassMember*>;
using CClassMethodList = std::vector<CClassMethod*>;
using CVariableList = std::vector<CVariable*>;

#include "pac_common.h"

// Represents a C++ class.
//
// For now we adopt a simple model:
//
// 1. All members have a protected member variable "name_" and a
// public constant access method "name()".
//
// 2. All methods are public.
//
// 3. We do not check repeated names.

class CClass {
public:
    CClass(const string& class_name);

    void AddMember(CClassMember* member);
    void AddMethod(CClassMember* method);

    void GenForwardDeclaration(Output* out_h);
    void GenCode(Output* out_h, Output* out_cc);

protected:
    string class_name_;
    CClassMemberList* members_;
    CClassMethodList* methods_;
};

class CVariable {
public:
    CVariable(const std::string& name, CType* type);

    string name() const { return name_; }
    CType* type() const { return type_; }

protected:
    string name_;
    CType* type_;
};

class CClassMember {
public:
    CClassMember(CVariable* var);
    void GenCode(Output* out_h, Output* out_cc);

    string decl() const;

protected:
    CVariable* var_;
};

class CClassMethod {
public:
    CClassMethod(CVariable* var, CVariableList* params);

    string decl() const;

protected:
    CVariable* var_;
    CVariableList* params_;
};

#endif // pac_cclass_h
