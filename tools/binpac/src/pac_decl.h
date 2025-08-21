// See the file "COPYING" in the main distribution directory for copyright.

#ifndef pac_decl_h
#define pac_decl_h

#include <cstdint>

#include "pac_common.h"
#include "pac_id.h"

class Decl : public Object {
public:
    // Note: ANALYZER is not for AnalyzerDecl (which is an
    // abstract class) , but for AnalyzerContextDecl.
    enum DeclType : uint8_t { ENUM, LET, TYPE, FUNC, CONN, FLOW, ANALYZER, HELPER, REGEX };

    Decl(ID* id, DeclType decl_type);
    virtual ~Decl();

    const ID* id() const { return id_; }
    DeclType decl_type() const { return decl_type_; }
    AnalyzerContextDecl* analyzer_context() const { return analyzer_context_; }

    // NULL except for TypeDecl or AnalyzerDecl
    virtual Env* env() const { return nullptr; }

    virtual void Prepare() = 0;

    // Generate declarations out of the "binpac" namespace
    virtual void GenExternDeclaration(Output* out_h) { /* do nothing */ }

    // Generate declarations before definition of classes
    virtual void GenForwardDeclaration(Output* out_h) = 0;

    virtual void GenCode(Output* out_h, Output* out_cc) = 0;

    void TakeExprList();
    void AddAttrs(AttrList* attrlist);
    void SetAnalyzerContext();

protected:
    virtual void ProcessAttr(Attr* a);

    ID* id_;
    DeclType decl_type_;
    AttrList* attrlist_ = nullptr;
    AnalyzerContextDecl* analyzer_context_ = nullptr;

public:
    static void ProcessDecls(Output* out_h, Output* out_cc);
    static Decl* LookUpDecl(const ID* id);

private:
    static DeclList* decl_list_;
    using DeclMap = map<const ID*, Decl*, ID_ptr_cmp>;
    static DeclMap decl_map_;
};

class HelperDecl : public Decl {
public:
    enum HelperType : uint8_t {
        HEADER,
        CODE,
        EXTERN,
    };
    HelperDecl(HelperType type, ID* context_id, EmbeddedCode* code);
    ~HelperDecl() override;

    void Prepare() override;
    void GenExternDeclaration(Output* out_h) override;
    void GenForwardDeclaration(Output* out_h) override { /* do nothing */ }
    void GenCode(Output* out_h, Output* out_cc) override;

private:
    HelperType helper_type_;
    ID* context_id_;
    EmbeddedCode* code_;

    static int helper_id_seq;
};

#endif // pac_decl_h
