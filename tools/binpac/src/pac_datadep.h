// See the file "COPYING" in the main distribution directory for copyright.

#ifndef pac_datadep_h
#define pac_datadep_h

#include <cstdint>

// To provide a way to traverse through the data dependency graph.
// That is, to evaluate X, what must be evaluated.

#include "pac_common.h"

class DataDepVisitor;

class DataDepElement {
public:
    enum DDE_Type : uint8_t {
        ATTR,
        CASEEXPR,
        EXPR,
        FIELD,
        INPUT_BUFFER,
        PARAM,
        TYPE,
    };

    DataDepElement(DDE_Type type);
    virtual ~DataDepElement() {}

    // Returns whether to continue traversal
    bool Traverse(DataDepVisitor* visitor);

    // Returns whether to continue traversal
    virtual bool DoTraverse(DataDepVisitor* visitor) = 0;

    DDE_Type dde_type() const { return dde_type_; }
    Expr* expr();
    Type* type();

protected:
    DDE_Type dde_type_;
    bool in_traversal = false;
};

class DataDepVisitor {
public:
    virtual ~DataDepVisitor() {}
    // Returns whether to continue traversal
    virtual bool PreProcess(DataDepElement* element) = 0;
    virtual bool PostProcess(DataDepElement* element) = 0;
};

class RequiresAnalyzerContext : public DataDepVisitor {
public:
    // Returns whether to continue traversal
    bool PreProcess(DataDepElement* element) override;
    bool PostProcess(DataDepElement* element) override;

    bool requires_analyzer_context() const { return requires_analyzer_context_; }

    static bool compute(DataDepElement* element);

protected:
    void ProcessExpr(Expr* expr);

    bool requires_analyzer_context_ = false;
};

#endif // pac_datadep_h
