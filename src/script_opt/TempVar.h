// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// Reducer helper class for managing temporary variables created during
// statement reduction for compilation.

#include <string>

#include "zeek/Expr.h"
#include "zeek/ID.h"
#include "zeek/script_opt/IDOptInfo.h"

namespace zeek::detail {

class TempVar {
public:
    TempVar(size_t num, ExprPtr rhs);

    const char* Name() const { return name.data(); }
    const Expr* RHS() const { return rhs.get(); }

    IDPtr Id() const { return id; }
    void SetID(IDPtr _id) {
        id = std::move(_id);
        id->GetOptInfo()->SetTemp();
    }
    void Deactivate() { active = false; }
    bool IsActive() const { return active; }

    // Associated constant expression, if any.
    const ConstExpr* Const() const { return id->GetOptInfo()->Const(); }

    // The most use of "const" in any single line in the Zeek
    // codebase :-P ... though only by one!
    void SetConst(const ConstExpr* _const) { id->GetOptInfo()->SetConst(_const); }

    IDPtr Alias() const { return alias; }
    void SetAlias(IDPtr id);

protected:
    std::string name;
    IDPtr id;
    ExprPtr rhs;
    bool active = true;
    IDPtr alias;
};

} // namespace zeek::detail
