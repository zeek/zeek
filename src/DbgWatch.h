// See the file "COPYING" in the main distribution directory for copyright.

// Structures and methods for implementing watches in the Zeek debugger.

#pragma once

namespace zeek {
class Obj;
}

namespace zeek::detail {

class Expr;

class DbgWatch {
public:
    explicit DbgWatch(Obj* var_to_watch);
    explicit DbgWatch(Expr* expr_to_watch);
    ~DbgWatch() = default;

protected:
    Obj* var;
    Expr* expr;
};

} // namespace zeek::detail
