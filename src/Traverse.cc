// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Traverse.h"

#include "zeek/Func.h"
#include "zeek/Scope.h"
#include "zeek/input.h"

#include "zeek/3rdparty/doctest.h"

namespace zeek::detail {

TraversalCode traverse_all(TraversalCallback* cb) {
    if ( ! global_scope() )
        return TC_CONTINUE;


    cb->current_scope = global_scope();

    TraversalCode tc = global_scope()->Traverse(cb);
    HANDLE_TC_STMT_PRE(tc);

    if ( stmts )
        // May be null when parsing fails.
        tc = stmts->Traverse(cb);

    HANDLE_TC_STMT_POST(tc);
}

} // namespace zeek::detail


TEST_SUITE_BEGIN("traverser");

namespace {
// Helper classes for tests below.
using namespace zeek::detail;

class SaveRestoreStmts {
public:
    SaveRestoreStmts() : orig(zeek::detail::stmts) {}
    ~SaveRestoreStmts() { zeek::detail::stmts = orig; }

    Stmt* orig;
};

class ZeekInitFinder : public TraversalCallback {
public:
    TraversalCode PreFunction(const zeek::Func* f) override {
        if ( f->GetName() == "zeek_init" )
            zeek_init_found = true;

        return TC_CONTINUE;
    }

    bool zeek_init_found = false;
};

} // namespace

TEST_CASE("traverse_all") {
    SUBCASE("ensure zeek_init() is found if stmts == nullptr") {
        SaveRestoreStmts save_restore_stmts;
        zeek::detail::stmts = nullptr; // force stmts to be a nullptr
        ZeekInitFinder cb;
        traverse_all(&cb);
        CHECK(cb.zeek_init_found);
    }
}

TEST_SUITE_END();
