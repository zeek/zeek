#include "zeek/ScriptValidation.h"

#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"

namespace zeek::detail
	{

// Validate context of break and next statement usage.
class BreakNextScriptValidation : public TraversalCallback
	{
public:
	BreakNextScriptValidation(bool _report) : report(_report) { }

	TraversalCode PreStmt(const Stmt* stmt)
		{
		if ( ! StmtIsRelevant(stmt) )
			return TC_CONTINUE;

		stmt_depths[stmt->Tag()] += 1;

		if ( stmt->Tag() == STMT_BREAK && ! BreakStmtIsValid() )
			Report(stmt, "break statement used outside of for, while or "
			             "switch statement and not within a hook. "
			             "With v6.1 this will become an error.");

		if ( stmt->Tag() == STMT_NEXT && ! NextStmtIsValid() )
			Report(stmt, "next statement used outside of for or while statement. "
			             "With v6.1 this will become an error.");

		return TC_CONTINUE;
		}

	TraversalCode PostStmt(const Stmt* stmt)
		{
		if ( ! StmtIsRelevant(stmt) )
			return TC_CONTINUE;

		--stmt_depths[stmt->Tag()];

		assert(stmt_depths[stmt->Tag()] >= 0);

		return TC_CONTINUE;
		}

	TraversalCode PreFunction(const zeek::Func* func)
		{
		if ( func->Flavor() == zeek::FUNC_FLAVOR_HOOK )
			++hook_depth;

		assert(hook_depth <= 1);

		return TC_CONTINUE;
		}

	TraversalCode PostFunction(const zeek::Func* func)
		{
		if ( func->Flavor() == zeek::FUNC_FLAVOR_HOOK )
			--hook_depth;

		assert(hook_depth >= 0);

		return TC_CONTINUE;
		}

	bool IsValid() const { return valid_script; }

private:
	bool StmtIsRelevant(const Stmt* stmt)
		{
		StmtTag tag = stmt->Tag();
		return tag == STMT_FOR || tag == STMT_WHILE || tag == STMT_SWITCH || tag == STMT_BREAK ||
		       tag == STMT_NEXT;
		}

	bool BreakStmtIsValid()
		{
		return hook_depth > 0 || stmt_depths[STMT_FOR] > 0 || stmt_depths[STMT_WHILE] > 0 ||
		       stmt_depths[STMT_SWITCH] > 0;
		}

	bool NextStmtIsValid() { return stmt_depths[STMT_FOR] > 0 || stmt_depths[STMT_WHILE] > 0; }

	void Report(const Stmt* stmt, const char* msg)
		{
		if ( report )
			{
			zeek::reporter->PushLocation(stmt->GetLocationInfo());
			zeek::reporter->Warning("%s", msg);
			zeek::reporter->PopLocation();
			}

		valid_script = false;
		}

	std::unordered_map<StmtTag, int> stmt_depths;
	int hook_depth = 0;
	bool report; // whether to report problems via "reporter"
	bool valid_script = true;
	};

void script_validation()
	{
	BreakNextScriptValidation bn_cb(true);
	traverse_all(&bn_cb);
	}

bool script_is_valid(const Stmt* stmt)
	{
	BreakNextScriptValidation bn_cb(false);
	stmt->Traverse(&bn_cb);
	return bn_cb.IsValid();
	}

	}
