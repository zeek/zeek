// See the file "COPYING" in the main distribution directory for copyright.

// ZAM compiler method declarations for built-in functions.
//
// This file is only included by ZAM.h, in the context of the ZAM class
// declaration (so these are methods, not standalone functions).  We maintain
// it separately so that the conceptual overhead of adding a new built-in
// is lower.

// If the given expression corresponds to a call to a ZAM built-in,
// then compiles the call and returns true.  Otherwise, returns false.
bool IsZAM_BuiltIn(const Expr* e);

// Built-ins return true if able to compile the call, false if not.
bool BuiltIn_Analyzer__name(const NameExpr* n, const ExprPList& args);
bool BuiltIn_Broker__flush_logs(const NameExpr* n, const ExprPList& args);
bool BuiltIn_Files__enable_reassembly(const NameExpr* n, const ExprPList& args);
bool BuiltIn_Files__set_reassembly_buffer(const NameExpr* n, const ExprPList& args);
bool BuiltIn_Log__write(const NameExpr* n, const ExprPList& args);
bool BuiltIn_current_time(const NameExpr* n, const ExprPList& args);
bool BuiltIn_get_port_etc(const NameExpr* n, const ExprPList& args);
bool BuiltIn_network_time(const NameExpr* n, const ExprPList& args);
bool BuiltIn_reading_live_traffic(const NameExpr* n, const ExprPList& args);
bool BuiltIn_reading_traces(const NameExpr* n, const ExprPList& args);
bool BuiltIn_strstr(const NameExpr* n, const ExprPList& args);
bool BuiltIn_sub_bytes(const NameExpr* n, const ExprPList& args);
bool BuiltIn_to_lower(const NameExpr* n, const ExprPList& args);
