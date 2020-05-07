// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>
#include <string>

#include "BroList.h"

extern int yyparse();
extern int yydebug;
extern int brolex();
extern char last_tok[128];

extern void add_essential_input_file(const char* file);
extern void add_input_file(const char* file);
extern void add_input_file_at_front(const char* file);

// Adds the substrings (using the given delimiter) in a string to the
// given namelist.
extern void add_to_name_list(char* s, char delim, name_list& nl);

extern void begin_RE();

extern void do_atif(Expr* expr);
extern void do_atifdef(const char* id);
extern void do_atifndef(const char* id);
extern void do_atelse();
extern void do_atendif();
extern void do_doc_token_start();
extern void do_doc_token_stop();

extern int line_number;
extern const char* filename;

extern int bro_argc;
extern char** bro_argv;
extern const char* prog;

extern std::vector<std::string> zeek_script_prefixes;	// -p flag
extern const char* command_line_policy;	// -e flag
extern std::vector<std::string> params;

FORWARD_DECLARE_NAMESPACED(Stmt, zeek::detail);
extern zeek::detail::Stmt* stmts;	// global statements
