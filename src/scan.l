%top{
// Include stdint.h at the start of the generated file. Typically
// MSVC will include this header later, after the definitions of
// the integral type macros. MSVC then complains that about the
// redefinition of the types. Including stdint.h early avoids this.
#include <stdint.h>
}

%{
// See the file "COPYING" in the main distribution directory for copyright.

#include <cerrno>
#include <climits>
#include <cstdlib>

#include <stack>
#include <list>
#include <string>
#include <algorithm>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <libgen.h>

#include "zeek/input.h"
#include "zeek/util.h"
#include "zeek/Scope.h"
#include "zeek/ZeekString.h"
#include "zeek/DNS_Mgr.h"
#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/Stmt.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Val.h"
#include "zeek/Var.h"
#include "zeek/Debug.h"
#include "zeek/PolicyFile.h"
#include "zeek/Reporter.h"
#include "zeek/RE.h"
#include "zeek/RunState.h"
#include "zeek/Traverse.h"
#include "zeek/module_util.h"
#include "zeek/ScannedFile.h"

#include "zeek/analyzer/Analyzer.h"
#include "zeek/zeekygen/Manager.h"

#include "zeek/plugin/Manager.h"

#include "zeekparse.h"

using namespace zeek::detail;

extern YYLTYPE yylloc;	// holds start line and column of token
extern zeek::EnumType* cur_enum_type;

// Track the @if... depth.
static std::intptr_t conditional_depth = 0;

zeek::detail::int_list entry_cond_depth; // @if depth upon starting file
zeek::detail::int_list entry_pragma_stack_depth; // @pragma push depth upon starting file
static std::vector<std::string> pragma_stack; // stack of @pragma pushes

// Tracks how many conditionals there have been.  This value only
// increases.  Its value is to support logic such as figuring out
// whether a function body has a conditional within it by comparing
// the epoch at the beginning of parsing the body with that at the end.
int conditional_epoch = 0;

// Whether the current file has included conditionals (so far).
bool current_file_has_conditionals = false;

// The files that include conditionals.  Used when compiling scripts to C++
// to flag issues for --optimize-files=/pat/ where one of the files includes
// conditional code.
std::unordered_set<std::string> files_with_conditionals;

zeek::detail::int_list if_stack;

// Whether we're parsing a "when" conditional, for which we treat
// the "local" keyword differently.
int in_when_cond = 0;

int line_number = 1;
const char* filename = 0; // Absolute path of file currently being parsed.
const char* last_filename = 0; // Absolute path of last file parsed.
static const char* last_id_tok = 0;

const char* last_tok_filename = 0;
const char* last_last_tok_filename = 0;
char last_tok[128];

extern std::set<std::string> module_names;

#define YY_USER_ACTION	strncpy(last_tok, yytext, sizeof(last_tok) - 1); \
                        last_last_tok_filename = last_tok_filename; \
                        last_tok_filename = ::filename;
#define YY_USER_INIT	last_tok[0] = '\0';

// We define our own YY_INPUT because we want to trap the case where
// a read fails.
#define YY_INPUT(buf,result,max_size) \
	if ( ((result = fread(buf, 1, max_size, yyin)) == 0) && ferror(yyin) ) \
		zeek::reporter->Error("read failed with \"%s\"", strerror(errno));

static std::string find_relative_file(const std::string& filename, const std::string& ext)
	{
	if ( filename.empty() )
		return std::string();

	if ( filename[0] == '.' )
		return zeek::util::find_file(filename, zeek::util::SafeDirname(::filename).result, ext);
	else
		return zeek::util::find_file(filename, zeek::util::zeek_path(), ext);
	}

static std::string find_relative_script_file(const std::string& filename)
	{
	if ( filename.empty() )
		return std::string();

	if ( filename[0] == '.' )
		return zeek::util::find_script_file(filename, zeek::util::SafeDirname(::filename).result);
	else
		return zeek::util::find_script_file(filename, zeek::util::zeek_path());
	}

static void start_conditional()
	{
	++conditional_depth;
	++conditional_epoch;

	if ( ! current_file_has_conditionals )
		// First time we've observed that this file includes conditionals.
		files_with_conditionals.insert(::filename);

	current_file_has_conditionals = true;
	}

static void do_pragma(const std::string& pragma)
	{
	static std::unordered_set <std::string> known_stack_pragmas = {
		"ignore-deprecations",
	};

	auto parts = zeek::util::split(pragma, " ");
	auto new_end = std::remove(parts.begin(), parts.end(), "");
	parts.erase(new_end, parts.end());

	if ( parts.empty() )
		{
		zeek::reporter->FatalError("@pragma without value");
		return;
		}

	if ( parts[0] == "push" )
		{
			if ( parts.size() < 2 )
				{
				zeek::reporter->FatalError("@pragma push without value");
				return;
				}

			if ( known_stack_pragmas.count(parts[1]) == 0 )
				zeek::reporter->Warning("pushing unknown @pragma value '%s'", parts[1].c_str());

			pragma_stack.push_back(parts[1]);
		}
	else if ( parts[0] == "pop" )
		{
		if ( pragma_stack.empty() || pragma_stack.size() == entry_pragma_stack_depth.back() )
			{
			zeek::reporter->FatalError("@pragma pop without active pragma");
			return;
			}

		// Popping with a value: Verify it's popping the right thing. Not providing
		// a pop value itself is valid. Don't return, probably blows up below anyway.
		if ( parts.size() > 1 && pragma_stack.back() != parts[1] ) {
			zeek::reporter->Error("@pragma pop with unexpected '%s', expected '%s'",
			                      parts[1].c_str(), pragma_stack.back().c_str());
		}

		// Just pop anything
		pragma_stack.pop_back();
		}
	else
		{
		zeek::reporter->Warning("Ignoring unknown pragma: '%s'", pragma.c_str());
		}

	// Cheap: Just walk the pragma_stack now to see if we should ignore deprecations.
	bool ignore_deprecations = std::any_of(pragma_stack.cbegin(), pragma_stack.cend(),
	                                       [](const auto& s) { return s == "ignore-deprecations"; });
	zeek::reporter->SetIgnoreDeprecations(ignore_deprecations);
	}


class FileInfo {
public:
	FileInfo(std::string restore_module = "");
	~FileInfo();

	YY_BUFFER_STATE buffer_state;
	std::string restore_module;
	const char* name = nullptr;
	int line = 0;
	int level = 0;
};

// A stack of input buffers we're scanning.  file_stack[len-1] is the
// top of the stack.
static zeek::PList<FileInfo> file_stack;

#define RET_CONST(v) \
	{ \
	yylval.val = v; \
	return TOK_CONSTANT; \
	}

// Returns true if the file is new, false if it's already been scanned.
static int load_files(const char* file);

// ### TODO: columns too - use yyless with '.' action?
%}

%option nounput nodefault

%x RE
%x IGNORE

OWS	[ \t]*
WS	[ \t]+
D	[0-9]+
HEX	[0-9a-fA-F]+
IDCOMPONENT [A-Za-z_][A-Za-z_0-9]*
ID	{IDCOMPONENT}(::{IDCOMPONENT})*
IP6 ("["({HEX}:){7}{HEX}"]")|("["0x{HEX}({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}:){6}({D}"."){3}{D}"]")|("["({HEX}|:)*"::"({HEX}|:)*({D}"."){3}{D}"]")
FILE	[^ \t\r\n]+
PREFIX	[^ \t\r\n]+
FLOAT	(({D}*"."?{D})|({D}"."?{D}*))([eE][-+]?{D})?
H	[A-Za-z0-9][A-Za-z0-9\-]*
HTLD	[A-Za-z][A-Za-z0-9\-]*
ESCSEQ	(\\([^\r\n]|[0-7]+|x[[:xdigit:]]+))

%%

##!.* {
	if ( zeek::detail::current_scope() == zeek::detail::global_scope() )
		zeek::detail::zeekygen_mgr->SummaryComment(::filename, yytext + 3);
	}

##<.* {
	if ( zeek::detail::current_scope() == zeek::detail::global_scope() )
		{
		std::string hint(cur_enum_type && last_id_tok ?
		            zeek::detail::make_full_var_name(zeek::detail::current_module.c_str(), last_id_tok) : "");

		zeek::detail::zeekygen_mgr->PostComment(yytext + 3, hint);
		}
}

##.* {
	if ( zeek::detail::current_scope() == zeek::detail::global_scope() )
		if ( yytext[2] != '#' )
			zeek::detail::zeekygen_mgr->PreComment(yytext + 2);
}

#{OWS}@no-test.* return TOK_NO_TEST;

#.*	/* eat comments */

{WS}	/* eat whitespace */

<INITIAL,IGNORE>\r?\n	{
			++line_number;
			++yylloc.first_line;
			++yylloc.last_line;
			}

	/* IPv6 literal constant patterns */
{IP6}	{
	RET_CONST(new zeek::AddrVal(zeek::util::detail::extract_ip(yytext)))
}

{IP6}{OWS}"/"{OWS}{D}	{
	int len = 0;
	std::string ip = zeek::util::detail::extract_ip_and_len(yytext, &len);
	RET_CONST(new zeek::SubNetVal(zeek::IPPrefix(zeek::IPAddr(ip), len, true)))
}

	/* IPv4 literal constant patterns */
({D}"."){3}{D}		RET_CONST(new zeek::AddrVal(yytext))

({D}"."){3}{D}{OWS}"/"{OWS}{D}	{
	int len = 0;
	std::string ip = zeek::util::detail::extract_ip_and_len(yytext, &len);
	RET_CONST(new zeek::SubNetVal(zeek::IPPrefix(zeek::IPAddr(ip), len)))
}

[!%*/+\-,:;<=>?()\[\]{}~$|&^]	return yytext[0];

"--"	return TOK_DECR;
"++"	return TOK_INCR;

"+="	return TOK_ADD_TO;
"-="	return TOK_REMOVE_FROM;

"=="	return TOK_EQ;
"!="	return TOK_NE;
">="	return TOK_GE;
"<="	return TOK_LE;

"&&"	return TOK_AND_AND;
"||"	return TOK_OR_OR;

"<<"	return TOK_LSHIFT;
">>"	return TOK_RSHIFT;

add	return TOK_ADD;
addr	return TOK_ADDR;
any	return TOK_ANY;
as	return TOK_AS;
bool	return TOK_BOOL;
break	return TOK_BREAK;
case	return TOK_CASE;
option	return TOK_OPTION;
const	return TOK_CONST;
copy	return TOK_COPY;
count	return TOK_COUNT;
default	return TOK_DEFAULT;
delete	return TOK_DELETE;
double	return TOK_DOUBLE;
else	return TOK_ELSE;
enum	return TOK_ENUM;
event	return TOK_EVENT;
export	return TOK_EXPORT;
fallthrough	return TOK_FALLTHROUGH;
file	return TOK_FILE;
for	return TOK_FOR;
while	return TOK_WHILE;
function	return TOK_FUNCTION;
global	return TOK_GLOBAL;
"?$"	return TOK_HAS_FIELD;
hook	return TOK_HOOK;
if	return TOK_IF;
in	return TOK_IN;
"!"{OWS}in/[^A-Za-z0-9]	return TOK_NOT_IN;	/* don't confuse w "! infoo"! */
int	return TOK_INT;
interval	return TOK_INTERVAL;
is	return TOK_IS;
list	return TOK_LIST;
local	return in_when_cond ? TOK_WHEN_LOCAL : TOK_LOCAL;
module	return TOK_MODULE;
next	return TOK_NEXT;
of	return TOK_OF;
opaque	return TOK_OPAQUE;
pattern	return TOK_PATTERN;
port	return TOK_PORT;
print	return TOK_PRINT;
record	return TOK_RECORD;
redef	return TOK_REDEF;
return	return TOK_RETURN;
schedule	return TOK_SCHEDULE;
set	return TOK_SET;
string	return TOK_STRING;
subnet	return TOK_SUBNET;
switch	return TOK_SWITCH;
table	return TOK_TABLE;
time	return TOK_TIME;
timeout	return TOK_TIMEOUT;
type	return TOK_TYPE;
vector	return TOK_VECTOR;
when	return TOK_WHEN;

&add_func	return TOK_ATTR_ADD_FUNC;
&create_expire	return TOK_ATTR_EXPIRE_CREATE;
&default	return TOK_ATTR_DEFAULT;
&delete_func	return TOK_ATTR_DEL_FUNC;
&deprecated	return TOK_ATTR_DEPRECATED;
&raw_output	return TOK_ATTR_RAW_OUTPUT;
&error_handler	return TOK_ATTR_ERROR_HANDLER;
&expire_func	return TOK_ATTR_EXPIRE_FUNC;
&group		return TOK_ATTR_GROUP;
&log		return TOK_ATTR_LOG;
&optional	return TOK_ATTR_OPTIONAL;
&is_assigned	return TOK_ATTR_IS_ASSIGNED;
&is_used	return TOK_ATTR_IS_USED;
&priority	return TOK_ATTR_PRIORITY;
&type_column	return TOK_ATTR_TYPE_COLUMN;
&read_expire	return TOK_ATTR_EXPIRE_READ;
&redef		return TOK_ATTR_REDEF;
&write_expire	return TOK_ATTR_EXPIRE_WRITE;
&on_change	return TOK_ATTR_ON_CHANGE;
&broker_store	return TOK_ATTR_BROKER_STORE;
&broker_allow_complex_type	return TOK_ATTR_BROKER_STORE_ALLOW_COMPLEX;
&backend	return TOK_ATTR_BACKEND;
&ordered    return TOK_ATTR_ORDERED;

@deprecated.* {
	auto num_files = file_stack.length();
	auto comment = zeek::util::skip_whitespace(yytext + 11);
	std::string loaded_from;

	if ( num_files > 0 )
		{
		auto lf = file_stack[num_files - 1];
		if ( lf->name )
			loaded_from = zeek::util::fmt(" from %s:%d", lf->name, lf->line);
		else
			loaded_from = " from command line arguments";
		}

	zeek::reporter->Deprecation(zeek::util::fmt("deprecated script loaded%s %s", loaded_from.c_str(), comment));
	}

@pragma.* {
	do_pragma(zeek::util::skip_whitespace(yytext + 7));
}

@DEBUG	return TOK_DEBUG;	// marks input for debugger

@DIR	{
	std::string rval = zeek::util::SafeDirname(::filename).result;

	if ( ! rval.empty() && rval[0] == '.' )
		{
		char path[MAXPATHLEN];

		if ( ! getcwd(path, MAXPATHLEN) )
			zeek::reporter->InternalError("getcwd failed: %s", strerror(errno));
		else
			rval = std::string(path) + "/" + rval;
		}

	RET_CONST(new zeek::StringVal(rval.c_str()));
	}

@FILENAME	{
	RET_CONST(new zeek::StringVal(zeek::util::SafeBasename(::filename).result));
	}

@load{WS}{FILE}	{
	const char* new_file = zeek::util::skip_whitespace(yytext + 5);	// Skip "@load".
	std::string loader = ::filename;  // load_files may change ::filename, save copy
	std::string loading = find_relative_script_file(new_file);
	(void) load_files(new_file);
	zeek::detail::zeekygen_mgr->ScriptDependency(loader, loading);
	}

@load-sigs{WS}{FILE} {
	const char* file = zeek::util::skip_whitespace(yytext + 10);
	std::string path = find_relative_file(file, ".sig");
	sig_files.emplace_back(file, path, GetCurrentLocation());
	}

@load-plugin{WS}{ID} {
	const char* plugin = zeek::util::skip_whitespace(yytext + 12);
	std::pair<int, std::optional<std::string>> rc;
	rc.first = PLUGIN_HOOK_WITH_RESULT(HOOK_LOAD_FILE, HookLoadFile(zeek::plugin::Plugin::PLUGIN, plugin, ""), -1);
	if ( rc.first < 0 )
		rc = PLUGIN_HOOK_WITH_RESULT(HOOK_LOAD_FILE_EXT, HookLoadFileExtended(zeek::plugin::Plugin::PLUGIN, plugin, ""), std::make_pair(-1, std::nullopt));

	switch ( rc.first ) {
	case -1:
		// No plugin in charge of this file. (We ignore any returned content.)
		zeek::plugin_mgr->ActivateDynamicPlugin(plugin);
		break;

	case 0:
		if ( ! zeek::reporter->Errors() )
			zeek::reporter->Error("Plugin reported error loading plugin %s", plugin);

		exit(1);
		break;

	case 1:
		// A plugin took care of it, just skip.
		break;

	default:
		assert(false);
		break;
	}
}

@unload{WS}{FILE}	{
	// Skip "@unload".
	const char* file = zeek::util::skip_whitespace(yytext + 7);
	std::string path = find_relative_script_file(file);

	if ( ! path.empty() && zeek::util::is_dir(path.c_str()) )
		{
		// open_package() appends __load__.zeek to path and verifies existence
		FILE *f = zeek::util::detail::open_package(path);
		if (f)
			fclose(f);
		else
			path = "";
		}

	if ( path.empty() )
		zeek::reporter->Error("failed find file associated with @unload %s", file);
	else
		{
		// All we have to do is pretend we've already scanned it.
		zeek::detail::ScannedFile sf(file_stack.length(), std::move(path), true);
		zeek::detail::files_scanned.push_back(std::move(sf));
		}
	}

@prefixes{WS}("+"?)={WS}{PREFIX}	{
	char* pref = zeek::util::skip_whitespace(yytext + 9);	// Skip "@prefixes".

	int append = 0;
	if ( *pref == '+' )
		{
		append = 1;
		++pref;
		}

	pref = zeek::util::skip_whitespace(pref + 1);	// Skip over '='.

	if ( ! append )
		zeek::detail::zeek_script_prefixes = { "" }; // don't delete the "" prefix

	zeek::util::tokenize_string(pref, ":", &zeek::detail::zeek_script_prefixes);
	}

@if	return TOK_ATIF;
@ifdef	return TOK_ATIFDEF;
@ifndef	return TOK_ATIFNDEF;
@else   return TOK_ATELSE;
@endif	do_atendif();

<IGNORE>@if	start_conditional();
<IGNORE>@ifdef	start_conditional();
<IGNORE>@ifndef	start_conditional();
<IGNORE>@else   return TOK_ATELSE;
<IGNORE>@endif	return TOK_ATENDIF;
<IGNORE>[^@\r\n]+	/* eat */
<IGNORE>.	/* eat */

T	RET_CONST(zeek::val_mgr->True()->Ref())
F	RET_CONST(zeek::val_mgr->False()->Ref())

{ID}	{
	yylval.str = zeek::util::copy_string(yytext);
	last_id_tok = yylval.str;
	return TOK_ID;
	}

{D}		{
		RET_CONST(zeek::val_mgr->Count(static_cast<zeek_uint_t>(strtoull(yytext, (char**) NULL, 10))).release())
		}
{FLOAT}		RET_CONST(new zeek::DoubleVal(atof(yytext)))

{D}"/tcp"	{
		uint32_t p = atoi(yytext);
		if ( p > 65535 )
			{
			zeek::reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(zeek::val_mgr->Port(p, TRANSPORT_TCP)->Ref())
		}
{D}"/udp"	{
		uint32_t p = atoi(yytext);
		if ( p > 65535 )
			{
			zeek::reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(zeek::val_mgr->Port(p, TRANSPORT_UDP)->Ref())
		}
{D}"/icmp"	{
		uint32_t p = atoi(yytext);
		if ( p > 255 )
			{
			zeek::reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(zeek::val_mgr->Port(p, TRANSPORT_ICMP)->Ref())
		}
{D}"/unknown"	{
		uint32_t p = atoi(yytext);
		if ( p > 255 )
			{
			zeek::reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(zeek::val_mgr->Port(p, TRANSPORT_UNKNOWN)->Ref())
		}

{FLOAT}{OWS}day(s?)	RET_CONST(new zeek::IntervalVal(atof(yytext),Days))
{FLOAT}{OWS}hr(s?)	RET_CONST(new zeek::IntervalVal(atof(yytext),Hours))
{FLOAT}{OWS}min(s?)	RET_CONST(new zeek::IntervalVal(atof(yytext),Minutes))
{FLOAT}{OWS}sec(s?)	RET_CONST(new zeek::IntervalVal(atof(yytext),Seconds))
{FLOAT}{OWS}msec(s?)	RET_CONST(new zeek::IntervalVal(atof(yytext),Milliseconds))
{FLOAT}{OWS}usec(s?)	RET_CONST(new zeek::IntervalVal(atof(yytext),Microseconds))

"0x"{HEX}+	RET_CONST(zeek::val_mgr->Count(static_cast<zeek_uint_t>(strtoull(yytext, 0, 16))).release())

({H}".")+{HTLD}		RET_CONST(zeek::detail::dns_mgr->LookupHost(yytext).release())

\"([^\\\r\\\n\"]|{ESCSEQ})*\"	{
	const char* text = yytext;
	int len = strlen(text) + 1;
	int i = 0;

	char* s = new char[len];

	// Skip leading quote.
	for ( ++text; *text; ++text )
		{
		if ( *text == '\\' )
			{
			++text;	// skip '\'
			s[i++] = zeek::util::detail::expand_escape(text);
			--text;	// point to end of sequence
			}
		else
			{
			s[i++] = *text;
			if ( i >= len )
				zeek::reporter->InternalError("bad string length computation");
			}
		}

	// Get rid of trailing quote.
	if ( s[i-1] != '"' )
		zeek::reporter->InternalError("string scanning confused");

	s[i-1] = '\0';

	RET_CONST(new zeek::StringVal(new zeek::String(1, (zeek::byte_vec) s, i-1)))
	}

<RE>([^/\\\r\\\n]|{ESCSEQ})+	{
	yylval.str = zeek::util::copy_string(yytext);
	return TOK_PATTERN_TEXT;
	}

<RE>"/"	{
	BEGIN(INITIAL);
	yylval.re_modes.ignore_case = false;
	yylval.re_modes.single_line = false;
	return TOK_PATTERN_END;
	}

<RE>(\/[is]{0,2})	{
	BEGIN(INITIAL);

	if ( strlen(yytext) == 2 )
		{
		yylval.re_modes.ignore_case = (yytext[1] == 'i');
		yylval.re_modes.single_line = (yytext[1] == 's');
		}
	else
		{
		if ( yytext[1] == yytext[2] )
			zeek::reporter->Error("pattern has duplicate mode %c", yytext[1]);

		yylval.re_modes.ignore_case = (yytext[1] == 'i' || yytext[2] == 'i');
		yylval.re_modes.single_line = (yytext[1] == 's' || yytext[2] == 's');
		}

	return TOK_PATTERN_END;
	}

<RE>\r?\n	 {
	zeek::reporter->Error("pattern not terminated before end of line");
}

<*>.	zeek::reporter->Error("unrecognized character: '%s'", zeek::util::get_escaped_string(yytext, false).data());

<<EOF>>	last_tok[0] = '\0'; return EOF;

%%

YYLTYPE zeek::detail::GetCurrentLocation()
	{
	static YYLTYPE currloc;

	currloc.filename = filename;
	currloc.first_line = currloc.last_line = line_number;

	return currloc;
	}

void zeek::detail::SetCurrentLocation(YYLTYPE currloc)
	{
	::filename = currloc.filename;
	line_number = currloc.first_line;
	}

static int load_files(const char* orig_file)
	{
	std::string file_path = find_relative_script_file(orig_file);

	std::pair<int, std::optional<std::string>> rc = {-1, std::nullopt};
	rc.first = PLUGIN_HOOK_WITH_RESULT(HOOK_LOAD_FILE, HookLoadFile(zeek::plugin::Plugin::SCRIPT, orig_file, file_path), -1);
	if ( rc.first < 0 )
		rc = PLUGIN_HOOK_WITH_RESULT(HOOK_LOAD_FILE_EXT, HookLoadFileExtended(zeek::plugin::Plugin::SCRIPT, orig_file, file_path), std::make_pair(-1, std::nullopt));

	if ( rc.first == 0 )
		{
		if ( ! zeek::reporter->Errors() )
			// This is just in case the plugin failed to report
			// the error itself, in which case we want to at
			// least tell the user that something went wrong.
			zeek::reporter->Error("Plugin reported error loading %s", orig_file);

		exit(1);
		}

	if ( rc.first == 1 && ! rc.second )
		return 0; // A plugin took care of it, just skip.

	FILE* f = nullptr;

	if ( rc.first == -1 )
		{
		if ( zeek::util::streq(orig_file, "-") )
			{
			f = stdin;
			file_path = zeek::detail::ScannedFile::canonical_stdin_path;

			if ( zeek::detail::g_policy_debug )
				{
				zeek::detail::debug_msg("Warning: can't use debugger while reading policy from stdin; turning off debugging.\n");
				zeek::detail::g_policy_debug = false;
				}
			}

		else
			{
			if ( file_path.empty() )
				zeek::reporter->FatalError("can't find %s", orig_file);

			if ( zeek::util::is_dir(file_path.c_str()) )
				f = zeek::util::detail::open_package(file_path);
			else
				f = zeek::util::open_file(file_path);

			if ( ! f )
				zeek::reporter->FatalError("can't open %s", file_path.c_str());
			}

		zeek::detail::ScannedFile sf(file_stack.length(), file_path);
		if ( sf.AlreadyScanned() )
			{
			if ( rc.first == -1 && f != stdin )
				fclose(f);

			return 0;
			}

		zeek::detail::files_scanned.push_back(std::move(sf));
		}

	if ( zeek::detail::g_policy_debug && ! file_path.empty() )
		{
		// Add the filename to the file mapping table (Debug.h).
		zeek::detail::Filemap* map = new zeek::detail::Filemap;
		zeek::detail::g_dbgfilemaps.emplace(file_path, map);
		LoadPolicyFileText(file_path.c_str(), rc.second);
		}

	// Remember where we were to restore the module scope in which
	// this @load was done when we're finished processing it.
	file_stack.push_back(new FileInfo(zeek::detail::current_module));

	zeek::detail::zeekygen_mgr->Script(file_path);

	// "orig_file" could be an alias for yytext, which is ephemeral
	//  and will be zapped after the yy_switch_to_buffer() below.
	YY_BUFFER_STATE buffer;

	if ( rc.first == 1 )
		{
		// Parse code provided by plugin.
		assert(rc.second);
		DBG_LOG(zeek::DBG_SCRIPTS, "Loading %s from code supplied by plugin ", file_path.c_str());
		buffer = yy_scan_bytes(rc.second->data(), rc.second->size()); // this copies the data
		}
	else
		{
		// Parse from file.
		assert(f);
		DBG_LOG(zeek::DBG_SCRIPTS, "Loading %s", file_path.c_str());
		buffer = yy_create_buffer(f, YY_BUF_SIZE);
		}

	yy_switch_to_buffer(buffer);
	yylloc.first_line = yylloc.last_line = line_number = 1;

	// Don't delete the old filename - it's pointed to by
	// every Obj created when parsing it.
	yylloc.filename = filename = zeek::util::copy_string(file_path.c_str());

	current_file_has_conditionals = files_with_conditionals.count(filename) > 0;

	entry_cond_depth.push_back(conditional_depth);
	entry_pragma_stack_depth.push_back(pragma_stack.size());

	return 1;
	}

void begin_RE()
	{
	BEGIN(RE);
	}

class LocalNameFinder : public zeek::detail::TraversalCallback {
public:
	LocalNameFinder()
		{}

	virtual zeek::detail::TraversalCode PreExpr(const zeek::detail::Expr* expr)
		{
		if ( expr->Tag() != EXPR_NAME )
			return zeek::detail::TC_CONTINUE;

		const zeek::detail::NameExpr* name_expr = static_cast<const zeek::detail::NameExpr*>(expr);

		if ( name_expr->Id()->IsGlobal() )
			return zeek::detail::TC_CONTINUE;

		local_names.push_back(name_expr);
		return zeek::detail::TC_CONTINUE;
		}

	std::vector<const zeek::detail::NameExpr*> local_names;
};

static void begin_ignoring()
	{
	if_stack.push_back(conditional_depth);
	BEGIN(IGNORE);
	}

static void resume_processing()
	{
	if_stack.pop_back();
	BEGIN(INITIAL);
	}

void do_atif(zeek::detail::Expr* expr)
	{
	start_conditional();

	LocalNameFinder cb;
	expr->Traverse(&cb);
	zeek::ValPtr val;

	if ( cb.local_names.empty() )
		val = expr->Eval(nullptr);
	else
		{
		for ( size_t i = 0; i < cb.local_names.size(); ++i )
			cb.local_names[i]->Error("referencing a local name in @if");
		}

	if ( ! val )
		{
		expr->Error("invalid expression in @if");
		return;
		}

	if ( ! val->AsBool() )
		begin_ignoring();
	}

void do_atifdef(const char* id)
	{
	start_conditional();

	const auto& i = zeek::detail::lookup_ID(id, zeek::detail::current_module.c_str());

	// If the ID didn't exist, look to see if this is a module name instead.
	bool found = (i != nullptr);
	if ( ! found )
		found = (module_names.count(id) != 0);

	if ( ! found )
		begin_ignoring();
	}

void do_atifndef(const char *id)
	{
	start_conditional();

	const auto& i = zeek::detail::lookup_ID(id, zeek::detail::current_module.c_str());

	// If the ID didn't exist, look to see if this is a module name instead.
	bool found = (i != nullptr);
	if ( ! found )
		found = (module_names.count(id) != 0);

	if ( found )
		begin_ignoring();
	}

void do_atelse()
	{
	if ( conditional_depth == 0 )
		zeek::reporter->Error("@else without @if...");

	if ( ! if_stack.empty() && conditional_depth > if_stack.back() )
		return;

	if ( YY_START == INITIAL )
		begin_ignoring();
	else
		resume_processing();
	}

void do_atendif()
	{
	if ( conditional_depth <= entry_cond_depth.back() )
		zeek::reporter->Error("unbalanced @if... @endif");

	if ( ! if_stack.empty() && conditional_depth == if_stack.back() )
		resume_processing();

	--conditional_depth;
	}

// If the given Stmt is a directive, trigger an error so that its usage is rejected.
void reject_directive(zeek::detail::Stmt* s)
	{
	if ( s->Tag() == STMT_NULL )
		if ( s->AsNullStmt()->IsDirective() )
			zeek::reporter->Error("incorrect use of directive");
	}

// Be careful to never delete things from this list, as the strings
// are referred to (in order to save the locations of tokens and statements,
// for error reporting and debugging).
static zeek::name_list input_files;
static zeek::name_list essential_input_files;

void add_essential_input_file(const char* file)
	{
	if ( ! file )
		zeek::reporter->InternalError("empty filename");

	if ( ! filename )
		(void) load_files(file);
	else
		essential_input_files.push_back(zeek::util::copy_string(file));
	}

void add_input_file(const char* file)
	{
	if ( ! file )
		zeek::reporter->InternalError("empty filename");

	if ( ! filename )
		(void) load_files(file);
	else
		input_files.push_back(zeek::util::copy_string(file));
	}

void add_input_file_at_front(const char* file)
	{
	if ( ! file )
		zeek::reporter->InternalError("empty filename");

	if ( ! filename )
		(void) load_files(file);
	else
		input_files.push_front(zeek::util::copy_string(file));
	}

void add_to_name_list(char* s, char delim, zeek::name_list& nl)
	{
	while ( s )
		{
		char* s_delim = strchr(s, delim);
		if ( s_delim )
			*s_delim = 0;

		nl.push_back(zeek::util::copy_string(s));

		if ( s_delim )
			s = s_delim + 1;
		else
			break;
		}
	}

int yywrap()
	{
	if ( entry_cond_depth.size() > 0 )
		{
		if ( conditional_depth > entry_cond_depth.back() )
			zeek::reporter->FatalError("unbalanced @if... @endif");
		entry_cond_depth.pop_back();
		}

	if ( entry_pragma_stack_depth.size() > 0 )
		{
		if ( pragma_stack.size() > entry_pragma_stack_depth.back() )
			zeek::reporter->FatalError("unbalanced @pragma push pop in file");

		entry_pragma_stack_depth.pop_back();
		}

	last_filename = ::filename;

	if ( zeek::reporter->Errors() > 0 )
		return 1;

	yy_delete_buffer(YY_CURRENT_BUFFER);

	if ( file_stack.length() > 0 )
		delete file_stack.remove_nth(file_stack.length() - 1);

	if ( YY_CURRENT_BUFFER )
		{
		// There's more on the stack to scan.
		current_file_has_conditionals = files_with_conditionals.count(::filename) > 0;
		return 0;
		}

	// Stack is now empty.
	while ( essential_input_files.length() > 0 || input_files.length() > 0 )
		{
		zeek::name_list& files = essential_input_files.length() > 0 ?
		             essential_input_files : input_files;

		if ( load_files(files[0]) )
			{
			// Don't delete the filename - it's pointed to by
			// every Obj created when parsing it.
			(void) files.remove_nth(0);
			return 0;
			}

		// We already scanned the file.  Pop it and try the next,
		// if any.
		(void) files.remove_nth(0);
		}

	// For each file scanned so far, and for each @prefix, look for a
	// prefixed and flattened version of the loaded file in ZEEKPATH. The
	// flattening involves taking the path in ZEEKPATH in which the
	// scanned file lives and replacing '/' path separators with a '.' If
	// the scanned file is "__load__.zeek", that part of the flattened
	// file name is discarded. If the prefix is non-empty, it gets placed
	// in front of the flattened path, separated with another '.'
	bool found_prefixed_files = false;
	for ( auto& scanned_file : zeek::detail::files_scanned )
		{
		if ( scanned_file.skipped || scanned_file.prefixes_checked )
			continue;

		scanned_file.prefixes_checked = true;
		// Prefixes are pushed onto a stack, so iterate backwards.
		for ( int i = zeek::detail::zeek_script_prefixes.size() - 1; i >= 0; --i )
			{
			// Don't look at empty prefixes.
			if ( ! zeek::detail::zeek_script_prefixes[i][0] )
				continue;

			std::string canon = zeek::util::detail::without_zeekpath_component(scanned_file.name);
			std::string flat = zeek::util::detail::flatten_script_name(canon, zeek::detail::zeek_script_prefixes[i]);
			std::string path = find_relative_script_file(flat);

			if ( ! path.empty() )
				{
				add_input_file(path.c_str());
				found_prefixed_files = true;
				}

			//printf("====== prefix search ======\n");
			//printf("File  : %s\n", scanned_file.name.c_str());
			//printf("Canon : %s\n", canon.c_str());
			//printf("Flat  : %s\n", flat.c_str());
			//printf("Found : %s\n", path.empty() ? "F" : "T");
			//printf("===========================\n");
			}
		}

	if ( found_prefixed_files )
		return 0;

	// Add redef statements for any X=Y command line parameters.
	if ( ! zeek::detail::params.empty() )
		{
		std::string policy;

		for ( const auto& pi : zeek::detail::params )
			{
			auto p = pi.data();

			while ( isalnum(*p) || *p == '_' || *p == ':' ) ++p;

			auto first_non_id_char = p - pi.data();
			auto eq_idx = pi.find('=', first_non_id_char);
			// Omit the '=' from op just to make fmt string below clearer.
			auto op = pi.substr(first_non_id_char, eq_idx - first_non_id_char);
			auto id_str = pi.substr(0, first_non_id_char);
			auto val_str = pi.substr(eq_idx + 1);
			const auto& id = zeek::id::find(id_str);

			if ( ! id )
				{
				zeek::reporter->Error("unknown identifier '%s' in command-line options",
				                      id_str.data());
				continue;
				}

			// Interpret the value based on the identifier's type.
			// So far, that just means quoting the value for string types.
			const auto& type = id->GetType();

			if ( ! type )
				{
				zeek::reporter->Error("can't set value of '%s' in command-line "
				                      "options: unknown type", id_str.data());
				continue;
				}

			if ( val_str.empty() && ! zeek::IsString(type->Tag()) )
				{
				zeek::reporter->Error("must assign non-empty value to '%s' in "
				                      "command-line options", id_str.data());
				continue;
				}

			auto use_quotes = zeek::IsString(type->Tag());
			auto fmt_str = use_quotes ? "redef %s %s= \"%s\";"
			                          : "redef %s %s= %s;";

			policy += zeek::util::fmt(fmt_str, id_str.data(), op.data(), val_str.data());
			}

		zeek::detail::params.clear();
		yylloc.filename = filename = "<params>";
		yy_scan_string(policy.c_str());
		return 0;
		}

	// If we got this far, then we ran out of files. Check if the user
	// specified additional code on the command line, if so, parse it.
	// Use a synthetic filename, and add an extra semicolon on its own
	// line (so that things like @load work), so that a semicolon is
	// not strictly necessary.
	if ( zeek::detail::command_line_policy )
		{
		int tmp_len = strlen(zeek::detail::command_line_policy) + 32;
		char* tmp = new char[tmp_len];
		snprintf(tmp, tmp_len, "%s\n;\n", zeek::detail::command_line_policy);
		yylloc.filename = filename = "<command line>";

		yy_scan_string(tmp);
		delete [] tmp;

		// Make sure we do not get here again:
		zeek::detail::command_line_policy = 0;

		return 0;
		}

	// Otherwise, we are done.
	return 1;
	}

FileInfo::FileInfo(std::string arg_restore_module)
	{
	buffer_state = YY_CURRENT_BUFFER;
	restore_module = arg_restore_module;
	name = ::filename;
	line = ::line_number;
	}

FileInfo::~FileInfo()
	{
	if ( yyin && yyin != stdin )
		fclose(yyin);

	yy_switch_to_buffer(buffer_state);
	yylloc.filename = filename = name;
	yylloc.first_line = yylloc.last_line = line_number = line;

	if ( restore_module != "" )
		zeek::detail::current_module = restore_module;
	}
