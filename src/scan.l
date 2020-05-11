%{
// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>

#include <stack>
#include <list>
#include <string>
#include <algorithm>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <libgen.h>

#include "input.h"
#include "util.h"
#include "Scope.h"
#include "BroString.h"
#include "DNS_Mgr.h"
#include "Expr.h"
#include "Func.h"
#include "Stmt.h"
#include "IntrusivePtr.h"
#include "Val.h"
#include "Var.h"
#include "Debug.h"
#include "PolicyFile.h"
#include "broparse.h"
#include "Reporter.h"
#include "RE.h"
#include "Net.h"
#include "Traverse.h"
#include "module_util.h"

#include "analyzer/Analyzer.h"
#include "zeekygen/Manager.h"

#include "plugin/Manager.h"

namespace {
struct ZeekINode {
	dev_t dev;
	ino_t ino;
};
}

extern YYLTYPE yylloc;	// holds start line and column of token
extern EnumType* cur_enum_type;

// Track the @if... depth.
ptr_compat_int current_depth = 0;

int_list if_stack;

int line_number = 1;
const char* filename = 0; // Absolute path of file currently being parsed.
const char* last_filename = 0; // Absolute path of last file parsed.
static const char* last_id_tok = 0;

const char* last_tok_filename = 0;
const char* last_last_tok_filename = 0;
char last_tok[128];

#define YY_USER_ACTION	strncpy(last_tok, yytext, sizeof(last_tok) - 1); \
                        last_last_tok_filename = last_tok_filename; \
                        last_tok_filename = ::filename;
#define YY_USER_INIT	last_tok[0] = '\0';

// We define our own YY_INPUT because we want to trap the case where
// a read fails.
#define YY_INPUT(buf,result,max_size) \
	if ( ((result = fread(buf, 1, max_size, yyin)) == 0) && ferror(yyin) ) \
		reporter->Error("read failed with \"%s\"", strerror(errno));

static void deprecated_attr(const char* attr)
	{
	reporter->Warning("Use of deprecated attribute: %s", attr);
	}

static std::string find_relative_file(const std::string& filename, const std::string& ext)
	{
	if ( filename.empty() )
		return std::string();

	if ( filename[0] == '.' )
		return find_file(filename, SafeDirname(::filename).result, ext);
	else
		return find_file(filename, bro_path(), ext);
	}

static std::string find_relative_script_file(const std::string& filename)
	{
	if ( filename.empty() )
		return std::string();

	if ( filename[0] == '.' )
		return find_script_file(filename, SafeDirname(::filename).result);
	else
		return find_script_file(filename, bro_path());
	}

static ZeekINode get_inode(FILE* f, const std::string& path)
	{
	struct stat b;

	if ( fstat(fileno(f), &b) )
		reporter->FatalError("fstat of %s failed: %s\n", path.c_str(),
		                     strerror(errno));

	return {b.st_dev, b.st_ino};
	}

static ZeekINode get_inode(const std::string& path)
	{
	FILE* f = open_file(path);

	if ( ! f )
		reporter->FatalError("failed to open %s\n", path.c_str());

	auto inode = get_inode(f, path);
	fclose(f);

	return inode;
	}

class FileInfo {
public:
	FileInfo(std::string restore_module = "");
	~FileInfo();

	YY_BUFFER_STATE buffer_state;
	std::string restore_module;
	const char* name;
	int line;
	int level;
};

// A stack of input buffers we're scanning.  file_stack[len-1] is the
// top of the stack.
static PList<FileInfo> file_stack;

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
FILE	[^ \t\n]+
PREFIX	[^ \t\n]+
FLOAT	(({D}*"."?{D})|({D}"."?{D}*))([eE][-+]?{D})?
H	[A-Za-z0-9][A-Za-z0-9\-]*
ESCSEQ	(\\([^\n]|[0-7]+|x[[:xdigit:]]+))

%%

##!.* {
	zeekygen_mgr->SummaryComment(::filename, yytext + 3);
	}

##<.* {
	std::string hint(cur_enum_type && last_id_tok ?
	            make_full_var_name(current_module.c_str(), last_id_tok) : "");

	zeekygen_mgr->PostComment(yytext + 3, hint);
}

##.* {
	if ( yytext[2] != '#' )
		zeekygen_mgr->PreComment(yytext + 2);
}

#{OWS}@no-test.* return TOK_NO_TEST;

#.*	/* eat comments */

{WS}	/* eat whitespace */

<INITIAL,IGNORE>\n	{
			++line_number;
			++yylloc.first_line;
			++yylloc.last_line;
			}

	/* IPv6 literal constant patterns */
{IP6}	{
	RET_CONST(new AddrVal(extract_ip(yytext)))
}

{IP6}{OWS}"/"{OWS}{D}	{
	int len = 0;
	std::string ip = extract_ip_and_len(yytext, &len);
	RET_CONST(new SubNetVal(IPPrefix(IPAddr(ip), len, true)))
}

	/* IPv4 literal constant patterns */
({D}"."){3}{D}		RET_CONST(new AddrVal(yytext))

({D}"."){3}{D}{OWS}"/"{OWS}{D}	{
	int len = 0;
	std::string ip = extract_ip_and_len(yytext, &len);
	RET_CONST(new SubNetVal(IPPrefix(IPAddr(ip), len)))
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
counter	return TOK_COUNTER;
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
local	return TOK_LOCAL;
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
timer	return TOK_TIMER;
type	return TOK_TYPE;
union	return TOK_UNION;
vector	return TOK_VECTOR;
when	return TOK_WHEN;

&add_func	return TOK_ATTR_ADD_FUNC;
&create_expire	return TOK_ATTR_EXPIRE_CREATE;
&default	return TOK_ATTR_DEFAULT;
&delete_func	return TOK_ATTR_DEL_FUNC;
&deprecated	return TOK_ATTR_DEPRECATED;
&raw_output return TOK_ATTR_RAW_OUTPUT;
&error_handler	return TOK_ATTR_ERROR_HANDLER;
&expire_func	return TOK_ATTR_EXPIRE_FUNC;
&log		return TOK_ATTR_LOG;
&optional	return TOK_ATTR_OPTIONAL;
&priority	return TOK_ATTR_PRIORITY;
&type_column	return TOK_ATTR_TYPE_COLUMN;
&read_expire	return TOK_ATTR_EXPIRE_READ;
&redef		return TOK_ATTR_REDEF;
&write_expire	return TOK_ATTR_EXPIRE_WRITE;
&on_change	return TOK_ATTR_ON_CHANGE;

@deprecated.* {
	auto num_files = file_stack.length();
	auto comment = skip_whitespace(yytext + 11);

	if ( num_files > 0 )
		{
		auto lf = file_stack[num_files - 1];

		if ( lf->name )
			reporter->Warning("deprecated script loaded from %s:%d %s",
			                  lf->name, lf->line, comment);
		else
			reporter->Warning("deprecated script loaded from command line arguments %s", comment);
		}
	else
		reporter->Warning("deprecated script loaded %s", comment);
	}

@DEBUG	return TOK_DEBUG;	// marks input for debugger

@DIR	{
	std::string rval = SafeDirname(::filename).result;

	if ( ! rval.empty() && rval[0] == '.' )
		{
		char path[MAXPATHLEN];

		if ( ! getcwd(path, MAXPATHLEN) )
			reporter->InternalError("getcwd failed: %s", strerror(errno));
		else
			rval = std::string(path) + "/" + rval;
		}

	RET_CONST(new StringVal(rval.c_str()));
	}

@FILENAME	{
	RET_CONST(new StringVal(SafeBasename(::filename).result));
	}

@load{WS}{FILE}	{
	const char* new_file = skip_whitespace(yytext + 5);	// Skip "@load".
	std::string loader = ::filename;  // load_files may change ::filename, save copy
	std::string loading = find_relative_script_file(new_file);
	(void) load_files(new_file);
	zeekygen_mgr->ScriptDependency(loader, loading);
	}

@load-sigs{WS}{FILE} {
	const char* file = skip_whitespace(yytext + 10);
	std::string path = find_relative_file(file, ".sig");
	int rc = PLUGIN_HOOK_WITH_RESULT(HOOK_LOAD_FILE, HookLoadFile(plugin::Plugin::SIGNATURES, file, path), -1);

	switch ( rc ) {
	case -1:
		// No plugin in charge of this file.
		if ( path.empty() )
			reporter->Error("failed to find file associated with @load-sigs %s",
			                file);
		else
			sig_files.push_back(copy_string(path.c_str()));
		break;

	case 0:
		if ( ! reporter->Errors() )
			reporter->Error("Plugin reported error loading signatures %s", file);

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

@load-plugin{WS}{ID} {
	const char* plugin = skip_whitespace(yytext + 12);
	int rc = PLUGIN_HOOK_WITH_RESULT(HOOK_LOAD_FILE, HookLoadFile(plugin::Plugin::PLUGIN, plugin, ""), -1);

	switch ( rc ) {
	case -1:
		// No plugin in charge of this file.
		plugin_mgr->ActivateDynamicPlugin(plugin);
		break;

	case 0:
		if ( ! reporter->Errors() )
			reporter->Error("Plugin reported error loading plugin %s", plugin);

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
	const char* file = skip_whitespace(yytext + 7);
	std::string path = find_relative_script_file(file);

	if ( path.empty() )
		reporter->Error("failed find file associated with @unload %s", file);
	else
		{
		// All we have to do is pretend we've already scanned it.
		auto i = get_inode(path);
		ScannedFile sf(i.dev, i.ino, file_stack.length(), path, true);
		files_scanned.push_back(sf);
		}
	}

@prefixes{WS}("+"?)={WS}{PREFIX}	{
	char* pref = skip_whitespace(yytext + 9);	// Skip "@prefixes".

	int append = 0;
	if ( *pref == '+' )
		{
		append = 1;
		++pref;
		}

	pref = skip_whitespace(pref + 1);	// Skip over '='.

	if ( ! append )
		zeek_script_prefixes = { "" }; // don't delete the "" prefix

	tokenize_string(pref, ":", &zeek_script_prefixes);
	}

@if	return TOK_ATIF;
@ifdef	return TOK_ATIFDEF;
@ifndef	return TOK_ATIFNDEF;
@else   return TOK_ATELSE;
@endif	--current_depth;

<IGNORE>@if	++current_depth;
<IGNORE>@ifdef	++current_depth;
<IGNORE>@ifndef	++current_depth;
<IGNORE>@else   return TOK_ATELSE;
<IGNORE>@endif	return TOK_ATENDIF;
<IGNORE>[^@\n]+	/* eat */
<IGNORE>.	/* eat */

T	RET_CONST(val_mgr->True()->Ref())
F	RET_CONST(val_mgr->False()->Ref())

{ID}	{
	yylval.str = copy_string(yytext);
	last_id_tok = yylval.str;
	return TOK_ID;
	}

{D}		{
		RET_CONST(val_mgr->Count(static_cast<bro_uint_t>(strtoull(yytext, (char**) NULL, 10))).release())
		}
{FLOAT}		RET_CONST(new Val(atof(yytext), TYPE_DOUBLE))

{D}"/tcp"	{
		uint32_t p = atoi(yytext);
		if ( p > 65535 )
			{
			reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(val_mgr->Port(p, TRANSPORT_TCP)->Ref())
		}
{D}"/udp"	{
		uint32_t p = atoi(yytext);
		if ( p > 65535 )
			{
			reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(val_mgr->Port(p, TRANSPORT_UDP)->Ref())
		}
{D}"/icmp"	{
		uint32_t p = atoi(yytext);
		if ( p > 255 )
			{
			reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(val_mgr->Port(p, TRANSPORT_ICMP)->Ref())
		}
{D}"/unknown"	{
		uint32_t p = atoi(yytext);
		if ( p > 255 )
			{
			reporter->Error("bad port number - %s", yytext);
			p = 0;
			}
		RET_CONST(val_mgr->Port(p, TRANSPORT_UNKNOWN)->Ref())
		}

{FLOAT}{OWS}day(s?)	RET_CONST(new IntervalVal(atof(yytext),Days))
{FLOAT}{OWS}hr(s?)	RET_CONST(new IntervalVal(atof(yytext),Hours))
{FLOAT}{OWS}min(s?)	RET_CONST(new IntervalVal(atof(yytext),Minutes))
{FLOAT}{OWS}sec(s?)	RET_CONST(new IntervalVal(atof(yytext),Seconds))
{FLOAT}{OWS}msec(s?)	RET_CONST(new IntervalVal(atof(yytext),Milliseconds))
{FLOAT}{OWS}usec(s?)	RET_CONST(new IntervalVal(atof(yytext),Microseconds))

"0x"{HEX}+	RET_CONST(val_mgr->Count(static_cast<bro_uint_t>(strtoull(yytext, 0, 16))).release())

{H}("."{H})+		RET_CONST(dns_mgr->LookupHost(yytext).release())

\"([^\\\n\"]|{ESCSEQ})*\"	{
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
			s[i++] = expand_escape(text);
			--text;	// point to end of sequence
			}
		else
			{
			s[i++] = *text;
			if ( i >= len )
				reporter->InternalError("bad string length computation");
			}
		}

	// Get rid of trailing quote.
	if ( s[i-1] != '"' )
		reporter->InternalError("string scanning confused");

	s[i-1] = '\0';

	RET_CONST(new StringVal(new BroString(1, (byte_vec) s, i-1)))
	}

<RE>([^/\\\n]|{ESCSEQ})+	{
	yylval.str = copy_string(yytext);
	return TOK_PATTERN_TEXT;
	}

<RE>"/"	{
	BEGIN(INITIAL);
	yylval.b = false;
	return TOK_PATTERN_END;
	}

<RE>"/i"	{
	BEGIN(INITIAL);
	yylval.b = true;
	return TOK_PATTERN_END;
	}

<RE>[\\\n]	return yytext[0];	// should cause a parse error

<*>.	reporter->Error("unrecognized character - %s", yytext);

<<EOF>>	last_tok[0] = '\0'; return EOF;

%%

YYLTYPE GetCurrentLocation()
	{
	static YYLTYPE currloc;

	currloc.filename = filename;
	currloc.first_line = currloc.last_line = line_number;

	return currloc;
	}

static bool already_scanned(ZeekINode in)
	{
	for ( const auto& it : files_scanned )
		if ( it.dev == in.dev && it.inode == in.ino )
			return true;

	return false;
	}

static bool already_scanned(const std::string& path)
	{
	return already_scanned(get_inode(path));
	}

static int load_files(const char* orig_file)
	{
	std::string file_path = find_relative_script_file(orig_file);
	int rc = PLUGIN_HOOK_WITH_RESULT(HOOK_LOAD_FILE, HookLoadFile(plugin::Plugin::SCRIPT, orig_file, file_path), -1);

	if ( rc == 1 )
		return 0; // A plugin took care of it, just skip.

	if ( rc == 0 )
		{
		if ( ! reporter->Errors() )
			// This is just in case the plugin failed to report
			// the error itself, in which case we want to at
			// least tell the user that something went wrong.
			reporter->Error("Plugin reported error loading %s", orig_file);

		exit(1);
		}

	assert(rc == -1); // No plugin in charge of this file.

	// Whether we pushed on a FileInfo that will restore the
	// current module after the final file has been scanned.
	bool did_module_restore = false;
	FILE* f = 0;

	if ( streq(orig_file, "-") )
		{
		f = stdin;
		file_path = "<stdin>";

		if ( g_policy_debug )
			{
			debug_msg("Warning: can't use debugger while reading policy from stdin; turning off debugging.\n");
			g_policy_debug = false;
			}
		}

	else
		{
		if ( file_path.empty() )
			reporter->FatalError("can't find %s", orig_file);

		if ( is_dir(file_path.c_str()) )
			f = open_package(file_path);
		else
			f = open_file(file_path);

		if ( ! f )
			reporter->FatalError("can't open %s", file_path.c_str());
		}

	auto i = get_inode(f, file_path);

	if ( already_scanned(i) )
		{
		if ( f != stdin )
			fclose(f);

		return 0;
		}

	ScannedFile sf(i.dev, i.ino, file_stack.length(), file_path);
	files_scanned.push_back(sf);

	if ( g_policy_debug && ! file_path.empty() )
		{
		// Add the filename to the file mapping table (Debug.h).
		Filemap* map = new Filemap;
		HashKey* key = new HashKey(file_path.c_str());
		g_dbgfilemaps.emplace(file_path, map);
		LoadPolicyFileText(file_path.c_str());
		}

	// Remember where we were.  If this is the first
	// file being pushed on the stack, i.e., the *last*
	// one that will be processed, then we want to
	// restore the module scope in which this @load
	// was done when we're finished processing it.
	if ( ! did_module_restore )
		{
		file_stack.push_back(new FileInfo(current_module));
		did_module_restore = true;
		}
	else
		file_stack.push_back(new FileInfo);

	zeekygen_mgr->Script(file_path);

	DBG_LOG(DBG_SCRIPTS, "Loading %s", file_path.c_str());

	// "orig_file", could be an alias for yytext, which is ephemeral
	//  and will be zapped after the yy_switch_to_buffer() below.
	yy_switch_to_buffer(yy_create_buffer(f, YY_BUF_SIZE));

	yylloc.first_line = yylloc.last_line = line_number = 1;

	// Don't delete the old filename - it's pointed to by
	// every BroObj created when parsing it.
	yylloc.filename = filename = copy_string(file_path.c_str());

	return 1;
	}

void begin_RE()
	{
	BEGIN(RE);
	}

class LocalNameFinder : public TraversalCallback {
public:
	LocalNameFinder()
		{}

	virtual TraversalCode PreExpr(const Expr* expr)
		{
		if ( expr->Tag() != EXPR_NAME )
			return TC_CONTINUE;

		const NameExpr* name_expr = static_cast<const NameExpr*>(expr);

		if ( name_expr->Id()->IsGlobal() )
			return TC_CONTINUE;

		local_names.push_back(name_expr);
		return TC_CONTINUE;
		}

	std::vector<const NameExpr*> local_names;
};

void do_atif(Expr* expr)
	{
	++current_depth;

	LocalNameFinder cb;
	expr->Traverse(&cb);
	IntrusivePtr<Val> val;

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
		{
		if_stack.push_back(current_depth);
		BEGIN(IGNORE);
		}
	}

void do_atifdef(const char* id)
	{
	++current_depth;

	auto i = lookup_ID(id, current_module.c_str());

	if ( ! i )
		{
		if_stack.push_back(current_depth);
		BEGIN(IGNORE);
		}
	}

void do_atifndef(const char *id)
	{
	++current_depth;

	auto i = lookup_ID(id, current_module.c_str());

	if ( i )
		{
		if_stack.push_back(current_depth);
		BEGIN(IGNORE);
		}
	}

void do_atelse()
	{
	if ( current_depth == 0 )
		reporter->Error("@else without @if...");

	if ( ! if_stack.empty() && current_depth > if_stack.back() )
		return;

	if ( YY_START == INITIAL )
		{
		if_stack.push_back(current_depth);
		BEGIN(IGNORE);
		}
	else
		{
		if_stack.pop_back();
		BEGIN(INITIAL);
		}
	}

void do_atendif()
	{
	if ( current_depth == 0 )
		reporter->Error("unbalanced @if... @endif");

	if ( current_depth == if_stack.back() )
		{
		BEGIN(INITIAL);
		if_stack.pop_back();
		}

	--current_depth;
	}

// Be careful to never delete things from this list, as the strings
// are referred to (in order to save the locations of tokens and statements,
// for error reporting and debugging).
static name_list input_files;
static name_list essential_input_files;

void add_essential_input_file(const char* file)
	{
	if ( ! file )
		reporter->InternalError("empty filename");

	if ( ! filename )
		(void) load_files(file);
	else
		essential_input_files.push_back(copy_string(file));
	}

void add_input_file(const char* file)
	{
	if ( ! file )
		reporter->InternalError("empty filename");

	if ( ! filename )
		(void) load_files(file);
	else
		input_files.push_back(copy_string(file));
	}

void add_input_file_at_front(const char* file)
	{
	if ( ! file )
		reporter->InternalError("empty filename");

	if ( ! filename )
		(void) load_files(file);
	else
		input_files.push_front(copy_string(file));
	}

void add_to_name_list(char* s, char delim, name_list& nl)
	{
	while ( s )
		{
		char* s_delim = strchr(s, delim);
		if ( s_delim )
			*s_delim = 0;

		nl.push_back(copy_string(s));

		if ( s_delim )
			s = s_delim + 1;
		else
			break;
		}
	}

int yywrap()
	{
	last_filename = ::filename;

	if ( reporter->Errors() > 0 )
		return 1;

	if ( ! did_builtin_init && file_stack.length() == 1 )
		{
		// ### This is a gross hack - we know that the first file
		// we parse is init-bare.zeek, and after it it's safe to initialize
		// the built-ins.  Furthermore, we want to initialize the
		// built-in's *right* after parsing bro.init, so that other
		// source files can use built-in's when initializing globals.
		init_builtin_funcs();
		}

	yy_delete_buffer(YY_CURRENT_BUFFER);

	if ( file_stack.length() > 0 )
		delete file_stack.remove_nth(file_stack.length() - 1);

	if ( YY_CURRENT_BUFFER )
		// There's more on the stack to scan.
		return 0;

	// Stack is now empty.
	while ( essential_input_files.length() > 0 || input_files.length() > 0 )
		{
		name_list& files = essential_input_files.length() > 0 ?
		             essential_input_files : input_files;

		if ( load_files(files[0]) )
			{
			// Don't delete the filename - it's pointed to by
			// every BroObj created when parsing it.
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
	std::list<ScannedFile>::iterator it;
	bool found_prefixed_files = false;
	for ( it = files_scanned.begin(); it != files_scanned.end(); ++it )
		{
		if ( it->skipped || it->prefixes_checked )
			continue;

		it->prefixes_checked = true;
		// Prefixes are pushed onto a stack, so iterate backwards.
		for ( int i = zeek_script_prefixes.size() - 1; i >= 0; --i )
			{
			// Don't look at empty prefixes.
			if ( ! zeek_script_prefixes[i][0] )
				continue;

			std::string canon = without_bropath_component(it->name);
			std::string flat = flatten_script_name(canon, zeek_script_prefixes[i]);
			std::string path = find_relative_script_file(flat);

			if ( ! path.empty() )
				{
				add_input_file(path.c_str());
				found_prefixed_files = true;
				}

			//printf("====== prefix search ======\n");
			//printf("File  : %s\n", it->name.c_str());
			//printf("Canon : %s\n", canon.c_str());
			//printf("Flat  : %s\n", flat.c_str());
			//printf("Found : %s\n", path.empty() ? "F" : "T");
			//printf("===========================\n");
			}
		}

	if ( found_prefixed_files )
		return 0;

	// Add redef statements for any X=Y command line parameters.
	if ( params.size() > 0 )
		{
		std::string policy;

		for ( unsigned int i = 0; i < params.size(); ++i )
			{
			char* param = copy_string(params[i].c_str());
			char* eq = strchr(param, '=');
			char* val = eq + 1;

			*eq = '\0';

			if ( strlen(val) == 0 )
				{
				delete [] param;
				continue;
				}

			// Try to find the type of the param, and interpret
			// the value intelligently for that type.  (So far,
			// that just means quoting the value if it's a
			// string type.)  If no type is found, the value
			// is left unchanged.
			std::string opt_quote;	// no optional quote by default
			auto param_id = lookup_ID(param, GLOBAL_MODULE_NAME);
			Val* v = param_id ? param_id->GetVal().get() : nullptr;

			if ( v && v->GetType() && v->GetType()->Tag() == TYPE_STRING )
				opt_quote = "\"";	// use quotes

			policy += std::string("redef ") + param + "="
					+ opt_quote + val + opt_quote + ";";

			delete [] param;
			}

		params.clear();
		yylloc.filename = filename = "<params>";
		yy_scan_string(policy.c_str());
		return 0;
		}

	// If we got this far, then we ran out of files. Check if the user
	// specified additional code on the command line, if so, parse it.
	// Use a synthetic filename, and add an extra semicolon on its own
	// line (so that things like @load work), so that a semicolon is
	// not strictly necessary.
	if ( command_line_policy )
		{
		int tmp_len = strlen(command_line_policy) + 32;
		char* tmp = new char[tmp_len];
		snprintf(tmp, tmp_len, "%s\n;\n", command_line_policy);
		yylloc.filename = filename = "<command line>";

		yy_scan_string(tmp);
		delete [] tmp;

		// Make sure we do not get here again:
		command_line_policy = 0;

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
		current_module = restore_module;
	}
