%{
#include <string.h>
#include <unistd.h>
#include "bif_arg.h"
#include "bif_parse.h"

char* copy_string(const char* s)
	{
	char* c = new char[strlen(s)+1];
	strcpy(c, s);
	return c;
	}

int line_number = 1;

extern int in_c_code;

int check_c_mode(int t)
	{
	if ( ! in_c_code )
		return t;

	yylval.str = copy_string(yytext);
	return TOK_C_TOKEN;
	}
%}

WS	[ \t]+
 /* Note, bifcl only accepts a single "::" in IDs while the policy
    layer acceptes multiple. (But the policy layer doesn't have 
	a hierachy. */
IDCOMPONENT [A-Za-z_][A-Za-z_0-9]*
ID	{IDCOMPONENT}(::{IDCOMPONENT})?
ESCSEQ	(\\([^\n]|[0-7]+|x[[:xdigit:]]+))
DEC [[:digit:]]+
HEX	[0-9a-fA-F]+


%option nodefault

%%

#.*	{
	yylval.str = copy_string(yytext);
	return TOK_COMMENT;
	}

\n	{
	++line_number;
	return TOK_LF;
	}

{WS}	{
	yylval.str = copy_string(yytext);
	return TOK_WS;
	}

[=,:;]	return check_c_mode(yytext[0]);

"%{"	return TOK_LPB;
"%}"	return TOK_RPB;
"%%{"	return TOK_LPPB;
"%%}"	return TOK_RPPB;

"%("		return check_c_mode(TOK_LPP);
"%)"		return check_c_mode(TOK_RPP);
"..."		return check_c_mode(TOK_VAR_ARG);
"function"	return check_c_mode(TOK_FUNCTION);
"event"		return check_c_mode(TOK_EVENT);
"const"		return check_c_mode(TOK_CONST);
"enum"		return check_c_mode(TOK_ENUM);
"type"		return check_c_mode(TOK_TYPE);
"record"	return check_c_mode(TOK_RECORD);
"set"		return check_c_mode(TOK_SET);
"table"		return check_c_mode(TOK_TABLE);
"vector"	return check_c_mode(TOK_VECTOR);
"module"    return check_c_mode(TOK_MODULE);

"@ARG@"		return TOK_ARG;
"@ARGS@"	return TOK_ARGS;
"@ARGC@"	return TOK_ARGC;

"T"	yylval.val = 1; return TOK_BOOL;
"F"	yylval.val = 0; return TOK_BOOL;

{DEC}	{
	yylval.str = copy_string(yytext);
	return TOK_INT;
	}

"0x"{HEX} {
	yylval.str = copy_string(yytext);
	return TOK_INT;
	}


{ID}	{
	yylval.str = copy_string(yytext);
	return TOK_ID;
	}

&{ID}	{
	int t = check_c_mode(TOK_ATTR);

	if ( t == TOK_ATTR )
		{
		yylval.str = copy_string(yytext);
		return TOK_ATTR;
		}
	else
		return t;
	}

\"([^\\\n\"]|{ESCSEQ})*\"	{
	yylval.str = copy_string(yytext);
	return TOK_CSTR;
	}

\'([^\\\n\']|{ESCSEQ})*\'	{
	yylval.str = copy_string(yytext);
	return TOK_CSTR;
	}

.	{
	yylval.val = yytext[0];
	return TOK_ATOM;
	}
%%

int yywrap()
	{
	yy_delete_buffer(YY_CURRENT_BUFFER);
	return 1;
	}

extern int yyparse();
char* input_filename = 0;

FILE* fp_bro_init = 0;
FILE* fp_func_def = 0;
FILE* fp_func_h = 0;
FILE* fp_func_init = 0;
FILE* fp_netvar_h = 0;
FILE* fp_netvar_def = 0;
FILE* fp_netvar_init = 0;

void remove_file(const char *surfix);
void err_exit(void);
FILE* open_output_file(const char* surfix);
void close_if_open(FILE **fpp);
void close_all_output_files(void);


FILE* open_output_file(const char* surfix)
	{
	char fn[1024];
	FILE* fp;

	snprintf(fn, sizeof(fn), "%s.%s", input_filename, surfix);
	if ( (fp = fopen(fn, "w")) == NULL )
		{
		fprintf(stderr, "Error: cannot open file: %s\n", fn);
		err_exit();
		}

	return fp;
	}


int main(int argc, char* argv[])
	{
	for ( int i = 1; i < argc; i++ )
		{
		FILE* fp_input;
		char* slash;

		input_filename = argv[i];
		slash = strrchr(input_filename, '/');

		if ( (fp_input = fopen(input_filename, "r")) == NULL )
			{
			fprintf(stderr, "Error: cannot open file: %s\n", input_filename);
			/* no output files open. can simply exit */
			exit(1);
			}

		if ( slash )
			input_filename = slash + 1;

		fp_bro_init = open_output_file("bro");
		fp_func_h = open_output_file("func_h");
		fp_func_def = open_output_file("func_def");
		fp_func_init = open_output_file("func_init");
		fp_netvar_h = open_output_file("netvar_h");
		fp_netvar_def = open_output_file("netvar_def");
		fp_netvar_init = open_output_file("netvar_init");

		yy_switch_to_buffer(yy_create_buffer(fp_input, YY_BUF_SIZE));
		yyparse();

		fclose(fp_input);
		close_all_output_files();

		}
	}

void close_if_open(FILE **fpp)
	{
	if (*fpp)
		fclose(*fpp);
	*fpp = NULL;
	}

void close_all_output_files(void)
	{
	close_if_open(&fp_bro_init);
	close_if_open(&fp_func_h);
	close_if_open(&fp_func_def);
	close_if_open(&fp_func_init);
	close_if_open(&fp_netvar_h);
	close_if_open(&fp_netvar_def);
	close_if_open(&fp_netvar_init);
	}

void remove_file(const char *surfix)
	{
	char fn[1024];

	snprintf(fn, sizeof(fn), "%s.%s", input_filename, surfix);
	unlink(fn);
	}

void err_exit(void) 
	{
	close_all_output_files();
	/* clean up. remove all output files we've generated so far */
	remove_file("bro");
	remove_file("func_h");
	remove_file("func_def");
	remove_file("func_init");
	remove_file("netvar_h");
	remove_file("netvar_def");
	remove_file("netvar_init");
	exit(1);
	}

