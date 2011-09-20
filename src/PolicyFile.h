// Functions for displaying the contents of policy files.
// Mostly useful for debugging code that wants to show context.
//
// Summary:
//	All files that are going to be accessed should be passed to LoadFile
//	(probably in the lexer). Then later any function that so desires
//	can call a relevant function. Note that since it caches the contents,
//	changes to the policy files will not be reflected until restart,
//	which is probably good since it'll always display the code that Bro
//	is actually using.

// policy_filename arguments should be absolute or relative paths;
// no expansion is done.

int how_many_lines_in(const char* policy_filename);

bool LoadPolicyFileText(const char* policy_filename);

// start_line is 1-based (the intuitive way)
bool PrintLines(const char* policy_filename, unsigned int start_line,
		unsigned int how_many_lines, bool show_numbers);
