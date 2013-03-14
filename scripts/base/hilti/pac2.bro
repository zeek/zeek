
module Pac2;

export {
	## Dump debug information about analyzers to stderr (for debugging only). 
	const dump_debug = F &redef;

	## Dump generated HILTI/BinPAC++ code to stderr (for debugging only).
	const dump_code = F &redef;

	## Dump generated HILTI/BinPAC++ code to stderr before finalizing the modules. (for
	## debugging only). 
	const dump_code_pre_finalize = F &redef;

	## Dump all HILTI/BinPAC++ code to stderr (for debugging only).
	const dump_code_all = F &redef;

	## Disable code verification (for debugging only).
	const no_verify = F &redef;

	## Generate code for all events no matter if they have a handler
	## defined or not.
	const compile_all = F &redef;

	## Debug level for compilation.
	const debug = T &redef;

	## Optimization level for code generation.
	const optimize = F &redef;

	## Tags for codegen debug output as colon-separated string.
	const cg_debug = "" &redef;

	## Save all generated BinPAC++ modules into "bro.<X>.pac2"
	const save_pac2 = F &redef;

	## Save all HILTI modules into "bro.<X>.hlt"
	const save_hilti = F &redef;

	## Save final linked LLVM assembly into "bro.ll"
	const save_llvm = F &redef;

}


