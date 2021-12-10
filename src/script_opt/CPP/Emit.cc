// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

void CPPCompile::StartBlock()
	{
	IndentUp();
	Emit("{");
	}

void CPPCompile::EndBlock(bool needs_semi)
	{
	Emit("}%s", needs_semi ? ";" : "");
	IndentDown();
	}

void CPPCompile::Indent() const
	{
	for ( auto i = 0; i < block_level; ++i )
		fprintf(write_file, "%s", "\t");
	}

	} // zeek::detail
