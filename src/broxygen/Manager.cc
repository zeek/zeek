#include "Manager.h"

using namespace broxygen;

Manager::Manager(const std::string& config)
	{
	// TODO
	}

void Manager::GenerateDocs() const
	{
	// TODO

	// may be a no-op if no config

	// does the old canon_doc_func_param stuff happen here now on the fly
	// for functions we're about to document?
	}

void Manager::File(const std::string& path)
	{
	// TODO
	// can be a file or directory?
	// determine path within BROPATH
	}

void Manager::ScriptDependency(const std::string& path, const std::string& dep)
	{
	// TODO:
	// need anything from BroDoc::AddImport?
	// warn about unconsumed comments (and discard any)
	}

void Manager::ModuleUsage(const std::string& path, const std::string& module)
	{
	// TODO lookup script and add module to a set
	}

void Manager::Identifier(const ID *id)
	{
	// TODO: lookup script to associate w/ by GetLocationInfo()->filename
	// do different things depending on Type? (eg function flavor versus state)
	// do different things based on redef attr + const ?
	// consume any buffered comments and associate w/ id
	// deal w/ type aliasing
	// special enum or record handing?
	// if it's a function we may already have added it (decl versus impl)
	}

void Manager::RecordField(const ID *id, const TypeDecl *field,
                          const std::string& path)
	{
	// TODO: consume comments
	// redef is implicit -- script path of field will differ from ID/type's
	}

void Manager::Redef(const ID* id, const string& path)
	{
	// TODO: lookup script w/ 'path' to associate the id in as redef'd
	// consume any buffered comments and associate w/ redef'd id
	// can sort notices here
	}

void Manager::SummaryComment(const std::string& script,
                             const std::string& comment)
	{
	// TODO
	// canon_doc_comment ?
	}

void Manager::PreComment(const std::string& comment)
	{
	// TODO
	// canon_doc_comment
	}

void Manager::PostComment(const std::string& comment)
	{
	// TODO this gets associated with the last thing registered
	// canon_doc_comment
	}


// TODO: "canon_doc_comment" means treat "##Text" and "## Text" the same
//       so that a single space doesn't generate an indentation level.


// TODO: creating proto/file analyzer docs
