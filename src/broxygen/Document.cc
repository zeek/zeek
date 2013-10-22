#include "Document.h"

#include "util.h"

using namespace broxygen;
using namespace std;

PackageDocument::PackageDocument(const string& arg_name)
    : Document(),
      pkg_loader_name(arg_name)
	{
	// TODO: probably need to determine modification times of all files
	//       within the directory, recursively
	}

IdentifierDocument::IdentifierDocument(ID* arg_id)
    : Document(),
      comments(), id(arg_id), initial_val(), redefs(), fields(),
      last_field_seen()
	{
	Ref(id);

	if ( id->ID_Val() )
		initial_val = id->ID_Val()->Clone();
	}

IdentifierDocument::~IdentifierDocument()
	{
	Unref(id);
	//Unref(initial_val); // TODO: problematic w/ PatternVals

	for ( RedefList::const_iterator it = redefs.begin(); it != redefs.end();
	      ++it )
		delete *it;

	for ( size_t i = 0; i < fields.size(); ++i )
		delete fields[i];
	}

void IdentifierDocument::AddRedef(const string& script,
                                  const vector<string>& comments)
	{
	Redefinition* redef = new Redefinition();
	redef->from_script = script;
	redef->new_val = id->ID_Val() ? id->ID_Val()->Clone() : 0;
	redef->comments = comments;
	redefs.push_back(redef);
	}

void IdentifierDocument::AddRecordField(const TypeDecl* field,
                                        const string& script,
                                        std::vector<string>& comments)
	{
	RecordField* rf = new RecordField();
	rf->field = new TypeDecl(*field);
	rf->from_script = script;
	rf->comments = comments;
	fields.push_back(rf);
	last_field_seen = rf;
	}

ScriptDocument::ScriptDocument(const string& arg_name)
    : Document(),
      name(arg_name),
      is_pkg_loader(safe_basename(name) == PACKAGE_LOADER),
      dependencies(), module_usages(), comments(), identifier_docs()
	{
	}

void ScriptDocument::AddIdentifierDoc(IdentifierDocument* doc)
	{
	identifier_docs[doc->Name()] = doc;
	// TODO: sort things (e.g. function flavor, state var vs. option var)
	}
