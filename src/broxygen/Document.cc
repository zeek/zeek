#include "Document.h"

#include "util.h"
#include "Val.h"

using namespace broxygen;
using namespace std;

static string ImplodeStringVec(const vector<string>& v)
	{
	string rval;

	for ( size_t i = 0; i < v.size(); ++i )
		{
		if ( i > 0 )
			rval += '\n';

		rval += v[i];
		}

	return rval;
	}

PackageDocument::PackageDocument(const string& arg_name)
    : Document(),
      pkg_name(arg_name)
	{
	// TODO: probably need to determine modification times of all files
	//       within the directory, recursively
	}

IdentifierDocument::IdentifierDocument(ID* arg_id)
    : Document(),
      comments(), id(arg_id), initial_val_desc(), redefs(), fields(),
      last_field_seen()
	{
	Ref(id);

	if ( id->ID_Val() )
		{
		ODesc d;
		id->ID_Val()->Describe(&d);
		initial_val_desc = d.Description();
		}
	}

IdentifierDocument::~IdentifierDocument()
	{
	Unref(id);

	for ( RedefList::const_iterator it = redefs.begin(); it != redefs.end();
	      ++it )
		delete *it;

	for ( RecordFieldMap::const_iterator it = fields.begin();
	      it != fields.end(); ++it )
		delete it->second;
	}

void IdentifierDocument::AddRedef(const string& script,
                                  const vector<string>& comments)
	{
	Redefinition* redef = new Redefinition();
	redef->from_script = script;

	if ( id->ID_Val() )
		{
		ODesc d;
		id->ID_Val()->Describe(&d);
		redef->new_val_desc = d.Description();
		}

	redef->comments = comments;
	redefs.push_back(redef);
	}

void IdentifierDocument::AddRecordField(const TypeDecl* field,
                                        const string& script,
                                        vector<string>& comments)
	{
	RecordField* rf = new RecordField();
	rf->field = new TypeDecl(*field);
	rf->from_script = script;
	rf->comments = comments;
	fields[rf->field->id] = rf;
	last_field_seen = rf;
	}

string IdentifierDocument::GetComments() const
	{
	return ImplodeStringVec(comments);
	}

string IdentifierDocument::GetFieldComments(const string& field) const
	{
	RecordFieldMap::const_iterator it = fields.find(field);

	if ( it == fields.end() )
		return string();

	return ImplodeStringVec(it->second->comments);
	}

ScriptDocument::ScriptDocument(const string& arg_name)
    : Document(),
      name(arg_name),
      is_pkg_loader(safe_basename(name) == PACKAGE_LOADER),
      dependencies(), module_usages(), comments(), identifier_docs(), redefs()
	{
	}

void ScriptDocument::AddIdentifierDoc(IdentifierDocument* doc)
	{
	identifier_docs[doc->Name()] = doc;
	// TODO: sort things (e.g. function flavor, state var vs. option var)
	}

string ScriptDocument::GetComments() const
	{
	return ImplodeStringVec(comments);
	}
