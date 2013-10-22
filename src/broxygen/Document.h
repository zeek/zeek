#ifndef BROXYGEN_DOCUMENT_H
#define BROXYGEN_DOCUMENT_H

#include <utility>
#include <string>
#include <list>
#include <vector>
#include <set>
#include <map>
#include <time.h>

#include "ID.h"
#include "Val.h"
#include "Type.h"

namespace broxygen {

// TODO: documentation...

class Document {

public:

	Document()
		{ }

	virtual ~Document()
		{ }

	time_t GetModificationTime() const
		{ return DoGetModificationTime(); }

private:

	virtual time_t DoGetModificationTime() const = 0;
};

class PackageDocument : public Document {

public:

	PackageDocument(const std::string& name);

private:

	// TODO
	time_t DoGetModificationTime() const
		{ return 0; }

	std::string pkg_loader_name;
};


class IdentifierDocument : public Document {

public:

	IdentifierDocument(ID* id);

	~IdentifierDocument();

	void AddComment(const std::string& comment)
		{ last_field_seen ? last_field_seen->comments.push_back(comment)
		                  : comments.push_back(comment); }

	void AddComments(const std::vector<std::string>& cmtns)
		{ comments.insert(comments.end(), cmtns.begin(), cmtns.end() ); }

	void AddRedef(const std::string& from_script,
	              const std::vector<std::string>& comments);

	void AddRecordField(const TypeDecl* field, const std::string& script,
	                    std::vector<std::string>& comments);

	string Name() const
		{ return id->Name(); }

	ID* GetID() const
		{ return id; }

private:

	struct Redefinition {
		std::string from_script;
		string new_val_desc;
		std::vector<std::string> comments;
	};

	struct RecordField {
		~RecordField()
			{ delete field; }

		TypeDecl* field;
		std::string from_script;
		std::vector<std::string> comments;
	};

	typedef std::list<Redefinition*> RedefList;

	// TODO
	time_t DoGetModificationTime() const
		{ return 0; }

	std::vector<std::string> comments;
	ID* id;
	string initial_val_desc;
	RedefList redefs;
	std::vector<RecordField*> fields;
	RecordField* last_field_seen;
};

class ScriptDocument : public Document {

public:

	ScriptDocument(const std::string& name);

	void AddComment(const std::string& comment)
		{ comments.push_back(comment); }

	void AddDependency(const std::string& name)
		{ dependencies.insert(name); }

	void AddModule(const std::string& name)
		{ module_usages.insert(name); }

	void AddIdentifierDoc(IdentifierDocument* doc);

	bool IsPkgLoader() const
		{ return is_pkg_loader; }

private:

	typedef std::map<std::string, IdentifierDocument*> IdentifierDocMap;

	// TODO
	time_t DoGetModificationTime() const
		{ return 0; }

	std::string name;
	bool is_pkg_loader;
	std::set<std::string> dependencies;
	std::set<std::string> module_usages;
	std::vector<std::string> comments;
	IdentifierDocMap identifier_docs;
};


} // namespace broxygen

#endif
