#ifndef BROXYGEN_DOCUMENT_H
#define BROXYGEN_DOCUMENT_H

#include <utility>
#include <string>
#include <list>
#include <vector>
#include <set>
#include <map>
#include <ctime>

#include "ID.h"
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

	std::string Name() const
		{ return DoName(); }

	std::string ReStructuredText(bool roles_only = false) const
		{ return DoReStructuredText(roles_only); }

	void InitPostScript()
		{ return DoInitPostScript(); }

private:

	virtual time_t DoGetModificationTime() const = 0;
	virtual std::string DoName() const = 0;
	virtual std::string DoReStructuredText(bool roles_only) const = 0;
	virtual void DoInitPostScript()
		{ }
};

class PackageDocument : public Document {

public:

	PackageDocument(const std::string& name);

	std::vector<std::string> GetReadme() const
		{ return readme; }

private:

	time_t DoGetModificationTime() const;

	std::string DoName() const
		{ return pkg_name; }

	std::string DoReStructuredText(bool roles_only) const;

	std::string pkg_name;
	std::vector<std::string> readme;
};


class ScriptDocument;

class IdentifierDocument : public Document {
public:

	IdentifierDocument(ID* id, ScriptDocument* script);

	~IdentifierDocument();

	void AddComment(const std::string& comment)
		{ last_field_seen ? last_field_seen->comments.push_back(comment)
		                  : comments.push_back(comment); }

	void AddComments(const std::vector<std::string>& cmtns)
		{ comments.insert(comments.end(), cmtns.begin(), cmtns.end()); }

	void AddRedef(const std::string& from_script,
	              const std::vector<std::string>& comments);

	void AddRecordField(const TypeDecl* field, const std::string& script,
	                    std::vector<std::string>& comments);

	void CompletedTypeDecl()
		{ last_field_seen = 0; }

	ID* GetID() const
		{ return id; }

	ScriptDocument* GetDeclaringScript() const
	    { return declaring_script; }

	std::string GetDeclaringScriptForField(const std::string& field) const;

	std::vector<std::string> GetComments() const;

	std::vector<std::string> GetFieldComments(const std::string& field) const;

	struct Redefinition {
		std::string from_script;
		std::string new_val_desc;
		std::vector<std::string> comments;
	};

	std::list<Redefinition> GetRedefs(const std::string& from_script) const;

private:

	time_t DoGetModificationTime() const;

	std::string DoName() const
		{ return id->Name(); }

	std::string DoReStructuredText(bool roles_only) const;

	struct RecordField {
		~RecordField()
			{ delete field; }

		TypeDecl* field;
		std::string from_script;
		std::vector<std::string> comments;
	};

	typedef std::list<Redefinition*> redef_list;
	typedef std::map<std::string, RecordField*> record_field_map;

	std::vector<std::string> comments;
	ID* id;
	std::string initial_val_desc;
	redef_list redefs;
	record_field_map fields;
	RecordField* last_field_seen;
	ScriptDocument* declaring_script;
};

class ScriptDocument : public Document {

public:

	ScriptDocument(const std::string& name, const std::string& path);

	void AddComment(const std::string& comment)
		{ comments.push_back(comment); }

	void AddDependency(const std::string& name)
		{ dependencies.insert(name); }

	void AddModule(const std::string& name)
		{ module_usages.insert(name); }

	void AddIdentifierDoc(IdentifierDocument* doc);

	void AddRedef(IdentifierDocument* doc)
		{ redefs.insert(doc); }

	bool IsPkgLoader() const
		{ return is_pkg_loader; }

	std::vector<std::string> GetComments() const;

private:

	typedef std::map<std::string, IdentifierDocument*> id_doc_map;
	typedef std::list<IdentifierDocument*> id_doc_list;
	typedef std::set<std::string> string_set;
	typedef std::set<IdentifierDocument*> doc_set;

	time_t DoGetModificationTime() const;

	std::string DoName() const
		{ return name; }

	std::string DoReStructuredText(bool roles_only) const;

	void DoInitPostScript() /* override */;

	std::string name;
	std::string path;
	bool is_pkg_loader;
	string_set dependencies;
	string_set module_usages;
	std::vector<std::string> comments;
	id_doc_map identifier_docs;
	id_doc_list options;
	id_doc_list constants;
	id_doc_list state_vars;
	id_doc_list types;
	id_doc_list events;
	id_doc_list hooks;
	id_doc_list functions;
	doc_set redefs;
};


} // namespace broxygen

#endif
