#ifndef BROXYGEN_CONFIGURATION_H
#define BROXYGEN_CONFIGURATION_H

#include "Document.h"
#include "BroDoc.h"

#include <string>
#include <vector>
#include <map>

namespace broxygen {

// TODO: documentation...

class Target {
public:

	typedef Target* (*factory_fn)(const std::string&, const std::string&);

	virtual ~Target()
		{ }

	void FindDependencies(const std::vector<Document*>& docs)
		{ DoFindDependencies(docs); }

	void Generate() const
		{ DoGenerate(); }

	bool MatchesPattern(Document* doc) const;

	std::string Name() const
		{ return name; }

	std::string Pattern() const
		{ return pattern; }

protected:

	Target(const std::string& arg_name, const std::string& arg_pattern);

private:

	virtual void DoFindDependencies(const std::vector<Document*>& docs) = 0;

	virtual void DoGenerate() const = 0;

	std::string name;
	std::string pattern;
	std::string prefix;
};

class AnalyzerTarget : public Target {
protected:

	typedef void (*doc_creator_fn)(FILE*);

	AnalyzerTarget(const std::string& name, const std::string& pattern,
	               doc_creator_fn cb)
		: Target(name, pattern), doc_creator_callback(cb)
		{ }

private:

	void DoFindDependencies(const std::vector<Document*>& docs);

	void DoGenerate() const;

	doc_creator_fn doc_creator_callback;
};

class ProtoAnalyzerTarget : public AnalyzerTarget {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new ProtoAnalyzerTarget(name, pattern); }

private:

	ProtoAnalyzerTarget(const std::string& name, const std::string& pattern)
		: AnalyzerTarget(name, pattern, &CreateProtoAnalyzerDoc)
		{ }
};

class FileAnalyzerTarget : public AnalyzerTarget {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new FileAnalyzerTarget(name, pattern); }

private:

	FileAnalyzerTarget(const std::string& name, const std::string& pattern)
		: AnalyzerTarget(name, pattern, &CreateFileAnalyzerDoc)
		{ }
};

class PackageTarget : public Target {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new PackageTarget(name, pattern); }

private:

	PackageTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern), pkg_deps(), script_deps(), pkg_manifest()
		{ }

	void DoFindDependencies(const std::vector<Document*>& docs);

	void DoGenerate() const;

	std::vector<PackageDocument*> pkg_deps;
	std::vector<ScriptDocument*> script_deps;
	typedef std::map<PackageDocument*,std::vector<ScriptDocument*> > manifest_t;
	manifest_t pkg_manifest;
};

class PackageIndexTarget : public Target {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new PackageIndexTarget(name, pattern); }

private:

	PackageIndexTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern), pkg_deps()
		{ }

	void DoFindDependencies(const std::vector<Document*>& docs);

	void DoGenerate() const;

	std::vector<PackageDocument*> pkg_deps;
};

class ScriptTarget : public Target {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new ScriptTarget(name, pattern); }

protected:

	ScriptTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern), script_deps()
		{ }

	std::vector<ScriptDocument*> script_deps;

private:

	void DoFindDependencies(const std::vector<Document*>& docs);

	void DoGenerate() const;
};

class ScriptSummaryTarget : public ScriptTarget {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new ScriptSummaryTarget(name, pattern); }

private:

	ScriptSummaryTarget(const std::string& name, const std::string& pattern)
		: ScriptTarget(name, pattern)
		{ }

	void DoGenerate() const /* override */;
};

class ScriptIndexTarget : public ScriptTarget {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new ScriptIndexTarget(name, pattern); }

private:

	ScriptIndexTarget(const std::string& name, const std::string& pattern)
		: ScriptTarget(name, pattern)
		{ }

	void DoGenerate() const /* override */;
};

class IdentifierTarget : public Target {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new IdentifierTarget(name, pattern); }

private:

	IdentifierTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern), id_deps()
		{ }

	void DoFindDependencies(const std::vector<Document*>& docs);

	void DoGenerate() const;

	std::vector<IdentifierDocument*> id_deps;
};

class Config {
public:

	Config(const std::string& file, const std::string& delim = "\t");

	~Config();

	void FindDependencies(const std::vector<Document*>& docs);

	void GenerateDocs() const;

	time_t GetModificationTime() const;

private:

	std::string file;
	std::vector<Target*> targets;
};


} // namespace broxygen

#endif
