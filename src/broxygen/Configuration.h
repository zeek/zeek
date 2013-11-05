#ifndef BROXYGEN_CONFIGURATION_H
#define BROXYGEN_CONFIGURATION_H

#include "Document.h"

#include <string>
#include <vector>
#include <list>

namespace broxygen {

// TODO: documentation...

class Target {
public:

	typedef Target* (*factory_fn)(const std::string&, const std::string&);

	virtual ~Target() { }

	void FindDependencies(const std::vector<Document*>& docs)
		{ DoFindDependencies(docs); }

	void Generate() const
		{ DoGenerate(); }

	bool MatchesPattern(Document* doc) const;

	void AddDependency(Document* doc)
		{ dependencies.push_back(doc); }

protected:

	Target(const std::string& arg_name, const std::string& arg_pattern)
		: name(arg_name), pattern(arg_pattern)
		{ }

	std::string name;
	std::string pattern;
	std::list<Document*> dependencies;

private:

	virtual void DoFindDependencies(const std::vector<Document*>& docs) = 0;

	virtual void DoGenerate() const = 0;
};

class ProtoAnalyzerTarget : public Target {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new ProtoAnalyzerTarget(name, pattern); }

private:

	ProtoAnalyzerTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern)
		{ }

	void DoFindDependencies(const std::vector<Document*>& docs)
		{ /* TODO */ }

	void DoGenerate() const
		{ /* TODO */ }
};

class FileAnalyzerTarget : public Target {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new FileAnalyzerTarget(name, pattern); }

private:

	FileAnalyzerTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern)
		{ }

	void DoFindDependencies(const std::vector<Document*>& docs)
		{ /* TODO */ }

	void DoGenerate() const
		{ /* TODO */ }
};

class PackageTarget : public Target {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new PackageTarget(name, pattern); }

private:

	PackageTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern)
		{ }

	void DoFindDependencies(const std::vector<Document*>& docs)
		{ /* TODO */ }

	void DoGenerate() const
		{ /* TODO */ }
};

class ScriptTarget : public Target {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new ScriptTarget(name, pattern); }

private:

	ScriptTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern)
		{ }

	void DoFindDependencies(const std::vector<Document*>& docs)
		{ /* TODO */ }

	void DoGenerate() const
		{ /* TODO */ }
};

class IdentifierTarget : public Target {
public:

	static Target* Instantiate(const std::string& name,
	                           const std::string& pattern)
		{ return new IdentifierTarget(name, pattern); }

private:

	IdentifierTarget(const std::string& name, const std::string& pattern)
		: Target(name, pattern)
		{ }

	void DoFindDependencies(const std::vector<Document*>& docs);

	void DoGenerate() const
		{ /* TODO */ }
};

class Config {
public:

	Config(const std::string& file, const std::string& delim = "\t");

	~Config();

	void FindDependencies(const std::vector<Document*>& docs);

	void GenerateDocs() const;

private:

	typedef std::list<Target*> target_list;

	target_list targets;
};


} // namespace broxygen

#endif
