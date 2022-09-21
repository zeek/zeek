// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Desc.h"
#include "zeek/Expr.h"

namespace zeek::detail
	{

// Base class for tracking information about a single cat() argument, with
// optimizations for some common cases.
class CatArg
	{
public:
	CatArg(std::string _s) : s(std::move(_s)) { max_size = s->size(); }

	virtual ~CatArg() { }

	size_t MaxSize(ZVal* zframe, int slot)
		{
		return max_size ? *max_size : ComputeMaxSize(zframe, slot);
		}

	virtual void RenderInto(ZVal* zframe, int slot, char*& res)
		{
		auto n = *max_size;
		memcpy(res, s->data(), n);
		res += n;
		}

protected:
	CatArg() { }
	CatArg(size_t _max_size) : max_size(_max_size) { }

	virtual size_t ComputeMaxSize(ZVal* zframe, int slot) { return 0; }

	// Present if max size is known a priori.
	std::optional<size_t> max_size;

	// Present if the argument is a constant.
	std::optional<std::string> s;
	};

class FixedCatArg : public CatArg
	{
public:
	FixedCatArg(const TypePtr& t);

	void RenderInto(ZVal* zframe, int slot, char*& res) override;

protected:
	const TypePtr& t;
	char tmp[256];
	};

class StringCatArg : public CatArg
	{
public:
	StringCatArg() : CatArg() { }

	void RenderInto(ZVal* zframe, int slot, char*& res) override
		{
		auto s = zframe[slot].AsString();
		auto n = s->Len();
		memcpy(res, s->Bytes(), n);
		res += n;
		}

protected:
	size_t ComputeMaxSize(ZVal* zframe, int slot) override
		{
		return zframe[slot].AsString()->Len();
		}
	};

class PatternCatArg : public CatArg
	{
public:
	PatternCatArg() : CatArg() { }

	void RenderInto(ZVal* zframe, int slot, char*& res) override
		{
		*(res++) = '/';
		strcpy(res, text);
		res += n;
		*(res++) = '/';
		}

protected:
	size_t ComputeMaxSize(ZVal* zframe, int slot) override;

	const char* text = nullptr;
	size_t n = 0;
	};

class DescCatArg : public CatArg
	{
public:
	DescCatArg(const TypePtr& _t) : CatArg(), t(_t) { d.SetStyle(RAW_STYLE); }

	void RenderInto(ZVal* zframe, int slot, char*& res) override
		{
		auto n = d.Len();
		memcpy(res, d.Bytes(), n);
		res += n;
		d.Clear();
		}

protected:
	size_t ComputeMaxSize(ZVal* zframe, int slot) override
		{
		zframe[slot].ToVal(t)->Describe(&d);
		return d.Len();
		}

	ODesc d;
	TypePtr t;
	};

	} // namespace zeek::detail
