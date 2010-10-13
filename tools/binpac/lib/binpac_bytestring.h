#ifndef binpac_bytestring_h
#define binpac_bytestring_h

#include <string.h>
#include <string>
#include "binpac.h"

namespace binpac
{

template<class T> class datastring;

template <class T>
class const_datastring
{
public:
	const_datastring()
		: begin_(0), end_(0)
		{ 
		}

	const_datastring(T const *data, int length)
		: begin_(data), end_(data + length)
		{
		}

	const_datastring(const T *begin, const T *end)
		: begin_(begin), end_(end)
		{
		}

	const_datastring(datastring<T> const &s)
		: begin_(s.begin()), end_(s.end())
		{
		}

	void init(const T *data, int length)
		{
		begin_ = data;
		end_ = data + length;
		}

	T const *begin() const	{ return begin_; }
	T const *end() const	{ return end_; }
	int length() const	{ return end_ - begin_; }

	T const &operator[](int index) const
		{
		return begin()[index];
		}

	bool operator==(const_datastring<T> const &s)
		{
		if ( length() != s.length() )
			return false;
		return memcmp((const void *) begin(), (const void *) s.begin(),
			sizeof(T) * length()) == 0;
		}

	void set_begin(T const *begin)	{ begin_ = begin; }
	void set_end(T const *end)	{ end_ = end; }

private:
	T const *begin_; 
	T const *end_;
};

typedef const_datastring<uint8>	const_bytestring;

template<class T>
class datastring
{
public:
	datastring()
		{ 
		clear();
		}

	datastring(T *data, int len)
		{
		set(data, len);
		}

	datastring(T const *begin, T const *end)
		{
		set_const(begin, end - begin);
		}

	datastring(datastring<T> const &x)
		: data_(x.data()), length_(x.length())
		{
		}

	explicit datastring(const_datastring<T> const &x)
		{
		set_const(x.begin(), x.length());
		}

	datastring const &operator=(datastring<T> const &x)
		{
		BINPAC_ASSERT(!data_);
		set(x.data(), x.length());
		return *this;
		}

	void init(T const *begin, int length)
		{
		BINPAC_ASSERT(!data_);
		set_const(begin, length);
		}

	void clear()
		{
		data_ = 0; length_ = 0;
		}

	void free()
		{
		if ( data_ )
			delete [] data_;
		clear();
		}

	void clone()
		{
		set_const(begin(), length());
		}

	datastring const &operator=(const_datastring<T> const &x)
		{
		BINPAC_ASSERT(!data_);
		set_const(x.begin(), x.length());
		return *this;
		}

	T const &operator[](int index) const
		{
		return begin()[index];
		}

	T *data() const		{ return data_; }
	int length() const	{ return length_; }

	T const *begin() const	{ return data_; }
	T const *end() const	{ return data_ + length_; }

private:
	void set(T *data, int len)
		{
		data_ = data;
		length_ = len;
		}

	void set_const(T const *data, int len)
		{
		length_ = len;
		data_ = new T[len + 1];
		memcpy(data_, data, sizeof(T) * len);
		data_[len] = 0;
		}

	T * data_;
	int length_;
};

typedef datastring<uint8> bytestring;

inline const char *c_str(bytestring const &s)
	{
	return (const char *) s.begin();
	}

inline std::string std_str(const_bytestring const &s) 
	{
	return std::string((const char *) s.begin(), (const char *) s.end());
	}

inline bool operator==(bytestring const &s1, const char *s2)
	{
	return strcmp(c_str(s1), s2) == 0;
	}

inline void get_pointers(const_bytestring const &s, 
		uint8 const **pbegin, uint8 const **pend)
	{
	*pbegin = s.begin();
	*pend = s.end();
	}

inline void get_pointers(bytestring const *s, 
		uint8 const **pbegin, uint8 const **pend)
	{
	*pbegin = s->begin();
	*pend = s->end();
	}

} // namespace binpac

#endif  // binpac_bytestring_h
