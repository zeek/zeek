// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"

#include "zeek/zeek-config.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <sstream> // Needed for unit testing

#include "zeek/3rdparty/doctest.h"
#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Val.h"
#include "zeek/util.h"

#ifdef DEBUG
#define DEBUG_STR(msg) DBG_LOG(zeek::DBG_STRING, msg)
#else
#define DEBUG_STR(msg)
#endif

using namespace std::string_literals;

namespace zeek
	{

// This constructor forces the user to specify arg_final_NUL.  When str
// is a *normal* NUL-terminated string, make arg_n == strlen(str) and
// arg_final_NUL == 1; when str is a sequence of n bytes, make
// arg_final_NUL == 0.

String::String(bool arg_final_NUL, byte_vec str, int arg_n)
	{
	b = str;
	n = arg_n;
	final_NUL = arg_final_NUL;
	use_free_to_delete = false;
	}

String::String(const u_char* str, int arg_n, bool add_NUL) : String()
	{
	Set(str, arg_n, add_NUL);
	}

String::String(std::string_view str) : String()
	{
	Set(str);
	}

String::String(const String& bs) : String()
	{
	*this = bs;
	}

String::String()
	{
	b = nullptr;
	n = 0;
	final_NUL = false;
	use_free_to_delete = false;
	}

void String::Reset()
	{
	if ( use_free_to_delete )
		free(b);
	else
		delete[] b;

	b = nullptr;
	n = 0;
	final_NUL = false;
	use_free_to_delete = false;
	}

const String& String::operator=(const String& bs)
	{
	Reset();
	n = bs.n;
	b = new u_char[n + 1];

	memcpy(b, bs.b, n);
	b[n] = '\0';

	final_NUL = true;
	use_free_to_delete = false;
	return *this;
	}

bool String::operator==(const String& bs) const
	{
	return Bstr_eq(this, &bs);
	}

bool String::operator<(const String& bs) const
	{
	return Bstr_cmp(this, &bs) < 0;
	}

bool String::operator==(std::string_view s) const
	{
	if ( static_cast<size_t>(n) != s.size() )
		return false;

	if ( b == nullptr )
		{
		return s.size() == 0;
		}

	return (memcmp(b, s.data(), n) == 0);
	}

bool String::operator!=(std::string_view s) const
	{
	return ! (*this == s);
	}

void String::Adopt(byte_vec bytes, int len)
	{
	Reset();

	b = bytes;

	// Check if the string ends with a NUL.  If so, mark it as having
	// a final NUL and adjust the length accordingly.
	final_NUL = (b[len - 1] == '\0');
	n = len - final_NUL;
	}

void String::Set(const u_char* str, int len, bool add_NUL)
	{
	Reset();

	n = len;
	b = new u_char[add_NUL ? n + 1 : n];
	memcpy(b, str, n);
	final_NUL = add_NUL;

	if ( add_NUL )
		b[n] = 0;

	use_free_to_delete = false;
	}

void String::Set(std::string_view str)
	{
	Reset();

	if ( str.data() )
		{
		n = str.size();
		b = new u_char[n + 1];
		memcpy(b, str.data(), n);
		b[n] = 0;
		final_NUL = true;
		use_free_to_delete = false;
		}
	}

void String::Set(const String& str)
	{
	*this = str;
	}

const char* String::CheckString() const
	{
	void* nulTerm;
	if ( n == 0 )
		return "";

	nulTerm = memchr(b, '\0', n + final_NUL);
	if ( nulTerm != &b[n] )
		{
		// Either an embedded NUL, or no final NUL.
		char* exp_s = Render();

		if ( nulTerm )
			reporter->Error("string with embedded NUL: \"%s\"", exp_s);
		else
			reporter->Error("string without NUL terminator: \"%s\"", exp_s);

		delete[] exp_s;
		return "<string-with-NUL>";
		}

	return (const char*)b;
	}

char* String::Render(int format, int* len) const
	{
	// Maximum character expansion is as \xHH, so a factor of 4.
	char* s = new char[n * 4 + 1]; // +1 is for final '\0'
	char* sp = s;
	int tmp_len;

	for ( int i = 0; i < n; ++i )
		{
		if ( b[i] == '\\' && (format & ESC_ESC) )
			{
			*sp++ = '\\';
			*sp++ = '\\';
			}

		else if ( (b[i] == '\'' || b[i] == '"') && (format & ESC_QUOT) )
			{
			*sp++ = '\\';
			*sp++ = b[i];
			}

		else if ( (b[i] < ' ' || b[i] > 126) && (format & ESC_HEX) )
			{
			char hex_fmt[16];

			*sp++ = '\\';
			*sp++ = 'x';
			sprintf(hex_fmt, "%02x", b[i]);
			*sp++ = hex_fmt[0];
			*sp++ = hex_fmt[1];
			}

		else if ( (b[i] < ' ' || b[i] > 126) && (format & ESC_DOT) )
			{
			*sp++ = '.';
			}

		else
			{
			*sp++ = b[i];
			}
		}

	*sp++ = '\0'; // NUL-terminate.
	tmp_len = sp - s;

	if ( (format & ESC_SER) )
		{
		char* result = new char[tmp_len + 16];
		snprintf(result, tmp_len + 16, "%u ", tmp_len - 1);
		tmp_len += strlen(result);
		memcpy(result + strlen(result), s, sp - s);
		delete[] s;
		s = result;
		}

	if ( len )
		*len = tmp_len;

	return s;
	}

std::ostream& String::Render(std::ostream& os, int format) const
	{
	char* tmp = Render(format);
	os << tmp;
	delete[] tmp;
	return os;
	}

std::istream& String::Read(std::istream& is, int format)
	{
	if ( (format & String::ESC_SER) )
		{
		int len;
		is >> len; // Get the length of the string

		char c;
		is.read(&c, 1); // Eat single whitespace

		char* buf = new char[len + 1];
		is.read(buf, len);
		buf[len] = '\0'; // NUL-terminate just for safety

		Adopt((u_char*)buf, len + 1);
		}
	else
		{
		std::string str;
		is >> str;
		Set(str);
		}

	return is;
	}

void String::ToUpper()
	{
	for ( int i = 0; i < n; ++i )
		if ( islower(b[i]) )
			b[i] = toupper(b[i]);
	}

String* String::GetSubstring(int start, int len) const
	{
	// This code used to live in zeek.bif's sub_bytes() routine.
	if ( start < 0 || start > n )
		return nullptr;

	if ( len < 0 || len > n - start )
		len = n - start;

	return new String(&b[start], len, true);
	}

int String::FindSubstring(const String* s) const
	{
	return util::strstr_n(n, b, s->Len(), s->Bytes());
	}

String::Vec* String::Split(const String::IdxVec& indices) const
	{
	size_t i;

	if ( indices.empty() )
		return nullptr;

	// Copy input, ensuring space for "0":
	IdxVec idx(1 + indices.size());

	idx[0] = 0;
	idx.insert(idx.end(), indices.begin(), indices.end());

	// Sanity checks.
	for ( i = 0; i < idx.size(); ++i )
		if ( idx[i] >= n || idx[i] < 0 )
			idx[i] = 0;

	// Sort it:
	sort(idx.begin(), idx.end());

	// Shuffle vector so duplicate entries are used only once:
	IdxVecIt end = unique(idx.begin(), idx.end());

	// Each element in idx is now the start index of a new
	// substring, and we know that all indices are within [0, n].
	//
	Vec* result = new Vec();
	int last_idx = -1;
	int next_idx;
	i = 0;

	for ( IdxVecIt it = idx.begin(); it != end; ++it, ++i )
		{
		int len = (it + 1 == end) ? -1 : idx[i + 1] - idx[i];
		result->push_back(GetSubstring(idx[i], len));
		}

	return result;
	}

VectorVal* String::VecToPolicy(Vec* vec)
	{
	auto result = make_intrusive<VectorVal>(id::string_vec);

	for ( unsigned int i = 0; i < vec->size(); ++i )
		{
		String* string = (*vec)[i];
		auto val = make_intrusive<StringVal>(string->Len(), (const char*)string->Bytes());
		result->Assign(i, std::move(val));
		}

	return result.release();
	}

String::Vec* String::VecFromPolicy(VectorVal* vec)
	{
	Vec* result = new Vec();

	for ( unsigned int i = 0; i < vec->Size(); ++i )
		{
		auto v = vec->StringAt(i);
		if ( ! v )
			continue;

		String* string = new String(*v);
		result->push_back(string);
		}

	return result;
	}

char* String::VecToString(const Vec* vec)
	{
	std::string result("[");

	for ( String::VecCIt it = vec->begin(); it != vec->end(); ++it )
		{
		result += (*it)->CheckString();
		result += ",";
		}

	result += "]";

	return strdup(result.c_str());
	}

bool StringLenCmp::operator()(String* const& bst1, String* const& bst2)
	{
	return _increasing ? (bst1->Len() < bst2->Len()) : (bst1->Len() > bst2->Len());
	}

std::ostream& operator<<(std::ostream& os, const String& bs)
	{
	char* tmp = bs.Render(String::EXPANDED_STRING);
	os << tmp;
	delete[] tmp;
	return os;
	}

int Bstr_eq(const String* s1, const String* s2)
	{
	if ( s1->Len() != s2->Len() )
		return 0;

	if ( ! s1->Bytes() || ! s2->Bytes() )
		// memcmp() arguments should never be null, so help avoid that
		return s1->Bytes() == s2->Bytes();

	return memcmp(s1->Bytes(), s2->Bytes(), s1->Len()) == 0;
	}

int Bstr_cmp(const String* s1, const String* s2)
	{
	int n = std::min(s1->Len(), s2->Len());
	// memcmp() arguments should never be null, so help avoid that
	// (assuming that we only ever have null pointers when lengths are zero).
	int cmp = n == 0 ? 0 : memcmp(s1->Bytes(), s2->Bytes(), n);

	if ( cmp || s1->Len() == s2->Len() )
		return cmp;

	// Compared equal, but one was shorter than the other.  Treat
	// it as less than the other.
	if ( s1->Len() < s2->Len() )
		return -1;
	else
		return 1;
	}

String* concatenate(std::vector<data_chunk_t>& v)
	{
	int n = v.size();
	int len = 0;
	int i;
	for ( i = 0; i < n; ++i )
		len += v[i].length;

	char* data = new char[len + 1];

	char* b = data;
	for ( i = 0; i < n; ++i )
		{
		memcpy(b, v[i].data, v[i].length);
		b += v[i].length;
		}

	*b = '\0';

	return new String(true, (byte_vec)data, len);
	}

String* concatenate(String::CVec& v)
	{
	int n = v.size();
	int len = 0;
	int i;
	for ( i = 0; i < n; ++i )
		len += v[i]->Len();

	char* data = new char[len + 1];

	char* b = data;
	for ( i = 0; i < n; ++i )
		{
		memcpy(b, v[i]->Bytes(), v[i]->Len());
		b += v[i]->Len();
		}
	*b = '\0';

	return new String(true, (byte_vec)data, len);
	}

String* concatenate(String::Vec& v)
	{
	String::CVec cv;

	for ( String::VecIt it = v.begin(); it != v.end(); ++it )
		cv.push_back(*it);

	return concatenate(cv);
	}

void delete_strings(std::vector<const String*>& v)
	{
	for ( auto& elem : v )
		delete elem;
	v.clear();
	}

	} // namespace zeek

TEST_SUITE_BEGIN("ZeekString");

TEST_CASE("construction")
	{
	zeek::String s1{};
	CHECK_EQ(s1.Len(), 0);
	CHECK_EQ(s1.Bytes(), nullptr);
	CHECK_EQ(s1, "");

	std::string text = "abcdef";
	zeek::byte_vec text2 = new u_char[7];
	memcpy(text2, text.c_str(), 7);

	zeek::String s2{text2, 6, false};
	CHECK_EQ(s2.Len(), 6);

	zeek::String s3{text2, 6, true};
	CHECK_EQ(s3.Len(), 6);

	zeek::String s4{"abcdef"};
	CHECK_EQ(s4.Len(), 6);

	zeek::String s5{std::string("abcdef")};
	CHECK_EQ(s5.Len(), 6);

	zeek::String s6{s5};
	CHECK_EQ(s6.Len(), 6);

	zeek::String s7{true, text2, 6};
	CHECK_EQ(s7.Len(), 6);
	CHECK_EQ(s7.Bytes(), text2);

	// Construct a temporary reporter object for the next two tests
	zeek::reporter = new zeek::Reporter(false);

	zeek::byte_vec text3 = new u_char[7];
	memcpy(text3, text.c_str(), 7);
	zeek::String s8{false, text3, 6};
	CHECK_EQ(std::string(s8.CheckString()), "<string-with-NUL>");

	zeek::byte_vec text4 = new u_char[7];
	memcpy(text4, text.c_str(), 7);
	text4[2] = '\0';
	zeek::String s9{false, text4, 6};
	CHECK_EQ(std::string(s9.CheckString()), "<string-with-NUL>");

	delete zeek::reporter;

	zeek::byte_vec text5 = (zeek::byte_vec)malloc(7);
	memcpy(text5, text.c_str(), 7);
	zeek::String s10{true, text5, 6};
	s10.SetUseFreeToDelete(1);
	CHECK_EQ(s10.Bytes(), text5);
	}

TEST_CASE("set/assignment/comparison")
	{
	zeek::String s{"abc"};
	CHECK_EQ(s, "abc");

	s.Set("def");
	CHECK_EQ(s, "def");

	s.Set(std::string("ghi"));
	CHECK_EQ(s, "ghi");

	zeek::String s2{"abc"};
	s.Set(s2);
	CHECK_EQ(s, "abc");

	zeek::String s3{"def"};
	s = s3;
	CHECK_EQ(s, "def");
	CHECK_EQ(s, s3);
	CHECK(s2 < s3);

	s.Set("ghi");
	CHECK_FALSE(s < s2);

	std::string text = "abcdef";
	zeek::byte_vec text2 = new u_char[7];
	memcpy(text2, text.c_str(), 7);
	s.Adopt(text2, 7);

	CHECK_EQ(s, "abcdef");
	CHECK_FALSE(s == s2);

	// This is a clearly invalid string and we probably shouldn't allow it to be
	// constructed, but this test covers one if statement in Bstr_eq.
	zeek::String s4(false, nullptr, 3);
	CHECK_FALSE(s4 == s2);

	zeek::String s5{};
	CHECK_LT(s5, s);
	CHECK_FALSE(s < s5);
	}

TEST_CASE("searching/modification")
	{
	zeek::String s{"this is a test"};
	auto* ss = s.GetSubstring(5, 4);
	CHECK_EQ(*ss, "is a");
	delete ss;

	auto* ss2 = s.GetSubstring(-1, 4);
	CHECK_EQ(ss2, nullptr);
	ss2 = s.GetSubstring(s.Len() + 5, 4);
	CHECK_EQ(ss2, nullptr);

	zeek::String s2{"test"};
	CHECK_EQ(s.FindSubstring(&s2), 10);

	s2.ToUpper();
	CHECK_EQ(s2, "TEST");

	zeek::String::IdxVec indexes;
	zeek::String::Vec* splits = s.Split(indexes);
	CHECK_EQ(splits, nullptr);

	indexes.insert(indexes.end(), {4, 7, 9, -1, 30});
	splits = s.Split(indexes);
	CHECK_EQ(splits->size(), 4);
	CHECK_EQ(*(splits->at(0)), "this");
	CHECK_EQ(*(splits->at(1)), " is");
	CHECK_EQ(*(splits->at(2)), " a");
	CHECK_EQ(*(splits->at(3)), " test");

	zeek::String* s3 = concatenate(*splits);
	CHECK_EQ(s.Len(), s3->Len());
	CHECK_EQ(s, *s3);
	delete s3;

	char* temp = zeek::String::VecToString(splits);
	CHECK_EQ(std::string(temp), "[this, is, a, test,]");
	free(temp);

	for ( auto* entry : *splits )
		delete entry;
	delete splits;
	}

TEST_CASE("rendering")
	{
	zeek::String s1("\\abcd\'\"");
	auto* r = s1.Render(zeek::String::ESC_ESC);
	CHECK_EQ(std::string(r), "\\\\abcd\'\"");
	delete[] r;

	r = s1.Render(zeek::String::ESC_QUOT);
	CHECK_EQ(std::string(r), "\\abcd\\\'\\\"");
	delete[] r;

	r = s1.Render(zeek::String::ESC_ESC | zeek::String::ESC_QUOT | zeek::String::ESC_SER);
	CHECK_EQ(std::string(r), "10 \\\\abcd\\\'\\\"");
	delete[] r;

	zeek::byte_vec text = new u_char[6];
	text[0] = 3;
	text[1] = 4;
	text[2] = 5;
	text[3] = 6;
	text[4] = '\\';
	text[5] = '\'';
	zeek::String s2(false, text, 6);

	r = s2.Render(zeek::String::ESC_HEX);
	CHECK_EQ(std::string(r), "\\x03\\x04\\x05\\x06\\\'");
	delete[] r;

	int test_length = 0;
	r = s2.Render(zeek::String::ESC_DOT, &test_length);
	CHECK_EQ(std::string(r), "....\\\'");
	CHECK_EQ(test_length, 7);
	delete[] r;

	r = s2.Render(zeek::String::ZEEK_STRING_LITERAL);
	CHECK_EQ(std::string(r), "\\x03\\x04\\x05\\x06\\\\\\\'");
	delete[] r;

	std::ostringstream os1;
	// This uses ESC_HEX, so it should be the same as the test above
	os1 << s2;
	CHECK_EQ(os1.str(), "\\x03\\x04\\x05\\x06\\\'");

	std::ostringstream os2;
	s2.Render(os2, zeek::String::ESC_HEX);
	CHECK_EQ(os2.str(), "\\x03\\x04\\x05\\x06\\\'");
	}

TEST_CASE("read")
	{
	std::string text1("5 abcde");
	std::istringstream iss1(text1);
	zeek::String s1{};
	s1.Read(iss1);
	CHECK_EQ(s1, "abcde");

	std::string text2("abcde");
	std::istringstream iss2(text2);
	zeek::String s2{};
	// Setting to something else disables reading the serialization format
	s2.Read(iss2, zeek::String::ESC_HEX);
	CHECK_EQ(s2, text2);
	}

TEST_CASE("misc")
	{
	std::vector<const zeek::String*> sv = {new zeek::String{}, new zeek::String{}};
	CHECK_EQ(sv.size(), 2);
	zeek::delete_strings(sv);
	CHECK_EQ(sv.size(), 0);

	std::vector<zeek::data_chunk_t> dv = {{5, "abcde"}, {6, "fghijk"}};
	auto* s = zeek::concatenate(dv);
	CHECK_EQ(*s, "abcdefghijk");
	delete s;

	std::vector<zeek::String*> sv2 = {new zeek::String{"abcde"}, new zeek::String{"fghi"}};
	std::sort(sv2.begin(), sv2.end(), zeek::StringLenCmp(true));
	CHECK_EQ(*(sv2.front()), "fghi");
	CHECK_EQ(*(sv2.back()), "abcde");

	std::sort(sv2.begin(), sv2.end(), zeek::StringLenCmp(false));
	CHECK_EQ(*(sv2.front()), "abcde");
	CHECK_EQ(*(sv2.back()), "fghi");

	for ( auto* entry : sv2 )
		delete entry;
	}

TEST_SUITE_END();
