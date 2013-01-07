
// This is a wrapper around the reporter's functionality needed by HILTI so
// that we don't need to include Bro's main reporter.h, which conflicts with
// some of the HILTI include files.

#ifndef  HILTI_LOCAL_REPORTER
#define  HILTI_LOCAL_REPORTER

namespace bro {
namespace hilti {
namespace reporter {

extern void         __error(const char* msg);
extern void         __weird(Connection* conn, const char* msg);
extern void         __push_location(const char* file, int line);
extern void         __pop_location();
extern  char*       __current_location();

inline void   push_location(const string& file, int line) { __push_location(file.c_str(), line); }
inline void   pop_location()                              { __pop_location(); }
inline void   error(const string& msg)                    { __error(msg.c_str()); }
inline void   weird(Connection* conn, const string& msg)  { __weird(conn, msg.c_str()); }

inline string current_location()
	{
	char* s = __current_location();
	string r = s;
	free(s);
	return r;
	}

}
}
}



#endif
