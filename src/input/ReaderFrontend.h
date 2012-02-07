// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERFRONTEND_H
#define INPUT_READERFRONTEND_H

#include "../threading/MsgThread.h"
#include "../threading/SerializationTypes.h"

namespace input {

class Manager;

class ReaderFrontend {
public:
	ReaderFrontend(bro_int_t type);

	virtual ~ReaderFrontend();

	void Init(string arg_source);

	void Update();

	void AddFilter( const int id, const int arg_num_fields, const threading::Field* const* fields );

	void Finish();

	/**
	 * Returns a descriptive name for the reader, including the type of
	 * the backend and the source used.
	 *
	 * This method is safe to call from any thread.
	 */
	string Name() const;

protected:
	friend class Manager;

	const string Source() const	{ return source; };	

	string ty_name;	// Name of the backend type. Set by the manager.

private:
	ReaderBackend* backend;	// The backend we have instanatiated.	
	string source;
	bool disabled;		// True if disabled.
	bool initialized;	// True if initialized.	

};

}


#endif /* INPUT_READERFRONTEND_H */


