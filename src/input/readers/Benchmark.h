// See the file "COPYING" in the main distribution directory for copyright.

#ifndef INPUT_READERS_BENCHMARK_H
#define INPUT_READERS_BENCHMARK_H


#include "../ReaderBackend.h"

namespace input { namespace reader {

class Benchmark : public ReaderBackend {
public:
    Benchmark(ReaderFrontend* frontend);
    ~Benchmark();
    
    static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Benchmark(frontend); }
    
protected:
	
	virtual bool DoInit(string path, int mode, int arg_num_fields, const threading::Field* const* fields);

	virtual void DoFinish();

	virtual bool DoUpdate();

private:

	virtual bool DoHeartbeat(double network_time, double current_time);

	unsigned int num_fields;

	double CurrTime();

	const threading::Field* const * fields; // raw mapping		
	
	threading::Value* EntryToVal(TypeTag Type, TypeTag subtype);

	int mode;
	int num_lines;

	double multiplication_factor;
	int spread;
	double autospread;
	int autospread_time;
	int add;
	int stopspreadat;
	double heartbeatstarttime;
	double timedspread;

	string RandomString(const int len);

};


}
}

#endif /* INPUT_READERS_BENCHMARK_H */
