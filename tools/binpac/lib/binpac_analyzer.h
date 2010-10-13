#ifndef binpac_an_h
#define binpac_an_h

namespace binpac {

// TODO: Add the Done() function

// The interface for a connection analyzer
class ConnectionAnalyzer {
public:
	virtual ~ConnectionAnalyzer() {}
	virtual void NewData(bool is_orig,
	                     const u_char *begin_of_data, 
	                     const u_char *end_of_data) = 0;
};

// The interface for a flow analyzer
class FlowAnalyzer {
public:
	virtual ~FlowAnalyzer() {}
	virtual void NewData(const u_char *begin_of_data, 
	                     const u_char *end_of_data) = 0;
};

}  // namespace binpac

#endif  // binpac_an_h
