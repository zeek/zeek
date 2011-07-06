
#ifndef modbus_h
#define modbus_h

#include "TCP.h"

#include "modbus_pac.h"

class Modbus_Analyzer : public TCP_ApplicationAnalyzer {
public:
        Modbus_Analyzer(Connection* conn);
        virtual ~Modbus_Analyzer();

        virtual void Done();
        virtual void DeliverStream(int len, const u_char* data, bool orig);
        virtual void Undelivered(int seq, int len, bool orig);

        static Analyzer* InstantiateAnalyzer(Connection* conn)
                { return new Modbus_Analyzer(conn); }

        // Put event names in this function
        static bool Available()
                { return modbus_request; }

protected:
        binpac::ModbusTCP::ModbusTCP_Conn* interp;
};

#endif

