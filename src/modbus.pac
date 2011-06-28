
analyzer ModbusTCP withcontext {
    connection:                 ModbusTCP_Conn;
    flow:                       ModbusTCP_Flow;
};

%include modbus-protocol.pac
%include modbus-analyzer.pac

