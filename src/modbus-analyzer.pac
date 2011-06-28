

connection ModbusTCP_Conn() {
    upflow = ModbusTCP_Flow(true);
    downflow = ModbusTCP_Flow(false);
};


#
# Flow
#
flow ModbusTCP_Flow(is_orig: bool) {
   	flowunit = ModbusTCP_PDU(is_orig) withcontext (connection, this);
};
