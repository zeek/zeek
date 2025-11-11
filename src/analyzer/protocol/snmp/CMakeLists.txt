spicy_add_analyzer(
    NAME SNMP
    SOURCES snmp.spicy snmp.evt asn1.spicy snmp_zeek.spicy
    MODULES SNMP ASN1 SNMP_Zeek LEGACY legacy)
