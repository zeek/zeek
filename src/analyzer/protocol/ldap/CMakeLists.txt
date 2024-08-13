spicy_add_analyzer(
    NAME LDAP
    PACKAGE_NAME spicy-ldap
    SOURCES ldap.spicy ldap.evt asn1.spicy ldap_zeek.spicy
    MODULES LDAP ASN1 LDAP_Zeek)
