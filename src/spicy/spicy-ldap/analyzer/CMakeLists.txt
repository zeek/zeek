spicy_add_analyzer(
    NAME LDAP
    PACKAGE_NAME spicy-ldap
    SOURCES ldap.spicy ldap.evt ldap_zeek.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
