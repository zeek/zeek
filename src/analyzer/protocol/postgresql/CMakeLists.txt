spicy_add_analyzer(
    NAME PostgreSQL
    PACKAGE_NAME spicy-postgresql
    SOURCES postgresql.spicy postgresql.evt postgresql_zeek.spicy
    MODULES PostgreSQL PostgreSQL_Zeek)
