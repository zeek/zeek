spicy_add_analyzer(
    NAME RESP
    PACKAGE_NAME spicy-resp
    SOURCES resp.spicy resp.evt redis.spicy zeek_redis.spicy
    SCRIPTS __load__.zeek main.zeek
)
