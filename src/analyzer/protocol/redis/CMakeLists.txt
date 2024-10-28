spicy_add_analyzer(
    NAME Redis
    PACKAGE_NAME spicy-redis
    SOURCES resp.spicy resp.evt redis.spicy zeek_redis.spicy
    SCRIPTS __load__.zeek main.zeek
)
