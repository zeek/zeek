spicy_add_analyzer(
    NAME NATMapping
    PACKAGE_NAME spicy-nat-mapping
    SOURCES natmapping.spicy natpmp.spicy pcp.spicy natmapping.evt
    MODULES NATMapping NATPMP PCP)
