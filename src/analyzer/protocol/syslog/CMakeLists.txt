spicy_add_analyzer(
    NAME Syslog
    SOURCES syslog.spicy syslog.evt syslog-tcp.spicy LEGACY legacy
    MODULES Syslog SyslogTCP)
