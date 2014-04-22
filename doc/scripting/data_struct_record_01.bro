type Service: record {
    name: string;
    ports: set[port];
    rfc: count;
};

function print_service(serv: Service): string
    {
    print fmt("Service: %s(RFC%d)",serv$name, serv$rfc);
    
    for ( p in serv$ports )
        print fmt("  port: %s", p);
    }

event bro_init()
    {
    local dns: Service = [$name="dns", $ports=set(53/udp, 53/tcp), $rfc=1035];
    local http: Service = [$name="http", $ports=set(80/tcp, 8080/tcp), $rfc=2616];
    
    print_service(dns);
    print_service(http);
    }
