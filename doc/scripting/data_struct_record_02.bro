type Service: record {
    name: string;
    ports: set[port];
    rfc: count;
    };

type System: record {
    name: string;
    services: set[Service];
    };

function print_service(serv: Service): string
    {
    print fmt("  Service: %s(RFC%d)",serv$name, serv$rfc);
    
    for ( p in serv$ports )
        print fmt("    port: %s", p);
    }

function print_system(sys: System): string
    {
    print fmt("System: %s", sys$name);
    
    for ( s in sys$services )
        print_service(s);
    }

event bro_init()
    {
    local server01: System;
    server01$name = "morlock";
    add server01$services[[ $name="dns", $ports=set(53/udp, 53/tcp), $rfc=1035]];
    add server01$services[[ $name="http", $ports=set(80/tcp, 8080/tcp), $rfc=2616]];
    print_system(server01);
    
    
    # local dns: Service = [ $name="dns", $ports=set(53/udp, 53/tcp), $rfc=1035];
    # local http: Service = [ $name="http", $ports=set(80/tcp, 8080/tcp), $rfc=2616];
    # print_service(dns);
    # print_service(http);
    }
