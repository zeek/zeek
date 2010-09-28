signature sslworm-probe {
  header ip[9:1] == 6
  header ip[16:4] == local_nets
  header tcp[2:2] == 80
  payload /.*GET \/ HTTP\/1\.1\x0d\x0a\x0d\x0a/
  event "Host may have been probed by Apache/SSL worm"
  }

signature sslworm-vulnerable-probe {
  requires-signature sslworm-probe
  eval sslworm_is_server_vulnerable
  event "Host may have been probed by Apache/SSL worm and is vulnerable"
  }

signature sslworm-exploit {
  header ip[9:1] == 6
  header ip[16:4] == local_nets
  header tcp[2:2] == 443
  eval sslworm_has_server_been_probed
  event "Apache/Worm has tried to exploit host"
  }

signature sslworm-infection {
  header ip[9:1] == 17
  header ip[12:4] == local_nets
  header udp[0:2] == 2002
  eval sslworm_has_server_been_exploited 
  event "Host has been infected by Apache/SSL worm"
}

signature sslworm-udp2002 {
  header ip[9:1] == 17
  header udp[0:2] == 2002
  header udp[2:2] == 2002
  event "Hosts may have been infected by Apache/SSL worm"
  }


