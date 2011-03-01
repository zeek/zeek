# $Id: snort.bro 720 2004-11-12 16:45:48Z rwinslow $
#
# Definitions needed for signatures converted by snort2bro.

# Servers for some services.
const dns_servers: set[subnet] = { local_nets } &redef;
const http_servers: set[subnet] = { local_nets } &redef;
const smtp_servers: set[subnet] = { local_nets } &redef;
const telnet_servers: set[subnet] = { local_nets } &redef;
const sql_servers: set[subnet] = { local_nets } &redef;

const aim_servers: set[subnet] = {
	64.12.24.0/24, 64.12.25.0/24, 64.12.26.14/24, 64.12.28.0/24,
	64.12.29.0/24, 64.12.161.0/24, 64.12.163.0/24, 205.188.5.0/24,
	205.188.9.0/24
} &redef;

# Ports for some services.
const http_ports = { 80/tcp, 8000/tcp, 8001/tcp, 8080/tcp };
const oracle_ports = { 1521/tcp };
const non_shellcode_ports = { 80/tcp };
