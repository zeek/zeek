// $Id: capstats.cc 6813 2009-07-07 18:54:12Z robin $
// 
// Counts captured packets. 
// 
// Robin Sommer <robin@icir.org>

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <getopt.h>
#include <string.h>
#include <pcap.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <iostream>
#include <syslog.h>

#include "config.h"

extern char Version[];

#ifdef USE_DAG
# include <dagapi.h>
// Length of ERF Header before Ethernet header.
# define DAG_ETH_ERFLEN 18
# define EXTRA_WINDOW_SIZE (4 * 1024 * 1024)
#endif 

bool CheckPayload = false;
bool WritePackets = false;
bool CheckSize = false;
bool UseDag = false;
bool UseSyslog = false;
const char *Filter;
const char *Interface = 0;
const char *OutputFile = 0;
int Interval = 0;
int Payload = 0;
int SnapLen = 8192;
int NumberInts = 0;
int UseSelect = false;
unsigned int Size = 0;
pcap_dumper_t *Dumper;

bool GotBreak = false;
bool GotAlarm = false;

double current_time();

struct Stats {
    unsigned long packets;
    unsigned long bytes;
    unsigned long size_mismatches;
    unsigned long payload_mismatches;
    unsigned long dag_drops;
    unsigned long dag_all;
    unsigned long proto[256];
    unsigned long non_ip;
    double start;

    Stats() { clear(); }

    void clear() {
        memset(proto, sizeof(proto), 0);
        packets = bytes = size_mismatches = payload_mismatches = non_ip = 0;
        dag_drops = dag_all = 0;
        start = current_time();
    }
};

Stats Total;
Stats Current;

unsigned long HdrSize = 14; // Ethernet

pcap_t* Pcap = 0;
struct bpf_program* Bpf = 0;
int Dag = -1;

const char* fmt_log(const char* prefix, const char* fmt, va_list ap)
{
    const int SIZE = 32768;
    static char buffer[SIZE];
    int n = 0;

    n += snprintf(buffer + n, SIZE - n, "%s: ", prefix);
	n += vsnprintf(buffer + n, SIZE - n, fmt, ap);

    strcat(buffer + n, "\n");

    return buffer;
}

void logMsg(const char* msg)
{
    if (UseSyslog) 
        syslog(LOG_NOTICE, "%s", msg);
    else 
        fprintf(stderr, "%.6f %s\n", current_time(), msg);
}

void error(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    const char* msg = fmt_log("error", fmt, ap);
    va_end(ap);
    fputs(msg, stdout);
    exit(1);
}

double current_time()
{
    struct timeval tv;
    if ( gettimeofday(&tv, 0) < 0 )
        error("gettimeofday failed in current_time()");

    return double(tv.tv_sec) + double(tv.tv_usec) / 1e6;
}

void setFilter()
{
    Bpf = new bpf_program;

    if ( pcap_compile(Pcap, Bpf, (char*)Filter, 1, 0) < 0 )
        error("can't compile %s: %s", Filter, pcap_geterr(Pcap));

    if ( pcap_setfilter(Pcap, Bpf) < 0 ) 
        error("can't set filter: %s", pcap_geterr(Pcap));
}

void pcapOpen()
{
    static char errbuf[PCAP_ERRBUF_SIZE];

    Pcap = pcap_open_live((char *)Interface, SnapLen, 1, UseSelect ? 1 : 10, errbuf);

    if ( ! Pcap )
        error("%s", errbuf);

#ifdef HAVE_LINUX
    // Copied from Bro (we generally mimic how Bro is doing non-blocking i/o.)   
    //    We use the smallest time-out possible to return almost immediately if
    //    no packets are available. (We can't use set_nonblocking() as it's
    //    broken on FreeBSD: even when select() indicates that we can read
    //    something, we may get nothing if the store buffer hasn't filled up
    //    yet.)
	if ( pcap_setnonblock(Pcap, 1, errbuf) < 0 )
        error("%s", errbuf);
#endif

	int dl = pcap_datalink(Pcap);
    if ( dl != DLT_EN10MB )
		error("unknown data link type 0x%x", dl);

    if ( Filter )
        setFilter();
}

bool pcapNext(const u_char **pkt, unsigned int *size)
{
    struct pcap_pkthdr* hdr;
    const u_char* data;
    int result;

    if ( UseSelect ) {
        int fd = pcap_fileno(Pcap);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;

        fd_set fd_read;
        FD_ZERO(&fd_read);
        FD_SET(fd, &fd_read);

        if ( select(fd + 1, &fd_read, 0, 0, &timeout) <= 0 ) {
            // Wait a bit to allow packets to arrive for next time.
            // This might look a bit odd (i.e., we could use a larger timeout 
            // right away) but we try to mimic the way Bro operates.
            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 20;
            select(0, 0, 0, 0, &timeout);
            return false;
        }
    }

    result = pcap_next_ex(Pcap, &hdr, &data);

    if ( result < 0 )
        error("no more input");

    if ( result == 0 )
        return false;

    *pkt = data;
    *size = hdr->caplen;

    if ( WritePackets )
        pcap_dump((u_char*) Dumper, hdr, data);

    return true;
}

void pcapStats(unsigned int* pkts, unsigned int* drops)
{
    static pcap_stat stats;
    if ( pcap_stats(Pcap, &stats) < 0 )
        error("can't get pcap stats");

#ifdef HAVE_LINUX
	// Linux clears its counters each time.
    if ( pkts )
        *pkts = stats.ps_recv;

    if ( drops )
        *drops = stats.ps_drop;
#else   
    static pcap_stat *last_stats = 0;

    if ( ! last_stats ) {
        last_stats = new pcap_stat;
        last_stats->ps_recv = 0;
        last_stats->ps_drop = 0;
    }

    if ( pkts )
        *pkts = stats.ps_recv - last_stats->ps_recv;

    if ( drops )
        *drops = stats.ps_drop - last_stats->ps_drop;

    *last_stats = stats;
#endif
}

void pcapClose()
{
    pcap_close(Pcap);
}

void dagOpen()
{
#ifdef USE_DAG
	Dag = dag_open((char*)Interface);
	if ( Dag < 0 )
		error("can't open dag interface %s", Interface);

	int dag_recordtype = dag_linktype(Dag);
	if ( dag_recordtype < TYPE_MIN || dag_recordtype > TYPE_MAX )
		error("dag_linktype");

	if ( dag_recordtype != TYPE_ETH )
		error("unsupported DAG link type 0x%x", dag_recordtype);

	// long= is needed to prevent the DAG card from truncating jumbo frames.
	const char* dag_configure_string = "slen=1500 varlen long=1500";

	if ( dag_configure(Dag, (char*)dag_configure_string) < 0 )
		error("dag_configure");

	if ( dag_attach_stream(Dag, 0, 0, EXTRA_WINDOW_SIZE) < 0 )
		error("dag_attach_stream");

	if ( dag_start_stream(Dag, 0) < 0 )
		error("dag_start_stream");

    // We open a dummy pcap file to get access to pcap data structures.
	Pcap = pcap_open_dead(DLT_EN10MB, 1500);
	if ( ! Pcap )
		error("pcap_open_dead");

    if ( Filter )
        setFilter();

#endif    
}

bool dagNext(const u_char **pkt, unsigned int *size)
{
#ifdef USE_DAG
    struct bpf_insn* fcode = 0;

    if ( Filter ) {
        fcode = Bpf->bf_insns;
        if ( ! fcode )
            error("filter code not valid when extracting DAG packet");
    }

    dag_record_t* r = (dag_record_t*) dag_rx_stream_next_record(Dag, 0);

    if ( ! r ) {
        if ( errno == EAGAIN )
            // Dry.
            return false;

        error("dag_rx_stream_next_record: %s", strerror(errno));
    }

    *size = ntohs(r->rlen) - DAG_ETH_ERFLEN;
    *pkt = (const u_char*) r->rec.eth.dst;
    Current.dag_drops += ntohs(r->lctr);
    Total.dag_drops += ntohs(r->lctr);

    if ( fcode && ! bpf_filter(fcode, (u_char*) *pkt, *size, *size) )
        return false;

    return true;

#else
    return false;
#endif    
}

void dagStats(unsigned int* pkts, unsigned int* drops, const Stats& s)
{
    *pkts = s.dag_all;
    *drops = s.dag_drops;
}

void dagClose()
{
#ifdef USE_DAG
    dag_stop_stream(Dag, 0);
    dag_detach_stream(Dag, 0);
    dag_close(Dag);
#endif 
}

void reportStats(const Stats& s)
{
    unsigned int pkts = 0, drops = 0;
    const int SIZE = 32768;
    static char buffer[SIZE];
    int n = 0;
    int i;
    unsigned long proto_other = 0;

    if ( UseDag )
        dagStats(&pkts, &drops, s);
    else
        pcapStats(&pkts, &drops);

    double dt = current_time() - s.start;

    double pps = s.packets / dt;
    double mbps = s.bytes / dt * 8 / 1000 / 1000;

    n += snprintf(buffer+n, SIZE-n, "pkts=%lu kpps=%.1f kbytes=%lu mbps=%.1f nic_pkts=%u nic_drops=%u",
            s.packets, pps / 1000,
            s.bytes / 1024, mbps,
            pkts, drops);

    for ( i=0; i<256; i++ )
        if ( i != IPPROTO_UDP && i != IPPROTO_TCP && i != IPPROTO_ICMP )
            proto_other += s.proto[i];

    n += snprintf(buffer+n, SIZE-n, " u=%lu t=%lu i=%lu o=%lu nonip=%lu",
                  s.proto[IPPROTO_UDP], s.proto[IPPROTO_TCP], s.proto[IPPROTO_ICMP], proto_other, s.non_ip);

    if ( CheckSize )
        n += snprintf(buffer+n, SIZE-n, " size_mism=%lu", s.size_mismatches);

    if ( CheckPayload )
        n += snprintf(buffer+n, SIZE-n, " payload_mism=%lu", s.size_mismatches);

    logMsg(buffer);

    Current.clear();
}

void alarmHandler(int signo)
{
    GotAlarm = true;
}

void scheduleAlarm()
{
    GotAlarm = false;
    if ( Interval ) {
        signal(SIGALRM, alarmHandler);
        alarm(Interval);
    }
}

void mainLoop()
{
    while ( ! GotBreak ) {        

        if ( GotAlarm ) {
            reportStats(Current);
            scheduleAlarm();

            if ( NumberInts == 1 )
                exit(0);

            if ( NumberInts )
                NumberInts--;
        }

        bool result;
        unsigned int size;
        const u_char* pkt;
        const struct ip *ip;
        const struct ether_header *eh;

        if ( UseDag )
            result = dagNext(&pkt, &size);
        else
            result = pcapNext(&pkt, &size);

        if ( ! result )
            continue;

        eh = (struct ether_header*)pkt;
        if ( ntohs(eh->ether_type) == ETHERTYPE_IP ) {
            ip = (struct ip*)(pkt + HdrSize);
            ++Current.proto[ip->ip_p];
            ++Total.proto[ip->ip_p];
        }
        else {
            ++Current.non_ip;
            ++Total.non_ip;
        }

        size -= HdrSize;
        pkt += HdrSize;

        ++Current.packets;
        ++Total.packets;
        Current.bytes += size;
        Total.bytes += size;

        if ( CheckSize )
            if ( size != Size ) {
                ++Current.size_mismatches;
                ++Total.size_mismatches;
            }

        if ( CheckPayload )
            for ( unsigned int i = 0; i < size; i++ ) {
                if ( pkt[i] != Payload ) {
                    ++Current.payload_mismatches;
                    ++Total.payload_mismatches;
                    break;
                }
            }

    }
}

void breakHandler(int signo)
{
    GotBreak = true;
}

void usage()
{
    printf("capstats [Options] -i interface\n"
           "\n"
           "  -i| --interface <interface>    Listen on interface\n"
           "  -d| --dag                      Use native DAG API\n"
           "  -f| --filter <filter>          BPF filter\n"
           "  -I| --interval <secs>          Stats logging interval\n"
           "  -l| --syslog                   Use syslog rather than print to stderr\n"
           "  -n| --number <count>           Stop after outputting <number> intervals\n"
           "  -N| --select                   Use select() for live pcap (for testing only)\n"
           "  -S| --size <size>              Verify packets to have given <size>\n"
           "  -s| --snaplen <size>           Use pcap snaplen = <size>\n"
           "  -v| --version                  Print version and exit\n"
           "  -w| --write <filename>         Write packets to file\n"
           "\n");

    exit(1);
}

static struct option long_options[] = {
    {"dag", no_argument, 0, 'd'},
    {"filter", required_argument, 0, 'f'},
    {"interface", required_argument, 0, 'i'},
    {"interval", required_argument, 0, 'I'},
    {"number", required_argument, 0, 'n'},
    {"select", no_argument, 0, 'N'},
    {"syslog", no_argument, 0, 'l'},
    {"payload", required_argument, 0, 'p'},
    {"size", required_argument, 0, 'S'},
    {"snaplen", required_argument, 0, 's'},
    {"version", no_argument, 0, 'v'},
    {"write", required_argument, 0, 's'},
    {0, 0, 0, 0}
};

int main(int argc, char **argv)
{
    while (1) {
        char c = getopt_long (argc, argv, "df:i:I:n:Nps:lvw:S:", long_options, 0);

        if ( c == -1 )
            break;

        switch ( c ) {
          case 'd':
            UseDag = true;
            break;

          case 'f':
            Filter = optarg;
            break;

          case 'i':
            Interface = optarg;
            break;

          case 'I':
            Interval = atoi(optarg);
            break;

          case 'l':
            UseSyslog = true;
            break;

          case 'n':
            NumberInts = atoi(optarg);
            break;

          case 'N':
            UseSelect = true;
            break;

          case 'p':
            CheckPayload = true;
            Payload = atoi(optarg);
            break;

          case 'S':
            CheckSize = true;
            Size = atoi(optarg);
            break;

          case 's':
            SnapLen = atoi(optarg);
            break;

          case 'w':
            OutputFile = optarg;
            WritePackets = true;
            break;

          case 'v':
            fprintf(stderr, "capstats %s\n", Version);
            exit(0);
            break;

          default:
            usage();
        }
    }

    if ( optind != argc )
        usage();

    if ( ! Interface )
        error("no interface given");

    openlog("capstats", LOG_PID, LOG_NOTICE);
    syslog(LOG_NOTICE, "starting if=%s interval=%d filter=%s", Interface, Interval, Filter);

    if ( UseDag ) 
        dagOpen();
    else 
        pcapOpen();

    if ( WritePackets ) {
        Dumper = pcap_dump_open(Pcap, OutputFile);
        if (not Dumper) 
            error("can't open pcap dump file: %s", pcap_geterr(Pcap));
    }

    signal(SIGINT, breakHandler);
    signal(SIGTERM, breakHandler);
    scheduleAlarm();

    pcapStats(0, 0);
    mainLoop();  

    reportStats(Current);
    logMsg("\n=== Total\n");
    reportStats(Total);

    if ( UseDag ) 
        dagClose();
    else 
        pcapClose();

    if ( Dumper ) 
        pcap_dump_close(Dumper);

    syslog(LOG_NOTICE, "exiting...");
    return 0;
    }



