#! /usr/bin/env python
#
# this script finds the end of the syslog file, and then watches
#  for new events to send to Bro.  Actually they are reformatted
#  as Broccoli events, and written to stdout. Then some other
#  process can send them to Bro.
#
# started as a perl script from unknon source
# modified for syslog parsing by Scott Campbell
# more options added by Brian Tierney
#
# CHANGELOG: started 07/07/05
# fixed IPv6 support in sshd login analysis
# 07/12/05 change logic in ssh deny parsing to only look at what
#          we want rather than reverse.
#
"""
script that looks at interesting entries in a syslog file
and print out information in a format that broccoli understands
"""
import optparse, logging, re, time
import select, socket, sys, threading

RE_SSH = re.compile(r"[\w,\s,\W]*sshd") 
RE_SSH_ACCEPT = re.compile(r"[\w,\s,\W]*Accept")
# all Failures; leads to false possitives
# RE_SSH_FAIL = re.compile(r"[\w,\s,\W]*Failed")
# just failed passwords
RE_SSH_FAIL = re.compile(r"[\w,\s,\W]*Failed[\s]*password")
RE_SSH_FAIL_ILLEGAL_USER = re.compile(r"[\w,\s,\W]*illegal[\s]*user|[\w,\s,\W]*invalid[\s]*user")
RE_SSH_EXCLUDE = re.compile(r"[\w,\s,\W]*com\.apple\.SecurityServer")

# only do failures for now

RE_SUDO = re.compile(r"[\w,\s,\W]*sudo[\w,\s,\W]+failure|[\w,\s,\W]*sudo[\w,\s,\W]+incorrect password attempts")
RE_SUDO_FORMAT1 = re.compile(r"[\w,\s,\W]*sudo[\w,\s,\W]+failure")
RE_SUDO_FORMAT2 = re.compile(r"[\w,\s,\W]*sudo[\w,\s,\W]+incorrect password attempts") 

RE_SU_SUCCESS = re.compile(r"[\w,\s\W]*su: \(|[\w,\s,\W]*su: SU |[\w,\s,\W]*su[\w,s,\W]+session opened") 
RE_SU_FORMAT1 = re.compile(r"[\w,\s,\W]*session opened for user [\w,\W]+ by [\w,\W]+")        
RE_SU_FORMAT2 = re.compile(r"[\w,\s,\W]*su:[\s]*\(to [\w]+\) [\w]+")        
RE_SU_FORMAT3 = re.compile(r"[\w,\s,\W]*su: SU")        


RE_SU_FAIL = re.compile(r"[\w,\s\W]* BAD SU |[\w,\s,\W]* FAILED SU |[\w,\s,\W]*su[\w,\s,\W]*authentication failure") 
RE_SU_FAIL_FORMAT1 = re.compile(r"[\w,\s,\W]*authentication failure")
RE_SU_FAIL_FORMAT2 = re.compile(r"[\w,\s,\W]*FAILED SU")
RE_SU_FAIL_FORMAT3 = re.compile(r"[\w,\s,\W]*BAD SU")

RE_GRID = re.compile(r"[\w,\s\W]* GRAM")
RE_GRID_AUTHORIZE_LOCALUSER = re.compile(r"[\w,\s,\W]* Authorized as local user")
RE_GRID_AUTHORIZE_LOCALUID = re.compile(r"[\w,\s,\W]* Authorized as local uid:")
RE_GRID_AUTHORIZE_LOCALGID = re.compile(r"[\w,\s,\W]* and local gid:")
RE_GRID_AUTHENTICATE = re.compile(r"[\w,\s,\W]* Authenticated globus user:")
RE_GRID_CONNECT = re.compile(r"[\w,\s,\W]* Got connection ")
RE_GRID_SERVICE = re.compile(r"[\w,\s,\W]* Requested service: ")
RE_GRID_INFO = re.compile(r"[\w,\s,W]*gridinfo")

# not done: generate Bro event for these too
RE_NEWUSER = re.compile(r"[\w,\s,\W]*new user:[\w,\s,\W]+useradd")

# not done: generate Bro event for user root sending mail to yahoo, gmail, hotmail, aol, etc.
#	(maybe even any .com ?)
RE_ROOT_EMAIL = re.compile(r"[\w,\s,\W]*sendmail[\w,\s,\W]+root[\w,\s,\W]+to `[\w,\s,\W]+\.com")


class HeartBeatThread(threading.Thread):
    """
    HeartBeat class that inherits from Python Thread class 
    """
    def __init__(self, sleep_seconds): 
        threading.Thread.__init__(self)
        self._sleeptime = sleep_seconds 

    def run(self):
        """
        Sends out a heartbeat event, then goes to sleep for 15 minutes
        """
        addr = socket.gethostbyname(socket.gethostname())
        heartbeat_string = "Syslog_daemon_heartbeat"
        while True: 
            time_double = time.time()
            print "heartbeat_event double=%d addr=%s string=%s" % (time_double, addr, heartbeat_string)
            time.sleep(self._sleeptime) 

def time_conversion(month, date, clocktime):
    """
    Convert time string to double, need to handle the
    year field
    """ 
    year = time.asctime().split()[-1:][0] 
    time_str = " ".join((month, date, clocktime, year)) 
    try:
        time_tuple = time.strptime(time_str, "%b %d %H:%M:%S %Y")
    except:
        log.error( "time.strptime error converting %s" % time_str )
        return 0.0
    time_double = time.mktime(time_tuple) 
    return time_double
    
def check_ip(ip):
    """
	Covert hostname to IP if necessary, and check if valid IP
    """

    try:
        ip = socket.gethostbyname(ip)
    except:
        log.error( "Error converting %s to an IP " % ip )
        return ""

    # if passed in something that looked like an IP, gethostbyname might not return an error, so best to check
    try:
        ips = ip.split('.')
    except:
        log.error("Error spliting IP into components: %s" % ip)
        return ""

    if len(ips) == 4:
        if int(ips[0]) < 256 and int(ips[1]) < 256 and int(ips[2]) < 256 and int(ips[3]) < 256:
            return ip
        else:
            return ""
    else:
        return ""

def find_user(fields):
    """
    Find the user in a list of fields where user is the name in user=name
    """
    user = "unknown"
    for f in fields: 
        try:
            user1, user2 = f.split('=')
            if user1 == 'user' or user1 == 'ruser':
                if user2 != "": 
                    return user2
        except: 
            pass 
    return user 

def parse_ssh(line, line_cnt): 
    """
    print out the ssh fields into the broccoli format

    Note: still needs to handle odd syslog formats, such as (double set of timestamps):
      Jan  1 00:03:44 127.0.0.1 2005-12-31 21:51:10.163447500 isthiswhatyouwant.jay.lbl.gov sshd[] PAM: Authentication failure for ldoolitt from astound-69-42-20-231.ca.astound.net

    There are many different formats, but the following seem fairly consistant:
        for username
        from hostname
     so look for works "for" and "from", and then take the fields after that

    """ 
    
    fields = line.split() 
    time_double = time_conversion(fields[0], fields[1], fields[2]) 
    # look for 'from' hostname
    n = 0
    from_ip = ""
    for f in fields:
        if f == "from":
            from_ip = fields[n+1]
            break
        n += 1

    # check for valid IP (some look like this: "::ffff:128.3.60.86")
    ipf = from_ip.split(':')
    if len(ipf) > 1:
        ip = ipf[len(ipf) - 1]
    else:
        ip = ipf[0]

    # verify that this is a valid IP address
    ip = check_ip(ip)
    lh_ip = check_ip(fields[3])

    success = False
    failed = False
    auth_type = "unknown"
    username = "unknown"

    if RE_SSH_ACCEPT.match(line):
        success = True
        try:
            auth_index = fields.index('Accepted')
            username_index = fields.index('for')
        except ValueError:
            log.error( "Error: sshd line with unknown format: line %d,%s" % (line_cnt, line))
            return 
            
        auth_type = fields[auth_index +1] 
        username = fields[username_index +1]

    if RE_SSH_FAIL.match(line) and not RE_SSH_EXCLUDE.match(line): 
        failed = True 
        try:
            auth_index = fields.index('Failed')
            username_index = fields.index('for') 
        except ValueError:
            log.error( "Error: sshd line with unknown format: line %d,%s" % (line_cnt, line))
            return 
        
        auth_type = fields[auth_index + 1] 
        if RE_SSH_FAIL_ILLEGAL_USER.match(line):
            username = fields[username_index +3] 
        else:
            username = fields[username_index +1]
    
    if ip and lh_ip:
        if success: 
            print "ssh_login double=%d addr=%s addr=%s string=%s string=%s" % (time_double, ip, lh_ip, username, auth_type)
           
        if failed:
            print "ssh_fail_login double=%d addr=%s addr=%s string=%s string=%s" % (time_double, ip, lh_ip, username, auth_type)
           
    else:
        log.error( "Error: sshd line with unknown format: line %d" % (line_cnt))
 
  
def parse_sudo(line):
    """
    print out the sudo fields in the broccoli format 
    Supports these formats
        1. host sudo(pam_unix)[5835]: authentication failure; logname=user uid=0 euid=0 tty=pts/4 ruser= rhost=  user=user
        2. host sudo:    user: 3 incorrect password attempts ;
        TTY=pts/11 ; PWD=directory COMMAND=/bin/ls

    """ 
    
    fields = line.split()
    time_double = time_conversion(fields[0], fields[1], fields[2]) 

    # look for user
    user = "unknown" 
    if RE_SUDO_FORMAT1.match(line): 
        user = find_user(fields)        
        
    if RE_SUDO_FORMAT2.match(line): 
        user = fields[5] 

    if user == "":
        user = "unknown" 

    # check if need to convert to IP addr
    lh_ip = check_ip(fields[3])

    if user == "unknown":
        log.debug("unhandled user in next line" )
        log.debug(line)
    
    print "failed_sudo double=%d addr=%s string=%s " % (time_double, lh_ip, user )

def parse_su_success(line, line_cnt):
    """
    print out the su fields in the broccoli format

    This one is hard because there are MANY formats used for this, including: 
        This function handles these 3 formats
        1. session opened for user by user
        2. (to root) user
        3. su: SU 
        
        user to root
        'su root' succeeded for user 

        Not quite done: does not always correctly find logname or username
    """
    fields = line.split()
    time_double = time_conversion(fields[0], fields[1], fields[2]) 
    logname = "unknown"
    user = "unknown" 
     
    if RE_SU_FORMAT1.match(line): 
        try:
            index = fields.index('user')
        except ValueError:
            log.error( "Error: su line with unknown format: line %d,%s" % (line_cnt, line))
            return 
            
        logname = fields[index +1] 
        user = fields[index +3] 
    
    if RE_SU_FORMAT2.match(line): 
        logname = fields[6].rstrip(')')
        user = fields[7]
    
    if RE_SU_FORMAT3.match(line): 
        try:
            index = fields.index('SU')
        except ValueError:
            log.error( "Error: su line with unknown format: line %d,%s" % (line_cnt, line))
            return 
        
        user = fields[index +1] 

    if user == "unknown": 
        log.debug("unhandled case on line: %d " % line_cnt)
        log.debug(line)
    lh_ip = check_ip(fields[3])
    print "successful_su double=%d addr=%s string=%s string=%s" % (time_double, lh_ip, logname, user) 
     

def parse_su_fail(line, line_cnt):
    """
    print out the su fields in the broccoli format
    This one is hard because there are MANY formats used for this, including:
        authentication failure; 
        logname=user uid=uid euid=0 tty= ruser=jason rhost=  user=root
        
        We match this case only
        1. BAD SU user to root
        These cases are not handled
        FAILED SU (to root) user
        'su root' failed for user 
    """
    fields = line.split() 
    time_double = time_conversion(fields[0], fields[1], fields[2]) 
    user = "unknown"
    
    if RE_SU_FAIL_FORMAT1.match(line):
        user = find_user(fields) 
    
    if RE_SU_FAIL_FORMAT2.match(line): 
        fail_test1 = False
        fail_test2 = False
        try:
            index = fields.index('to') 
        except:
            fail_test1 = True
        try:
            index = fields.index('(to') 
        except:    
            fail_test2 = True 
        
        if fail_test1 and fail_test2:
            log.error("su fail: -to- not found: line %d" % line_cnt)
        else: 
            user = fields[index +1]
    
    if RE_SU_FAIL_FORMAT3.match(line): 
        try:
            index = fields.index('to') 
            user = fields[index - 1]
        except:
            log.error("su fail: -to- not found: line %d " % line_cnt)
        
    if user == "":
        user = "unknown" 

    if user == "unknown":
        log.debug("unhandled case on line %d" % line_cnt)
        log.debug(line)

    lh_ip = check_ip(fields[3])

    print "failed_su double=%d addr=%s string=%s" % (time_double, lh_ip, user) 

def parse_gate(line, line_cnt):
    """
    print out the globus fields in the broccoli format

    Not finished
    """
    fields = line.split() 
    time_double = time_conversion(fields[0], fields[1], fields[2]) 
    
    if RE_GRID_AUTHORIZE_LOCALUSER.match(line): 
        gate_ip = check_ip(fields[3])
        pid = fields[5].strip("gatekeeper[]:") 
        user = fields[10]
        print "gatekeeper_local_user addr=%s count=%s string=%s string=Authorized" % (gate_ip, pid, user) 
        
    elif RE_GRID_AUTHORIZE_LOCALUID.match(line):
        gate_ip = check_ip(fields[3])
        pid = fields[5].strip("gatekeeper[]:")
        uid = fields[10]
        print "gatekeeper_local_uid addr=%s count=%s string=%s string=Authorized" % (gate_ip, pid, uid)
    elif RE_GRID_AUTHORIZE_LOCALGID.match(line):
        gate_ip = check_ip(fields[3])
        pid = fields[5].strip("gatekeeper[]:")
        gid = fields[9]
        print "gatekeeper_local_uid addr=%s count=%s string=%s string=Authorized" % (gate_ip, pid, gid)
    elif RE_GRID_AUTHENTICATE.match(line):
        print "authenticate"
        gate_ip = check_ip(fields[3])
        pid = fields[5].strip("gatekeeper[]:")
        dn = " ".join(fields[9:])
        print "gatekeeper_auth_user addr=%s count=%s string=%s string=Authorized" % (gate_ip, pid, dn) 
    elif RE_GRID_CONNECT.match(line): 
        gate_ip = check_ip(fields[3])
        src_ip = check_ip(fields[8])
        pid = fields[5].strip("gatekeeper[]:")
        print "gateekeeper_connect double=%d addr=%s addr=%s count=%s" % (time_double, gate_ip, src_ip, pid) 
    elif RE_GRID_SERVICE.match(line): 
        gate_ip = check_ip(fields[3]) 
        pid = fields[5].strip("gatekeeper[]:")
        service = fields[8]
        print "gatekeeper_service double=%d addr=%s count=%s string=%s" % (time_double, gate_ip, pid, service) 
  
    else:
        log.debug("unhandled case on line %d" % line_cnt)
        log.debug(line)
    
    
    

    

    

def parse_newuser(line):
    """
    print out the newuser fields in the broccoli format

    Not finished
    """
    fields = line.split() 
    time_double = time_conversion(fields[0], fields[1], fields[2]) 
    lh_ip = check_ip(fields[3])

    #print "new_user double=%d addr=%s string=%s" % (time_double, lh_ip, user) 

def parse_root_email(line):
    """
    print out the root email fields in the broccoli format

    Not finished
    """
    fields = line.split() 
    time_double = time_conversion(fields[0], fields[1], fields[2]) 
    lh_ip = check_ip(fields[3])

    #print "root_email double=%d addr=%s addr=%s" % (time_double, lh_ip, ip) 



def log_parse(syslog_file, opts):
    """
    Continually parse the log file, and print information to stdout
    """

    line_cnt = 0
    done = 0
    if opts.begin_tail or opts.begin:
        tail = 0
    else:
        tail = 1

    day = int(time.strftime("%d")) # day that program is started
    today = time.strftime("%Y-%m-%d") 

    while not done:
        try:  
            line = syslog_file.readline()
        except Exception, E:
            log.error ("Error reading file. Possibly log file was rotated, so try to reopen " )
            syslog_file.close() 
            fname = "%s/all-%s" % (opts.path, today)
            try:
                syslog_file = open(fname) 
            except:
                log.error( "Error opening syslog file %s " % (fname))
                sys.exit(-1)

        if len(line) == 0 and opts.begin: # if not tailing the file
            done = 1
            log.debug ("End of file. Num lines = %d. Exiting" % line_cnt)
            sys.exit(1);
 
        if len(line) == 0 and opts.begin_tail and tail == 0:
            tail = 1   # start tailing the file
            log.debug ("Reached End of file, now tailing the file") 

        line_cnt += 1
        if not (line_cnt % 50000):
            log.debug ("Processed %d lines" % line_cnt)


	try:
           if RE_SSH.match(line) and ( RE_SSH_ACCEPT.match(line) or RE_SSH_FAIL.match(line) ):
               parse_ssh(line, line_cnt) 
             
           elif RE_SUDO.match(line):
               parse_sudo(line) 
             
           elif RE_SU_SUCCESS.match(line):
               parse_su_success(line, line_cnt)
 
           elif RE_SU_FAIL.match(line):
               parse_su_fail(line, line_cnt)

           elif RE_GRID.match(line):
               parse_gate(line, line_cnt) 

           elif RE_NEWUSER.match(line):
               parse_newuser(line.split()) 

           elif RE_ROOT_EMAIL.match(line):
               parse_root_email(line.split()) 

           else:
               #This outputs too much information, this should be turned
               #on if we set verbose to the next level
               #log.debug("Not matching line: %s" % line)
               pass 

        except:
            log.error ("Error parsing log file. Corrupt log entry: %s" % line )
	    continue

        sys.stdout.flush()

        if tail: # go slow if tailing the file
            select.select([], [], [], .01) 
            # if tailing the file and path is set, 
            #need to roll over to a new file at midnight
            if opts.path:
                check_day = int(time.strftime("%d"))
                if day != check_day:
                    # new day, so open new file
                    syslog_file.close() 
                    today = time.strftime("%Y-%m-%d") 
                    fname = "%s/all-%s" % (opts.path, today)
                    log.debug( "New Day, so opening new syslog file: %s " % (fname))
                    try:
                        syslog_file = open(fname) 
                    except:
                        log.error( "Error opening syslog file %s " % (fname))
                        sys.exit(-1)
                    day = check_day 
                    line_cnt = 0

 
def log_open(opts):
    """
    open the logfile at the beginning or end
    depending on the command line arguments
    """
    global log
    logging.basicConfig()
    log = logging.getLogger("sys2broccoli")

    if opts.verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.NOTSET) 
    
    if opts.path and opts.start_date: 
        fname = "%s/all-%s" % (opts.path, opts.start_date)
    else:
        fname = opts.syslog_file
    
    try:
        syslog_file = open(fname) 
    except:
        log.error( "Error opening syslog file %s " % (fname))
        sys.exit(-1)

    if opts.begin or opts.begin_tail:
        log.debug("Will start at the beginning of the file.")    
    else:
        syslog_file.seek(0, 2)

    log_parse(syslog_file, opts)        
            
         

def main():
    """
    Read in the command line arguments, then open the log
    """
    parser = optparse.OptionParser()
    begin_help = """Start at the begining of the syslog file,
                    and exit when get to the end""" 
    parser.add_option("-b", action="store_true", dest="begin", 
                      help=begin_help, default=False)
    begin_tail_help = """Start at the begining of the syslog file, 
                         and tail the file when get to the end""" 
    parser.add_option("-B", action="store_true", dest="begin_tail", 
                     help=begin_tail_help, default=False)
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", 
                      help="be more verbose", default=False)
    parser.add_option("-f", "--file", action="store", dest="syslog_file", 
                      help="Location of the syslog file.", 
                      default="/var/log/syslog")
    # these are for use on syslog.lbl.gov
    parser.add_option("-d", "--dir", action="store", dest="path", 
                      help="Directory of the archived syslog files.")
    parser.add_option("-t", "--date", action="store", dest="start_date", 
                      help="Date of file to process.", default=False)
    opts, args = parser.parse_args()
    heartbeat = HeartBeatThread(900)
    heartbeat.setDaemon(True)
    heartbeat.start() 
    log_open(opts) 
    


if __name__ == "__main__": main()
