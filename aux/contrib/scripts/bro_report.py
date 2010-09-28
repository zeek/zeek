#!/usr/bin/env python
#
# Alternate script to generate a report using the alarm and 
#    conn files for a given day. 
# Notes: My experience is that everyone has their own ideas on what
#   Bro reports should look like, so rather than try to please 
#   everyone, we'd like to include several sample report scripts, and
#   encourage people to generate their own script based on the 
#   sample scripts. This is one such example. If you have your
#   own script to contribute, please email to the Bro team.
#
# Brian Tierney, LBL
#
# input: date of report, bro.cfg file, and bro/site/local.site.bro file
# output: a report emailed address specified
#

__doc__="""
   Usage: bro_report.py [-s start_time -e end_time] [-x] -m email_address 
	default start/end time = 24 period ending now
	date format = YYYY-MM-DD-HH-mm
	[-y] put connection logs at the end of the report 
"""

# TO DO:
#  add ability to use report_alarms instead of ignore_alarms
#  add non-html option (for Vern :-) )
#  add css for more formatting options
#

import os, time, sys, datetime, socket, getopt, glob, re 

# initialize globals

# set this for your preferences
ignore_alarms = ["AddressScan", "PortScan", "ScanSummary", "AddressDropped"]
# not yet implemented
report_alarms = []

brohome = os.getenv("BROHOME")
if brohome == None:
    brohome = "/usr/local/bro" # try using this

path = "%s/logs" % brohome
cf = "%s/bin/cf" % brohome 
hf = "%s/bin/hf -l" % brohome 
# this program uses mutt to send email with attachment
# Note: probably want to add something like this to your .muttrc file
#    set from="bro@brohost.mysite.org"
# There is probably a more standard way to make this work...

mutt = "/usr/local/bin/mutt"
bro_local_nets = "%s/site/local.site.bro" % brohome

use_mtime = 1  # if set, use file modification time to find alarm files,
#conn_reports_at_end = 0  # set if want all connection info at end of the report 
########################################################
#		otherwise use file name



def get_file_names(start_time, end_time):
    """
     using stat, get a list of all files modified on a given date
    """

    global alarm_file_list
    global conn_file_list

    print "looking for alarms between %s and %s " % (time.ctime(start_time), time.ctime(end_time))
    alarm_file_list = []
    if use_mtime:
        globstring = "%s/alarm*" % (path)
        alarm_files = glob.glob(globstring)
        cnt = 0
        for afile in alarm_files:
            st = os.stat(afile)
            ctime = st[8]
            mtime = st[9]
            if (mtime >= start_time or ctime >= start_time) and (mtime <= end_time or ctime >= end_time):
                alarm_file_list.append(afile)
                cnt += 1
    else:
        rdate = time.strftime("%y-%m-%d", time.localtime(start_time))
        globstring = "%s/alarm*%s*" % (path,rdate)
        alarm_files = glob.glob(globstring)
        cnt = 0
        for afile in alarm_files:
            alarm_file_list.append(afile)
            cnt += 1

    #print "Using this list of alarm files: ", alarm_file_list

    conn_file_list = []
    globstring = "%s/conn*" % (path)
    conn_files = glob.glob(globstring)
    for cfile in conn_files:
        st = os.stat(cfile)
        ctime = st[8]
        mtime = st[9]
        #if mtime >= start_time and mtime <= end_time:
        if (mtime >= start_time or ctime >= start_time) and (mtime <= end_time or ctime >= end_time):
            conn_file_list.append(cfile)

    #print "Using this list of conn files: ", conn_file_list
    return cnt

########################################################

def get_time(sdate):
    """
	take command line arg and generate time
     """

    if len(sdate.split("-")) == 3:
        yr,mn,dy  = sdate.split("-")
        stime = (int(yr), int(mn), int(dy), 0, 0, 0, 0, 0, -1)
    elif len(sdate.split("-")) == 4:
        yr,mn,dy,hr  = sdate.split("-")
        stime = (int(yr), int(mn), int(dy), int(hr), 0, 0, 0, 0, -1)
    elif len(sdate.split("-")) == 5:
        try:
            yr,mn,dy,hr,min  = sdate.split("-")
        except:
            print "Error parsing date: ", sdate
            usage()
        stime = (int(yr), int(mn), int(dy), int(hr), int(min), 0, 0, 0, -1)
    else:
        print "Invalid data format"
        usage()
    rtime = time.mktime(stime)

    return rtime

########################################################

def get_site_name(broConfig):

    f = open(broConfig)
    lines = f.readlines()
    site_name = "Default"
    for line in lines:
        if line.startswith("BRO_SITE_NAME"):
            site_name = line.split("=")[1]
            site_name = site_name.replace('"','')
    # no way to pass this directly to mutt, need to put in .muttrc instead
    #if line.startswith("BRO_EMAIL_FROM"):
    #    mail_from = line.split("=")[1]
    #    mail_from = site_name.replace('"','')

    return site_name

########################################################
def get_local_nets(localnets):
    """
    reads Bro local.site.bro file to get a list of local networks
    """

    # this ugly thing will match IP addresses
    regexp = re.compile("([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0 -5])\.([01]?\d\d?|2[0-4]\d|25[0-5])")

    f = open(localnets)
    lines = f.readlines()

    local_nets = []
    if len(lines) > 0: 
        for line in lines:
            fields = line.split()
            if len(fields) > 0 and not fields[0].startswith("#"):  # skip comment lines
                #print fields
                for f in fields:
                    match = regexp.match(f)
                    if match:
                        t = f.split("/")
                        local_nets.append(t[0])
    else:
        print "Bro local nets not found. Exiting. "
        sys.exit(-1)

    return local_nets

########################################################

def get_local_host(ip1,ip2,sh,dh,local_nets):
    """
	based on contents of bro site file, determine which host is local
    """
    local_host = ""
    if ip2 != "none":
        #print "debug:", ip1, ip2, sh, dh, local_nets
        # HACK Alert: this will only work for /16 and /24 networks
        for net in local_nets:
            if net.split(".")[2] == "0":  # assume class B
                ipa = "%s.%s.0.0" % (ip1.split(".")[0] , ip1.split(".")[1] ) 
                ipb = "%s.%s.0.0" % (ip2.split(".")[0] , ip2.split(".")[1] ) 
            else: # assume class C
                ipa = "%s.%s.%s.0" % (ip1.split(".")[0] , ip1.split(".")[1], ip1.split(".")[2] ) 
                ipb = "%s.%s.%s.0" % (ip2.split(".")[0] , ip2.split(".")[1], ip2.split(".")[2] ) 

            if ipa == net: 
                local_host = sh
                break
            if ipb == net: 
                local_host = dh
                break
    else:
        local_host = sh
    #print "   found local host: ", local_host

    if local_host == "":  # sometimes see packets not on either net!
        local_host = "host from unknown subnet!"
    return local_host

########################################################

def create_alarm_info(aline, start_time, end_time):
    """
	create log info record from alarm message
    """

    # assume tagged alarm file; trick to parse correctly
    if aline[:2] != "t=":   # if line does not start with "t=", continue
        print "Warning: not a tagged alarm: ", aline
	return []
    reformated_alarm = [t.replace('~',' ') for t in aline.replace('\\ ','~').split()]
    ip1 = ip2 = sp = dp =  "none"
    alarm = msg = tm = tag = ""
    for s in reformated_alarm:
        field = s.split("=")
        if field[0] == "sa":
            ip1 = field[1]
        if field[0] == "sp":
            sp = field[1]
        if field[0] == "da":
            ip2 = field[1]
        if field[0] == "dp":
            dp = field[1]
        if field[0] == "t":
            try:
                utime = float(field[1]) # unix-style time in seconds
            except:
                print "Error, unknown alarm format ", reformated_alarm
                return []
            if utime < start_time or utime > end_time:
                return []
            tm = time.ctime(float(field[1]))
        if field[0] == "no":
            alarm = field[1]
        if field[0] == "tag":
            tag = field[1]
        if field[0] == "msg":
            msg = field[1]
            msg = msg.replace('\\ ', ' ')
    # end for

    if alarm in ignore_alarms:  # skip if wrong type of alarm
        return []

    if tag == "": 
        tag = "missing tag"
        print "Warning: Alarm tag not found: ", reformated_alarm
    #return [] # only continue for tagged alarms

    # look up src/dst addresses
    sh = [""]
    dh = [""]
    try:
        sh = socket.gethostbyaddr(ip1);
    except:
        sh[0] = ip1
    try:
        dh = socket.gethostbyaddr(ip2);
    except:
        dh[0] = ip2
    #print "hostnames: %s = %s; %s = %s" % (ip1, sh[0], ip2, dh[0])

    # save all useful info from this alarm
    alarm_info = [alarm, tm, ip1, sp, sh[0], ip2, dp, dh[0], msg, tag, 0]

    #print "alarm info: ", alarm_info
    return alarm_info

########################################################

def load_alarms(start_time, end_time):
    """
	load alarms from alarm log files into alarm_list 
    """

    # fills in alarm_list and host_list data structure

    global alarm_list 
    global host_list 

    alarm_list = []
    host_list = []

    report_date = time.strftime("%y-%m-%d", time.localtime(end_time))
    yr, mn, dy = report_date.split("-")

    cnt = 0
    for afile in alarm_file_list:
        print "opening file:", afile
        fd = open(afile)

        # first read through entire alarm file and create list of hosts involved.
        done = 0
        while not done:
            try:
                tl = fd.readline()
            except Exception, E:
                print E
                done = 1
                continue
            #print "read line: ",tl

            if len(tl) == 0:
                done = 1
                #print "end of file"
                continue

            alarm_info = create_alarm_info(tl,start_time, end_time)
            if alarm_info != []:
                cnt += 1
                #only add if this alarm for this host pair has not been seen before
                alarm_exists = 0
                for curr_alarm_info in alarm_list:
                    alarm,tm,ip1,sp,shost,ip2,dp,dhost,msg,tag,a_cnt = curr_alarm_info
                    if alarm  == alarm_info[0] and ip1 == alarm_info[2] and ip2 == alarm_info[5]:
                        curr_alarm_info[10] += 1   # increment count
                        alarm_exists = 1
                if not alarm_exists:
                    alarm_list.append(alarm_info)

                # figure out which host is local and add to host_list[]
                local_host = get_local_host(alarm_info[2], alarm_info[5], alarm_info[4], alarm_info[7], local_nets)
                if local_host not in host_list:
                    print "Adding to host list: ", local_host
                    host_list.append(local_host)

    #print host_list
    #print alarm_list
    print "Found %d alarms in this time period " % cnt
    return cnt

######################################################################
def print_alarm(alarminfo,out):
    """ Formats and outputs the alarms
    """

    alarm,tm,ip1,sp,sh,ip2,dp,dh,msg,tag,a_cnt = alarminfo

    out.write ('<table border="0" cellspacing="2" cellpadding="2"> \n <tr> \n')
    out.write ('<td><div align="right"><strong> ')
    # reformat alarm and write to file in a more readable format
    alarm_string =  '<strong>%s</strong>: <td> %s </td> </tr> \n <tr align="left"> <td align="right"> source: </td> <td align="left"> %s </td> <td> %s </td> <td> port = %s </td> </tr> \n <tr align="left"> <td align="right"> dest: </td> <td align="left"> %s </td> <td> %s </td> <td> port = %s </td> </tr> \n <tr> <td align="right"> alarm message: </td> <td colspan= 3 align="left"> %s %s </td> </tr> </table> \n' % (alarm, tm, ip1, sh, sp, ip2, dh, dp, msg, tag) 
    out.write(alarm_string)
    if a_cnt > 1:
        out.write("<ul>%d instances of this alarm for this host pair </ul>" % a_cnt)

    out.write ("<p> \n")

######################################################################
def print_connections(connfiles,ip,tag,out):
    """ Formats and outputs the connection logs
     """

    # there must be a clever way to do this with the pipes module, but this will work for now
    # only include connections that have state SF or S1 (should also include RSTO)

    cmd = "grep -h ' %s ' %s | grep -e 'SF' -e 'S1' -e 'RSTO' | grep -A 10 -B 5 '%s$' | %s | %s > %s" % (ip, connfiles, tag, cf, hf, "/tmp/bro-report.tmp")
    print "running program: ", cmd
    os.system(cmd)       
    f = open("/tmp/bro-report.tmp")
    lines = f.readlines()  # read entire file

    if len(lines) > 0:
        out.write ('\n <table border="0" cellspacing="2" cellpadding="2"> \n')
        out.write('<tr align="right"><td colspan= 3> Time </td> <td> Duration </td><td> Src host </td><td> Dst host </td> <td> Service </td> <td> Src port </td> <td> Dst port </td> <td> Prot </td> <td> Bytes sent </td><td> Bytes rcv </td> <td> State </td><td> Flag </td><td> Tag </td> </tr>')

        for line in lines:
            fields = line.split()
            out.write('<tr align="right">')
            for f in fields:
                out.write("<td> %s </td>" % f)
            out.write("</tr>")
        out.write("</table> \n ")

    else:
        out.write ("<ul> No suscessful connections found. </ul> \n")

    out.write ("<hr>\n")


######################################################################
def usage(m=None):
    """This just prints the doc string for the whole program.
    """
    if m: print "Error: %s" % m
    print __doc__
    sys.exit()

########################################################

def main():
    """
	parse opts, collect alarms, generate report
    """

    global local_nets 
    global report_date
    global conn_reports_at_end 
    conn_reports_at_end = 0

    try:    
        options,prog_args = getopt.getopt(sys.argv[1:],'hxys:e:m:')
    except getopt.GetoptError, E:       
        usage(E)

    do_today = 0
    report_date = sdate = edate = dest = ""
    for opt,val in options:
        if opt == '-s':
            sdate = val
        elif opt == '-e':
            edate = val
        elif opt == '-m':
            dest = val
        elif opt == '-y':
            conn_reports_at_end = 1 
        else:
            usage()

    if dest == "":
        print "Missing email address for report"
        usage()

    if sdate == "":
        # set defauts
        end_time = time.time()
        start_time = end_time - (24 * 60 * 60)  # number of seconds in 1 day
    else:
        # if start/stop times given at the command line, convert them to Unix time
        if sdate != "":
            start_time = get_time(sdate)
            if edate == "":  # if not specified, add 24 hrs
                end_time = start_time + (24 * 60 * 60) 
        if edate != "":
            end_time = get_time(edate)
            if sdate == "":  # if not specified, subtract 24 hrs
                start_time = end_time + (24 * 60 * 60) 
        else:
            end_time = start_time + (24 * 60 * 60)  # number of seconds in 1 day

    #print "start time: %f, %s " % (start_time, time.ctime(start_time))
    #print "end time: %f, %s " % (end_time, time.ctime(end_time))

    outfile = "%s/reports/bro.report.%d.html" % (brohome, os.getpid())
    out = open(outfile, 'w') 

    if conn_reports_at_end:   # open file to save all conn information, then cat to report at the end
        outfile_conn = "%s/reports/bro.report.%d.tmp" % (brohome, os.getpid())
        out_conn = open(outfile_conn, 'w') 

    rstart = time.strftime("%y-%m-%d %H:%M", time.localtime(start_time))
    rend = time.strftime("%y-%m-%d %H:%M", time.localtime(end_time))

    if get_file_names(start_time, end_time) <= 0:
        print "No alarms found for time specified"
        out.write ("<HTML><HEAD><TITLE> Bro Report %s to %s </TITLE></HEAD>\n" % (rstart, rend ) )
        out.write ("<BODY><p> Bro Report %s-%s <p> \n"  % (rstart, rend ) )
        out.write ("<BODY><p><p> No alarms found for time specified \n </BODY></HTML>"  )
        sys.exit(0)

    connfiles = ""
    for connfile in conn_file_list:  # build single string with all names in it
        connfiles += "%s " % connfile
    #print "connfiles ", connfiles

    site_name = get_site_name("%s/etc/bro.cfg" % brohome)
    local_nets = get_local_nets(bro_local_nets)
    cnt = load_alarms(start_time, end_time)

    out.write ("<HTML><HEAD><TITLE> Bro Report %s-%s </TITLE></HEAD>\n" % (rstart, rend ) )
    out.write ("<BODY>")
    out.write ("<p> Bro Report: %s-%s \n" % (rstart, rend ) )
    out.write ("<p> Total Number of Alarms: %d \n " % cnt)
    if cnt > 0:
        out.write ("<br> List of %s hosts with Alarms in this report: \n <ul> " % site_name)

        # now loop through alarm_list and generate report
        for host in host_list:
            out.write ("  <p> <strong> %s </strong>" % (host))
        out.write ("</ul> <p> <hr> \n")
    else:
        print "No Alarms found"

    for alarm in alarm_list:
        #print alarm
        print_alarm(alarm,out)
        tag = alarm[9]

        if conn_reports_at_end:   
            taglink = "#alarm%s" % (tag)
            out.write ('\n <ul> <a href="%s"> Successful Connections</a> just before and after this alarm </ul> <p>\n' % taglink)
        else:
            out.write ("Successful Connections just before and after this alarm: \n\n <p> \n" )

        print "searching conn files '%s' for tag %s " % ( connfiles, tag)

        if conn_reports_at_end:   
            out_conn.write('<P><A name="%s"></A>\n' % taglink.strip("#"))

        if len(connfiles) > 0:
            if conn_reports_at_end:   
                out_conn.write ('\n <p> \n Successful Connections just before and after alarm %s  <p>\n' % tag)
                print_connections(connfiles, alarm[2], tag, out_conn )
            else:
                print_connections(connfiles, alarm[2], tag, out )

    if conn_reports_at_end and cnt > 0:   
        out.write ("<hr> \n")
        out.write ("<p> Connection Summary Information \n" )
        out_conn.close()
        out.close()
        cmd = "cat %s >> %s " % (outfile_conn, outfile)
        print "Running command: ", cmd
        os.system(cmd)       
        # next reopen the file
        out = open(outfile, 'a')  

    out.write ("</body></html> \n")
    out.close()

    # done building report, now send it

    #cmd = "/usr/bin/Mail -s 'Bro Report: %s' %s < %s" % (tm, dest, outfile)
    # mail does not handle HTML attachments, so use mutt instead
    cmd = "%s -s 'Bro Report from %s: %s to %s ' -a %s %s < /dev/null" % (mutt, socket.gethostname(), rstart, rend, outfile, dest)
    print "running program: ", cmd
    os.system(cmd)       

    try:
        os.remove("/tmp/bro-report.tmp")
    #os.remove(outfile)
    except:
        pass

    sys.exit(0)

######################################################################
if __name__ == '__main__': main()

