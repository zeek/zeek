# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

@load protocols/http/detect-sqli

event zeek_init()
	{
	local positive_matches: set[string];
	local negative_matches: set[string];

	add positive_matches["/index.asp?ID='+convert(int,convert(varchar,0x7b5d))+'"];
	add positive_matches["/index.asp?ID='+cASt(somefield as int)+'"];
	add positive_matches["/index.asp?ID=1'+139+'0"];
	add positive_matches["/index.asp?ID='+139+'0"];
	add positive_matches["/index.php?blah=123'/*blooblah*/;select * from something;--"];
	add positive_matches["/index.cfm?ID=3%' and '%'='"];
	add positive_matches["/index.php?mac=\" OR whatever LIKE \"%"];
	add positive_matches["/index.cfm?ID=3;declare @d int;--"];
	add positive_matches["/index.cfm?subjID=12;create table t_jiaozhu(jiaozhu varchar(200))"];
	add positive_matches["/index.cfm?subjID=12%' and(char(94)+user+char(94))>0 and '%'='"];
	add positive_matches["/index.cgi?cgi_state=view&ARF_ID=1+(642*truncate(log10(10),0))"];
	add positive_matches["/index.cgi?view=1 regexp IF((ascii(substring(version(),6,1))>>(0)&1),char(42),1) AND 1=1"];
	add positive_matches["/index.cfm?News=203 and char(124)+db_name()+char(124)=0 --"];
	add positive_matches["/index.php?action=&type=view&s=&id=-1' UNION SELECT 0,252381211,0,0,0,0,0/*"];
	add positive_matches["/index.php?x=browse&category='UNION SELECT '1','2','pixelpost_category_sql_injection.nasl','1183412908','5'/*"];
	add positive_matches["/index.php?id='UNION/**/SELECT/**/0,0,1648909705,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0/*"];
	add positive_matches["/index.php?id=-1/**/UNION/**/ALL/**/SELECT/**/1,0x7430705038755A7A20616E64207870726F67206F776E616765,convert(concat((SELECT/**/svalue/**/from/**/sconfig/**/where/**/soption=0x61646D696E5F6E616D65),0x3a,(SELECT/**/svalue/**/from/**/sconfig/**/where/**/soption=0x61646D696E5F70617373))/**/using/**/latin1),4,5,6,7,8,9/*"];
	add positive_matches["/index.jsp?arfID=5 AND ascii(lower(substring((SELECT TOP 1 name from sysobjects WHERE xtype=âUâ), 1,1)))>109"];
	add positive_matches["/?main_menu=10&sub_menu=2&id=-1 union select aes_decrypt(aes_encrypt(LOAD_FILE('/etc/passwd'),0x70),0x70)/*"];
	add positive_matches["/index.asp?file=50' and 1=1 and ''='"];
	add positive_matches["/index.php?cat=999 UNION SELECT null,CONCAT(666,CHAR(58),user_pass,CHAR(58),666,CHAR(58)),null,null,null FROM wp_users where id=1/*"];
	add positive_matches["/index.asp?authornumber=1);insert into SubjectTable(Sub_id, SubjectName, display) values (666, 'ChkQualysRprt', 1); --"];
	add positive_matches["/index.php?ID=60 and (select unicode(substring(isNull(cast(db_name() as varchar(8000)),char(32)),29,1)))"];
	add positive_matches["/index.php?sort=all&&active=NO' union select 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0/* and '1'='1"];
	add positive_matches["/index.php?sort=all&&active=no' and 1=2 union select 1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1/* and '1'='1"];
	add positive_matches["/index.php?sort=all&&active=no' and (select count(table_name) from user_tables)>0 and '1'='1"];
	add positive_matches["/index.php?id=22 /*!49999 and 1=2*/-- and 1=1"];
	add positive_matches["/index.php?ID=59 and (select count(table_name) from user_tables)>0 and 1=1"];
	add positive_matches["/index.php?ID=60 and exists (select * from [news])"];

	# These are not detected currently.
	#add positive_matches["/index.asp?ARF_ID=(1/(1-(asc(mid(now(),18,1))\(2^7) mod 2)))"];
	#add positive_matches["/index.php' and 1=convert(int,(select top 1 table_name from information_schema.tables))--sp_password"];
	#add positive_matches["/index.php?id=873 and user=0--"];
	#add positive_matches["?id=1;+if+(1=1)+waitfor+delay+'00:00:01'--9"];
	#add positive_matches["?id=1+and+if(1=1,BENCHMARK(728000,MD5(0x41)),0)9"];

	# The positive_matches below are from the mod_security evasion challenge.
	# All supported attacks are uncommented.
	# http://blog.spiderlabs.com/2011/07/modsecurity-sql-injection-challenge-lessons-learned.html
	add positive_matches["/index.asp?id=100&arftype=46'	XoR	'8'='8"];
	#add positive_matches[unescape_URI("/testphp.vulnweb.com/artists.php?artist=0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user")];
	#add positive_matches[unescape_URI("/index.php?hUserId=22768&FromDate=a1%27+or&ToDate=%3C%3Eamount+and%27&sendbutton1=Get+Statement")];
	#add positive_matches["after=1 AND (select DCount(last(username)&after=1&after=1) from users where username='ad1min')&before=d"];
	#add positive_matches["hUserId=22768&FromDate=1&ToDate=1'UNION/*!0SELECT user,2,3,4,5,6,7,8,9/*!0from/*!0mysql.user/*-&sendbutton1=Get+Statement"];
	add positive_matches[unescape_URI("/test.php?artist=-2%20div%201%20union%20all%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yea%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%23yeaah%0A%23yeah%20babc%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaf%23%0A%23fdsafdsafa%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaafv%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%23fafsfaaf%0Aselect%200x00,%200x41%20like/*!31337table_name*/,3%20from%20information_schema.tables%20limit%201")];	;
	#add positive_matches[unescape_URI("/test.php?artist=%40%40new%20union%23sqlmapsqlmap...%0Aselect%201,2,database%23sqlmap%0A%28%29 ")];
	add positive_matches[unescape_URI("/test.php?artist=-2%20div%201%20union%20all%23hack%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23hpys%20player%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%0A%23fabuloso%23modsec%0A%23hpys%20player%0A%23fabuloso%23great%23%0A%23fabuloso%23great%23%0Aselect%200x00%2C%200x41%20not%20like%2F*%2100000table_name*%2F%2C3%20from%20information_schema.tables%20limit%201")];
	add positive_matches[unescape_URI("/test.php?artist=1%0bAND(SELECT%0b1%20FROM%20mysql.x)")];

	add negative_matches["/index.asp?db=a9h&jid=JHE&scope=site"];
	add negative_matches["/blah/?q=?q=archive+title=Read the older content in our archive"];
	add negative_matches["/blah/?q=?q= title=Return to the main page"];
	add negative_matches["/index.pl?http://search.ebscohost.com.proxy.lib.ohio-state.edu/direct.asp?db=s3h&jid=22EG&scope=site"];
	add negative_matches["/search?q=eugene svirsky&spell=1&access=p&output=xml_no_dtd&ie=UTF-8&client=default_frontend&site=default_collection&proxystylesheet=default_frontend"];
	add negative_matches["/index.htm?List=<ows:ListProperty Select='Name'"];
	add negative_matches["/index.aspx?TreeviewPk=67&startat=f&filter=tree_pk='f502530'&stopat=b"];
	add negative_matches["/index.asp?A0=23&A1=||17||=0&A2=||7|| desc&A3=||6||=62512 AND ||_System_||=0&A4=1,7,16,5,9&A5=2&A6=1&A7=0&A8=0&A9=0&A10="];
	add negative_matches["/?q=?q= title=Return to the main page"];
	add negative_matches["/index.swf?MMredirectURL='+MMredirectURL+'&MMplayerType=PlugIn"];
	add negative_matches["/search?q=Drop-a-GEC Course&btnG=Search Ohio State&entqr=0&output=xml_no_dtd&sort=date:D:L:d1&ie=UTF-8&client=default_frontend&ud=1&y=15&oe=UTF-8&proxystylesheet=default_frontend&x=77&site=default_collection"];
	add negative_matches["/index?config=joe&restrict=&exclude=&matchesperpage=8&method=and&format=long&sort=score&words=organizational change policy"];
	add negative_matches["/index.swf?clickTag=http://xads.zedo.com//ads2/c?a=309530;x=3613;g=0,0;c=162000122,162000122;i=0;n=162;s=94;;i=0;u=FFFFFFFFFFFFFFFFF;e=i;s=94;g=172;w=38;m=69;p=6;f=351860;h=265048;k=http://ad.doubleclick.net/jump/N1057.Und/B2331434.43;sz=1x1;ord=0.8798379284729?"];
	add negative_matches["/blah/?q=?q=\" title=\"Return to the main page."];
	add negative_matches["/blah?pg=thread;sz=160x600;tile=2;pos=1;bl=n;comp=;is_guest=1;ord=38872342341?"];
	add negative_matches["/index/a.b.com/ros;sect=ros;sz=728x90,468x60;click=http://a.b.com/servlet/click/media?zid=0&cid=0&mid=1104&pid=0&default=false&random=449290001&timestamp=20110426084929&test=false&referrer=http://b.com/darryl+worley-lyrics-964.html&redirect=;tile=1;ord=1309979795.5?"];
	add negative_matches["/index/?keywordCharEnc=latin1&cb=' + dartDate + '"];
	add negative_matches["/search/searchresult.jsp?op2=and&query3=&scope3=metadata&queryText=(+((yu)<in>metadata+)+<and>+((munson)<in>metadata+)+)"];
	add negative_matches["/index?Z=300x250&s=299359&_salt=523454521`54&B=10&u=http://ad.doubleclick.net/adi/answ.science/;dcopt=ist;kw=biased+sample;tid=2735125;scat=health;scat=business;pcat=science;pos=1;tile=1;sz=300x250;csrc=2451;csrc=2191;csrc=2665;csrc=2750;or&r=0"];
	add negative_matches["/index.php?sid=FirstSearch:AveryIndex&genre=article&issn=1590-1394&isbn=&atitle=Paesaggio+artificiale:+una+cava+diventa+parco+urbano+=++Artificial+landscape:+a+quarry+becomes+an+urban+park&title=Metamorfosi&issue=66&spage=58&epage=60&date=2007-05&sici=1590-1394(200705/06)66<58:PAUCDP>2.0.TX;2-C&id=doi:&pid=<accession+number>858994226+858994226</accession+number><fssessid>fsapp13-52547-fhscgzal-jqsb44</fssessid>&url_ver=Z39.88-2004&rfr_id=info:sid/firstsearch.oclc.org:AveryIndex&rft_val_fmt=info:ofi/fmt:kev:mtx:journal&req_dat=<sessionid>fsapp13-52547-fhscgzal-jqsb44</sessionid>&rfe_dat=<accessionnumber>858994226+858994226</accessionnumber>&rft_id=urn:ISSN:1590-1394&rft.atitle=Paesaggio+artificiale:+una+cava+diventa+parco+urbano+=++Artificial+landscape:+a+quarry+becomes+an+urban+park&rft.jtitle=Metamorfosi&rft.date=2007-05&rft.issue=66&rft.spage=58&rft.epage=60&rft.issn=1590-1394&rft.genre=article&rft.sici=1590-1394(200705/06)66<58:PAUCDP>2.0.TX;2-C"];
	add negative_matches["/index?body=linker&reqidx=00012345(2005)L.349"];
	add negative_matches["/index.jsp?SortField=Score&SortOrder=desc&ResultCount=25&maxdoc=100&coll1=&coll2=ieeecnfs&coll3=ieecnfs&coll4=&coll5=&coll6=&coll7=&coll8=&srchres=0&history=yes&queryText=((curran)<IN>metadata)&oldqrytext=(~~simon+curran~~+<in>+metadata)+<and>+(4389466+<in>+punumber)&radiobutton=cit"];
	add negative_matches["/index.php?action=uid=32651(makessc) gid=32652(makessc) groups=32652(makessc)"];
	add negative_matches["/index.cgi?t=event&id=3947&year=2007&week=13&wday=3&rt=n&hour=13&min=30&lengthmin=90&title=771 (4) Biomedical Instrumentation - J. Liu&data=&startyear=2007&startweek=13&startwday=3&duration=1&alval=&altype=&alchk=&strike=0&todo=0&mail=0&lock=0&priv=0"];
	add negative_matches["/index.php?site=EagleTribunePublishingCompany&adSpace=ROS&size=468x60&type=horiz&requestID='+((new Date()).getTime()  2147483648) + Math.random()+'"];
	add negative_matches["/blah?callback=google.language.callbacks.id100&context=22&q=) or articles from the online magazine archive will need to log in, in order to access the content they have purchased.&langpair=|en&key=notsupplied&v=1.0"];
	add negative_matches["/blah?hl=en&rlz=1T4DDWQ_enUS432US432&q=\"andrew+foobar\""];
	add negative_matches["/index.cfm?filename=32423411.GP4&ip=1.2.3.4&id_num=0063&proj_num=2906&sheet_name=2 AND 3 FLR&sheet_num=2E&path=L:\ARF\DATA\13000\95013889.GP4"];
	add negative_matches["/index.pl\?supersite=stations&station=ABCD&path='+location.pathname+'&'+location.search.substring(1)+'\\\"\\"];
	add negative_matches["/ntpagetag.gif?js=1&ts=123412341234.568&lc=http://a.b.org/default.aspx?mode=js#&rs=1440x900&cd=32&ln=en&tz=GMT -04:00&jv=1&ets=123412341234.623&select_challenge_from_gallery=1&ci=RCC00000000"];
	
	# These are still being matched accidentally.
	#add negative_matches["/A-B-C-D/inc/foobar.php?img=1179681280a b c d arf union.jpg"];
	#add negative_matches["/test,+soviet+union&searchscope=7&SORT=DZ/test,+soviet+union&foobar=7"];
	#add negative_matches["/search?hl=en&q=fee union western"];
	#add negative_matches["/search?hl=en&q=ceiling drop tile"];
	#add negative_matches["/index/hmm.gif?utmdt=Record > Create a Graph"];
	#add negative_matches["/index.php?test='||\x0aTO_CHAR(foo_bar.Foo_Bar_ID)||"];

	print "If anything besides this line prints out, there is a problem.";
	for ( test in positive_matches )
	{
		if ( HTTP::match_sql_injection_uri !in test )
			print fmt("Missed: %s", test );
	}
	print "";
	for ( test in negative_matches )
	{
		if ( HTTP::match_sql_injection_uri in test )
			print fmt("False Positive: %s", test);
	}

}
