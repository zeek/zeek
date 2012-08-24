@load base/utils/files
@load base/protocols/modbus/utils

global modbus_ports={502/tcp};

redef dpd_config+={[ANALYZER_MODBUS]=[$ports=modbus_ports]};



global path:string="/home/dina/pcaps_all/logs/simulations/";
#global path:string="./simulations/"

# raise this (simple) event if you do not have the specific one bellow
event modbus_request(c:connection,is_orig:bool,tid:count, pid:count,uid:count, fc:count)
{
	local e : file;
	local g:file;
	local ftime:string;
	local src:string;
        local dst:string;
        local src_p:string;
        local dst_p:string;
		
	e=open_for_append (string_cat(path,"fall.log"));
	g=open_for_append (string_cat(path,"missing_fc.log"));
        
	ftime=strftime("%F %T",network_time());
	src_p=cat(c$id$orig_p);
	dst_p=cat(c$id$resp_p);
	src= cat(c$id$orig_h);
        dst=cat(c$id$resp_h);


	local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t",cat(uid),"\t",cat(check_e(fc)),"\n");


	local nfc:count;
	nfc=check_e(fc);
	if ((nfc!=3)&&(nfc!=7)&&(nfc!=16)&&(nfc!=23)) 
	{
		write_file(e,text);
		local missing=string_cat(cat(nfc),"\n");
		write_file(g,missing);
	}
	close(e);
	close(g);
}



event modbus_response(c:connection,is_orig:bool,tid:count,pid: count,uid:count, fc:count)
{
	local e : file;
	local g : file;
	local ftime:string;
	local src:string;
        local dst:string;
	local src_p:string;
        local dst_p:string;


	e=open_for_append (string_cat(path,"fall.log"));
	g=open_for_append (string_cat(path,"missing_fc_new.log"));
        ftime=strftime("%F %T",network_time());

        src= cat(c$id$orig_h);
        dst=cat(c$id$resp_h);
	src_p=cat(c$id$orig_p);
        dst_p=cat(c$id$resp_p);

	local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t RESPONSE \t",cat(tid), "\t",cat(pid),"\t",cat(uid),"\t",cat(check_e(fc)),"\n");

	local nfc:count;
	nfc=check_e(fc);
	if ((nfc!=3)&&(nfc!=4)&&(nfc!=5)&&(nfc!=6)&&(nfc!=7)&&(nfc!=16)&&(nfc!=23))
        {

                write_file(e,text);
                local missing=string_cat(cat(nfc),"\n");
 #              print fmt("******************************************************************* I got this: %d ",fc);
		write_file(g,missing); 
        }

	#print fmt("Ola amigo, transaction id is %d, process id is %d, slave address is %d, function code request is %d",tid,pid,uid,fc);
	
	close(e);
	close(g);
}


#REQUEST FC=1
event modbus_read_coils_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count, ref:count, bcount:count)
        {

                local f:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                f=open_for_append (string_cat(path,"f1_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                #according to the specification, this FC typically has 0xxxx offset in the memory map


                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t", cat(ref), "\t", cat(bcount),"\n");

                write_file(f,text);
                write_file(m,text);

                print fmt("flying");
                close(f);
                close(m);

        }



#RESPONSE FC=1
event modbus_read_coils_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count, bcount:count,bits:string)
        {

                local f:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                f=open_for_append (string_cat(path,"f1_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                #according to the specification, this FC typically has 0xxxx offset in the memory map


                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t RESPONSE \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t", cat(bcount),"\t",bits,"\n");

                write_file(f,text);
                write_file(m,text);

                print fmt("flying");
                close(f);
                close(m);

        }


#REQUEST FC=2
event modbus_read_input_discretes_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count, ref:count, bcount:count)
        {
                local f:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                f=open_for_append (string_cat(path,"f2_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                #according to the specification, this FC typically has 1xxxx offset in the memory map
                local prefix_ref:count;
                prefix_ref=ref+10000;


                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t", cat(prefix_ref), "\t", cat(bcount),"\n");

                write_file(f,text);
                write_file(m,text);

                print fmt("flying");
                close(f);
                close(m);
        }


#RESPONSE FC=2
event modbus_read_input_discretes_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count, bcount:count,bits:string)
        {

                local f:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                f=open_for_append (string_cat(path,"f2_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                #according to the specification, this FC typically has 1xxxx offset in the memory map
                #local prefix_ref:count;
                #prefix_ref=ref+10000;


                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t RESPONSE \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(bcount),"\t", bits,"\n");

                write_file(f,text);
                write_file(m,text);

                print fmt("flying");
                close(f);
                close(m);
        }





#REQUEST FC=3
event modbus_read_multi_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count, ref:count, wcount:count,len:count)
	{
	
		local f:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;
	
		f=open_for_append (string_cat(path,"f3_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));
		ftime=strftime("%F %T",network_time());

		src= cat(c$id$orig_h);
		dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

		#according to the specification, this FC typically has 4xxxx offset in the memory map
		local prefix_ref:count;
                prefix_ref=ref+40000;


		local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t REQUEST \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t", cat(prefix_ref), "\t", cat(wcount),"\n");

		write_file(f,text);
		write_file(m,text);

		print fmt("flying");
		close(f);
		close(m);

	}	


#RESPONSE FC=3
event modbus_read_multi_response(c:connection,is_orig:bool,t:int_vec,tid:count,pid:count,uid:count,fc:count,bCount:count,len:count)
	{

		local h:file;
      		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;	
		
		h=open_for_append (string_cat(path,"f3_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));
		ftime=strftime("%F %T",network_time());
	
        	src= cat(c$id$orig_h);
        	dst=cat(c$id$resp_h);
		src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

 		local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t RESPONSE \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(bCount), "\t",cat(t),"\n");

       		write_file(h,text);
		write_file(m,text);

	
       		close(h);
		close(m);

	}



#REQUEST FC=4
event modbus_read_input_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count, ref:count, wcount:count,len:count)
        {

                local f:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;
	
		f=open_for_append (string_cat(path,"f4_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));
		ftime=strftime("%F %T",network_time());
               
               
                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
		src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);
		
		#according to the specification, this FC typically has 3xxxx offset in the memory map
		local prefix_ref:count;
		prefix_ref=ref+30000;

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t REQUEST \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t", cat(prefix_ref), "\t", cat(wcount),"\n");              
                write_file(f,text);
               	write_file(m,text);

		print fmt("flying");

                close(f);
                close(m);

        }





#RESPONSE FC=4
event modbus_read_input_response(c:connection,is_orig:bool,t:int_vec,tid:count,pid:count,uid:count,fc:count,bCount:count,len:count)
        {

                local h:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;
                
		h=open_for_append (string_cat(path,"f4_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));
		ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
               	dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);
		
		
		local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t RESPONSE \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(bCount), "\t",cat(t),"\n");

                write_file(h,text);
                write_file(m,text);


                close(h);
                close(m);

        }





#REQUEST FC=5
event modbus_write_coil_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,ref:count,onOff:count,other:count)
        {

                local h:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f5_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));

                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
		
		src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);
	
		#according to the specification, this FC typically has 0xxxx offset in the memory map
			
		local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(ref), "\t",cat(onOff),"\t",cat(other),"\n");
		
		write_file(h,text);
                write_file(m,text);
		
		close(h);
                close(m);

        }


#RESPONSE FC=5
event modbus_write_coil_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,ref:count,onOff:count,other:count)
        {

                local h:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f5_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));

                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                #according to the specification, this FC typically has 0xxxx offset in the memory map
               

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t RESPONSE \t","\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(ref), "\t",cat(onOff),"\t",cat(other),"\n");

                write_file(h,text);
                write_file(m,text);

                close(h);
                close(m);

        }



#REQUEST FC=6
event modbus_write_single_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,len:count,ref:count,value:count)
        {

                local h:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f6_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));

                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                #according to the specification, this FC typically has 4xxxx offset in the memory map
                local prefix_ref:count;
                prefix_ref=ref+40000;


                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t REQUEST \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(prefix_ref), "\t",cat(value),"\n");

                write_file(h,text);
                write_file(m,text);

                close(h);
                close(m);

        }

#RESPONSE FC=6
event modbus_write_single_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,len:count,ref:count,value:count)
        {

                local h:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f6_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
		ftime=strftime("%F %T",network_time());
                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);
		
		#according to the specification, this FC usually has 4xxxx offset in the memory map
		local prefix_ref:count;
                prefix_ref=ref+40000;

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t RESPONSE \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(prefix_ref), "\t",cat(value),"\n");

                write_file(h,text);
                write_file(m,text);
		
		close(h);
                close(m);

        }

#REQUEST FC=15
event modbus_force_coils_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,ref:count,bitCount:count,byteCount:count,coils:string)
        {

                local h:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f15_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());
                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                #according to the specification, this FC usually has 0xxxx offset in the memory map
                

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(ref), "\t",cat(bitCount),"\t",cat(byteCount),coils,"\n");

                write_file(h,text);
                write_file(m,text);

                close(h);
                close(m);

        }



#RESPONSE FC=15
event modbus_force_coils_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,ref:count,bitCount:count)
        {

                local h:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f15_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());
                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                #according to the specification, this FC usually has 0xxxx offset in the memory map
               

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t RESPONSE \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(ref), "\t",cat(bitCount),"\n");

                write_file(h,text);
                write_file(m,text);

                close(h);
                close(m);

        }



#REQUEST FC=16
event modbus_write_multi_request(c:connection,is_orig:bool,t:int_vec,tid:count,pid:count,uid:count,fc:count,ref:count,wCount:count,bCount:count,len:count)
	{

		local k:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;


		k=open_for_append (string_cat(path,"f16_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
		src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);
		
		#according to the specification, this FC usually has 4xxxx offset in the memory map
		local prefix_ref:count;
                prefix_ref=ref+40000;

			
		local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t REQUEST \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(prefix_ref), "\t",cat(wCount), "\t", cat(bCount),"\t",cat(t),"\n"); 
			
		write_file(k,text);
		write_file(m,text);
		
		close(k);
		close(m);

	}

#RESPONSE FC=16
event modbus_write_multi_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count, ref:count, wcount:count,len:count)
	{
		local o:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;

		o=open_for_append (string_cat(path,"f16_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));
		ftime=strftime("%F %T",network_time());

                
                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
		src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);
			
		#according to the specification, this FC usually has 4xxxx offset in the memory map
		local prefix_ref:count;
                prefix_ref=ref+40000;
		
 		local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t RESPONSE \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(prefix_ref), "\t", cat(wcount),"\n");

		write_file(o,text);
		write_file(m,text);
			
		close(m);
		close(o);

	}





#REQUEST FC=20
event modbus_read_reference_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,refCount:count,t:int_vec)
        {

                 local k:file;
                 local m:file;
                 local ftime:string;
                 local src:string;
                 local dst:string;
                 local src_p:string;
                 local dst_p:string;


                 k=open_for_append (string_cat(path,"f20_new.log"));
                 m=open_for_append (string_cat(path,"fall_new.log"));
                 ftime=strftime("%F %T",network_time());

                 src= cat(c$id$orig_h);
                 dst=cat(c$id$resp_h);
                 src_p=cat(c$id$orig_p);
                 dst_p=cat(c$id$resp_p);


                local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(refCount),"\t",cat(t),"\n");

                write_file(k,text);
                write_file(m,text);

                close(k);
                close(m);

        }



#RESPONSE FC=20
event modbus_read_reference_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,byteCount:count,t:int_vec)  
        {

                local k:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;


                k=open_for_append (string_cat(path,"f20_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);


               local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t RESPONSE \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(byteCount),"\t",cat(t),"\n");

                write_file(k,text);
                write_file(m,text);

                close(k);
                close(m);

        }


#REQUEST FC=20 (for single reference)
event modbus_read_single_reference_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,refType:count,refNumber:count,wordCount:count)
        {

                local k:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;


                k=open_for_append (string_cat(path,"f20_singles_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);


               local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(refType),"\t",cat(refNumber),"\t",cat(wordCount),"\n");

                write_file(k,text);
                write_file(m,text);

                close(k);
                close(m);

        }

#RESPONSE FC=20 (for single reference)
event modbus_read_single_reference_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,byteCount:count,refType:count,t:int_vec)
        {

                local k:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;


                k=open_for_append (string_cat(path,"f20_singles_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);


               local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t RESPONSE \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(byteCount),"\t",cat(refType),"\t",cat(t),"\n");

                write_file(k,text);
                write_file(m,text);

                close(k);
                close(m);

        }




#REQUEST FC=21
event modbus_write_reference_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,byteCount:count,t:int_vec)
        {

                local k:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;


                k=open_for_append (string_cat(path,"f21_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);


               local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(byteCount),"\t",cat(t),"\n");

                write_file(k,text);
                write_file(m,text);

                close(k);
                close(m);

        }


#RESPONSE FC=21
event modbus_read_reference_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,byteCount:count,t:int_vec)
        {

                local k:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;


                k=open_for_append (string_cat(path,"f21_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);


               local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t RESPONSE \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(byteCount),"\t",cat(t),"\n");

                write_file(k,text);
                write_file(m,text);

                close(k);
                close(m);

        }

#REQUEST/RESPONSE FC=21 (for single reference)
event modbus_write_single_reference(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,refType:count,refNumber:count,wordCount:count,t:int_vec)
        {

                local k:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                k=open_for_append (string_cat(path,"f21_singles_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

               local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t REQUEST/RESPONSE \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(refType),"\t",cat(refNumber),"\t",cat(wordCount),"\t",cat(t),"\n");

                write_file(k,text);
                write_file(m,text);

                close(k);
                close(m);

        }

#REQUEST FC=22
event modbus_mask_write_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,ref:count,andMask:count,orMask:count)
        {

                local h:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f22_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));

                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(ref), "\t",cat(andMask),"\t",cat(orMask),"\n");

                write_file(h,text);
                write_file(m,text);

                close(h);
                close(m);
        }

#RESPONSE FC=22
event modbus_mask_write_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,ref:count,andMask:count,orMask:count)
        {

                local h:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f22_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));

                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t RESPONSE \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(ref), "\t",cat(andMask),"\t",cat(orMask),"\n");

                write_file(h,text);
                write_file(m,text);

                close(h);
                close(m);
        }




# RESPONSE FC=23
event modbus_read_write_response(c:connection,is_orig:bool,t:int_vec,tid:count,pid:count,uid:count,fc:count,bCount:count,len:count)
        {

                local g:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;

               	g=open_for_append (string_cat(path,"f23_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));
		ftime=strftime("%F %T",network_time());
		src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
		src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);	

		local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t RESPONSE \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(bCount), "\t",cat(t),"\n");
               
		write_file(g,text);
		write_file(m,text);
               
		close(g);
		close(m);

        }




# REQUST FC=23
event modbus_read_write_request(c:connection,is_orig:bool,t:int_vec,tid:count,pid:count,uid:count,fc:count,refRead:count,wcRead:count,refWrite:count,wcWrite:count,bCount:count,len:count)
        {

                local n:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;
	                
		n=open_for_append (string_cat(path,"f23_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));
		ftime=strftime("%F %T",network_time());
                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
		src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

		#according to the specification, this FC usually has 4xxxx offset in the memory map
		local prefix_refR:count;
		local prefix_refW:count;

                prefix_refR=refRead+40000;
		prefix_refW=refWrite+40000;
		
		local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t REQUEST \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t",cat(fc),"\t",cat(prefix_refR),"\t",cat(wcRead),"\t ",cat(prefix_refW),"\t ",cat(wcWrite),"\t",cat(bCount), "\t",cat(t),"\n");
		
	         write_file(n,text);
		 write_file(m,text);

                 close(n);
		 close(m);
        }


#REQUEST FC=24
event modbus_read_FIFO_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count, ref:count)
        {

                local f:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                f=open_for_append (string_cat(path,"f23_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t REQUEST \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t", cat(ref), "\t","\n");

                write_file(f,text);
                write_file(m,text);

                print fmt("flying");
                close(f);
                close(m);

        }


#RESPONSE FC=24
event modbus_read_FIFO_response(c:connection,is_orig:bool,t:int_vec,tid:count,pid:count,uid:count,fc:count,bcount:count)
        {

                local h:file;
                local m:file;
                local ftime:string;
                local src:string;
                local dst:string;
                local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f3_new.log"));
                m=open_for_append (string_cat(path,"fall_new.log"));
                ftime=strftime("%F %T",network_time());

                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);
                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t", src_p, "\t RESPONSE \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(fc),"\t",cat(bcount),"\t",cat(t),"\n");

                write_file(h,text);
                write_file(m,text);

                close(h);
                close(m);
        }





# REQUEST FC=7 (exception)
event modbus_read_except_request(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,len:count)
        {

                local h:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;
		
                h=open_for_append (string_cat(path,"f7_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));

                ftime=strftime("%F %T",network_time());
                src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t REQUEST \t",cat(len),"\t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(check_e(fc)),"\n");

                
                write_file(h,text);
                write_file(m,text);

		close(h);
                close(m);
        }

# RESPONSE FC=7 (exception)
event modbus_read_except_response(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count,status:count,len:count)
        {

                local h:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"f7_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));

                ftime=strftime("%F %T",network_time());
		src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t RESPONSE \t",cat(tid), "\t",cat(len),"\t",cat(pid),"\t", cat(uid),"\t", cat(check_e(fc)),"\t",cat(status),"\n");

		write_file(h,text);
               	write_file(m,text);
		
		close(h);
                close(m);
        }


# GENERAL EXCEPTION
event modbus_exception(c:connection,is_orig:bool,tid:count,pid:count,uid:count,fc:count, code:count)
        {

 	        local h:file;
		local m:file;
		local ftime:string;
		local src:string;
                local dst:string;
		local src_p:string;
                local dst_p:string;

                h=open_for_append (string_cat(path,"fE_new.log"));
		m=open_for_append (string_cat(path,"fall_new.log"));

                ftime=strftime("%F %T",network_time());
		src= cat(c$id$orig_h);
                dst=cat(c$id$resp_h);

                src_p=cat(c$id$orig_p);
                dst_p=cat(c$id$resp_p);

                local text=string_cat(ftime,"\t",src,"\t",dst,"\t",src_p, "\t EXCEPTION \t",cat(tid), "\t",cat(pid),"\t", cat(uid),"\t", cat(check_e(fc)),"\t",cat(code),"\n");

                 write_file(h,text);
                 write_file(m,text);
              	 close(h);
                 close(m);
        }
