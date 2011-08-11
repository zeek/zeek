##! Local site policy loaded only by the manager in a cluster.

@load base/frameworks/notice/main

# If you are running a cluster you should define your Notice::policy here 
# so that notice processing occurs on the manager.
redef Notice::policy += {

};
