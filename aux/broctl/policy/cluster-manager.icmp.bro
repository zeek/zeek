# $Id: cluster-manager.scan.bro 6740 2009-06-12 17:59:44Z robin $

redef FilterDuplicates::filters += {
    [ICMPAddressScan] = FilterDuplicates::match_src_num
};
	
# $Id: cluster-manager.scan.bro 6740 2009-06-12 17:59:44Z robin $

redef FilterDuplicates::filters += {
    [ICMPAddressScan] = FilterDuplicates::match_src_num
};
	
