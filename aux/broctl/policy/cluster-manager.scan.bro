# $Id: cluster-manager.scan.bro 6811 2009-07-06 20:41:10Z robin $

redef FilterDuplicates::filters += {
    [AddressScan] = FilterDuplicates::match_src_num,
    [PortScan] = FilterDuplicates::match_src_num,
    [PasswordGuessing] = FilterDuplicates::match_src_num,
	
    [ScanSummary] = FilterDuplicates::match_src,
    [PortScanSummary] = FilterDuplicates::match_src,
    [LowPortScanSummary] = FilterDuplicates::match_src,
    [BackscatterSeen] = FilterDuplicates::match_src,
    [Landmine] = FilterDuplicates::match_src,
    [ShutdownThresh] = FilterDuplicates::match_src,
    [LowPortTrolling] = FilterDuplicates::match_src
};

