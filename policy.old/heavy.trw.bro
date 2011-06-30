# $Id: heavy.trw.bro 4723 2007-08-07 18:14:35Z vern $

redef TRW::scan_sources &write_expire = 1 day;
redef TRW::benign_sources &write_expire = 1 day;
redef TRW::failed_locals &write_expire = 12 hrs;
redef TRW::successful_locals &write_expire = 12 hrs;
redef TRW::lambda &write_expire = 12 hrs;
redef TRW::num_scanned_locals &write_expire = 12 hrs;
