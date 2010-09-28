/*
 * See the file "COPYING" in the main distribution directory for copyright.
 *
 * @(#) $Id: setsignal.h 6219 2008-10-01 05:39:07Z vern $ (LBL)
 */
#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif
