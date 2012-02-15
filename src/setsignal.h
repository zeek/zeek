/*
 * See the file "COPYING" in the main distribution directory for copyright.
 *
 */
#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif
