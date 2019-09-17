/*
 * See the file "COPYING" in the main distribution directory for copyright.
 *
 */
#pragma once

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
