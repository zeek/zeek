/*
 * Copyright (c) 2011-2015 James Swaro
 * Copyright (c) 2011-2015 Internetworking Research Group, Ohio University
 */


#include "TCPRS_Support.h"

using namespace analyzer::tcp;

/****************************************************************************
 Code for Duplicate Ack class
*****************************************************************************/
DuplicateAck::DuplicateAck(uint32 seq, double current_time) {
	sequence = seq;

	dupCount = 0;
	fastRTX = false;

	first = current_time;
	last = first;
	updateDupAck(current_time);
}

DuplicateAck::DuplicateAck(const DuplicateAck& copy) {
	sequence = copy.sequence;
	dupCount = copy.dupCount;
	fastRTX = copy.fastRTX;
	first = copy.first;
	last = copy.last;
	timestamps = copy.timestamps;
}

void DuplicateAck::updateDupAck(double arg) {
	setTS(arg);
	++dupCount;
	last = arg;
}

