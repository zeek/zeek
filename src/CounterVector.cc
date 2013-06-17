#include "CounterVector.h"

#include "BitVector.h"
#include "Serializer.h"

CounterVector::CounterVector(size_t width, size_t cells)
  : bits_(new BitVector(width * cells)), width_(width)
  {
  }

CounterVector::~CounterVector()
  {
  delete bits_;
  }

bool CounterVector::Increment(size_type cell, count_type value)
  {
  // TODO
  assert(! "not yet implemented");
  return false;
  }

bool CounterVector::Decrement(size_type cell, count_type value)
  {
  // TODO
  assert(! "not yet implemented");
  return false;
  }

CounterVector::count_type CounterVector::Count(size_type cell) const
  {
  // TODO
  assert(! "not yet implemented");
  return 0;
  }

CounterVector::size_type CounterVector::Size() const
  {
  return bits_->Blocks() / width_;
  }

bool CounterVector::Serialize(SerialInfo* info) const
  {
  return SerialObj::Serialize(info);
  }

CounterVector* CounterVector::Unserialize(UnserialInfo* info)
  {
  return reinterpret_cast<CounterVector*>(
      SerialObj::Unserialize(info, SER_COUNTERVECTOR));
  }

IMPLEMENT_SERIAL(CounterVector, SER_COUNTERVECTOR)

bool CounterVector::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COUNTERVECTOR, SerialObj);
  if ( ! bits_->Serialize(info) )
    return false;
	return SERIALIZE(static_cast<uint64>(width_));
  }

bool CounterVector::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);
	bits_ = BitVector::Unserialize(info);
  if ( ! bits_ )
    return false;
  uint64 width;
  if ( ! UNSERIALIZE(&width) )
    return false;
	width_ = static_cast<size_t>(width);
	return true;
  }

