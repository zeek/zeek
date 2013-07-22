#include "CounterVector.h"

#include <limits>
#include "BitVector.h"
#include "Serializer.h"

CounterVector::CounterVector(size_t width, size_t cells)
  : bits_(new BitVector(width * cells)),
    width_(width)
  {
  }

CounterVector::~CounterVector()
  {
  delete bits_;
  }

bool CounterVector::Increment(size_type cell, count_type value)
  {
  assert(cell < Size());
  assert(value != 0);
  size_t lsb = cell * width_;
  if (value >= Max())
  {
    bool r = false;
    for (size_t i = 0; i < width_; ++i)
      if (! (*bits_)[lsb + i])
      {
        bits_->Set(lsb + i);
        if (! r)
          r = true;
      }
    return r;
  }
  bool carry = false;
  for (size_t i = 0; i < width_; ++i)
  {
    bool b1 = (*bits_)[lsb + i];
    bool b2 = value & (1 << i);
    (*bits_)[lsb + i] ^= b2 != carry; // bit1 ^ bit2 ^ carry
    carry = carry ? b1 || b2 : b1 && b2;
  }
  if (! carry)
    return true;
  for (size_t i = 0; i < width_; ++i)
    bits_->Set(lsb + i);
  return false;
  }

bool CounterVector::Decrement(size_type cell, count_type value)
  {
  assert(cell < Size());
  size_t lsb = cell * width_;
  bool success;
  while (value --> 0)
    {
    success = false;
    for (size_t i = lsb; i < lsb + width_; ++i)
      if ((*bits_)[i])
        {
        bits_->Reset(i);
        while (i && i > lsb)
          bits_->Set(--i);
        success = true;
        break;
        }
    }
  return success;
  }

CounterVector::count_type CounterVector::Count(size_type cell) const
  {
  assert(cell < Size());
  size_t cnt = 0, order = 1;
  size_t lsb = cell * width_;
  for (size_t i = lsb; i < lsb + width_; ++i, order <<= 1)
    if ((*bits_)[i])
      cnt |= order;
  return cnt;
  }

CounterVector::size_type CounterVector::Size() const
  {
  return bits_->Size() / width_;
  }

size_t CounterVector::Max() const
  {
  return std::numeric_limits<size_t>::max()
    >> (std::numeric_limits<size_t>::digits - width_);
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

