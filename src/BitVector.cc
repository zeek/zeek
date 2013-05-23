#include "BitVector.h"

#include <cassert>
#include <limits>

BitVector::size_type BitVector::npos = static_cast<BitVector::size_type>(-1);
BitVector::block_type BitVector::bits_per_block =
  std::numeric_limits<BitVector::block_type>::digits;

namespace {

uint8_t count_table[] = {
  0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2,
  3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3,
  3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3,
  4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4,
  3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5,
  6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4,
  4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5,
  6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 2, 3, 3, 4, 3, 4, 4, 5,
  3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 3,
  4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6,
  6, 7, 6, 7, 7, 8
};

} // namespace <anonymous>

BitVector::Reference::Reference(block_type& block, block_type i)
  : block_(block),
    mask_(block_type(1) << i)
  {
  assert(i < bits_per_block);
  }

BitVector::Reference& BitVector::Reference::flip()
  {
  block_ ^= mask_;
  return *this;
  }

BitVector::Reference::operator bool() const
  {
  return (block_ & mask_) != 0;
  }

bool BitVector::Reference::operator~() const
  {
  return (block_ & mask_) == 0;
  }

BitVector::Reference& BitVector::Reference::operator=(bool x)
  {
  x ? block_ |= mask_ : block_ &= ~mask_;
  return *this;
  }

BitVector::Reference& BitVector::Reference::operator=(Reference const& other)
  {
  other ? block_ |= mask_ : block_ &= ~mask_;
  return *this;
  }

BitVector::Reference& BitVector::Reference::operator|=(bool x)
  {
  if (x) 
    block_ |= mask_;
  return *this;
  }

BitVector::Reference& BitVector::Reference::operator&=(bool x)
  {
  if (! x)
    block_ &= ~mask_;
  return *this;
  }
    
BitVector::Reference& BitVector::Reference::operator^=(bool x)
  {
  if (x)
    block_ ^= mask_;
  return *this;
  }

BitVector::Reference& BitVector::Reference::operator-=(bool x)
  {
  if (x)
    block_ &= ~mask_;
  return *this;
  }


BitVector::BitVector() : num_bits_(0) { }

BitVector::BitVector(size_type size, bool value)
  : bits_(bits_to_blocks(size), value ? ~block_type(0) : 0),
    num_bits_(size)
{ }

BitVector::BitVector(BitVector const& other)
  : bits_(other.bits_),
    num_bits_(other.num_bits_)
{ }

BitVector BitVector::operator~() const
  {
  BitVector b(*this);
  b.flip();
  return b;
  }

BitVector& BitVector::operator=(BitVector const& other)
  {
  bits_ = other.bits_;
  return *this;
  }

BitVector BitVector::operator<<(size_type n) const
  {
  BitVector b(*this);
  return b <<= n;
  }

BitVector BitVector::operator>>(size_type n) const
  {
  BitVector b(*this);
  return b >>= n;
  }

BitVector& BitVector::operator<<=(size_type n)
  {
  if (n >= num_bits_)
    return reset();

  if (n > 0)
    {
    size_type last = blocks() - 1;
    size_type div = n / bits_per_block;
    block_type r = bit_index(n);
    block_type* b = &bits_[0];
    assert(blocks() >= 1);
    assert(div <= last);

    if (r != 0)
      {
      for (size_type i = last - div; i > 0; --i)
        b[i + div] = (b[i] << r) | (b[i - 1] >> (bits_per_block - r));
      b[div] = b[0] << r;
      }
    else
      {
      for (size_type i = last-div; i > 0; --i)
        b[i + div] = b[i];
      b[div] = b[0];
      }

    std::fill_n(b, div, block_type(0));
    zero_unused_bits();
    }

  return *this;
  }

BitVector& BitVector::operator>>=(size_type n)
  {
  if (n >= num_bits_)
      return reset();

  if (n > 0)
    {
    size_type last = blocks() - 1;
    size_type div = n / bits_per_block;
    block_type r = bit_index(n);
    block_type* b = &bits_[0];
    assert(blocks() >= 1);
    assert(div <= last);

    if (r != 0)
      {
      for (size_type i = last - div; i > 0; --i)
        b[i - div] = (b[i] >> r) | (b[i + 1] << (bits_per_block - r));
      b[last - div] = b[last] >> r;
      }
    else
      {
      for (size_type i = div; i <= last; ++i)
        b[i-div] = b[i];
      }

    std::fill_n(b + (blocks() - div), div, block_type(0));
    }
  return *this;
  }

BitVector& BitVector::operator&=(BitVector const& other)
  {
  assert(size() >= other.size());
  for (size_type i = 0; i < blocks(); ++i)
    bits_[i] &= other.bits_[i];
  return *this;
  }

BitVector& BitVector::operator|=(BitVector const& other)
  {
  assert(size() >= other.size());
  for (size_type i = 0; i < blocks(); ++i)
    bits_[i] |= other.bits_[i];
  return *this;
  }

BitVector& BitVector::operator^=(BitVector const& other)
  {
  assert(size() >= other.size());
  for (size_type i = 0; i < blocks(); ++i)
    bits_[i] ^= other.bits_[i];
  return *this;
  }

BitVector& BitVector::operator-=(BitVector const& other)
  {
  assert(size() >= other.size());
  for (size_type i = 0; i < blocks(); ++i)
    bits_[i] &= ~other.bits_[i];
  return *this;
  }

BitVector operator&(BitVector const& x, BitVector const& y)
  {
  BitVector b(x);
  return b &= y;
  }

BitVector operator|(BitVector const& x, BitVector const& y)
  {
  BitVector b(x);
  return b |= y;
  }

BitVector operator^(BitVector const& x, BitVector const& y)
  {
  BitVector b(x);
  return b ^= y;
  }

BitVector operator-(BitVector const& x, BitVector const& y)
  {
  BitVector b(x);
  return b -= y;
  }

bool operator==(BitVector const& x, BitVector const& y)
  {
  return x.num_bits_ == y.num_bits_ && x.bits_ == y.bits_;
  }

bool operator!=(BitVector const& x, BitVector const& y)
  {
  return ! (x == y);
  }

bool operator<(BitVector const& x, BitVector const& y)
  {
  assert(x.size() == y.size());
  for (BitVector::size_type r = x.blocks(); r > 0; --r)
    {
    BitVector::size_type i = r - 1;
    if (x.bits_[i] < y.bits_[i])
      return true;
    else if (x.bits_[i] > y.bits_[i])
      return false;
    }
  return false;
  }

void BitVector::resize(size_type n, bool value)
  {
  size_type old = blocks();
  size_type required = bits_to_blocks(n);
  block_type block_value = value ? ~block_type(0) : block_type(0);

  if (required != old)
    bits_.resize(required, block_value);

  if (value && (n > num_bits_) && extra_bits())
    bits_[old - 1] |= (block_value << extra_bits());

  num_bits_ = n;
  zero_unused_bits();
  }

void BitVector::clear()
  {
  bits_.clear();
  num_bits_ = 0;
  }

void BitVector::push_back(bool bit)
  {
  size_type s = size();
  resize(s + 1);
  set(s, bit);
  }

void BitVector::append(block_type block)
  {
  size_type excess = extra_bits();
  if (excess)
    {
    assert(! bits_.empty());
    bits_.push_back(block >> (bits_per_block - excess));
    bits_[bits_.size() - 2] |= (block << excess);
    }
  else
    {
    bits_.push_back(block);
    }
  num_bits_ += bits_per_block;
  }

BitVector& BitVector::set(size_type i, bool bit)
  {
  assert(i < num_bits_);

  if (bit)
      bits_[block_index(i)] |= bit_mask(i);
  else
      reset(i);

  return *this;
  }

BitVector& BitVector::set()
  {
  std::fill(bits_.begin(), bits_.end(), ~block_type(0));
  zero_unused_bits();
  return *this;
  }

BitVector& BitVector::reset(size_type i)
  {
  assert(i < num_bits_);
  bits_[block_index(i)] &= ~bit_mask(i);
  return *this;
  }

BitVector& BitVector::reset()
  {
  std::fill(bits_.begin(), bits_.end(), block_type(0));
  return *this;
  }

BitVector& BitVector::flip(size_type i)
  {
  assert(i < num_bits_);
  bits_[block_index(i)] ^= bit_mask(i);
  return *this;
  }

BitVector& BitVector::flip()
  {
  for (size_type i = 0; i < blocks(); ++i)
      bits_[i] = ~bits_[i];
  zero_unused_bits();
  return *this;
  }

bool BitVector::operator[](size_type i) const
  {
  assert(i < num_bits_);
  return (bits_[block_index(i)] & bit_mask(i)) != 0;
  }

BitVector::Reference BitVector::operator[](size_type i)
  {
  assert(i < num_bits_);
  return Reference(bits_[block_index(i)], bit_index(i));
  }

BitVector::size_type BitVector::count() const
  {
  std::vector<block_type>::const_iterator first = bits_.begin();
  size_t n = 0;
  size_type length = blocks();
  while (length)
    {
    block_type block = *first;
    while (block)
      {
      // TODO: use __popcnt if available.
      n += count_table[block & ((1u << 8) - 1)];
      block >>= 8;
      }
    ++first;
    --length;
    }
  return n;
  }

BitVector::size_type BitVector::blocks() const
  {
  return bits_.size();
  }

BitVector::size_type BitVector::size() const
  {
  return num_bits_;
  }

bool BitVector::empty() const
  {
  return bits_.empty();
  }

BitVector::size_type BitVector::find_first() const
  {
  return find_from(0);
  }

BitVector::size_type BitVector::find_next(size_type i) const
  {
  if (i >= (size() - 1) || size() == 0)
    return npos;
  ++i;
  size_type bi = block_index(i);
  block_type block = bits_[bi] & (~block_type(0) << bit_index(i));
  return block ? bi * bits_per_block + lowest_bit(block) : find_from(bi + 1);
  }

BitVector::size_type BitVector::lowest_bit(block_type block)
  {
  block_type x = block - (block & (block - 1));
  size_type log = 0;
  while (x >>= 1)
    ++log;
  return log;
  }

BitVector::block_type BitVector::extra_bits() const
  {
  return bit_index(size());
  }

void BitVector::zero_unused_bits()
  {
  if (extra_bits())
    bits_.back() &= ~(~block_type(0) << extra_bits());
  }

BitVector::size_type BitVector::find_from(size_type i) const
  {
  while (i < blocks() && bits_[i] == 0)
    ++i;
  if (i >= blocks())
    return npos;
  return i * bits_per_block + lowest_bit(bits_[i]);
  }
