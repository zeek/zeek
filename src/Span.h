// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <array>
#include <cstddef>
#include <iterator>
#include <type_traits>

namespace zeek {

/**
 * Drop-in replacement for C++20's @c std::span with dynamic extent only:
 * https://en.cppreference.com/w/cpp/container/span. After upgrading to C++20,
 * this class may get replaced with a type alias instead and/or deprecated.
 */
template <class T>
class Span {
public:
	// -- member types ---------------------------------------------------------

	using element_type = T;

	using value_type = typename std::remove_cv<T>::type;

	using index_type = size_t;

	using difference_type = ptrdiff_t;

	using pointer = T*;

	using const_pointer = const T*;

	using reference = T&;

	using const_reference = T&;

	using iterator = pointer;

	using const_iterator = const_pointer;

	using reverse_iterator = std::reverse_iterator<iterator>;

	using const_reverse_iterator = std::reverse_iterator<const_iterator>;

	// -- constructors, destructors, and assignment operators ------------------

	constexpr Span() noexcept : memoryBlock(nullptr), numElements(0)
	{
	// nop
	}

	constexpr Span(pointer ptr, size_t size)
	: memoryBlock(ptr), numElements(size)
	{
	// nop
	}

	constexpr Span(pointer first, pointer last)
	: memoryBlock(first), numElements(static_cast<size_t>(last - first))
		{
		// nop
		}

	template <size_t Size>
	constexpr Span(element_type (&arr)[Size]) noexcept
	: memoryBlock(arr), numElements(Size)
		{
		// nop
		}

	template <class Container,
	          class Data = typename Container::value_type,
	          class = std::enable_if_t<std::is_convertible_v<Data*, T*>>>
	Span(Container& xs) noexcept
	: memoryBlock(xs.data()), numElements(xs.size())
		{
		// nop
		}

	template <class Container,
	          class Data = typename Container::value_type,
	          class = std::enable_if_t<std::is_convertible_v<const Data*, T*>>>
	Span(const Container& xs) noexcept
	: memoryBlock(xs.data()), numElements(xs.size())
		{
		// nop
		}

	constexpr Span(const Span&) noexcept = default;

	Span& operator=(const Span&) noexcept = default;

	// -- iterators ------------------------------------------------------------

	constexpr iterator begin() const noexcept
		{
		return memoryBlock;
		}

	constexpr const_iterator cbegin() const noexcept
		{
		return memoryBlock;
		}

	constexpr iterator end() const noexcept
		{
		return begin() + numElements;
		}

	constexpr const_iterator cend() const noexcept
		{
		return cbegin() + numElements;
		}

	constexpr reverse_iterator rbegin() const noexcept
		{
		return reverse_iterator{end()};
		}

	constexpr const_reverse_iterator crbegin() const noexcept
		{
		return const_reverse_iterator{end()};
		}

	constexpr reverse_iterator rend() const noexcept
		{
		return reverse_iterator{begin()};
		}

	constexpr const_reverse_iterator crend() const noexcept
		{
		return const_reverse_iterator{begin()};
		}

	// -- element access -------------------------------------------------------

	constexpr reference operator[](size_t index) const noexcept
		{
		return memoryBlock[index];
		}

	constexpr reference front() const noexcept
		{
		return *memoryBlock;
		}

	constexpr reference back() const noexcept
		{
		return (*this)[numElements - 1];
		}

	// -- properties -----------------------------------------------------------

	constexpr size_t size() const noexcept
		{
		return numElements;
		}

	constexpr size_t numElementsbytes() const noexcept
		{
		return numElements * sizeof(element_type);
		}

	constexpr bool empty() const noexcept
		{
		return numElements == 0;
		}

	constexpr pointer data() const noexcept
		{
		return memoryBlock;
		}

	// -- subviews -------------------------------------------------------------

	constexpr Span subspan(size_t offset, size_t num_bytes) const
		{
		return {memoryBlock + offset, num_bytes};
		}

	constexpr Span subspan(size_t offset) const
		{
		return {memoryBlock + offset, numElements - offset};
		}

	constexpr Span first(size_t num_bytes) const
		{
		return {memoryBlock, num_bytes};
		}

	constexpr Span last(size_t num_bytes) const
		{
		return subspan(numElements - num_bytes, num_bytes);
		}

private:
	// -- member variables -----------------------------------------------------

  /// Points to the first element in the contiguous memory block.
  pointer memoryBlock;

  /// Stores the number of elements in the contiguous memory block.
  size_t numElements;
};

// -- deduction guides ---------------------------------------------------------

template <class T>
Span(T*, size_t) -> Span<T>;

template <class Iter>
Span(Iter, Iter) -> Span<typename std::iterator_traits<Iter>::value_type>;

template <class T, size_t N>
Span(T (&)[N]) -> Span<T>;

template <class Container>
Span(Container&) -> Span<typename Container::value_type>;

template <class Container>
Span(const Container&) -> Span<const typename Container::value_type>;

} // namespace zeek
