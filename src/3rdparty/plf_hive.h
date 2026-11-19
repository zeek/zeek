// Copyright (c) 2026, Matthew Bentley (mattreecebentley@gmail.com) www.plflib.org

// zLib license (https://www.zlib.net/zlib_license.html):
// This software is provided 'as-is', without any express or implied
// warranty. In no event will the authors be held liable for any damages
// arising from the use of this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
// 1. The origin of this software must not be misrepresented; you must not
// 	claim that you wrote the original software. If you use this software
// 	in a product, an acknowledgement in the product documentation would be
// 	appreciated but is not required.
// 2. Altered source versions must be plainly marked as such, and must not be
// 	misrepresented as being the original software.
// 3. This notice may not be removed or altered from any source distribution.


#ifndef PLF_HIVE_H
#define PLF_HIVE_H
#define __cpp_lib_hive


#define PLF_EXCEPTIONS_SUPPORT

#if ((defined(__clang__) || defined(__GNUC__)) && !defined(__EXCEPTIONS)) || (defined(_MSC_VER) && !defined(_CPPUNWIND))
	#undef PLF_EXCEPTIONS_SUPPORT
	#include <exception> // std::terminate
#endif

#if defined(_MSC_VER) && !defined(__clang__) && !defined(__GNUC__)
	// Suppress incorrect (unfixed MSVC bug at warning level 4) warnings re: constant expressions in constexpr-if statements
	#pragma warning ( push )
	#pragma warning ( disable : 4127 )
#endif

#include <algorithm> // std::fill_n, std::sort, std::swap
#include <cstdint> // uint_least16_t etc
#include <cassert>	// assert
#include <cstring>	// memset, memcpy, size_t
#include <limits>  // std::numeric_limits
#include <memory> // std::allocator, std::to_address
#include <iterator> // std::bidirectional_iterator_tag, iterator_traits, make_move_iterator, std::distance for range insert
#include <stdexcept> // std::length_error, std::out_of_range
#include <functional> // std::less
#include <cstddef> // offsetof, used in blank()
#include <cstdint> // uint_least16_t, etc
#include <type_traits> // std::is_trivially_destructible, enable_if_t, type_identity_t, etc
#include <utility> // std::move
#include <initializer_list>
#include <concepts>
#include <compare> // std::strong_ordering
#include <ranges>



namespace plf
{
	// For getting std:: overloads to match hive iterators specifically:
	template <class T>
	concept hive_iterator_concept = requires { typename T::hive_iterator_tag; };

	#ifndef PLF_FROM_RANGE // To ensure interoperability with other plf lib containers
		#define PLF_FROM_RANGE

		// Until such point as standard libraries ubiquitously include std::from_range_t, including this so the rangesv3 constructor overloads will work unambiguously:
		namespace ranges
		{
			struct from_range_t {};
			inline constexpr from_range_t from_range;
		}
	#endif
}



// Overloads for advance etc must be defined here as they are called by range-assign/insert functions - otherwise compiler will call std:: bidirectional overloads:
namespace std
{
	template <plf::hive_iterator_concept it_type, typename distance_type>
	void advance(it_type &it, const distance_type distance)
	{
		it.advance(static_cast<typename iterator_traits<it_type>::difference_type>(distance));
	}



	template <plf::hive_iterator_concept it_type>
	[[nodiscard]] it_type next(it_type it, const typename iterator_traits<it_type>::difference_type distance = 1)
	{
		it.advance(distance);
		return it;
	}



	template <plf::hive_iterator_concept it_type>
	[[nodiscard]] it_type prev(it_type it, const typename iterator_traits<it_type>::difference_type distance = 1)
	{
		it.advance(-distance);
		return it;
	}



	template <plf::hive_iterator_concept it_type>
	typename iterator_traits<it_type>::difference_type distance(const it_type first, const it_type last)
	{
		return first.distance(last);
	}
}



namespace plf
{


struct hive_limits // for use in block_capacity setting/getting functions and constructors
{
	size_t min, max;
	constexpr hive_limits(const size_t minimum, const size_t maximum) noexcept : min(minimum), max(maximum) {}
};



template <class element_type, class allocator_type = std::allocator<element_type> >
class hive : private allocator_type // Empty base class optimisation - inheriting allocator functions
{
	typedef std::conditional_t<(sizeof(element_type) > 10 || alignof(element_type) > 10), uint_least16_t, uint_least8_t> skipfield_type;

public:
	// Standard container typedefs:
	typedef element_type value_type;
	typedef typename std::allocator_traits<allocator_type>::size_type 			size_type;
	typedef typename std::allocator_traits<allocator_type>::difference_type 	difference_type;
	typedef element_type &														reference;
	typedef const element_type &												const_reference;
	typedef typename std::allocator_traits<allocator_type>::pointer				pointer;
	typedef typename std::allocator_traits<allocator_type>::const_pointer		const_pointer;

	// Iterator forward declarations:
	template <bool is_const> class			hive_iterator;
	typedef hive_iterator<false>			iterator;
	typedef hive_iterator<true> 			const_iterator;
	friend iterator;
	friend const_iterator;

	template <bool is_const_r> class		hive_reverse_iterator;
	typedef hive_reverse_iterator<false>	reverse_iterator;
	typedef hive_reverse_iterator<true>		const_reverse_iterator;
	friend reverse_iterator;
	friend const_reverse_iterator;



private:

	// The element as allocated in memory needs to be at-least 2*skipfield_type width in order to support free list indexes in erased element memory space, so:
	// make the size of this struct the larger of alignof(T), sizeof(T) or 2*skipfield_type (the latter is only relevant for type char/uchar), and
	// make the alignment alignof(T).
	// This type is used mainly for correct pointer arithmetic while iterating over elements in memory.
	struct alignas(alignof(element_type)) aligned_element_struct
	{
		 // Using char as sizeof is always guaranteed to be 1 byte regardless of the number of bits in a byte on given computer, whereas for example, uint8_t would fail on machines where there are more than 8 bits in a byte eg. Texas Instruments C54x DSPs.
		char data[
		(sizeof(element_type) < (sizeof(skipfield_type) * 2)) ?
		((sizeof(skipfield_type) * 2) < alignof(element_type) ? alignof(element_type) : (sizeof(skipfield_type) * 2)) :
		((sizeof(element_type) < alignof(element_type)) ? alignof(element_type) : sizeof(element_type))
		];
	};


	// We combine the allocation of elements and skipfield into one allocation to save performance. This memory must be allocated as an aligned type with the same alignment as T in order for the elements to align with memory boundaries correctly (which won't happen if we allocate as char or uint_8). But the larger the sizeof in the type we use for allocation, the greater the chance of creating a lot of unused memory in the skipfield portion of the allocated block. So we create a type that is sizeof(alignof(T)), as in most cases alignof(T) < sizeof(T). If alignof(t) >= sizeof(t) this makes no difference.
	struct alignas(alignof(element_type)) aligned_allocation_struct
	{
	  char data[alignof(element_type)];
	};


	// Calculate the capacity of a group's elements+skipfield memory block when expressed in multiples of the value_type's alignment (rounding up).
	static size_type get_aligned_block_capacity(const skipfield_type elements_per_group) noexcept
	{
		return ((elements_per_group * (sizeof(aligned_element_struct) + sizeof(skipfield_type))) + sizeof(skipfield_type) + sizeof(aligned_allocation_struct) - 1) / sizeof(aligned_allocation_struct);
	}



	// forward declarations for typedefs below
	struct group;
	struct item_index_tuple; // for use in sort()


	// These two need to be raw pointers as instances of this type have pointer arithmetic done to them:
	typedef aligned_element_struct *	aligned_pointer_type; // pointer to the (potentially overaligned) element type, not the original element type
	typedef skipfield_type *			skipfield_pointer_type;

	typedef typename std::allocator_traits<allocator_type>::template rebind_alloc<aligned_element_struct>		aligned_allocator_type;
	typedef typename std::allocator_traits<allocator_type>::template rebind_alloc<group>							group_allocator_type;
	typedef typename std::allocator_traits<allocator_type>::template rebind_alloc<skipfield_type>				skipfield_allocator_type;
	typedef typename std::allocator_traits<allocator_type>::template rebind_alloc<aligned_allocation_struct> aligned_struct_allocator_type;
	typedef typename std::allocator_traits<allocator_type>::template rebind_alloc<item_index_tuple> 			tuple_allocator_type;

	typedef typename std::allocator_traits<group_allocator_type>::pointer				group_pointer_type;
	typedef typename std::allocator_traits<aligned_struct_allocator_type>::pointer	aligned_struct_pointer_type;
	typedef typename std::allocator_traits<tuple_allocator_type>::pointer				tuple_pointer_type;



	// To simplify conversion when allocator supplies non-raw pointers:
	template <class destination_pointer_type, class source_pointer_type>
	static constexpr destination_pointer_type pointer_cast(const source_pointer_type source_pointer) noexcept
	{
		if constexpr (std::is_trivially_constructible<destination_pointer_type>::value)
		{
			if constexpr (std::is_trivially_constructible<source_pointer_type>::value)
			{
				return reinterpret_cast<destination_pointer_type>(source_pointer);
			}
			else
			{
				return reinterpret_cast<destination_pointer_type>(std::to_address(source_pointer));
			}
		}
		else
		{
			return destination_pointer_type(std::to_address(source_pointer));
		}
	}


	// Function purely to save typing:
	template <class source_pointer_type>
	static constexpr aligned_pointer_type to_aligned_pointer(const source_pointer_type source_pointer) noexcept
	{
		return pointer_cast<aligned_pointer_type>(source_pointer);
	}



	// group == element memory block + skipfield + block metadata

	// Skipfield implementation notes:
	// (1) Follows low-complexity jump-counting pattern rules as described here: archive.org/details/matt_bentley_-_the_low_complexity_jump-counting_pattern
	// (2) Initialized to 0 by-default, which means 'non-erased' ie. either no element has ever been constructed there, or an element has been constructed there. Whereas non-zero means an element has been constructed there and subsequently erased. The value of the first and last non-zero nodes in a run of non-zero nodes determines jump length. See the paper for details.
	// (3) This definition means we can bulk-initialize each group's skipfield to 0, rather than bulk-initialize to non-zero then subsequently change individual skipfield nodes to 0 upon insertion - which is obviously slower. Defining unconstructed elements as 0 has no impact on iteration since they're after end(). Note that this definition is violated slightly during splice: unconstructed element nodes at the end of the destination hive's back block will have their corresponding skipfield nodes flipped to 'erased' in order to make iteration work, because they will not longer be after end() once the source hive's blocks are appended.
	// (4) There will always be one additional skipfield node allocated compared to the group's number of elements. This ensures a faster ++ iterator operation (fewer checks are required when it is present). The extra node is unused and always 0, but checked, and not having it will result in out-of-bounds memory errors.


	struct group
	{
		skipfield_pointer_type					skipfield;			// Skipfield storage. The element and skipfield arrays are allocated contiguously, in a single allocation, in this implementation, hence the skipfield pointer also functions as a 'one-past-end' pointer for the elements array. This is present before elements in the group struct as it is referenced constantly by the ++ operator, hence having it first results in a minor performance increase.
		group_pointer_type						next_group;			// Next group in the linked list of all groups. nullptr if no following group. 2nd in struct because it is so frequently used during iteration.
		const aligned_struct_pointer_type	elements;			// Element storage.
		group_pointer_type						previous_group;		// Previous group in the linked list of all groups. nullptr if no preceding group.
		skipfield_type 							free_list_head;		// The index of the last erased element in the group. The last erased element will, in turn, contain the number of the index of the next erased element, and so on. If this is == maximum skipfield_type value then free_list is empty ie. no erasures have occurred in the group (or if they have, the erased locations have subsequently been reused via insert/emplace/assign).
		const skipfield_type 					capacity;			// The element capacity of this particular group - can also be calculated from reinterpret_cast<aligned_pointer_type>(group->skipfield) - group->elements, however this space is effectively free due to struct padding and the sizeof(skipfield_type), and calculating it once is faster in benchmarking.
		skipfield_type 							size; 				// The total number of active elements in group - changes with insert and erase commands - used to check for empty group in erase function, as an indication to remove the group. Also used in combination with capacity to check if group is full, which is used in the next/previous/advance/distance overloads, and range-erase.
		group_pointer_type						erasures_list_next_group, erasures_list_previous_group; // The next and previous groups in the list of groups with erasures ie. with active erased-element free lists. nullptr if no next or previous group.
		size_type									group_number;		// Used for comparison (> < >= <= <=>) iterator operators (used by distance function and user).



		group(aligned_struct_allocator_type &aligned_struct_allocator, const skipfield_type elements_per_group, const group_pointer_type previous):
			next_group(nullptr),
			elements(std::allocator_traits<aligned_struct_allocator_type>::allocate(aligned_struct_allocator, get_aligned_block_capacity(elements_per_group), (previous == nullptr) ? 0 : previous->elements)),
			previous_group(previous),
			free_list_head(std::numeric_limits<skipfield_type>::max()),
			capacity(elements_per_group),
			size(1),
			erasures_list_next_group(nullptr),
			erasures_list_previous_group(nullptr),
			group_number((previous == nullptr) ? 0 : previous->group_number + 1u)
		{
			skipfield = pointer_cast<skipfield_pointer_type>(to_aligned_pointer(elements) + elements_per_group);
			std::memset(std::to_address(skipfield), 0, sizeof(skipfield_type) * (static_cast<size_type>(elements_per_group) + 1u));
		}



		void reset(const skipfield_type increment, const group_pointer_type next, const group_pointer_type previous, const size_type group_num) noexcept
		{
			next_group = next;
			free_list_head = std::numeric_limits<skipfield_type>::max();
			previous_group = previous;
			size = increment;
			erasures_list_next_group = nullptr;
			erasures_list_previous_group = nullptr;
			group_number = group_num;

			std::memset(std::to_address(skipfield), 0, sizeof(skipfield_type) * static_cast<size_type>(capacity)); // capacity + 1 is not necessary here as the final skipfield node is never written to after initialization
		}
	};



	// Hive member variables:

	iterator 				end_iterator, begin_iterator;
	group_pointer_type	erasure_groups_head,	// Head of doubly-linked list of groups which have erased-element memory locations available for re-use
								unused_groups_head;		// Head of singly-linked list of reserved groups retained by erase()/clear() or created by reserve()
	size_type				total_size, total_capacity;
	skipfield_type 		min_block_capacity, max_block_capacity;

	group_allocator_type group_allocator;
	aligned_struct_allocator_type aligned_struct_allocator;
	skipfield_allocator_type skipfield_allocator;
	tuple_allocator_type tuple_allocator;



	static constexpr size_t max_size_static() noexcept
	{
		return static_cast<size_t>(std::allocator_traits<allocator_type>::max_size(allocator_type()));
	}



	// Adaptive minimum based around aligned size, sizeof(group) and sizeof(hive):
	static constexpr skipfield_type block_capacity_default_min() noexcept
	{
		const skipfield_type adaptive_size = static_cast<skipfield_type>(((sizeof(hive) + sizeof(group)) * 2) / sizeof(aligned_element_struct));
		const skipfield_type max_block_capacity = block_capacity_default_max(); // Necessary to check against in situations with > 64bit pointer sizes and small sizeof(T)
		return std::max(static_cast<skipfield_type>(8), std::min(adaptive_size, max_block_capacity));
	}



	// Adaptive maximum based on numeric_limits and best outcome from multiple benchmark's (on balance) in terms of memory usage and performance:
	static constexpr skipfield_type block_capacity_default_max() noexcept
	{
		return static_cast<skipfield_type>(std::min(std::min(static_cast<size_t>(std::numeric_limits<skipfield_type>::max()), static_cast<size_t>(8192u)), max_size_static()));
	}



	void check_capacities_conformance(const hive_limits capacities) const
	{
		constexpr hive_limits hard_capacities = block_capacity_hard_limits();

		if (capacities.min < hard_capacities.min || capacities.min > capacities.max || capacities.max > hard_capacities.max)
		{
			#ifdef PLF_EXCEPTIONS_SUPPORT
				throw std::out_of_range("Supplied memory block capacity limits are either invalid or outside of block_capacity_hard_limits()");
			#else
				std::terminate();
			#endif
		}
	}



	void blank() noexcept
	{
		if constexpr (std::is_standard_layout<hive>::value && std::allocator_traits<allocator_type>::is_always_equal::value && std::is_trivially_destructible<group_pointer_type>::value)
		{ // If all pointer types are trivial, we can just nuke the member variables from orbit with memset (nullptr is always 0):
			std::memset(static_cast<void *>(this), 0, offsetof(hive, min_block_capacity));
		}
		else
		{
			end_iterator.group_pointer = nullptr;
			end_iterator.element_pointer = nullptr;
			end_iterator.skipfield_pointer = nullptr;
			begin_iterator.group_pointer = nullptr;
			begin_iterator.element_pointer = nullptr;
			begin_iterator.skipfield_pointer = nullptr;
			erasure_groups_head = nullptr;
			unused_groups_head = nullptr;
			total_size = 0;
			total_capacity = 0;
		}
	}



	template <class iterator_type>
	void reserve_and_range_fill(const size_type size, const iterator_type it)
	{
		if (size != 0)
		{
			reserve(size);
			end_iterator.group_pointer->next_group = unused_groups_head;
			range_fill_unused_groups(size, it, 0, nullptr, begin_iterator.group_pointer);
		}
	}



public:


	static constexpr hive_limits block_capacity_default_limits() noexcept
	{
		return hive_limits(static_cast<size_t>(block_capacity_default_min()), static_cast<size_t>(block_capacity_default_max()));
	}



	// Default constructors:

	constexpr explicit hive(const allocator_type &alloc) noexcept:
		allocator_type(alloc),
		erasure_groups_head(nullptr),
		unused_groups_head(nullptr),
		total_size(0),
		total_capacity(0),
		min_block_capacity(block_capacity_default_min()),
		max_block_capacity(block_capacity_default_max()),
		group_allocator(*this),
		aligned_struct_allocator(*this),
		skipfield_allocator(*this),
		tuple_allocator(*this)
	{}



	constexpr hive() noexcept(noexcept(allocator_type())) :
		hive(allocator_type())
	{}



	constexpr hive(const hive_limits block_limits, const allocator_type &alloc):
		allocator_type(alloc),
		erasure_groups_head(nullptr),
		unused_groups_head(nullptr),
		total_size(0),
		total_capacity(0),
		min_block_capacity(static_cast<skipfield_type>(block_limits.min)),
		max_block_capacity(static_cast<skipfield_type>(block_limits.max)),
		group_allocator(*this),
		aligned_struct_allocator(*this),
		skipfield_allocator(*this),
		tuple_allocator(*this)
	{
		check_capacities_conformance(block_limits);
	}



	constexpr explicit hive(const hive_limits block_limits):
		hive(block_limits, allocator_type())
	{}



	// Copy constructors:

	hive(const hive &source, const std::type_identity_t<allocator_type> &alloc):
		allocator_type(alloc),
		erasure_groups_head(nullptr),
		unused_groups_head(nullptr),
		total_size(0),
		total_capacity(0),
		min_block_capacity(std::max(source.min_block_capacity, static_cast<skipfield_type>(std::min(source.total_size, static_cast<size_type>(source.max_block_capacity))))), // min group size is set to value closest to total number of elements in source hive, in order to not create unnecessary small groups in the range-insert below, then reverts to the original min group size afterwards. This effectively saves a call to reserve.
		max_block_capacity(source.max_block_capacity),
		group_allocator(*this),
		aligned_struct_allocator(*this),
		skipfield_allocator(*this),
		tuple_allocator(*this)
	{ // can skip checking for skipfield conformance here as source will have already checked theirs. Same applies for other copy and move constructors below
		reserve_and_range_fill(source.total_size, source.begin_iterator);
		min_block_capacity = source.min_block_capacity; // reset to correct value for future operations
	}



	hive(const hive &source):
		hive(source, std::allocator_traits<allocator_type>::select_on_container_copy_construction(source))
	{}



	// Move constructors:

	hive(hive &&source, const std::type_identity_t<allocator_type> &alloc):
		allocator_type(alloc),
		end_iterator(source.end_iterator),
		begin_iterator(source.begin_iterator),
		erasure_groups_head(source.erasure_groups_head),
		unused_groups_head(source.unused_groups_head),
		total_size(source.total_size),
		total_capacity(source.total_capacity),
		min_block_capacity(source.min_block_capacity),
		max_block_capacity(source.max_block_capacity),
		group_allocator(alloc),
		aligned_struct_allocator(alloc),
		skipfield_allocator(alloc),
		tuple_allocator(alloc)
	{
		if constexpr (!std::allocator_traits<allocator_type>::is_always_equal::value)
		{
			if (alloc != static_cast<allocator_type &>(source))
			{
				blank();
				reserve_and_range_fill(source.total_size, std::make_move_iterator(source.begin_iterator));
				source.destroy_all_data();
			}
		}

		source.blank();
	}



  	hive(hive &&source) noexcept:
		allocator_type(static_cast<allocator_type &>(source)),
		end_iterator(std::move(source.end_iterator)),
		begin_iterator(std::move(source.begin_iterator)),
		erasure_groups_head(std::move(source.erasure_groups_head)),
		unused_groups_head(std::move(source.unused_groups_head)),
		total_size(source.total_size),
		total_capacity(source.total_capacity),
		min_block_capacity(source.min_block_capacity),
		max_block_capacity(source.max_block_capacity),
		group_allocator(*this),
		aligned_struct_allocator(*this),
		skipfield_allocator(*this),
		tuple_allocator(*this)
	{
		source.blank();
	}



	// Fill constructors:

	hive(const size_type fill_number, const element_type &element, const hive_limits block_limits, const allocator_type &alloc = allocator_type()):
		allocator_type(alloc),
		erasure_groups_head(nullptr),
		unused_groups_head(nullptr),
		total_size(0),
		total_capacity(0),
		min_block_capacity(static_cast<skipfield_type>(block_limits.min)),
		max_block_capacity(static_cast<skipfield_type>(block_limits.max)),
		group_allocator(*this),
		aligned_struct_allocator(*this),
		skipfield_allocator(*this),
		tuple_allocator(*this)
	{
		check_capacities_conformance(block_limits);

		if (fill_number != 0)
		{
			reserve(fill_number);
			end_iterator.group_pointer->next_group = unused_groups_head;
			fill_unused_groups(fill_number, element, 0, nullptr, begin_iterator.group_pointer);
		}
	}



	hive(const size_type fill_number, const element_type &element, const allocator_type &alloc = allocator_type()) :
		hive(fill_number, element, block_capacity_default_limits(), alloc)
	{}



	// Default-value fill constructors:

	hive(const size_type fill_number, const hive_limits block_limits, const allocator_type &alloc = allocator_type()):
		hive(fill_number, element_type(), block_limits, alloc)
	{}



	hive(const size_type fill_number, const allocator_type &alloc = allocator_type()):
		hive(fill_number, element_type(), block_capacity_default_limits(), alloc)
	{}



	// Range constructors:

	template<typename iterator_type>
	hive(const typename std::enable_if_t<!std::numeric_limits<iterator_type>::is_integer, iterator_type> &first, const iterator_type &last, const hive_limits block_limits, const allocator_type &alloc = allocator_type()):
		allocator_type(alloc),
		erasure_groups_head(nullptr),
		unused_groups_head(nullptr),
		total_size(0),
		total_capacity(0),
		min_block_capacity(static_cast<skipfield_type>(block_limits.min)),
		max_block_capacity(static_cast<skipfield_type>(block_limits.max)),
		group_allocator(*this),
		aligned_struct_allocator(*this),
		skipfield_allocator(*this),
		tuple_allocator(*this)
	{
		check_capacities_conformance(block_limits);
		assign<iterator_type>(first, last);
	}



	template<typename iterator_type>
	hive(const typename std::enable_if_t<!std::numeric_limits<iterator_type>::is_integer, iterator_type> &first, const iterator_type &last, const allocator_type &alloc = allocator_type()):
		hive(first, last, block_capacity_default_limits(), alloc)
	{}



	// Initializer-list constructors:

	hive(const std::initializer_list<element_type> &element_list, const hive_limits block_limits, const allocator_type &alloc = allocator_type()):
		allocator_type(alloc),
		erasure_groups_head(nullptr),
		unused_groups_head(nullptr),
		total_size(0),
		total_capacity(0),
		min_block_capacity(static_cast<skipfield_type>(block_limits.min)),
		max_block_capacity(static_cast<skipfield_type>(block_limits.max)),
		group_allocator(*this),
		aligned_struct_allocator(*this),
		skipfield_allocator(*this),
		tuple_allocator(*this)
	{
		check_capacities_conformance(block_limits);
		reserve_and_range_fill(static_cast<size_type>(element_list.size()), element_list.begin());
	}



	hive(const std::initializer_list<element_type> &element_list, const allocator_type &alloc = allocator_type()):
		hive(element_list, block_capacity_default_limits(), alloc)
	{}



	// Ranges v3 constructors:

	template<class range_type>
		requires std::ranges::range<range_type>
	hive(plf::ranges::from_range_t, range_type &&rg, const hive_limits block_limits, const allocator_type &alloc = allocator_type()):
		allocator_type(alloc),
		erasure_groups_head(nullptr),
		unused_groups_head(nullptr),
		total_size(0),
		total_capacity(0),
		min_block_capacity(static_cast<skipfield_type>(block_limits.min)),
		max_block_capacity(static_cast<skipfield_type>(block_limits.max)),
		group_allocator(*this),
		aligned_struct_allocator(*this),
		skipfield_allocator(*this),
		tuple_allocator(*this)
	{
		check_capacities_conformance(block_limits);
		reserve_and_range_fill(static_cast<size_type>(std::ranges::distance(rg)), std::ranges::begin(rg));
	}



	template<class range_type>
		requires std::ranges::range<range_type>
	hive(plf::ranges::from_range_t, range_type &&rg, const allocator_type &alloc = allocator_type()):
		hive(plf::ranges::from_range, std::move(rg), block_capacity_default_limits(), alloc)
	{}



	// Everything else:

	iterator begin() noexcept
	{
		return begin_iterator;
	}



	const_iterator begin() const noexcept
	{
		return begin_iterator;
	}



	iterator end() noexcept
	{
		return end_iterator;
	}



	const_iterator end() const noexcept
	{
		return end_iterator;
	}



	const_iterator cbegin() const noexcept
	{
		return begin_iterator;
	}



	const_iterator cend() const noexcept
	{
		return end_iterator;
	}



	reverse_iterator rbegin() noexcept
	{
		return (end_iterator.group_pointer != nullptr) ? ++reverse_iterator(end_iterator.group_pointer, end_iterator.element_pointer, end_iterator.skipfield_pointer) : reverse_iterator(begin_iterator.group_pointer, begin_iterator.element_pointer - 1, begin_iterator.skipfield_pointer - 1);
	}



	const_reverse_iterator rbegin() const noexcept
	{
		return crbegin();
	}



	reverse_iterator rend() noexcept
	{
		return reverse_iterator(begin_iterator.group_pointer, begin_iterator.element_pointer - 1, begin_iterator.skipfield_pointer - 1);
	}



	const_reverse_iterator rend() const noexcept
	{
		return crend();
	}



	const_reverse_iterator crbegin() const noexcept
	{
		return (end_iterator.group_pointer != nullptr) ? ++const_reverse_iterator(end_iterator.group_pointer, end_iterator.element_pointer, end_iterator.skipfield_pointer) : const_reverse_iterator(begin_iterator.group_pointer, begin_iterator.element_pointer - 1, begin_iterator.skipfield_pointer - 1);
	}



	const_reverse_iterator crend() const noexcept
	{
		return const_reverse_iterator(begin_iterator.group_pointer, begin_iterator.element_pointer - 1, begin_iterator.skipfield_pointer - 1);
	}



	~hive() noexcept
	{
		destroy_all_data();
	}




private:

	group_pointer_type allocate_new_group(const skipfield_type elements_per_group, const group_pointer_type previous = nullptr)
	{
		if (max_size() - total_capacity < elements_per_group) // Just in case max_size is a lower amount than the actual memory available (uncommon platform). Comparison avoids overflow.
		{
			#ifdef PLF_EXCEPTIONS_SUPPORT
				throw std::length_error("New block allocation would create capacity greater than max_size()");
			#else
				std::terminate();
			#endif
		}

		const group_pointer_type new_group = std::allocator_traits<group_allocator_type>::allocate(group_allocator, 1, previous);
		total_capacity += elements_per_group; // I don't know why GCC creates better/smaller codegen when this is placed here rather than at bottom of function, But it does.

		#ifdef PLF_EXCEPTIONS_SUPPORT
			try
			{
				std::allocator_traits<group_allocator_type>::construct(group_allocator, new_group, aligned_struct_allocator, elements_per_group, previous);
			}
			catch (...)
			{
				std::allocator_traits<group_allocator_type>::deallocate(group_allocator, new_group, 1);
				total_capacity -= elements_per_group;
				throw;
			}
		#else
			std::allocator_traits<group_allocator_type>::construct(group_allocator, new_group, aligned_struct_allocator, elements_per_group, previous);
		#endif

		return new_group;
	}



	void deallocate_group(const group_pointer_type the_group) noexcept
	{
		std::allocator_traits<aligned_struct_allocator_type>::deallocate(aligned_struct_allocator, the_group->elements, get_aligned_block_capacity(the_group->capacity));
		std::allocator_traits<group_allocator_type>::deallocate(group_allocator, the_group, 1);
	}



	void deallocate_group_remove_capacity(const group_pointer_type the_group) noexcept
	{
		total_capacity -= the_group->capacity;
		deallocate_group(the_group);
	}



	constexpr void destroy_element(const aligned_pointer_type element) noexcept
	{
		if constexpr (!std::is_trivially_destructible<element_type>::value) // to avoid codegen in this function for trivial types
		{
			std::allocator_traits<allocator_type>::destroy(*this, pointer_cast<pointer>(element));
		}
	}



	void destroy_remainder(const_iterator it) noexcept
	{
		if constexpr (!std::is_trivially_destructible<element_type>::value)
		{
			while (it != end_iterator) destroy_element(it++.element_pointer);
		}
	}



	void destroy_group(const_iterator current, const aligned_pointer_type end) noexcept
	{
		if constexpr (!std::is_trivially_destructible<element_type>::value)
		{
			do
			{
				destroy_element(current.element_pointer);
				current.element_pointer += static_cast<size_type>(*++current.skipfield_pointer) + 1u;
				current.skipfield_pointer += *current.skipfield_pointer;
			} while(current.element_pointer != end);
		}
	}



	void destroy_dealloc_begin_group(const aligned_pointer_type end) noexcept
	{
		destroy_group(begin_iterator, end);
		deallocate_group(begin_iterator.group_pointer);
	}



	void destroy_all_data() noexcept
	{
		if (begin_iterator.group_pointer != nullptr)
		{
			end_iterator.group_pointer->next_group = unused_groups_head; // Link used and unused_group lists together

			if constexpr (!std::is_trivially_destructible<element_type>::value)
			{
				if (total_size != 0)
				{
					while (begin_iterator.group_pointer != end_iterator.group_pointer) // Erase elements without bothering to update skipfield - much faster:
					{
						const group_pointer_type next_group = begin_iterator.group_pointer->next_group;
						destroy_dealloc_begin_group(to_aligned_pointer(begin_iterator.group_pointer->skipfield));
						begin_iterator.group_pointer = next_group;
						begin_iterator.element_pointer = to_aligned_pointer(next_group->elements) + *(next_group->skipfield);
						begin_iterator.skipfield_pointer = next_group->skipfield + *(next_group->skipfield);
					}

					destroy_dealloc_begin_group(end_iterator.element_pointer);
					begin_iterator.group_pointer = unused_groups_head;
				}
			}

			while (begin_iterator.group_pointer != nullptr)
			{
				const group_pointer_type next_group = begin_iterator.group_pointer->next_group;
				deallocate_group(begin_iterator.group_pointer);
				begin_iterator.group_pointer = next_group;
			}
		}
	}



	void initialize(const skipfield_type first_group_size)
	{
		end_iterator.group_pointer = begin_iterator.group_pointer = allocate_new_group(first_group_size);
		end_iterator.element_pointer = begin_iterator.element_pointer = to_aligned_pointer(begin_iterator.group_pointer->elements);
		end_iterator.skipfield_pointer = begin_iterator.skipfield_pointer = begin_iterator.group_pointer->skipfield;
	}



	void edit_free_list(const skipfield_pointer_type location, const skipfield_type value) noexcept
	{
 		std::allocator_traits<skipfield_allocator_type>::destroy(skipfield_allocator, location);
		std::allocator_traits<skipfield_allocator_type>::construct(skipfield_allocator, location, value);
	}



	void edit_free_list_prev(const aligned_pointer_type location, const skipfield_type value) noexcept // Write to the 'previous erased element' index in the erased element memory location
	{
		edit_free_list(pointer_cast<skipfield_pointer_type>(location), value);
	}



	void edit_free_list_next(const aligned_pointer_type location, const skipfield_type value) noexcept // Ditto 'next'
	{
		edit_free_list(pointer_cast<skipfield_pointer_type>(location) + 1, value);
	}



	void edit_free_list_head(const aligned_pointer_type location, const skipfield_type value) noexcept
	{
		const skipfield_pointer_type converted_location = pointer_cast<skipfield_pointer_type>(location);
		edit_free_list(converted_location, value);
		edit_free_list(converted_location + 1, std::numeric_limits<skipfield_type>::max());
	}



	void update_skipblock(const iterator &new_location, const skipfield_type prev_free_list_index) noexcept
	{
		const skipfield_type new_value = static_cast<skipfield_type>(*(new_location.skipfield_pointer) - 1);

		if (new_value != 0) // ie. skipfield was not originally length 1, hence we need to truncate it
		{
			// set (new) start and (original) end of skipblock to new value:
			*(new_location.skipfield_pointer + new_value) = *(new_location.skipfield_pointer + 1) = new_value;

			// transfer free list node to new start node:
			++(erasure_groups_head->free_list_head);

			if (prev_free_list_index != std::numeric_limits<skipfield_type>::max()) // ie. not the tail free list node
			{
				edit_free_list_next(to_aligned_pointer(new_location.group_pointer->elements) + prev_free_list_index, erasure_groups_head->free_list_head);
			}

			edit_free_list_head(new_location.element_pointer + 1, prev_free_list_index);
		}
		else // single-node skipblock, remove skipblock
		{
			erasure_groups_head->free_list_head = prev_free_list_index;

			if (prev_free_list_index != std::numeric_limits<skipfield_type>::max()) // ie. not the last free list node
			{
				edit_free_list_next(to_aligned_pointer(new_location.group_pointer->elements) + prev_free_list_index, std::numeric_limits<skipfield_type>::max());
			}
			else // remove this group from the list of groups with erasures
			{
				erasure_groups_head = erasure_groups_head->erasures_list_next_group; // update_skipblock is only used within insert/emplace, where the head group is being used, so no need for additional checks here
			}
		}

		*(new_location.skipfield_pointer) = 0;
		++(new_location.group_pointer->size);

		if (new_location.group_pointer == begin_iterator.group_pointer && new_location.element_pointer < begin_iterator.element_pointer)
		{ /* ie. begin_iterator was moved forwards as the result of an erasure at some point, this erased element is before the current begin, hence, set current begin iterator to this element */
			begin_iterator = new_location;
		}

		++total_size;
	}



	void reset() noexcept
	{
		destroy_all_data();
		blank();
	}



	void update_subsequent_group_numbers(size_type current_group_number, group_pointer_type update_group) noexcept
	{
		do
		{
			update_group->group_number = current_group_number++;
			update_group = update_group->next_group;
		} while (update_group != nullptr);
	}



	void reset_group_numbers() noexcept
	{
		update_subsequent_group_numbers(0, begin_iterator.group_pointer);
	}



	void reset_group_numbers_if_necessary() noexcept
	{
		if (end_iterator.group_pointer->group_number == std::numeric_limits<size_type>::max()) [[unlikely]] reset_group_numbers();
	}



	group_pointer_type reuse_unused_group() noexcept
	{
		const group_pointer_type reused_group = unused_groups_head;
		unused_groups_head = reused_group->next_group;
		reset_group_numbers_if_necessary();
		reused_group->reset(1, nullptr, end_iterator.group_pointer, end_iterator.group_pointer->group_number + 1u);
		return reused_group;
	}



	template<typename pointer_type, typename... arguments>
	constexpr void construct_element(const pointer_type location, arguments &&... parameters)
	{
		std::allocator_traits<allocator_type>::construct(*this, pointer_cast<pointer>(location), std::forward<arguments>(parameters) ...);
	}



public:


	iterator insert(const element_type &element) // Note: defining insert & and insert && as calls to emplace results in larger codegen in release mode (under GCC at least), and prevents more accurate is_nothrow tests
	{
		if (end_iterator.element_pointer != nullptr) // ie. empty hive, no blocks allocated yet
		{
			if (erasure_groups_head == nullptr) // ie. there are no erased elements
			{
				if (end_iterator.element_pointer != to_aligned_pointer(end_iterator.group_pointer->skipfield)) // ie. end_iterator is not at end of block
				{
					construct_element(end_iterator.element_pointer, element);

					const iterator return_iterator = end_iterator;
					++end_iterator.element_pointer;
					++end_iterator.skipfield_pointer;
					++(end_iterator.group_pointer->size);
					++total_size;
					return return_iterator;
				}

				group_pointer_type next_group;

				if (unused_groups_head == nullptr)
				{
					reset_group_numbers_if_necessary();
					next_group = allocate_new_group(static_cast<skipfield_type>(std::min(total_size, static_cast<size_type>(max_block_capacity))), end_iterator.group_pointer);

					#ifdef PLF_EXCEPTIONS_SUPPORT
						if constexpr (!std::is_nothrow_copy_constructible<element_type>::value)
						{
							try
							{
								construct_element(next_group->elements, element);
							}
							catch (...)
							{
								deallocate_group_remove_capacity(next_group);
								throw;
							}
						}
						else
					#endif
					{
						construct_element(next_group->elements, element);
					}
				}
				else
				{
					construct_element(unused_groups_head->elements, element);
					next_group = reuse_unused_group();
				}

				end_iterator.group_pointer->next_group = next_group;
				end_iterator.group_pointer = next_group;
				end_iterator.element_pointer = to_aligned_pointer(next_group->elements) + 1;
				end_iterator.skipfield_pointer = next_group->skipfield + 1;
				++total_size;

				return iterator(next_group, to_aligned_pointer(next_group->elements), next_group->skipfield);
			}
			else // there are erased elements, reuse those memory locations
			{
				iterator new_location(erasure_groups_head, to_aligned_pointer(erasure_groups_head->elements) + erasure_groups_head->free_list_head, erasure_groups_head->skipfield + erasure_groups_head->free_list_head);

				// We always reuse the element at the start of the skipblock, this is also where the free-list information for that skipblock is stored. Get the previous free-list node's index from this memory space, before we write to our element to it. 'Next' index is always the free_list_head (as represented by the maximum value of the skipfield type) here so we don't need to get it:
				const skipfield_type prev_free_list_index = *pointer_cast<skipfield_pointer_type>(new_location.element_pointer);
				construct_element(new_location.element_pointer, element);
				update_skipblock(new_location, prev_free_list_index);

				return new_location;
			}
		}
		else // ie. newly-constructed hive, no insertions yet and no groups
		{
			initialize(min_block_capacity);

			#ifdef PLF_EXCEPTIONS_SUPPORT
				if constexpr (!std::is_nothrow_copy_constructible<element_type>::value)
				{
					try
					{
						construct_element(end_iterator.element_pointer++, element);
					}
					catch (...)
					{
						reset();
						throw;
					}
				}
				else
			#endif
			{
				construct_element(end_iterator.element_pointer++, element);
			}

			++end_iterator.skipfield_pointer;
			total_size = 1;
			return begin_iterator;
		}
	}



	iterator insert([[maybe_unused]] const_iterator &hint, const element_type &element) // Note: hint is ignored, purely to serve other standard library functions like insert_iterator
	{
		return insert(element);
	}



	iterator insert(element_type &&element) // The move-insert function is near-identical to the regular insert function, with the exception of the element construction method and is_nothrow tests.
	{
		if (end_iterator.element_pointer != nullptr)
		{
			if (erasure_groups_head == nullptr)
			{
				if (end_iterator.element_pointer != to_aligned_pointer(end_iterator.group_pointer->skipfield))
				{
					construct_element(end_iterator.element_pointer, std::move(element));

					const iterator return_iterator = end_iterator;
					++end_iterator.element_pointer;
					++end_iterator.skipfield_pointer;
					++(end_iterator.group_pointer->size);
					++total_size;

					return return_iterator;
				}

				group_pointer_type next_group;

				if (unused_groups_head == nullptr)
				{
					reset_group_numbers_if_necessary();
					next_group = allocate_new_group(static_cast<skipfield_type>(std::min(total_size, static_cast<size_type>(max_block_capacity))), end_iterator.group_pointer);

					#ifdef PLF_EXCEPTIONS_SUPPORT
						if constexpr (!std::is_nothrow_move_constructible<element_type>::value)
						{
							try
							{
								construct_element(next_group->elements, std::move(element));
							}
							catch (...)
							{
								deallocate_group_remove_capacity(next_group);
								throw;
							}
						}
						else
					#endif
					{
						construct_element(next_group->elements, std::move(element));
					}
				}
				else
				{
					construct_element(unused_groups_head->elements, std::move(element));
					next_group = reuse_unused_group();
				}

				end_iterator.group_pointer->next_group = next_group;
				end_iterator.group_pointer = next_group;
				end_iterator.element_pointer = to_aligned_pointer(next_group->elements) + 1;
				end_iterator.skipfield_pointer = next_group->skipfield + 1;
				++total_size;

				return iterator(next_group, to_aligned_pointer(next_group->elements), next_group->skipfield);
			}
			else
			{
				iterator new_location(erasure_groups_head, to_aligned_pointer(erasure_groups_head->elements) + erasure_groups_head->free_list_head, erasure_groups_head->skipfield + erasure_groups_head->free_list_head);

				const skipfield_type prev_free_list_index = *pointer_cast<skipfield_pointer_type>(new_location.element_pointer);
				construct_element(new_location.element_pointer, std::move(element));
				update_skipblock(new_location, prev_free_list_index);

				return new_location;
			}
		}
		else
		{
			initialize(min_block_capacity);

			#ifdef PLF_EXCEPTIONS_SUPPORT
				if constexpr (!std::is_nothrow_move_constructible<element_type>::value)
				{
					try
					{
						construct_element(end_iterator.element_pointer++, std::move(element));
					}
					catch (...)
					{
						reset();
						throw;
					}
				}
				else
			#endif
			{
				construct_element(end_iterator.element_pointer++, std::move(element));
			}

			++end_iterator.skipfield_pointer;
			total_size = 1;
			return begin_iterator;
		}
	}



	iterator insert([[maybe_unused]] const_iterator &hint, element_type &&element)
	{
		return insert(std::forward<element_type &&>(element));
	}



	template<typename... arguments>
	iterator emplace(arguments &&... parameters) // The emplace function is near-identical to the regular insert function, with the exception of the element construction method, and change to is_nothrow tests.
	{
		if (end_iterator.element_pointer != nullptr)
		{
			if (erasure_groups_head == nullptr)
			{
				if (end_iterator.element_pointer != to_aligned_pointer(end_iterator.group_pointer->skipfield))
				{
					construct_element(end_iterator.element_pointer, std::forward<arguments>(parameters) ...);

					const iterator return_iterator = end_iterator;
					++end_iterator.element_pointer;
					++end_iterator.skipfield_pointer;
					++(end_iterator.group_pointer->size);
					++total_size;

					return return_iterator;
				}

				group_pointer_type next_group;

				if (unused_groups_head == nullptr)
				{
					reset_group_numbers_if_necessary();
					next_group = allocate_new_group(static_cast<skipfield_type>(std::min(total_size, static_cast<size_type>(max_block_capacity))), end_iterator.group_pointer);

					#ifdef PLF_EXCEPTIONS_SUPPORT
						if constexpr (!std::is_nothrow_constructible<element_type>::value)
						{
							try
							{
								construct_element(next_group->elements, std::forward<arguments>(parameters) ...);
							}
							catch (...)
							{
								deallocate_group_remove_capacity(next_group);
								throw;
							}
						}
						else
					#endif
					{
						construct_element(next_group->elements, std::forward<arguments>(parameters) ...);
					}
				}
				else
				{
					construct_element(unused_groups_head->elements, std::forward<arguments>(parameters) ...);
					next_group = reuse_unused_group();
				}

				end_iterator.group_pointer->next_group = next_group;
				end_iterator.group_pointer = next_group;
				end_iterator.element_pointer = to_aligned_pointer(next_group->elements) + 1;
				end_iterator.skipfield_pointer = next_group->skipfield + 1;
				++total_size;

				return iterator(next_group, to_aligned_pointer(next_group->elements), next_group->skipfield);
			}
			else
			{
				iterator new_location(erasure_groups_head, to_aligned_pointer(erasure_groups_head->elements) + erasure_groups_head->free_list_head, erasure_groups_head->skipfield + erasure_groups_head->free_list_head);

				const skipfield_type prev_free_list_index = *pointer_cast<skipfield_pointer_type>(new_location.element_pointer);
				construct_element(new_location.element_pointer, std::forward<arguments>(parameters) ...);
				update_skipblock(new_location, prev_free_list_index);

				return new_location;
			}
		}
		else
		{
			initialize(min_block_capacity);

			#ifdef PLF_EXCEPTIONS_SUPPORT
				if constexpr (!std::is_nothrow_constructible<element_type>::value)
				{
					try
					{
						construct_element(end_iterator.element_pointer++, std::forward<arguments>(parameters) ...);
					}
					catch (...)
					{
						reset();
						throw;
					}
				}
				else
			#endif
			{
				construct_element(end_iterator.element_pointer++, std::forward<arguments>(parameters) ...);
			}

			++end_iterator.skipfield_pointer;
			total_size = 1;
			return begin_iterator;
		}
	}



	template<typename... arguments>
	iterator emplace_hint([[maybe_unused]] const_iterator &hint, arguments &&... parameters)
	{
		return emplace(std::forward<arguments>(parameters) ...);
	}



private:

	// For catch blocks in fill() and range_fill()
	void recover_from_partial_fill()
	{
		#ifdef PLF_EXCEPTIONS_SUPPORT
			if constexpr ((!std::is_copy_constructible<element_type>::value && !std::is_nothrow_move_constructible<element_type>::value) || !std::is_nothrow_copy_constructible<element_type>::value) // to avoid unnecessary codegen, since this function will never be called if this line isn't true
			{
				const skipfield_type elements_constructed_before_exception = static_cast<skipfield_type>(end_iterator.element_pointer - to_aligned_pointer(end_iterator.group_pointer->elements));
				end_iterator.group_pointer->size = elements_constructed_before_exception;
				end_iterator.skipfield_pointer = end_iterator.group_pointer->skipfield + elements_constructed_before_exception;
				total_size += elements_constructed_before_exception;
				unused_groups_head = end_iterator.group_pointer->next_group;
				end_iterator.group_pointer->next_group = nullptr;
			}
		#endif
	}



	void fill(const element_type &element, const skipfield_type size)
	{
		#ifdef PLF_EXCEPTIONS_SUPPORT
			if constexpr (!std::is_nothrow_copy_constructible<element_type>::value)
			{
				const aligned_pointer_type fill_end = end_iterator.element_pointer + size;

				do
				{
					try
					{
						construct_element(end_iterator.element_pointer, element);
					}
					catch (...)
					{
						recover_from_partial_fill();
						throw;
					}
				} while (++end_iterator.element_pointer != fill_end);
			}
			else
		#endif
		if constexpr (std::is_trivially_copyable<element_type>::value && std::is_trivially_copy_constructible<element_type>::value) // ie. we can get away with using the cheaper fill_n here if there is no chance of an exception being thrown:
		{
			if constexpr (sizeof(aligned_element_struct) != sizeof(element_type))
			{
				alignas (alignof(aligned_element_struct)) element_type aligned_copy = element; // to avoid potentially violating memory boundaries in line below, create an initial object copy of same (but aligned) type
				std::fill_n(end_iterator.element_pointer, size, *to_aligned_pointer(&aligned_copy));
			}
			else
			{
				std::fill_n(pointer_cast<pointer>(end_iterator.element_pointer), size, element);
			}

			end_iterator.element_pointer += size;
		}
		else // If at least nothrow_constructible (or exceptions disabled), can remove the large block of 'catch' code above
		{
			const aligned_pointer_type fill_end = end_iterator.element_pointer + size;

			do
			{
				construct_element(end_iterator.element_pointer, element);
			} while (++end_iterator.element_pointer != fill_end);
		}

		total_size += size;
	}



	// For catch blocks in range_fill_skipblock and fill_skipblock
	void recover_from_partial_skipblock_fill(const aligned_pointer_type location, const aligned_pointer_type current_location, const skipfield_pointer_type skipfield_pointer, const skipfield_type prev_free_list_node)
	{
		#ifdef PLF_EXCEPTIONS_SUPPORT
			if constexpr ((!std::is_copy_constructible<element_type>::value && !std::is_nothrow_move_constructible<element_type>::value) || !std::is_nothrow_copy_constructible<element_type>::value) // to avoid unnecessary codegen
			{
				// Reconstruct existing skipblock and free-list indexes to reflect partially-reused skipblock:
				const skipfield_type elements_constructed_before_exception = static_cast<skipfield_type>(current_location - location);
				erasure_groups_head->size += elements_constructed_before_exception;
				total_size += elements_constructed_before_exception;

				std::memset(std::to_address(skipfield_pointer), 0, elements_constructed_before_exception * sizeof(skipfield_type));

				edit_free_list_head(location + elements_constructed_before_exception, prev_free_list_node);

				const skipfield_type new_skipblock_head_index = static_cast<skipfield_type>((location - to_aligned_pointer(erasure_groups_head->elements)) + elements_constructed_before_exception);
				erasure_groups_head->free_list_head = new_skipblock_head_index;

				if (prev_free_list_node != std::numeric_limits<skipfield_type>::max())
				{
					edit_free_list_next(to_aligned_pointer(erasure_groups_head->elements) + prev_free_list_node, new_skipblock_head_index);
				}
			}
		#endif
	}



	void fill_skipblock(const element_type &element, const aligned_pointer_type location, const skipfield_pointer_type skipfield_pointer, const skipfield_type size)
	{
		#ifdef PLF_EXCEPTIONS_SUPPORT
			if constexpr (!std::is_nothrow_copy_constructible<element_type>::value)
			{
				const aligned_pointer_type fill_end = location + size;
				const skipfield_type prev_free_list_node = *pointer_cast<skipfield_pointer_type>(location); // in case of exception, grabbing indexes before free_list node is reused

				for (aligned_pointer_type current_location = location; current_location != fill_end; ++current_location)
				{
					try
					{
						construct_element(current_location, element);
					}
					catch (...)
					{
						recover_from_partial_skipblock_fill(location, current_location, skipfield_pointer, prev_free_list_node);
						throw;
					}
				}
			}
			else
		#endif
		if constexpr (std::is_trivially_copyable<element_type>::value && std::is_trivially_copy_constructible<element_type>::value)
		{
			if constexpr (sizeof(aligned_element_struct) != sizeof(element_type))
			{
				alignas (alignof(aligned_element_struct)) element_type aligned_copy = element;
				std::fill_n(location, size, *to_aligned_pointer(&aligned_copy));
			}
			else
			{
				std::fill_n(pointer_cast<pointer>(location), size, element);
			}
		}
		else
		{
			const aligned_pointer_type fill_end = location + size;

			for (aligned_pointer_type current_location = location; current_location != fill_end; ++current_location)
			{
				construct_element(current_location, element);
			}
		}

		std::memset(std::to_address(skipfield_pointer), 0, size * sizeof(skipfield_type)); // reset skipfield nodes within skipblock to 0
		erasure_groups_head->size += size;
		total_size += size;
	}



	void fill_unused_groups(size_type size, const element_type &element, size_type group_number, group_pointer_type previous_group, const group_pointer_type current_group)
	{
		for (end_iterator.group_pointer = current_group; end_iterator.group_pointer->capacity < size; end_iterator.group_pointer = end_iterator.group_pointer->next_group)
		{
			const skipfield_type capacity = end_iterator.group_pointer->capacity;
			end_iterator.group_pointer->reset(capacity, end_iterator.group_pointer->next_group, previous_group, group_number++);
			previous_group = end_iterator.group_pointer;
			size -= static_cast<size_type>(capacity);
			end_iterator.element_pointer = to_aligned_pointer(end_iterator.group_pointer->elements);
			fill(element, capacity);
		}

		// Deal with final group (partial fill)
		unused_groups_head = end_iterator.group_pointer->next_group;
		end_iterator.group_pointer->reset(static_cast<skipfield_type>(size), nullptr, previous_group, group_number);
		end_iterator.element_pointer = to_aligned_pointer(end_iterator.group_pointer->elements);
		end_iterator.skipfield_pointer = end_iterator.group_pointer->skipfield + size;
		fill(element, static_cast<skipfield_type>(size));
	}



public:

	// Fill insert

	void insert(size_type size, const element_type &element)
	{
		if (size == 0)
		{
			return;
		}
		else if (size == 1)
		{
			insert(element);
			return;
		}

		if (total_size == 0)
		{
			prepare_groups_for_assign(size);
			fill_unused_groups(size, element, 0, nullptr, begin_iterator.group_pointer);
			return;
		}

		reserve(total_size + size);

		// Use up erased locations if available:
		while(erasure_groups_head != nullptr) // skipblock loop: breaks when hive is exhausted of reusable skipblocks, or returns if size == 0
		{
			const aligned_pointer_type element_pointer = to_aligned_pointer(erasure_groups_head->elements) + erasure_groups_head->free_list_head;
			const skipfield_pointer_type skipfield_pointer = erasure_groups_head->skipfield + erasure_groups_head->free_list_head;
			const skipfield_type skipblock_size = *skipfield_pointer;

			if (erasure_groups_head == begin_iterator.group_pointer && element_pointer < begin_iterator.element_pointer)
			{
				begin_iterator.element_pointer = element_pointer;
				begin_iterator.skipfield_pointer = skipfield_pointer;
			}

			if (skipblock_size <= size)
			{
				erasure_groups_head->free_list_head = *pointer_cast<skipfield_pointer_type>(element_pointer); // set free list head to previous free list node
				fill_skipblock(element, element_pointer, skipfield_pointer, skipblock_size);
				size -= skipblock_size;

				if (erasure_groups_head->free_list_head != std::numeric_limits<skipfield_type>::max()) // ie. there are more skipblocks to be filled in this group
				{
					edit_free_list_next(to_aligned_pointer(erasure_groups_head->elements) + erasure_groups_head->free_list_head, std::numeric_limits<skipfield_type>::max()); // set 'next' index of new free list head to 'end' (numeric max)
				}
				else
				{
					erasure_groups_head = erasure_groups_head->erasures_list_next_group; // change groups
				}

				if (size == 0) return;
			}
			else // skipblock is larger than remaining number of elements
			{
				const skipfield_type prev_index = *pointer_cast<skipfield_pointer_type>(element_pointer); // save before element location is overwritten
				fill_skipblock(element, element_pointer, skipfield_pointer, static_cast<skipfield_type>(size));
				const skipfield_type new_skipblock_size = static_cast<skipfield_type>(skipblock_size - size);

				// Update skipfield (earlier nodes already memset'd in fill_skipblock function):
				*(skipfield_pointer + size) = new_skipblock_size;
				*(skipfield_pointer + skipblock_size - 1) = new_skipblock_size;
				erasure_groups_head->free_list_head += static_cast<skipfield_type>(size); // set free list head to new start node

				// Update free list with new head:
				edit_free_list_head(element_pointer + size, prev_index);

				if (prev_index != std::numeric_limits<skipfield_type>::max())
				{
					edit_free_list_next(to_aligned_pointer(erasure_groups_head->elements) + prev_index,  erasure_groups_head->free_list_head); // set 'next' index of previous skipblock to new start of skipblock
				}

				return;
			}
		}


		// Use up remaining available element locations in end group:
		// This variable is either the remaining capacity of the group or the number of elements yet to be filled, whichever is smaller:
		const skipfield_type group_remainder = static_cast<skipfield_type>(std::min(static_cast<size_type>(to_aligned_pointer(end_iterator.group_pointer->skipfield) - end_iterator.element_pointer), size));

		if (group_remainder != 0)
		{
			fill(element, group_remainder);
			end_iterator.group_pointer->size += end_iterator.group_pointer->size;

			if (size == group_remainder) // ie. remaining capacity was >= remaining elements to be filled
			{
				end_iterator.skipfield_pointer = end_iterator.group_pointer->skipfield + end_iterator.group_pointer->size;
				return;
			}

			size -= group_remainder;
		}


		// Use unused groups:
		end_iterator.group_pointer->next_group = unused_groups_head;
		if ((std::numeric_limits<size_type>::max() - end_iterator.group_pointer->group_number) < size) [[unlikely]] reset_group_numbers();
		fill_unused_groups(size, element, end_iterator.group_pointer->group_number + 1u, end_iterator.group_pointer, unused_groups_head);
	}



private:

	template <class iterator_type>
	void range_fill(iterator_type &it, const skipfield_type size)
	{
		const aligned_pointer_type fill_end = end_iterator.element_pointer + size;

		#ifdef PLF_EXCEPTIONS_SUPPORT
			if constexpr ((!std::is_copy_constructible<element_type>::value && !std::is_nothrow_move_constructible<element_type>::value) || !std::is_nothrow_copy_constructible<element_type>::value)
			{
				do
				{
					try
					{
						if constexpr (!std::is_copy_constructible<element_type>::value)
						{
							construct_element(end_iterator.element_pointer, std::move(*it++));
						}
						else
						{
							construct_element(end_iterator.element_pointer, *it++);
						}
					}
					catch (...)
					{
						recover_from_partial_fill();
						throw;
					}
				} while (++end_iterator.element_pointer != fill_end);
			}
			else
		#endif
		if constexpr (std::is_copy_constructible<element_type>::value)
		{
			do
			{
				construct_element(end_iterator.element_pointer, *it++);
			} while (++end_iterator.element_pointer != fill_end);
		}
		else // assumes moveable-but-not-copyable type
		{
			do
			{
				construct_element(end_iterator.element_pointer, std::move(*it++));
			} while (++end_iterator.element_pointer != fill_end);
		}

		total_size += size;
	}



	template <class iterator_type>
	void range_fill_skipblock(iterator_type &it, const aligned_pointer_type location, const skipfield_pointer_type skipfield_pointer, const skipfield_type size)
	{
		const aligned_pointer_type fill_end = location + size;

		#ifdef PLF_EXCEPTIONS_SUPPORT
			if constexpr ((!std::is_copy_constructible<element_type>::value && !std::is_nothrow_move_constructible<element_type>::value) || !std::is_nothrow_copy_constructible<element_type>::value)
			{
				const skipfield_type prev_free_list_node = *pointer_cast<skipfield_pointer_type>(location); // in case of exception, grabbing indexes before free_list node is reused

				for (aligned_pointer_type current_location = location; current_location != fill_end; ++current_location)
				{
					try
					{
						if constexpr (!std::is_copy_constructible<element_type>::value)
						{
							construct_element(current_location, std::move(*it++));
						}
						else
						{
							construct_element(current_location, *it++);
						}
					}
					catch (...)
					{
						recover_from_partial_skipblock_fill(location, current_location, skipfield_pointer, prev_free_list_node);
						throw;
					}
				}
			}
			else
		#endif
		if constexpr (std::is_copy_constructible<element_type>::value)
		{
			for (aligned_pointer_type current_location = location; current_location != fill_end; ++current_location)
			{
				construct_element(current_location, *it++);
			}
		}
		else // assumes moveable-but-not-copyable type
		{
			for (aligned_pointer_type current_location = location; current_location != fill_end; ++current_location)
			{
				construct_element(current_location, std::move(*it++));
			}
		}

		std::memset(std::to_address(skipfield_pointer), 0, size * sizeof(skipfield_type)); // reset skipfield nodes within skipblock to 0
		erasure_groups_head->size += size;
		total_size += size;
	}



	template <class iterator_type>
	void range_fill_unused_groups(size_type size, iterator_type it, size_type group_number, group_pointer_type previous_group, const group_pointer_type current_group)
	{
		for (end_iterator.group_pointer = current_group; end_iterator.group_pointer->capacity < size; end_iterator.group_pointer = end_iterator.group_pointer->next_group)
		{
			const skipfield_type capacity = end_iterator.group_pointer->capacity;
			end_iterator.group_pointer->reset(capacity, end_iterator.group_pointer->next_group, previous_group, group_number++);
			previous_group = end_iterator.group_pointer;
			size -= static_cast<size_type>(capacity);
			end_iterator.element_pointer = to_aligned_pointer(end_iterator.group_pointer->elements);
			range_fill(it, capacity);
		}

		// Deal with final group (partial fill)
		unused_groups_head = end_iterator.group_pointer->next_group;
		end_iterator.group_pointer->reset(static_cast<skipfield_type>(size), nullptr, previous_group, group_number);
		end_iterator.element_pointer = to_aligned_pointer(end_iterator.group_pointer->elements);
		end_iterator.skipfield_pointer = end_iterator.group_pointer->skipfield + size;
		range_fill(it, static_cast<skipfield_type>(size));
	}



	template <class iterator_type>
	void range_insert(iterator_type it, size_type size) // this is near-identical to the fill insert, with the only alteration being incrementing an iterator for construction, rather than using a const element. And the fill etc function calls are changed to range_fill to match this pattern. See fill insert for code explanations
	{
		if (size == 0)
		{
			return;
		}
		else if (size == 1)
		{
			insert(*it);
			return;
		}

		if (total_size == 0)
		{
			prepare_groups_for_assign(size);
			range_fill_unused_groups(size, it, 0, nullptr, begin_iterator.group_pointer);
			return;
		}

		reserve(total_size + size);

		while(erasure_groups_head != nullptr)
		{
			const aligned_pointer_type element_pointer = to_aligned_pointer(erasure_groups_head->elements) + erasure_groups_head->free_list_head;
			const skipfield_pointer_type skipfield_pointer = erasure_groups_head->skipfield + erasure_groups_head->free_list_head;
			const skipfield_type skipblock_size = *skipfield_pointer;

			if (erasure_groups_head == begin_iterator.group_pointer && element_pointer < begin_iterator.element_pointer)
			{
				begin_iterator.element_pointer = element_pointer;
				begin_iterator.skipfield_pointer = skipfield_pointer;
			}

			if (skipblock_size <= size)
			{
				erasure_groups_head->free_list_head = *pointer_cast<skipfield_pointer_type>(element_pointer);
				range_fill_skipblock(it, element_pointer, skipfield_pointer, skipblock_size);
				size -= skipblock_size;

				if (erasure_groups_head->free_list_head != std::numeric_limits<skipfield_type>::max())
				{
					edit_free_list_next(to_aligned_pointer(erasure_groups_head->elements) + erasure_groups_head->free_list_head, std::numeric_limits<skipfield_type>::max());
				}
				else
				{
					erasure_groups_head = erasure_groups_head->erasures_list_next_group;
				}

				if (size == 0) return;
			}
			else
			{
				const skipfield_type prev_index = *pointer_cast<skipfield_pointer_type>(element_pointer);
				range_fill_skipblock(it, element_pointer, skipfield_pointer, static_cast<skipfield_type>(size));
				const skipfield_type new_skipblock_size = static_cast<skipfield_type>(skipblock_size - size);

				*(skipfield_pointer + size) = new_skipblock_size;
				*(skipfield_pointer + skipblock_size - 1) = new_skipblock_size;
				erasure_groups_head->free_list_head += static_cast<skipfield_type>(size);
				edit_free_list_head(element_pointer + size, prev_index);

				if (prev_index != std::numeric_limits<skipfield_type>::max())
				{
					edit_free_list_next(to_aligned_pointer(erasure_groups_head->elements) + prev_index, erasure_groups_head->free_list_head);
				}

				return;
			}
		}

		const skipfield_type group_remainder = static_cast<skipfield_type>(std::min(static_cast<size_type>(to_aligned_pointer(end_iterator.group_pointer->skipfield) - end_iterator.element_pointer), size));

		if (group_remainder != 0)
		{
			range_fill(it, group_remainder);
			end_iterator.group_pointer->size += group_remainder;

			if (size == group_remainder)
			{
				end_iterator.skipfield_pointer = end_iterator.group_pointer->skipfield + end_iterator.group_pointer->size;
				return;
			}

			size -= group_remainder;
		}


		end_iterator.group_pointer->next_group = unused_groups_head;
		if ((std::numeric_limits<size_type>::max() - end_iterator.group_pointer->group_number) < size) [[unlikely]] reset_group_numbers();
		range_fill_unused_groups(size, it, end_iterator.group_pointer->group_number + 1u, end_iterator.group_pointer, unused_groups_head);
	}



public:

	// Range insert:

	template <class iterator_type>
	void insert(const typename std::enable_if_t<!std::numeric_limits<iterator_type>::is_integer, iterator_type> &first, const iterator_type &last)
	{
		range_insert(first, static_cast<size_type>(std::distance(first, last)));
	}



	// Range insert, move_iterator overload:

	template <class iterator_type>
	void insert(const std::move_iterator<iterator_type> &first, const std::move_iterator<iterator_type> &last)
	{
		range_insert(first, static_cast<size_type>(std::distance(first.base(), last.base())));
	}



	// Initializer-list insert:

	void insert (const std::initializer_list<element_type> &element_list)
	{
		range_insert(element_list.begin(), static_cast<size_type>(element_list.size()));
	}



	template<class range_type>
		requires std::ranges::range<range_type>
	void insert_range(range_type &&the_range)
	{
		range_insert(std::ranges::begin(the_range), static_cast<size_type>(std::ranges::distance(the_range)));
	}



private:


	void add_to_groups_with_erasures_list(const group_pointer_type group_to_add) noexcept
	{
		group_to_add->erasures_list_next_group = erasure_groups_head;

		if (erasure_groups_head != nullptr)
		{
			erasure_groups_head->erasures_list_previous_group = group_to_add;
		}

		erasure_groups_head = group_to_add;
	}



	void remove_from_groups_with_erasures_list(const group_pointer_type group_to_remove) noexcept
	{
		if (group_to_remove != erasure_groups_head)
		{
			group_to_remove->erasures_list_previous_group->erasures_list_next_group = group_to_remove->erasures_list_next_group;

			if (group_to_remove->erasures_list_next_group != nullptr)
			{
				group_to_remove->erasures_list_next_group->erasures_list_previous_group = group_to_remove->erasures_list_previous_group;
			}
		}
		else
		{
			erasure_groups_head = erasure_groups_head->erasures_list_next_group;
		}
	}



	void reset_only_group_left(const group_pointer_type group_pointer) noexcept
	{
		erasure_groups_head = nullptr;
		group_pointer->reset(0, nullptr, nullptr, 0);

		// Reset begin and end iterators:
		end_iterator.element_pointer = begin_iterator.element_pointer = to_aligned_pointer(group_pointer->elements);
		end_iterator.skipfield_pointer = begin_iterator.skipfield_pointer = group_pointer->skipfield;
	}



	void add_to_unused_groups_list(group * const group_pointer) noexcept
	{
		group_pointer->next_group = unused_groups_head;
		unused_groups_head = group_pointer;
	}



public:

	iterator erase(const const_iterator &it) // if uninitialized/invalid iterator supplied, function could generate an exception
	{
		assert(total_size != 0);
		assert(it.group_pointer != nullptr); // ie. not uninitialized iterator
		assert(it.element_pointer != end_iterator.element_pointer); // ie. != end()
		assert(*(it.skipfield_pointer) == 0); // ie. element pointed to by iterator has not been erased previously

		if constexpr (!std::is_trivially_destructible<element_type>::value)
		{
			destroy_element(it.element_pointer);
		}

		--total_size;

		if (--(it.group_pointer->size) != 0) // ie. non-empty group at this point in time, don't consolidate
		{
			// Code logic for following section:
			// ---------------------------------
			// If current skipfield node has no skipblock on either side, create new skipblock of size 1
			// If node only has skipblock on left, set current node and start node of the skipblock to left node value + 1.
			// If node only has skipblock on right, make this node the start node of the skipblock and update end node
			// If node has skipblocks on left and right, set start node of left skipblock and end node of right skipblock to the values of the left + right nodes + 1

			// Optimization explanation:
			// The contextual logic below is the same as that in the insert() functions but in this case the value of the current skipfield node will always be
			// zero (since it is not yet erased), meaning no additional manipulations are necessary for the previous skipfield node comparison - we only have to check against zero
			const char prev_skipfield = *(it.skipfield_pointer - (it.skipfield_pointer != it.group_pointer->skipfield)) != 0; // true if previous node is erased or this node is at beginning of skipfield
			const char after_skipfield = *(it.skipfield_pointer + 1) != 0;  // NOTE: boundary test (checking against end-of-elements) is able to be skipped due to the extra skipfield node (compared to element field) - which is present to enable faster iterator operator ++ operations
			skipfield_type update_value = 1;

			if (!(prev_skipfield | after_skipfield)) // no consecutive erased elements
			{
				*it.skipfield_pointer = 1; // solo skipped node
				const skipfield_type index = static_cast<skipfield_type>(it.element_pointer - to_aligned_pointer(it.group_pointer->elements));

				if (it.group_pointer->free_list_head != std::numeric_limits<skipfield_type>::max()) // ie. if this group already has some erased elements
				{
					edit_free_list_next(to_aligned_pointer(it.group_pointer->elements) + it.group_pointer->free_list_head, index); // set prev free list head's 'next index' number to the index of the current element
				}
				else
				{
					add_to_groups_with_erasures_list(it.group_pointer);
				}

				edit_free_list_head(it.element_pointer, it.group_pointer->free_list_head);
				it.group_pointer->free_list_head = index;
			}
			else if (prev_skipfield & (!after_skipfield)) // previous erased consecutive elements, none following
			{
				*(it.skipfield_pointer - *(it.skipfield_pointer - 1)) = *it.skipfield_pointer = static_cast<skipfield_type>(*(it.skipfield_pointer - 1) + 1);
			}
			else if ((!prev_skipfield) & after_skipfield) // following erased consecutive elements, none preceding
			{
				const skipfield_type following_value = static_cast<skipfield_type>(*(it.skipfield_pointer + 1) + 1);
				*(it.skipfield_pointer + following_value - 1) = *(it.skipfield_pointer) = following_value;

				const skipfield_type following_previous = *(pointer_cast<skipfield_pointer_type>(it.element_pointer + 1));
				const skipfield_type following_next = *(pointer_cast<skipfield_pointer_type>(it.element_pointer + 1) + 1);
				edit_free_list_prev(it.element_pointer, following_previous);
				edit_free_list_next(it.element_pointer, following_next);

				const skipfield_type index = static_cast<skipfield_type>(it.element_pointer - to_aligned_pointer(it.group_pointer->elements));

				if (following_previous != std::numeric_limits<skipfield_type>::max())
				{
					edit_free_list_next(to_aligned_pointer(it.group_pointer->elements) + following_previous, index); // Set next index of previous free list node to this node's 'next' index
				}

				if (following_next != std::numeric_limits<skipfield_type>::max())
				{
					edit_free_list_prev(to_aligned_pointer(it.group_pointer->elements) + following_next, index);	// Set previous index of next free list node to this node's 'previous' index
				}
				else
				{
					it.group_pointer->free_list_head = index;
				}

				update_value = following_value;
			}
			else // both preceding and following consecutive erased elements - erased element is between two skipblocks
			{
				*(it.skipfield_pointer) = 1; // This line necessary in order for get_iterator() to work - ensures that erased element skipfield nodes are always non-zero
				const skipfield_type preceding_value = *(it.skipfield_pointer - 1);
				const skipfield_type following_value = static_cast<skipfield_type>(*(it.skipfield_pointer + 1) + 1);

				// Join the skipblocks
				*(it.skipfield_pointer - preceding_value) = *(it.skipfield_pointer + following_value - 1) = static_cast<skipfield_type>(preceding_value + following_value);

				// Remove the following skipblock's entry from the free list
				const skipfield_type following_previous = *(pointer_cast<skipfield_pointer_type>(it.element_pointer + 1));
				const skipfield_type following_next = *(pointer_cast<skipfield_pointer_type>(it.element_pointer + 1) + 1);

				if (following_previous != std::numeric_limits<skipfield_type>::max())
				{
					edit_free_list_next(to_aligned_pointer(it.group_pointer->elements) + following_previous, following_next); // Set next index of previous free list node to this node's 'next' index
				}

				if (following_next != std::numeric_limits<skipfield_type>::max())
				{
					edit_free_list_prev(to_aligned_pointer(it.group_pointer->elements) + following_next, following_previous); // Set previous index of next free list node to this node's 'previous' index
				}
				else
				{
					it.group_pointer->free_list_head = following_previous;
				}

				update_value = following_value;
			}

			iterator return_iterator(it.group_pointer, it.element_pointer + update_value, it.skipfield_pointer + update_value);

			if (return_iterator.element_pointer == to_aligned_pointer(it.group_pointer->skipfield) && it.group_pointer != end_iterator.group_pointer)
			{
				return_iterator.group_pointer = it.group_pointer->next_group;
				const aligned_pointer_type elements = to_aligned_pointer(return_iterator.group_pointer->elements);
				const skipfield_pointer_type skipfield = return_iterator.group_pointer->skipfield;
				return_iterator.element_pointer = elements + *skipfield;
				return_iterator.skipfield_pointer = skipfield + *skipfield;
			}

			if (it.element_pointer == begin_iterator.element_pointer) begin_iterator = return_iterator; // If original iterator was first element in hive, update it's value with the next non-erased element:

			return return_iterator;
		}

		// else: group is empty, consolidate groups
		const bool in_back_block = (it.group_pointer->next_group == nullptr), in_front_block = (it.group_pointer == begin_iterator.group_pointer);

		if (in_back_block & in_front_block) // ie. only group in hive
		{
			// Reset skipfield and free list rather than clearing - leads to fewer allocations/deallocations:
			reset_only_group_left(it.group_pointer);
			return end_iterator;
		}
		else if ((!in_back_block) & in_front_block) // ie. Remove first group, change first group to next group
		{
			it.group_pointer->next_group->previous_group = nullptr; // Cut off this group from the chain
			begin_iterator.group_pointer = it.group_pointer->next_group; // Make the next group the first group

			if (it.group_pointer->free_list_head != std::numeric_limits<skipfield_type>::max()) // Erasures present within the group, ie. was part of the linked list of groups with erasures.
			{
				remove_from_groups_with_erasures_list(it.group_pointer);
			}

			deallocate_group_remove_capacity(it.group_pointer);

			// note: end iterator only needs to be changed if the deleted group was the final group in the chain ie. not in this case
			begin_iterator.element_pointer = to_aligned_pointer(begin_iterator.group_pointer->elements) + *(begin_iterator.group_pointer->skipfield); // If the beginning index has been erased (ie. skipfield != 0), skip to next non-erased element
			begin_iterator.skipfield_pointer = begin_iterator.group_pointer->skipfield + *(begin_iterator.group_pointer->skipfield);

			return begin_iterator;
		}
		else if (!(in_back_block | in_front_block)) // this is a non-first group but not final group in chain: delete the group, then link previous group to the next group in the chain:
		{
			it.group_pointer->next_group->previous_group = it.group_pointer->previous_group;
			const group_pointer_type return_group = it.group_pointer->previous_group->next_group = it.group_pointer->next_group; // close the chain, removing this group from it

			if (it.group_pointer->free_list_head != std::numeric_limits<skipfield_type>::max())
			{
				remove_from_groups_with_erasures_list(it.group_pointer);
			}

			if (it.group_pointer->next_group != end_iterator.group_pointer)
			{
				deallocate_group_remove_capacity(it.group_pointer);
			}
			else
			{
				add_to_unused_groups_list(it.group_pointer);
			}

			// Return next group's first non-erased element:
			return iterator(return_group, to_aligned_pointer(return_group->elements) + *(return_group->skipfield), return_group->skipfield + *(return_group->skipfield));
		}
		else // this is a non-first group and the final group in the chain
		{
			if (it.group_pointer->free_list_head != std::numeric_limits<skipfield_type>::max())
			{
				remove_from_groups_with_erasures_list(it.group_pointer);
			}

			it.group_pointer->previous_group->next_group = nullptr;
			end_iterator.group_pointer = it.group_pointer->previous_group; // end iterator needs to be changed as element supplied was the back element of the hive
			end_iterator.element_pointer = to_aligned_pointer(end_iterator.group_pointer->skipfield);
			end_iterator.skipfield_pointer = end_iterator.group_pointer->skipfield + end_iterator.group_pointer->capacity;

			add_to_unused_groups_list(it.group_pointer);

			return end_iterator;
		}
	}



private:


	void partially_erase_group(const const_iterator &start, const aligned_pointer_type end)
	{
		// For the partial block erasures, we have to remove the existing skipblocks within the range from the intra-block free list of skipblocks. However if there're no erasures in the block, we can avoid doing so.
		const_iterator current = start;
		skipfield_type erasure_count = 0;

		// First erase all elements until end of block & remove all skipblocks post-initial position from the free_list. Then, either update preceding skipblock or create new one:

		if (start.group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max()) // ie. no other erasures/skipblocks in block
		{
			erasure_count += static_cast<skipfield_type>(end - start.element_pointer);
			add_to_groups_with_erasures_list(start.group_pointer);

			if constexpr (!std::is_trivially_destructible<element_type>::value)
			{
				do // Avoid checking skipfield as there are no erased elements
				{
					destroy_element(current.element_pointer);
				} while (++current.element_pointer != end);
			}
		}
		else
		{
			while (current.element_pointer != end)
			{
				if (*current.skipfield_pointer == 0)
				{
					if constexpr (!std::is_trivially_destructible<element_type>::value) destroy_element(current.element_pointer);

					++erasure_count;
					++current.element_pointer;
					++current.skipfield_pointer;
				}
				else // remove skipblock
				{
					const skipfield_type prev_free_list_index = *(pointer_cast<skipfield_pointer_type>(current.element_pointer));
					const skipfield_type next_free_list_index = *(pointer_cast<skipfield_pointer_type>(current.element_pointer) + 1);

					current.element_pointer += *(current.skipfield_pointer);
					current.skipfield_pointer += *(current.skipfield_pointer);

					if (next_free_list_index == std::numeric_limits<skipfield_type>::max() && prev_free_list_index == std::numeric_limits<skipfield_type>::max()) // if this is the last skipblock in the free list
					{
						current.group_pointer->free_list_head = std::numeric_limits<skipfield_type>::max();
						erasure_count += static_cast<skipfield_type>(end - current.element_pointer);

						if constexpr (!std::is_trivially_destructible<element_type>::value)
						{
							while (current.element_pointer != end) destroy_element(current.element_pointer++); // Avoids checking skipfield, as there are no erased elements left in block
						}

						break; // end overall while loop
					}
					else if (next_free_list_index == std::numeric_limits<skipfield_type>::max()) // if this is the head of the free list
					{
						current.group_pointer->free_list_head = prev_free_list_index; // make free list head equal to next free list node
						edit_free_list_next(to_aligned_pointer(current.group_pointer->elements) + prev_free_list_index, std::numeric_limits<skipfield_type>::max());
					}
					else // either a tail or middle free list node
					{
						edit_free_list_prev(to_aligned_pointer(current.group_pointer->elements) + next_free_list_index, prev_free_list_index);

						if (prev_free_list_index != std::numeric_limits<skipfield_type>::max()) // ie. not the tail free list node
						{
							edit_free_list_next(to_aligned_pointer(current.group_pointer->elements) + prev_free_list_index, next_free_list_index);
						}
					}
				}
			}
		}

		// Update jump-counting skipfield:
		const size_type distance_to_end = static_cast<skipfield_type>(end - start.element_pointer);
		const skipfield_type start_index = static_cast<skipfield_type>(start.element_pointer - to_aligned_pointer(start.group_pointer->elements)); // distance between start element and start of block
		const size_type previous_node_value = (start_index == 0) ? 0 : *(start.skipfield_pointer - 1);

		if (previous_node_value == 0) // start element is either at start of block, or previous element is non-erased so no adjacent skipblock
		{
			*(start.skipfield_pointer) = *(start.skipfield_pointer + distance_to_end - 1) = static_cast<skipfield_type>(distance_to_end); // set start and end node of skipblock

			if (start.group_pointer->free_list_head != std::numeric_limits<skipfield_type>::max()) // ie. if this group already has some erased elements
			{
				edit_free_list_next(to_aligned_pointer(start.group_pointer->elements) + start.group_pointer->free_list_head, start_index);
			}

			edit_free_list_head(start.element_pointer, start.group_pointer->free_list_head);
			start.group_pointer->free_list_head = start_index;
		}
		else
		{
			// Just update existing skipblock, no need to create new free list node:
			*(start.skipfield_pointer - previous_node_value) = *(start.skipfield_pointer + distance_to_end - 1) = static_cast<skipfield_type>(previous_node_value + distance_to_end);
		}

		if (distance_to_end > 2) // if the skipblock is longer than 2 nodes, fill in the middle nodes with non-zero values so that get_iterator() will work
		{
			std::memset(std::to_address(start.skipfield_pointer + 1), 1, sizeof(skipfield_type) * (distance_to_end - 2));
		}

		// Update group and hive size:
		start.group_pointer->size -= erasure_count;
		total_size -= erasure_count;
	}



public:


	// Range erase:

	iterator erase(const const_iterator &iterator1, const const_iterator &iterator2)	// if uninitialized/invalid iterators supplied, function could generate an exception. If iterator1 > iterator2, behaviour is undefined.
	{
		// General code logic: if iterator1 and iterator2 point to elements in the same block, we skip to code section 3 (final block).
		// If they aren't and iterator1 isn't the first non-erased element in first block, we erase part of that block and update accordingly in code Section 1.
		// If it is the first non-erased element, it gets handled in code section 2.
		// In code Section 2 we fully erase and remove all intermediate blocks which aren't the final block. This's optimal as we can just discard the blocks and not do any skipfield or free list updating.
		// In code Section 3 we either partially or fully erase (if iterator2 == end()) the final block in the supplied sequence. If iterator2 was the first non-erased element in it's block or iterator1 == iterator2, this is caught at this point and no action is taken.

		assert(iterator1 <= iterator2);

		const_iterator current = iterator1;

		if (iterator1.group_pointer != iterator2.group_pointer)
		{
			// Section 1: process first block, if partial block erasure
			// ========================================================
			if (current.element_pointer != to_aligned_pointer(current.group_pointer->elements) + *(current.group_pointer->skipfield)) // if iterator1 is not the first non-erased element in it's block - most common case
			{
				partially_erase_group(iterator1, to_aligned_pointer(iterator1.group_pointer->skipfield));
				current.group_pointer = current.group_pointer->next_group;
			}


			// Section 2: remove all intermediate blocks before final block (including first block if it's a full block erasure rather than partial)
			// ====================================================================================================================================
			const group_pointer_type previous_group = current.group_pointer->previous_group;

			while (current.group_pointer != iterator2.group_pointer)
			{
				if constexpr (!std::is_trivially_destructible<element_type>::value)
				{
					current.element_pointer = to_aligned_pointer(current.group_pointer->elements) + *(current.group_pointer->skipfield);
					current.skipfield_pointer = current.group_pointer->skipfield + *(current.group_pointer->skipfield);

					destroy_group(current, to_aligned_pointer(current.group_pointer->skipfield));
				}

				if (current.group_pointer->free_list_head != std::numeric_limits<skipfield_type>::max())
				{
					remove_from_groups_with_erasures_list(current.group_pointer);
				}

				total_size -= current.group_pointer->size;
				const group_pointer_type current_group = current.group_pointer;
				current.group_pointer = current.group_pointer->next_group;

				if (current_group != end_iterator.group_pointer && current_group->next_group != end_iterator.group_pointer)
				{
					deallocate_group_remove_capacity(current_group);
				}
				else
				{
					add_to_unused_groups_list(current_group);
				}
			}

			current.element_pointer = to_aligned_pointer(current.group_pointer->elements) + *(current.group_pointer->skipfield);
			current.skipfield_pointer = current.group_pointer->skipfield + *(current.group_pointer->skipfield);
			current.group_pointer->previous_group = previous_group; // Join this group to the previous non-removed group

			if (previous_group != nullptr)
			{
				previous_group->next_group = current.group_pointer;
			}
			else
			{
				begin_iterator = iterator(iterator2.group_pointer, iterator2.element_pointer, iterator2.skipfield_pointer); // This line is included primarily to avoid a secondary if statement within the if block below - it is not needed otherwise
			}
		}


		// Section 3: final block
		// =======================================================================
		// Code logic:
		// If not erasing entire final block, 1. Destruct elements (if non-trivial destructor), 2. add skipblock location to group's free list of skipblocks, and 3. update skipfield.
		// If erasing entire block, 1. Destruct elements (if non-trivial destructor), 2. if no elements left in hive reset the group, otherwise 3. reset end_iterator and remove group from groups-with-erasures list (if prior erasures are present).
		// Note: only way that entire block can be erased is if iterator2 == end() in this case, hence why we reset end_iterator.

		if (current.element_pointer != iterator2.element_pointer) // in case iterator2 was at beginning of it's block - also covers empty range case (first == last)
		{
			if (iterator2.element_pointer != end_iterator.element_pointer || current.element_pointer != to_aligned_pointer(current.group_pointer->elements) + *(current.group_pointer->skipfield)) // ie. not erasing entire block. Second condition will only be false if iterator1 & iterator2 are in same block.
			{
				partially_erase_group(current, iterator2.element_pointer);

				if (iterator1.element_pointer == begin_iterator.element_pointer)
				{
					begin_iterator = iterator(iterator2.group_pointer, iterator2.element_pointer, iterator2.skipfield_pointer);
				}
			}
			else // ie. full block erasure
			{
				if constexpr (!std::is_trivially_destructible<element_type>::value)
				{
					destroy_group(current, iterator2.element_pointer);
				}

				if ((total_size -= current.group_pointer->size) != 0) // ie. hive is not empty
				{
					if (current.group_pointer->free_list_head != std::numeric_limits<skipfield_type>::max())
					{
						remove_from_groups_with_erasures_list(current.group_pointer);
					}

					current.group_pointer->previous_group->next_group = current.group_pointer->next_group;

					end_iterator.group_pointer = current.group_pointer->previous_group;
					end_iterator.element_pointer = to_aligned_pointer(end_iterator.group_pointer->skipfield);
					end_iterator.skipfield_pointer = end_iterator.group_pointer->skipfield + end_iterator.group_pointer->capacity;
					add_to_unused_groups_list(current.group_pointer);
				}
				else // ie. hive is now empty
				{
					// Reset skipfield and free list rather than clearing - leads to fewer allocations/deallocations:
					reset_only_group_left(current.group_pointer);
				}

				return end_iterator;
			}
		}

		return iterator(iterator2.group_pointer, iterator2.element_pointer, iterator2.skipfield_pointer);
	}



private:


	void prepare_groups_for_assign(const size_type size)
	{
		if constexpr (!std::is_trivially_destructible<element_type>::value) destroy_remainder(begin_iterator);

		if (size < total_capacity && (total_capacity - size) >= min_block_capacity)
		{
			size_type difference = total_capacity - size;
			end_iterator.group_pointer->next_group = unused_groups_head;

			// Remove surplus groups which're under the difference limit:
			group_pointer_type current_group = begin_iterator.group_pointer, previous_group = nullptr;

			do
			{
				const group_pointer_type next_group = current_group->next_group;

				if (current_group->capacity <= difference)
				{ // Remove group:
					difference -= current_group->capacity;
					deallocate_group_remove_capacity(current_group);

					if (current_group == begin_iterator.group_pointer) begin_iterator.group_pointer = next_group;
				}
				else
				{
					if (previous_group != nullptr) previous_group->next_group = current_group;
					previous_group = current_group;
				}

				current_group = next_group;
			} while (current_group != nullptr);

			previous_group->next_group = nullptr;
		}
		else
		{
			if (size > total_capacity) reserve(size);

			// Join all unused_groups to main chain:
			end_iterator.group_pointer->next_group = unused_groups_head;
		}

		begin_iterator.element_pointer = to_aligned_pointer(begin_iterator.group_pointer->elements);
		begin_iterator.skipfield_pointer = begin_iterator.group_pointer->skipfield;
		erasure_groups_head = nullptr;
		total_size = 0;
	}



public:


	// Fill assign:

	void assign(size_type size, const element_type &element)
	{
		if (size == 0)
		{
			reset();
			return;
		}

		if constexpr ((std::is_trivially_destructible<element_type>::value && std::is_trivially_constructible<element_type>::value && std::is_trivially_copy_assignable<element_type>::value) || !std::is_copy_assignable<element_type>::value) // ie. If there is no benefit nor difference to assigning vs constructing, or if we can't assign, use faster method:
		{
			prepare_groups_for_assign(size);
			fill_unused_groups(size, element, 0, nullptr, begin_iterator.group_pointer);
		}
		else
		{
			if (total_size == 0)
			{
				prepare_groups_for_assign(size);
				fill_unused_groups(size, element, 0, nullptr, begin_iterator.group_pointer);
			}
			else if (size < total_size)
			{
				iterator current = begin_iterator;

				do
				{
					*current++ = element;
				} while (--size != 0);

				erase(current, end_iterator);
			}
			else
			{
				iterator current = begin_iterator;

				do
				{
					*current = element;
				} while (++current != end_iterator);

				insert(size - total_size, element);
			}
		}
	}



private:


	void reset_group_range_assign(iterator &it) noexcept
	{
		std::memset(std::to_address(it.group_pointer->skipfield), 0, it.group_pointer->capacity * sizeof(skipfield_type));
		it.group_pointer->size = static_cast<skipfield_type>(it.element_pointer - to_aligned_pointer(it.group_pointer->elements));
	}



	void make_back_group_range_assign(iterator &it) noexcept
	{
		// Add all subsequent active groups to unused_groups list:
 		if (it.group_pointer != end_iterator.group_pointer)
		{
			end_iterator.group_pointer->next_group = unused_groups_head;
			unused_groups_head = it.group_pointer->next_group;
		}

		end_iterator = it;
		it.group_pointer->next_group = nullptr;
	}



	void finish_range_assign(iterator &it) noexcept
	{
		reset_group_range_assign(it);
		make_back_group_range_assign(it);
	}



	void check_iterator_end_of_block(const_iterator &it) noexcept
	{
		if constexpr (!std::is_trivially_destructible<element_type>::value)
		{
			if (it.element_pointer == to_aligned_pointer(it.group_pointer->skipfield))
			{
				it.group_pointer = it.group_pointer->next_group;
				const skipfield_type skip = *(it.group_pointer->skipfield);
				it.element_pointer = to_aligned_pointer(it.group_pointer->elements) + skip;
				it.skipfield_pointer = it.group_pointer->skipfield + skip;
			}
		}
	}



	// Range assign core:

	template <class iterator_type>
	void range_assign(iterator_type it, size_type size)
	{
		if (size == 0)
		{
			reset();
			return;
		}

		if (total_size == 0)
		{
			prepare_groups_for_assign(size);
			range_fill_unused_groups(size, it, 0, nullptr, begin_iterator.group_pointer);
		}
		else
		{
			erasure_groups_head = nullptr;
			total_size = 0;
			begin_iterator.element_pointer = to_aligned_pointer(begin_iterator.group_pointer->elements);
			begin_iterator.skipfield_pointer = begin_iterator.group_pointer->skipfield;


			for (iterator current(begin_iterator); current.group_pointer != nullptr;)
			{
				current.element_pointer = to_aligned_pointer(current.group_pointer->elements);
				current.skipfield_pointer = current.group_pointer->skipfield;
				current.group_pointer->free_list_head = std::numeric_limits<skipfield_type>::max();

				for (const aligned_pointer_type end = (current.group_pointer == end_iterator.group_pointer) ? end_iterator.element_pointer : to_aligned_pointer(current.group_pointer->skipfield); current.element_pointer != end;)
				{
					if (*(current.skipfield_pointer) != 0)
					{
						skipfield_type skipblock_length = *(current.skipfield_pointer);
						const_iterator next_element(current.group_pointer, current.element_pointer + skipblock_length, current.skipfield_pointer + skipblock_length);
						skipblock_length = (skipblock_length > size) ? static_cast<skipfield_type>(size) : skipblock_length;

						for (const aligned_pointer_type fill_end = current.element_pointer + skipblock_length; current.element_pointer != fill_end; ++current.element_pointer, ++current.skipfield_pointer)
						{
							#ifdef PLF_EXCEPTIONS_SUPPORT
								if constexpr (!std::is_nothrow_copy_constructible<element_type>::value)
								{
									try
									{
										construct_element(current.element_pointer, *it++);
									}
									catch (...)
									{
										if constexpr (!std::is_trivially_destructible<element_type>::value)
										{
											check_iterator_end_of_block(next_element);
											destroy_remainder(next_element);
										}
										finish_range_assign(current);
										throw;
									}
								} else
							#endif
							{
								construct_element(current.element_pointer, *it++);
							}

							++total_size;
						}

						if ((size -= skipblock_length) == 0)
						{
							if constexpr (!std::is_trivially_destructible<element_type>::value)
							{
								check_iterator_end_of_block(next_element);
								destroy_remainder(next_element);
							}

							finish_range_assign(current);
							return;
						}
					}
					else
					{
						#ifdef PLF_EXCEPTIONS_SUPPORT
							if constexpr (!std::is_nothrow_copy_assignable<element_type>::value)
							{
								try
								{
									*pointer_cast<pointer>(current.element_pointer) = *it++;
								}
								catch (...)
								{
									if constexpr (!std::is_trivially_destructible<element_type>::value) destroy_remainder(current);
									finish_range_assign(current);
									throw;
								}
							} else
						#endif
						{
							*pointer_cast<pointer>(current.element_pointer) = *it++;
						}

						++total_size;

						if (--size == 0)
						{
							if constexpr (!std::is_trivially_destructible<element_type>::value) destroy_remainder(++iterator(current)); // To potentially allow for skipping over a skipblock
							++current.element_pointer; // As opposed to just incrementing, as we do here
							++current.skipfield_pointer;
							finish_range_assign(current);
							return;
						}

						++current.element_pointer;
						++current.skipfield_pointer;
					}
				}

				reset_group_range_assign(current);
				current.group_pointer = current.group_pointer->next_group;
			}

			// Use up any remaining space at end of end block (would not be correctly identified above because the skipfield in unused nodes is 0)
			for (const aligned_pointer_type end = to_aligned_pointer(end_iterator.group_pointer->skipfield); end_iterator.element_pointer != end;)
			{
				construct_element(end_iterator.element_pointer, *it++);
				++total_size;
				++end_iterator.group_pointer->size;
				++end_iterator.element_pointer;
				++end_iterator.skipfield_pointer;

				if (--size == 0) return;
			}

			// Indicates we've reached the end of existing groups with elements, now can only reused unused groups or create new ones:
			range_insert(it, size);
		}
	}



public:

	// Range assign:

	template <class iterator_type>
	void assign(const typename std::enable_if_t<!std::numeric_limits<iterator_type>::is_integer, iterator_type> &first, const iterator_type &last)
	{
		range_assign(first, static_cast<size_type>(std::distance(first, last)));
	}



	// Range assign, move_iterator overload:

	template <class iterator_type>
	void assign (const std::move_iterator<iterator_type> first, const std::move_iterator<iterator_type> last)
	{
		range_assign(first, static_cast<size_type>(std::distance(first.base(),last.base())));
	}



	// Initializer-list assign:

	void assign(const std::initializer_list<element_type> &element_list)
	{
		range_assign(element_list.begin(), static_cast<size_type>(element_list.size()));
	}



	template<class range_type>
		requires std::ranges::range<range_type>
	void assign_range(range_type &&the_range)
	{
		range_assign(std::ranges::begin(the_range), static_cast<size_type>(std::ranges::distance(the_range)));
	}



	[[nodiscard]] bool empty() const noexcept
	{
		return total_size == 0;
	}



	size_type size() const noexcept
	{
		return total_size;
	}



	size_type max_size() const noexcept
	{
		return std::allocator_traits<allocator_type>::max_size(*this);
	}



	size_type capacity() const noexcept
	{
		return total_capacity;
	}



	#ifdef PLF_BENCH_H
		size_type memory() const noexcept // Used for checking memory use during benchmarking
		{
			size_type memory_use = sizeof(*this); // sizeof hive basic structure
			end_iterator.group_pointer->next_group = unused_groups_head; // temporarily link the active and reserved (unused) groups in order to only have one loop below instead of two

			for(group_pointer_type current = begin_iterator.group_pointer; current != nullptr; current = current->next_group)
			{
				memory_use += sizeof(group) + (get_aligned_block_capacity(current->capacity) * sizeof(aligned_allocation_struct)); // add element/skipfield memory block sizes + size of the group struct
			}

			end_iterator.group_pointer->next_group = nullptr; // unlink active & reserved groups
			return memory_use;
		}
	#endif



private:

	// get all elements contiguous in memory and shrink to fit, remove erasures and free lists. Invalidates all iterators and pointers to elements.
	void consolidate(const skipfield_type new_min, const skipfield_type new_max)
	{
		hive temp(plf::hive_limits(new_min, new_max));
		temp.reserve(total_size);
		temp.end_iterator.group_pointer->next_group = temp.unused_groups_head;

		if constexpr (!std::is_trivially_copyable<element_type>::value && std::is_nothrow_move_constructible<element_type>::value)
		{
			temp.range_fill_unused_groups(total_size, std::make_move_iterator(begin_iterator), 0, nullptr, temp.begin_iterator.group_pointer);
		}
		else
		{
			temp.range_fill_unused_groups(total_size, begin_iterator, 0, nullptr, temp.begin_iterator.group_pointer);
		}

		*this = std::move(temp);
	}



public:


	void reshape(const plf::hive_limits block_limits)
	{
		check_capacities_conformance(block_limits);
		const skipfield_type new_min = static_cast<skipfield_type>(block_limits.min), new_max = static_cast<skipfield_type>(block_limits.max);

		if (total_capacity != 0)
		{
			if (total_size != 0)
			{
				if (min_block_capacity > new_max || max_block_capacity < new_min) // If none of the original blocks could potentially fit within the new limits, skip checking of blocks and just consolidate:
				{
					consolidate(new_min, new_max);
					return;
				}

				if (min_block_capacity < new_min || max_block_capacity > new_max) // ie. If existing blocks could be outside of the new limits
				{
					// Otherwise need to check all group sizes here (not just back one, which is most likely largest), because splice might append smaller blocks after a larger block:
					for (group_pointer_type current_group = begin_iterator.group_pointer; current_group != nullptr; current_group = current_group->next_group)
					{
						if (current_group->capacity < new_min || current_group->capacity > new_max)
						{
							consolidate(new_min, new_max);
							return;
						}
					}
				}
			}
			else // include first group to be checked in the loop below
			{
				begin_iterator.group_pointer->next_group = unused_groups_head;
				unused_groups_head = begin_iterator.group_pointer;
			}

			// If a consolidation or throw has not occured, process reserved/unused groups and deallocate where they don't fit the new limits:

			for (group_pointer_type current_group = unused_groups_head, previous_group = nullptr; current_group != nullptr;)
			{
				const group_pointer_type next_group = current_group->next_group;

				if (current_group->capacity < new_min || current_group->capacity > new_max)
				{
					deallocate_group_remove_capacity(current_group);

					if (previous_group == nullptr)
					{
						unused_groups_head = next_group;
					}
					else
					{
						previous_group->next_group = next_group;
					}
				}
				else
				{
					previous_group = current_group;
				}

				current_group = next_group;
			}

			if (total_size == 0)
			{
				if (unused_groups_head == nullptr)
				{
					blank();
				}
				else
				{
					begin_iterator.group_pointer = unused_groups_head;
					unused_groups_head = begin_iterator.group_pointer->next_group;
					begin_iterator.group_pointer->next_group = nullptr;
				}
			}
		}

		min_block_capacity = new_min;
		max_block_capacity = new_max;
	}



	constexpr hive_limits block_capacity_limits() const noexcept
	{
		return hive_limits(static_cast<size_t>(min_block_capacity), static_cast<size_t>(max_block_capacity));
	}



	static constexpr hive_limits block_capacity_hard_limits() noexcept
	{
		return hive_limits(3, std::min(static_cast<size_t>(std::numeric_limits<skipfield_type>::max()), max_size_static()));
	}



	void clear() noexcept
	{
		if (total_size == 0) return;

		// Destroy all elements if element type is non-trivial:
		if constexpr (!std::is_trivially_destructible<element_type>::value) destroy_remainder(begin_iterator);

		if (begin_iterator.group_pointer != end_iterator.group_pointer)
		{ // Move all other groups onto the unused_groups list
			end_iterator.group_pointer->next_group = unused_groups_head;
			unused_groups_head = begin_iterator.group_pointer->next_group;
			end_iterator.group_pointer = begin_iterator.group_pointer; // other parts of iterator reset in the function below
		}

		reset_only_group_left(begin_iterator.group_pointer);
		erasure_groups_head = nullptr;
		total_size = 0;
	}



	hive & operator = (const hive &source)
	{
		assert(&source != this);

		if constexpr (std::allocator_traits<allocator_type>::propagate_on_container_copy_assignment::value)
		{
			if constexpr (!std::allocator_traits<allocator_type>::is_always_equal::value)
			{ // Deallocate existing blocks as source allocator is not necessarily able to do so
				if (static_cast<allocator_type &>(*this) != static_cast<const allocator_type &>(source))
				{
					reset();
				}
			}

			static_cast<allocator_type &>(*this) = static_cast<const allocator_type &>(source);
			// Reconstruct rebinds:
			group_allocator = group_allocator_type(*this);
			aligned_struct_allocator = aligned_struct_allocator_type(*this);
			skipfield_allocator = skipfield_allocator_type(*this);
			tuple_allocator = tuple_allocator_type(*this);
		}

		range_assign(source.begin_iterator, source.total_size);
		return *this;
	}



private:

	void move_assign(hive &&source) noexcept(std::allocator_traits<allocator_type>::propagate_on_container_move_assignment::value || std::allocator_traits<allocator_type>::is_always_equal::value)
	{
		destroy_all_data();

		if constexpr ((std::is_trivially_copyable<allocator_type>::value || std::allocator_traits<allocator_type>::is_always_equal::value) && std::is_trivially_copyable<group_pointer_type>::value)
		{
			std::memcpy(static_cast<void *>(this), &source, sizeof(hive));
		}
		else
		{
			end_iterator = std::move(source.end_iterator);
			begin_iterator = std::move(source.begin_iterator);
			erasure_groups_head = std::move(source.erasure_groups_head);
			unused_groups_head =  std::move(source.unused_groups_head);
			total_size = source.total_size;
			total_capacity = source.total_capacity;
			min_block_capacity = source.min_block_capacity;
			max_block_capacity = source.max_block_capacity;

			if constexpr(std::allocator_traits<allocator_type>::propagate_on_container_move_assignment::value)
			{
				static_cast<allocator_type &>(*this) = static_cast<allocator_type &>(source);
				// Reconstruct rebinds:
				group_allocator = group_allocator_type(*this);
				aligned_struct_allocator = aligned_struct_allocator_type(*this);
				skipfield_allocator = skipfield_allocator_type(*this);
				tuple_allocator = tuple_allocator_type(*this);
			}
		}
	}



public:

	// Move assignment
	hive & operator = (hive &&source) noexcept(std::allocator_traits<allocator_type>::propagate_on_container_move_assignment::value || std::allocator_traits<allocator_type>::is_always_equal::value)
	{
		assert(&source != this);

		if constexpr (std::allocator_traits<allocator_type>::propagate_on_container_move_assignment::value || std::allocator_traits<allocator_type>::is_always_equal::value)
		{	// Note: we need this to be constexpr to avoid warning errors on the potentially-throwing section further down.
			move_assign(std::move(source));
		}
		else if (static_cast<allocator_type &>(*this) == static_cast<allocator_type &>(source))
		{
			move_assign(std::move(source));
		}
		else // Allocator isn't propagatable so move/copy elements from source and deallocate the source's blocks - could throw here:
		{
			if constexpr (!(std::is_move_constructible<element_type>::value && std::is_move_assignable<element_type>::value))
			{
				range_assign(source.begin_iterator, source.total_size);
			}
			else
			{
				range_assign(std::make_move_iterator(source.begin_iterator), source.total_size);
			}

			source.destroy_all_data();
		}

		source.blank();
		return *this;
	}



	hive & operator = (const std::initializer_list<element_type> &element_list)
	{
		range_assign(element_list.begin(), static_cast<size_type>(element_list.size()));
		return *this;
	}



	void shrink_to_fit()
	{
		if (total_size == total_capacity)
		{
			return;
		}
		else if (total_size == 0)
		{
			reset();
			return;
		}

		consolidate(min_block_capacity, max_block_capacity);
	}



	void trim_capacity() noexcept
	{
		if (end_iterator.element_pointer == nullptr) return; // empty hive

		while(unused_groups_head != nullptr)
		{
			const group_pointer_type next_group = unused_groups_head->next_group;
			deallocate_group_remove_capacity(unused_groups_head);
			unused_groups_head = next_group;
		}

		if (begin_iterator.element_pointer == end_iterator.element_pointer) // ie. clear() has been called prior
		{
			deallocate_group(begin_iterator.group_pointer);
			blank();
		}
	}



	void trim_capacity(const size_type capacity_retain) noexcept
	{
		const size_type capacity_difference = total_capacity - capacity_retain;

		if (end_iterator.element_pointer == nullptr || total_capacity <= capacity_retain || total_size >= capacity_retain || capacity_difference < min_block_capacity) return;

		size_type number_of_elements_to_remove = capacity_difference;

		for (group_pointer_type current_group = unused_groups_head, previous_group = nullptr; current_group != nullptr;)
		{
			const group_pointer_type next_group = current_group->next_group;

			if (number_of_elements_to_remove >= current_group->capacity)
			{
				number_of_elements_to_remove -= current_group->capacity;
				deallocate_group(current_group);

				if (previous_group == nullptr)
				{
					unused_groups_head = next_group;
				}
				else
				{
					previous_group->next_group = next_group;
				}

				if (number_of_elements_to_remove < min_block_capacity)
				{
					break;
				}
			}
			else
			{
				previous_group = current_group;
			}

			current_group = next_group;
		}


		if (begin_iterator.element_pointer == end_iterator.element_pointer) // ie. clear() has been called prior
		{
			if (number_of_elements_to_remove >= begin_iterator.group_pointer->capacity)
			{
				number_of_elements_to_remove -= begin_iterator.group_pointer->capacity;
				deallocate_group(begin_iterator.group_pointer);

				if (unused_groups_head != nullptr) // some of the reserved blocks were not removed as they were too large, so use one of these to make the new begin group
				{
					begin_iterator.group_pointer = unused_groups_head;
					begin_iterator.element_pointer = to_aligned_pointer(unused_groups_head->elements);
					begin_iterator.skipfield_pointer = unused_groups_head->skipfield;
					end_iterator = begin_iterator;

					unused_groups_head = unused_groups_head->next_group;
					begin_iterator.group_pointer->next_group = nullptr;
				}
				else
				{
					blank();
					return;
				}
			}
		}

		total_capacity -= capacity_difference - number_of_elements_to_remove;
	}



	void reserve(size_type new_capacity)
	{
		if (new_capacity == 0 || new_capacity <= total_capacity) return; // ie. We already have enough space allocated

		if (new_capacity > max_size())
		{
			#ifdef PLF_EXCEPTIONS_SUPPORT
				throw std::length_error("Capacity requested via reserve() greater than max_size()");
			#else
				std::terminate();
			#endif
		}

		new_capacity -= total_capacity;

		size_type number_of_max_groups = new_capacity / max_block_capacity;
		skipfield_type remainder = static_cast<skipfield_type>(new_capacity - (number_of_max_groups * max_block_capacity)), negative_remainder = 0;
		group_pointer_type deallocatable_group = nullptr;

		if (remainder == 0)
		{
			remainder = max_block_capacity;
			--number_of_max_groups;
		}
		else
		{
			// Here we try to increase iteration performance by deallocating a small unused group and allocating one larger group.
			// This also means that if remainder < min_block_capacity we don't have to allocate a min capacity group and then spread the difference over subsequent groups (see subsequent if block).
			// The smaller group is not deallocated immediately so that, in the event that an exception is triggered when allocating the larger group, we don't end up with lower capacity than before reserve().

			if (unused_groups_head != nullptr && max_block_capacity - remainder >= min_block_capacity)
			{
				deallocatable_group = unused_groups_head;
				group_pointer_type prev_unused_group = nullptr;

				do
				{
					const skipfield_type current_capacity = deallocatable_group->capacity;

					// If there exists an unused group which's of low-enough capacity, deallocate that later and add it's capacity to the remainder group:
					if (std::numeric_limits<skipfield_type>::max() - current_capacity > remainder && /* <- to make sure we don't overflow in next line */
						max_block_capacity >= current_capacity + remainder)
					{
						remainder += current_capacity;
						const group_pointer_type next_group = deallocatable_group->next_group;

						if (prev_unused_group != nullptr)
						{
							prev_unused_group->next_group = next_group;
						}
						else
						{
						  	unused_groups_head = next_group;
						}

						break;
					}

					prev_unused_group = deallocatable_group;
					deallocatable_group = deallocatable_group->next_group;
				} while (deallocatable_group != nullptr);
			}


			if (remainder < min_block_capacity) // Implies we were unable to consolidate remainder with an existing unused group, in the if-block above
			{
				// Note: negative_remainder is used to take the difference between the minimum block capacity limit and the actual remainder, and spread this negative difference over subsequent blocks which are in the usual case at max capacity.
				negative_remainder = min_block_capacity - remainder;
				remainder = min_block_capacity;

	  			// This line checks to see - if we have to reduce the size of the max-capacity blocks to spread the negative_remainder out - whether even reducing the max blocks to min capacity will be enough to keep the capacity under max_size(). We add 1 for the initial (remainder) block. This guards against situations where, for example, the min/max limits are very similar so spreading the negative remainder out is less doable:
				if (max_size() - total_capacity < ((number_of_max_groups + 1) * min_block_capacity))
				{
					#ifdef PLF_EXCEPTIONS_SUPPORT
						throw std::length_error("Reserve cannot increase capacity to >= n without being > max_size() due to current capacity() and block capacity limits");
					#else
						std::terminate();
					#endif
				}
			}
		}


		group_pointer_type current_group, first_unused_group;

		if (begin_iterator.group_pointer == nullptr) // Most common scenario - uninitialized container
		{
			initialize(remainder);
			begin_iterator.group_pointer->size = 0; // Note: this is set to 1 by default in the initialize function (which is optimised for insert())

			if (number_of_max_groups == 0) return;

			// Make the first allocated unused group:
			const skipfield_type new_block_capacity = (max_block_capacity - negative_remainder < min_block_capacity) ? min_block_capacity : max_block_capacity - negative_remainder;
			negative_remainder -= max_block_capacity - new_block_capacity;
			first_unused_group = current_group = allocate_new_group(new_block_capacity, begin_iterator.group_pointer);
			--number_of_max_groups;
		}
		else // Non-empty hive, add first new unused group:
		{
			#ifdef PLF_EXCEPTIONS_SUPPORT
				try
				{
					first_unused_group = current_group = allocate_new_group(remainder, end_iterator.group_pointer);
				}
				catch (...)
				{
					if (deallocatable_group != nullptr) // roll back group removal
					{
						add_to_unused_groups_list(deallocatable_group);
					}
					throw;
				}
			#else
				first_unused_group = current_group = allocate_new_group(remainder, end_iterator.group_pointer);
			#endif

			// We've now successfully allocated another group which is guaranteed to be larger than this group, so capacity is larger than it was before reserve() was called even if the other allocations below trigger an exception, and we can deallocate the group:
			if (deallocatable_group != nullptr) deallocate_group_remove_capacity(deallocatable_group);
		}


		while (number_of_max_groups != 0)
		{
			const skipfield_type new_block_capacity = (max_block_capacity - negative_remainder < min_block_capacity) ? min_block_capacity : max_block_capacity - negative_remainder;
			negative_remainder -= max_block_capacity - new_block_capacity;

			#ifdef PLF_EXCEPTIONS_SUPPORT
				try
				{
					current_group->next_group = allocate_new_group(new_block_capacity, current_group);
				}
				catch (...)
				{
					current_group->next_group = unused_groups_head;
					unused_groups_head = first_unused_group;
					throw;
				}
			#else
				current_group->next_group = allocate_new_group(new_block_capacity, current_group);
			#endif

			current_group = current_group->next_group;
			--number_of_max_groups;
		}

		current_group->next_group = unused_groups_head;
		unused_groups_head = first_unused_group;
	}



private:

	template <bool is_const>
	hive_iterator<is_const> get_it(const pointer element_pointer) const noexcept
	{
		if (end_iterator.group_pointer != nullptr)
		{
			const aligned_pointer_type aligned_element_pointer = to_aligned_pointer(element_pointer);
			// Note: we start with checking the back group first, as it will be the largest group in most cases, so there's a statistically-higher chance of the element being within it.

			// Special case for back group in case the element was in a group which became empty and got moved to the unused_groups list or was deallocated, and then that memory was re-used (ie. it became the current back group). The following prevents the function from mistakenly returning an iterator which is beyond the back element of the hive:
			if (std::greater_equal()(aligned_element_pointer, to_aligned_pointer(end_iterator.group_pointer->elements)) && std::less()(aligned_element_pointer, end_iterator.element_pointer))
			{
				const skipfield_pointer_type skipfield_pointer = end_iterator.group_pointer->skipfield + (aligned_element_pointer - to_aligned_pointer(end_iterator.group_pointer->elements));
				return (*skipfield_pointer == 0) ? hive_iterator<is_const>(end_iterator.group_pointer, aligned_element_pointer, skipfield_pointer) : end_iterator;
			}

			// All other groups, if any exist:
			for (group_pointer_type current_group = end_iterator.group_pointer->previous_group; current_group != nullptr; current_group = current_group->previous_group)
			{
				if (std::greater_equal()(aligned_element_pointer, to_aligned_pointer(current_group->elements)) && std::less()(aligned_element_pointer, to_aligned_pointer(current_group->skipfield)))
				{
					const skipfield_pointer_type skipfield_pointer = current_group->skipfield + (aligned_element_pointer - to_aligned_pointer(current_group->elements));
					return (*skipfield_pointer == 0) ? hive_iterator<is_const>(current_group, aligned_element_pointer, skipfield_pointer) : end_iterator;
				}
			}
		}

		return end_iterator;
	}



public:

	iterator get_iterator(const pointer element_pointer) noexcept
	{
		return get_it<false>(element_pointer);
	}



	const_iterator get_iterator(const const_pointer element_pointer) const noexcept
	{
		return get_it<true>(const_cast<pointer>(element_pointer));
	}



	allocator_type get_allocator() const noexcept
	{
		return static_cast<allocator_type>(*this);
	}



private:

	void source_blocks_incompatible()
	{
		#ifdef PLF_EXCEPTIONS_SUPPORT
			throw std::length_error("A source memory block capacity is outside of the destination's minimum or maximum memory block capacity limits - please change either the source or the destination's min/max block capacity limits using reshape() before calling splice() in this case");
		#else
			std::terminate();
		#endif
	}



public:

	void splice(hive &source)
	{
		// Process: if there are unused memory spaces at the end of the current back group of the chain, convert them
		// to skipped elements and add the locations to the group's free list.
		// Then link the destination's groups to the source's groups and nullify the source.
		// If the source has more unused memory spaces in the back group than the destination, swap them before processing to reduce the number of locations added to a free list and also the number of jumps during iteration.

		assert(&source != this);

		if (source.total_size == 0) return;

		// Throw if incompatible block capacities found in source:
		if (source.min_block_capacity > max_block_capacity || source.max_block_capacity < min_block_capacity) // ie. source blocks cannot possibly fit within *this's block capacity limits
		{
			source_blocks_incompatible();
		}
		else if (source.min_block_capacity < min_block_capacity || source.max_block_capacity > max_block_capacity) // ie. source blocks may or may not fit
		{
			for (group_pointer_type current_group = source.begin_iterator.group_pointer; current_group != nullptr; current_group = current_group->next_group)
			{
				if (current_group->capacity < min_block_capacity || current_group->capacity > max_block_capacity)
				{
					source_blocks_incompatible();
				}
			}
		}


		if (total_size != 0)
		{
			// If there's more unused element locations in back memory block of destination than in back memory block of source, swap with source to reduce number of skipped elements during iteration:
			if ((to_aligned_pointer(end_iterator.group_pointer->skipfield) - end_iterator.element_pointer) > (to_aligned_pointer(source.end_iterator.group_pointer->skipfield) - source.end_iterator.element_pointer))
			{
				swap(source);
				// Swap back unused groups list and block capacity limits so that source and *this retain their original ones:
				std::swap(source.unused_groups_head, unused_groups_head);
				std::swap(source.min_block_capacity, min_block_capacity);
				std::swap(source.max_block_capacity, max_block_capacity);
			}


			// Add source list of groups-with-erasures to destination list of groups-with-erasures:
			if (source.erasure_groups_head != nullptr)
			{
				if (erasure_groups_head != nullptr)
				{
					group_pointer_type tail_group = erasure_groups_head;

					while (tail_group->erasures_list_next_group != nullptr)
					{
						tail_group = tail_group->erasures_list_next_group;
					}

					tail_group->erasures_list_next_group = source.erasure_groups_head;
					source.erasure_groups_head->erasures_list_previous_group = tail_group;
				}
				else
				{
					erasure_groups_head = source.erasure_groups_head;
				}
			}


			const skipfield_type distance_to_end = static_cast<skipfield_type>(to_aligned_pointer(end_iterator.group_pointer->skipfield) - end_iterator.element_pointer);

			if (distance_to_end != 0) // 0 == edge case
			{	 // Mark unused element memory locations from back group as skipped/erased:
				// Update skipfield:
				const skipfield_type previous_node_value = *(end_iterator.skipfield_pointer - 1);

				if (previous_node_value == 0) // no previous skipblock
				{
					*end_iterator.skipfield_pointer = distance_to_end;
					*(end_iterator.skipfield_pointer + distance_to_end - 1) = distance_to_end;

					if (distance_to_end > 2) // make erased middle nodes non-zero for get_iterator
					{
						std::memset(std::to_address(end_iterator.skipfield_pointer + 1), 1, sizeof(skipfield_type) * (distance_to_end - 2));
					}

					const skipfield_type index = static_cast<skipfield_type>(end_iterator.element_pointer - to_aligned_pointer(end_iterator.group_pointer->elements));

					if (end_iterator.group_pointer->free_list_head != std::numeric_limits<skipfield_type>::max()) // ie. if this group already has some erased elements
					{
						edit_free_list_next(to_aligned_pointer(end_iterator.group_pointer->elements) + end_iterator.group_pointer->free_list_head, index); // set prev free list head's 'next index' number to the index of the current element
					}
					else
					{
						add_to_groups_with_erasures_list(end_iterator.group_pointer);
					}

					edit_free_list_head(end_iterator.element_pointer, end_iterator.group_pointer->free_list_head);
					end_iterator.group_pointer->free_list_head = index;
				}
				else
				{ // update previous skipblock, no need to update free list:
					*(end_iterator.skipfield_pointer - previous_node_value) = *(end_iterator.skipfield_pointer + distance_to_end - 1) = static_cast<skipfield_type>(previous_node_value + distance_to_end);

					if (distance_to_end > 1) // make erased middle nodes non-zero for get_iterator
					{
						std::memset(std::to_address(end_iterator.skipfield_pointer), 1, sizeof(skipfield_type) * (distance_to_end - 1));
					}
				}
			}


			// Join the destination and source group chains:
			end_iterator.group_pointer->next_group = source.begin_iterator.group_pointer;
			source.begin_iterator.group_pointer->previous_group = end_iterator.group_pointer;

			// Update group numbers if necessary:
			if (source.begin_iterator.group_pointer->group_number <= end_iterator.group_pointer->group_number)
			{
				size_type source_group_count = 0;

				for (group_pointer_type current_group = source.begin_iterator.group_pointer; current_group != nullptr; current_group = current_group->next_group, ++source_group_count) {}

				if ((std::numeric_limits<size_type>::max() - end_iterator.group_pointer->group_number) >= source_group_count)
				{
					update_subsequent_group_numbers(end_iterator.group_pointer->group_number + 1u, source.begin_iterator.group_pointer);
				}
				else [[unlikely]]
				{
					reset_group_numbers();
				}
			}

			end_iterator = source.end_iterator;
			total_size += source.total_size;
			total_capacity += source.total_capacity;
		}
		else // If *this is empty():
		{
			// Preserve unused_groups_head and de-link so that destroy_all_data doesn't remove them:
			const group_pointer_type original_unused_groups = unused_groups_head;
			unused_groups_head = nullptr;
			destroy_all_data();
			unused_groups_head = original_unused_groups;

			// Move source data to *this:
			end_iterator = source.end_iterator;
			begin_iterator = source.begin_iterator;
			erasure_groups_head = source.erasure_groups_head;
			total_size = source.total_size;
			total_capacity = source.total_capacity;

			// Add capacity for unused groups back into *this:
			for (group_pointer_type current = original_unused_groups; current != nullptr; current = current->next_group)
			{
				total_capacity += current->capacity;
			}
		}


		// Reset source values:
		const group_pointer_type original_unused_groups_head = source.unused_groups_head; // grab value before it gets wiped
		source.blank(); // blank source before adding capacity from unused groups back in

		if (original_unused_groups_head != nullptr) // If there were unused groups in source, re-link them and remove their capacity count from *this while adding it to source:
		{
			size_type source_unused_groups_capacity = 0;

			// Count capacity in source unused_groups:
			for (group_pointer_type current = original_unused_groups_head; current != nullptr; current = current->next_group)
			{
				source_unused_groups_capacity += current->capacity;
			}

			total_capacity -= source_unused_groups_capacity;
			source.total_capacity = source_unused_groups_capacity;

			// Establish first group from source unused_groups as first active group in source, link rest as reserved groups:
			source.unused_groups_head = original_unused_groups_head->next_group;
			source.begin_iterator.group_pointer = original_unused_groups_head;
			source.begin_iterator.element_pointer = to_aligned_pointer(original_unused_groups_head->elements);
			source.begin_iterator.skipfield_pointer = original_unused_groups_head->skipfield;
			source.end_iterator = source.begin_iterator;
			original_unused_groups_head->reset(0, nullptr, nullptr, 0);
		}
	}



	void splice(hive &&source)
	{
		splice(std::move(source));
	}



private:

	struct item_index_tuple
	{
		pointer original_location;
		size_type original_index;

		item_index_tuple(const pointer _item, const size_type _index) noexcept:
			original_location(_item),
			original_index(_index)
		{}
	};



	template <class comparison_function>
	struct sort_dereferencer
	{
		comparison_function stored_instance;

		explicit sort_dereferencer(const comparison_function &function_instance):
			stored_instance(function_instance)
		{}

		bool operator() (const item_index_tuple first, const item_index_tuple second)
		{
			return stored_instance(*(first.original_location), *(second.original_location));
		}
	};



	// Try and find space in the unused blocks or the back block instead of allocating for sort:
	template <class the_type>
	aligned_pointer_type get_free_space() const noexcept
	{
		const size_type number_of_elements_needed = ((total_size * sizeof(the_type)) + sizeof(aligned_element_struct) - 1) / sizeof(aligned_element_struct); // rounding up

		if (number_of_elements_needed < max_block_capacity)
		{
			if (static_cast<size_type>(to_aligned_pointer(end_iterator.group_pointer->skipfield) - end_iterator.element_pointer) >= number_of_elements_needed)
			{ // there is enough space at the back of the back block
				return end_iterator.element_pointer;
			}

			for (group_pointer_type current = unused_groups_head; current != nullptr; current = current->next_group)
			{
				if (current->capacity >= number_of_elements_needed)
				{ // there is enough space in one of the unused blocks
					return to_aligned_pointer(current->elements);
				}
			}
		}

		return nullptr;
	}



public:

	template <class comparison_function = std::less<element_type>>
	void sort(comparison_function compare = comparison_function())
	{
		if (total_size < 2) return;

		if constexpr ((std::is_trivially_copyable<element_type>::value || std::is_move_assignable<element_type>::value) && sizeof(element_type) <= sizeof(pointer) * 2) // If element is <= 2 pointers, just copy to an array and sort that then copy back - consumes less memory and may be faster
		{
			pointer sort_array = pointer_cast<pointer>(get_free_space<element_type>());
			const bool need_to_allocate = (sort_array == nullptr);

			if (need_to_allocate)
			{
				sort_array = std::allocator_traits<allocator_type>::allocate(*this, total_size, end_iterator.skipfield_pointer);
			}

			const pointer end = sort_array + total_size;

			if constexpr (!std::is_trivially_copyable<element_type>::value && std::is_move_assignable<element_type>::value)
			{
				std::uninitialized_copy(std::make_move_iterator(begin_iterator), std::make_move_iterator(end_iterator), sort_array);
			}
			else
			{
				std::uninitialized_copy(begin_iterator, end_iterator, sort_array);
			}

			std::sort(sort_array, end, compare);

			if constexpr (!std::is_trivially_copyable<element_type>::value && std::is_move_assignable<element_type>::value)
			{
				std::copy(std::make_move_iterator(sort_array), std::make_move_iterator(end), begin_iterator);
			}
			else
			{
				std::copy(sort_array, end, begin_iterator);

				if constexpr (!std::is_trivially_destructible<element_type>::value)
				{
					for (pointer current = sort_array; current != end; ++current)
					{
						std::allocator_traits<allocator_type>::destroy(*this, current);
					}
				}
			}

			if (need_to_allocate)
			{
				std::allocator_traits<allocator_type>::deallocate(*this, sort_array, total_size);
			}
		}
 		else
		{
			item_index_tuple *sort_array = pointer_cast<item_index_tuple *>(get_free_space<item_index_tuple>());
			const bool need_to_allocate = (sort_array == nullptr);

			if (need_to_allocate)
			{
				sort_array = std::allocator_traits<tuple_allocator_type>::allocate(tuple_allocator, total_size, end_iterator.skipfield_pointer);
			}

			tuple_pointer_type tuple_pointer = sort_array;

			// Construct pointers to all elements in the sequence:
			size_type index = 0;

			for (iterator current_element = begin_iterator; current_element != end_iterator; ++current_element, ++tuple_pointer, ++index)
			{
				std::allocator_traits<tuple_allocator_type>::construct(tuple_allocator, tuple_pointer, &*current_element, index);
			}

			// Now, sort the pointers by the values they point to:
			std::sort(sort_array, tuple_pointer, sort_dereferencer<comparison_function>(compare));

			// Sort the actual elements via the tuple array:
			index = 0;

			for (tuple_pointer_type current_tuple = sort_array; current_tuple != tuple_pointer; ++current_tuple, ++index)
			{
				if (current_tuple->original_index != index)
				{
					element_type end_value = std::move(*(current_tuple->original_location));
					size_type destination_index = index;
					size_type source_index = current_tuple->original_index;

					do
					{
						*(sort_array[destination_index].original_location) = std::move(*(sort_array[source_index].original_location));
						destination_index = source_index;
						source_index = sort_array[destination_index].original_index;
						sort_array[destination_index].original_index = destination_index;
					} while (source_index != index);

					*(sort_array[destination_index].original_location) = std::move(end_value);
				}
			}

			if (need_to_allocate)
			{
				std::allocator_traits<tuple_allocator_type>::deallocate(tuple_allocator, sort_array, total_size);
			}
		}
	}




	template <class comparison_function = std::equal_to<element_type>>
	size_type unique(comparison_function compare = comparison_function())
	{
		if (total_size < 2) return 0;

		size_type count = 0;
		const const_iterator end = end_iterator;

		for(const_iterator current = begin_iterator, previous = begin_iterator; ++current != end; previous = current)
		{
			if (compare(*current, *previous))
			{
				const size_type original_count = ++count;
				const_iterator last = current;

				while(++last != end && compare(*last, *previous))
				{
					++count;
				}

				if (count != original_count)
				{
					current = erase(current, last); // optimised range-erase
				}
				else
				{
					current = erase(current);
				}

				if (last == end) break;
			}
		}

		return count;
	}




	void swap(hive &source) noexcept(std::allocator_traits<allocator_type>::propagate_on_container_swap::value || std::allocator_traits<allocator_type>::is_always_equal::value)
	{
		assert(&source != this);

		if constexpr (std::allocator_traits<allocator_type>::is_always_equal::value && std::is_trivially_copyable<group_pointer_type>::value) // if all pointer types are trivial we can just copy using memcpy - avoids constructors/destructors etc and is faster
		{
			char temp[sizeof(hive)];
			std::memcpy(&temp, static_cast<void *>(this), sizeof(hive));
			std::memcpy(static_cast<void *>(this), static_cast<void *>(&source), sizeof(hive));
			std::memcpy(static_cast<void *>(&source), &temp, sizeof(hive));
		}
		else if constexpr (std::is_move_assignable<group_pointer_type>::value && std::is_move_constructible<group_pointer_type>::value)
		{
			hive temp(std::move(source));
			source = std::move(*this);
			*this = std::move(temp);
		}
		else
		{
			// Otherwise, make the reads/writes as contiguous in memory as-possible:
			const iterator 					swap_end_iterator = end_iterator, swap_begin_iterator = begin_iterator;
			const group_pointer_type		swap_erasure_groups_head = erasure_groups_head, swap_unused_groups_head = unused_groups_head;
			const size_type					swap_total_size = total_size, swap_total_capacity = total_capacity;
			const skipfield_type 			swap_min_block_capacity = min_block_capacity, swap_max_block_capacity = max_block_capacity;

			end_iterator = source.end_iterator;
			begin_iterator = source.begin_iterator;
			erasure_groups_head = source.erasure_groups_head;
			unused_groups_head = source.unused_groups_head;
			total_size = source.total_size;
			total_capacity = source.total_capacity;
			min_block_capacity = source.min_block_capacity;
			max_block_capacity = source.max_block_capacity;

			source.end_iterator = swap_end_iterator;
			source.begin_iterator = swap_begin_iterator;
			source.erasure_groups_head = swap_erasure_groups_head;
			source.unused_groups_head = swap_unused_groups_head;
			source.total_size = swap_total_size;
			source.total_capacity = swap_total_capacity;
			source.min_block_capacity = swap_min_block_capacity;
			source.max_block_capacity = swap_max_block_capacity;

			if constexpr (std::allocator_traits<allocator_type>::propagate_on_container_swap::value && !std::allocator_traits<allocator_type>::is_always_equal::value)
			{
				std::swap(static_cast<allocator_type &>(source), static_cast<allocator_type &>(*this));

				// Reconstruct rebinds for swapped allocators:
				group_allocator = group_allocator_type(*this);
				aligned_struct_allocator = aligned_struct_allocator_type(*this);
				skipfield_allocator = skipfield_allocator_type(*this);
				tuple_allocator = tuple_allocator_type(*this);
				source.group_allocator = group_allocator_type(source);
				source.aligned_struct_allocator = aligned_struct_allocator_type(source);
				source.skipfield_allocator = skipfield_allocator_type(source);
				source.tuple_allocator = tuple_allocator_type(source);
			} // else: undefined behaviour, as per standard
		}
	}



	// Iterators:
	template <bool is_const>
	class hive_iterator
	{
	private:
		typedef typename hive::group_pointer_type 		group_pointer_type;
		typedef typename hive::aligned_pointer_type 		aligned_pointer_type;
		typedef typename hive::skipfield_pointer_type 	skipfield_pointer_type;

		group_pointer_type		group_pointer {nullptr};
		aligned_pointer_type 	element_pointer {nullptr};
		skipfield_pointer_type	skipfield_pointer {nullptr};

	public:
		struct hive_iterator_tag {};
		typedef std::bidirectional_iterator_tag		iterator_category;
		typedef std::bidirectional_iterator_tag		iterator_concept;
		typedef typename hive::value_type 			value_type;
		typedef typename hive::difference_type		difference_type;
		typedef hive_reverse_iterator<is_const> 	reverse_type;
		typedef typename std::conditional_t<is_const, typename hive::const_pointer, typename hive::pointer>		pointer;
		typedef typename std::conditional_t<is_const, typename hive::const_reference, typename hive::reference>	reference;

		friend class hive;
		friend reverse_iterator;
		friend const_reverse_iterator;

		template <hive_iterator_concept it_type, typename distance_type>
		friend void std::advance(it_type &it, const distance_type distance);

		template <hive_iterator_concept it_type>
		friend it_type std::next(it_type it, const typename std::iterator_traits<it_type>::difference_type distance);

		template <hive_iterator_concept it_type>
		friend it_type std::prev(it_type it, const typename std::iterator_traits<it_type>::difference_type distance);

		template <hive_iterator_concept it_type>
		friend typename std::iterator_traits<it_type>::difference_type std::distance(const it_type first, const it_type last);



		hive_iterator() noexcept = default;



		hive_iterator (const hive_iterator &source) noexcept = default;



		template <bool is_const_it = is_const, class = std::enable_if_t<is_const_it> >
		hive_iterator(const hive_iterator<false> &source) noexcept:
			group_pointer(source.group_pointer),
			element_pointer(source.element_pointer),
			skipfield_pointer(source.skipfield_pointer)
		{}



		hive_iterator(hive_iterator &&source) noexcept = default;



		template <bool is_const_it = is_const, class = std::enable_if_t<is_const_it> >
		hive_iterator(hive_iterator<false> &&source) noexcept:
			group_pointer(std::move(source.group_pointer)),
			element_pointer(std::move(source.element_pointer)),
			skipfield_pointer(std::move(source.skipfield_pointer))
		{}



		hive_iterator & operator = (const hive_iterator &source) noexcept = default;



		template <bool is_const_it = is_const, class = std::enable_if_t<is_const_it> >
		hive_iterator & operator = (const hive_iterator<false> &source) noexcept
		{
			group_pointer = source.group_pointer;
			element_pointer = source.element_pointer;
			skipfield_pointer = source.skipfield_pointer;
			return *this;
		}



		hive_iterator & operator = (hive_iterator &&source) noexcept = default;



		template <bool is_const_it = is_const, class = std::enable_if_t<is_const_it> >
		hive_iterator & operator = (hive_iterator<false> &&source) noexcept
		{
			group_pointer = std::move(source.group_pointer);
			element_pointer = std::move(source.element_pointer);
			skipfield_pointer = std::move(source.skipfield_pointer);
			return *this;
		}



		bool operator == (const hive_iterator &rh) const noexcept
		{
			return (element_pointer == rh.element_pointer);
		}



		bool operator == (const hive_iterator<!is_const> &rh) const noexcept
		{
			return (element_pointer == rh.element_pointer);
		}



		bool operator != (const hive_iterator &rh) const noexcept
		{
			return (element_pointer != rh.element_pointer);
		}



		bool operator != (const hive_iterator<!is_const> &rh) const noexcept
		{
			return (element_pointer != rh.element_pointer);
		}



		reference operator * () const // may cause exception with uninitialized iterator
		{
			return *pointer_cast<pointer>(element_pointer);
		}



		pointer operator -> () const
		{
			return pointer_cast<pointer>(element_pointer);
		}



		hive_iterator & operator ++ ()
		{
			assert(group_pointer != nullptr); // covers uninitialised hive_iterator
			skipfield_type skip = *(++skipfield_pointer);

			if ((element_pointer += static_cast<size_type>(skip) + 1u) == to_aligned_pointer(group_pointer->skipfield) && group_pointer->next_group != nullptr) // ie. beyond end of current memory block. Second condition allows iterator to reach end(), which may be 1 past end of block, if block has been fully used and another block is not allocated
			{
				group_pointer = group_pointer->next_group;
				const aligned_pointer_type elements = to_aligned_pointer(group_pointer->elements);
				const skipfield_pointer_type skipfield = group_pointer->skipfield;
				skip = *skipfield;
				element_pointer = elements + skip;
				skipfield_pointer = skipfield;
			}

			skipfield_pointer += skip;
			return *this;
		}



		hive_iterator operator ++(int)
		{
			const hive_iterator copy(*this);
			++*this;
			return copy;
		}



		hive_iterator & operator -- ()
		{
			assert(group_pointer != nullptr);

			if (--skipfield_pointer >= group_pointer->skipfield) // ie. not already at beginning of group prior to decrementation
			{
				element_pointer -= static_cast<size_type>(*skipfield_pointer) + 1u;
				if ((skipfield_pointer -= *skipfield_pointer) >= group_pointer->skipfield) return *this; // ie. skipfield jump value does not takes us beyond beginning of group
			}

			group_pointer = group_pointer->previous_group;
			const skipfield_pointer_type skipfield = group_pointer->skipfield + group_pointer->capacity - 1;
			const skipfield_type skip = *skipfield;
			element_pointer = (to_aligned_pointer(group_pointer->skipfield) - 1) - skip;
			skipfield_pointer = skipfield - skip;
			return *this;
		}



		hive_iterator operator -- (int)
		{
			const hive_iterator copy(*this);
			--*this;
			return copy;
		}



		// Less-than etc operators retained as GCC codegen synthesis from <=> is slower and bulkier for same operations:
		template <bool is_const_it>
		bool operator > (const hive_iterator<is_const_it> &rh) const noexcept
		{
			return ((group_pointer == rh.group_pointer) & std::greater()(element_pointer, rh.element_pointer)) ||
				(group_pointer != rh.group_pointer && group_pointer->group_number > rh.group_pointer->group_number);
		}



		template <bool is_const_it>
		bool operator < (const hive_iterator<is_const_it> &rh) const noexcept
		{
			return rh > *this;
		}



		template <bool is_const_it>
		bool operator >= (const hive_iterator<is_const_it> &rh) const noexcept
		{
			return !(rh > *this);
		}



		template <bool is_const_it>
		bool operator <= (const hive_iterator<is_const_it> &rh) const noexcept
		{
			return !(*this > rh);
		}



		template <bool is_const_it>
		std::strong_ordering operator <=> (const hive_iterator<is_const_it> &rh) const noexcept
		{
			return (element_pointer == rh.element_pointer) ? std::strong_ordering::equal : ((*this > rh) ? std::strong_ordering::greater : std::strong_ordering::less);
		}



	private:
		// Used by cend(), erase() etc:
		hive_iterator(const group_pointer_type group_p, const aligned_pointer_type element_p, const skipfield_pointer_type skipfield_p) noexcept:
			group_pointer(group_p),
			element_pointer(element_p),
			skipfield_pointer(skipfield_p)
		{}



		// Advance implementation:

		void advance(difference_type distance) // Cannot be noexcept due to the possibility of an uninitialized iterator
		{
			assert(group_pointer != nullptr); // covers uninitialized hive_iterator && empty group

			// Now, run code based on the nature of the distance type: negative, positive or 0:
			if (distance > 0) // ie. +=
			{
				// Code explanation:
				// For the initial state of the iterator, we don't know which elements have been erased before that element in that group.
				// So for the first group, we follow the following logic:
				// 1. If no elements have been erased in the group, we do simple pointer addition to progress, either to within the group (if the distance is small enough) or the end of the group and subtract from distance accordingly.
				// 2. If any of the first group's elements have been erased, we manually iterate, as we don't know whether the erased elements occur before or after the initial iterator position, and we subtract 1 from the distance amount each time we iterate. Iteration continues until either distance becomes 0, or we reach the end of the group.

				// For all subsequent groups, we follow this logic:
				// 1. If distance is larger than the total number of non-erased elements in a group, we skip that group and subtract the number of elements in that group from distance.
				// 2. If distance is smaller than the total number of non-erased elements in a group, then:
				//   a. If there are no erased elements in the group we simply add distance to group->elements to find the new location for the iterator.
				//   b. If there are erased elements in the group, we manually iterate and subtract 1 from distance on each iteration, until the new iterator location is found ie. distance = 0.

				// Note: incrementing element_pointer is avoided until necessary to avoid needless calculations.

				if (group_pointer->next_group == nullptr && element_pointer == to_aligned_pointer(group_pointer->skipfield)) return; // Check if we're already beyond back of final block

				// Special case for initial element pointer and initial group (we don't know how far into the group the element pointer is)
				if (element_pointer != to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield))	// ie. != first non-erased element in group - otherwise we skip this section and just treat the first block as we would an intermediary block
				{
					const difference_type distance_from_end = to_aligned_pointer(group_pointer->skipfield) - element_pointer;

					if (group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max()) // ie. if there are no erasures in the group
					{
						if (distance < distance_from_end)
						{
							element_pointer += distance;
							skipfield_pointer += distance;
							return;
						}
						else if (group_pointer->next_group == nullptr) // either we've reached end() or gone beyond it, so bound to back of block
						{
							element_pointer += distance_from_end;
							skipfield_pointer += distance_from_end;
							return;
						}
						else
						{
							distance -= distance_from_end;
						}
					}
					else
					{
						const skipfield_pointer_type endpoint = skipfield_pointer + distance_from_end;

						while(true)
						{
							skipfield_pointer += *++skipfield_pointer;
							--distance;

							if (skipfield_pointer == endpoint)
							{
								break;
							}
							else if (distance == 0)
							{
								element_pointer = to_aligned_pointer(group_pointer->elements) + (skipfield_pointer - group_pointer->skipfield);
								return;
							}
						}

						if (group_pointer->next_group == nullptr) // either we've reached end() or gone beyond it, so bound to end of block
						{
							element_pointer = to_aligned_pointer(group_pointer->skipfield);
							return;
						}
					}

					group_pointer = group_pointer->next_group;

					if (distance == 0)
					{
						element_pointer = to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield);
						skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);
						return;
					}
				}


				// Intermediary groups - at the start of this code block and the subsequent block, the position of the iterator is assumed to be the first non-erased element in the current group:
				while (static_cast<difference_type>(group_pointer->size) <= distance)
				{
					if (group_pointer->next_group == nullptr) // either we've reached end() or gone beyond it, so bound to end of block
					{
						element_pointer = to_aligned_pointer(group_pointer->skipfield);
						skipfield_pointer = group_pointer->skipfield + group_pointer->capacity;
						return;
					}
					else if ((distance -= group_pointer->size) == 0)
					{
						group_pointer = group_pointer->next_group;
						element_pointer = to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield);
						skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);
						return;
					}
					else
					{
						group_pointer = group_pointer->next_group;
					}
				}


				// Final group (if not already reached):
				if (group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max()) // No erasures in this group, use straight pointer addition
				{
					element_pointer = to_aligned_pointer(group_pointer->elements) + distance;
					skipfield_pointer = group_pointer->skipfield + distance;
				}
				else	 // We already know size > distance due to the intermediary group checks above - safe to ignore endpoint check condition while incrementing here:
				{
					skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);

					do
					{
						skipfield_pointer += *++skipfield_pointer;
					} while(--distance != 0);

					element_pointer = to_aligned_pointer(group_pointer->elements) + (skipfield_pointer - group_pointer->skipfield);
				}
			}
			else if (distance < 0)
			{
				// Code logic is very similar to += above
				if(group_pointer->previous_group == nullptr && element_pointer == to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield)) return; // check if we're already at begin()
				distance = -distance;

				// Special case for initial element pointer and initial group (we don't know how far into the group the element pointer is)
				if (element_pointer != to_aligned_pointer(group_pointer->skipfield)) // not currently at the back of a block
				{
					if (group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max()) // ie. no prior erasures have occurred in this group
					{
						const difference_type distance_from_beginning = static_cast<difference_type>(element_pointer - to_aligned_pointer(group_pointer->elements));

						if (distance <= distance_from_beginning)
						{
							element_pointer -= distance;
							skipfield_pointer -= distance;
							return;
						}
						else if (group_pointer->previous_group == nullptr) // ie. we've gone before begin(), so bound to begin()
						{
							element_pointer = to_aligned_pointer(group_pointer->elements);
							skipfield_pointer = group_pointer->skipfield;
							return;
						}
						else
						{
							distance -= distance_from_beginning;
						}
					}
					else
					{
						const skipfield_pointer_type beginning_point = group_pointer->skipfield + *(group_pointer->skipfield);

						while(skipfield_pointer != beginning_point)
						{
							skipfield_pointer -= *--skipfield_pointer;

							if (--distance == 0)
							{
								element_pointer = to_aligned_pointer(group_pointer->elements) + (skipfield_pointer - group_pointer->skipfield);
								return;
							}
						}

						if (group_pointer->previous_group == nullptr)
						{
							element_pointer = to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield); // This is first group, so bound to begin() (just in case final decrement took us before begin())
							skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);
							return;
						}
					}

					group_pointer = group_pointer->previous_group;
				}


				// Intermediary groups - at the start of this code block and the subsequent block, the position of the iterator is assumed to be either the first non-erased element in the next group over, or end():
				while(static_cast<difference_type>(group_pointer->size) < distance)
				{
					if (group_pointer->previous_group == nullptr) // we've gone beyond begin(), so bound to it
					{
						element_pointer = to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield);
						skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);
						return;
					}

					distance -= group_pointer->size;
					group_pointer = group_pointer->previous_group;
				}


				// Final group (if not already reached):
				if (static_cast<difference_type>(group_pointer->size) == distance) // go to front of group
				{
					element_pointer = to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield);
					skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);
				}
				else if (group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max()) // ie. no erased elements in this group
				{
					element_pointer = to_aligned_pointer(group_pointer->skipfield) - distance;
					skipfield_pointer = (group_pointer->skipfield + group_pointer->size) - distance;
				}
				else // ie. no more groups to traverse but there are erased elements in this group
				{
					skipfield_pointer = group_pointer->skipfield + (to_aligned_pointer(group_pointer->skipfield) - to_aligned_pointer(group_pointer->elements));

					do
					{
						skipfield_pointer -= *--skipfield_pointer;
					} while(--distance != 0);

					element_pointer = to_aligned_pointer(group_pointer->elements) + (skipfield_pointer - group_pointer->skipfield);
				}
			}
		}



		// distance implementation:

		difference_type distance(const hive_iterator &last) const
		{
			// Code logic:
			// If iterators are the same, return 0
			// If they are not pointing to elements in the same group, process the intermediate groups and add distances,
			// skipping manual incrementation in all but the initial and final groups.
			// In the initial and final groups, manual incrementation must be used to calculate distance, if there have been no prior erasures in those groups.
			// If there are no prior erasures in either of those groups, we can use pointer arithmetic to calculate the distances for those groups.

			assert(!(group_pointer == nullptr) && !(last.group_pointer == nullptr));  // Check that they are both initialized

			if (last.element_pointer == element_pointer) return 0;

			difference_type distance = 0;
			hive_iterator iterator1 = *this, iterator2 = last;

			if (iterator1.group_pointer != iterator2.group_pointer) // if not in same group, process intermediate groups
			{
				// Process initial group:
				if (iterator1.group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max()) // If no prior erasures have occured in this group we can do simple addition
				{
					distance += static_cast<difference_type>(to_aligned_pointer(iterator1.group_pointer->skipfield) - iterator1.element_pointer);
				}
				else if (iterator1.element_pointer == to_aligned_pointer(iterator1.group_pointer->elements) + *(iterator1.group_pointer->skipfield)) // ie. element is at start of group - rare case
				{
					distance += static_cast<difference_type>(iterator1.group_pointer->size);
				}
				else // Manually iterate to find distance to end of group:
				{
					const skipfield_pointer_type endpoint = iterator1.skipfield_pointer + (to_aligned_pointer(iterator1.group_pointer->skipfield) - iterator1.element_pointer);

					while (iterator1.skipfield_pointer != endpoint)
					{
						iterator1.skipfield_pointer += *++iterator1.skipfield_pointer;
						++distance;
					}
				}

				// Process all other intermediate groups:
				iterator1.group_pointer = iterator1.group_pointer->next_group;

				while (iterator1.group_pointer != iterator2.group_pointer)
				{
					distance += static_cast<difference_type>(iterator1.group_pointer->size);
					iterator1.group_pointer = iterator1.group_pointer->next_group;
				}

				iterator1.skipfield_pointer = iterator1.group_pointer->skipfield + *(iterator1.group_pointer->skipfield);
			}


			if (iterator2.group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max()) // ie. no erasures in this group, direct subtraction is possible
			{
				distance += iterator2.skipfield_pointer - iterator1.skipfield_pointer;
			}
 			else if (iterator1.element_pointer == to_aligned_pointer(iterator2.group_pointer->elements) + *(iterator2.group_pointer->skipfield) && iterator2.element_pointer + 1 + *(iterator2.skipfield_pointer + 1) == to_aligned_pointer(iterator2.group_pointer->skipfield)) // ie. if iterator1 is at beginning of block (have to check this in case first and last are in the same block to begin with) and iterator2 is last element in the block
			{
				distance += static_cast<difference_type>(iterator2.group_pointer->size) - 1;
			}
			else
			{
				while (iterator1.skipfield_pointer != iterator2.skipfield_pointer)
				{
					iterator1.skipfield_pointer += *++iterator1.skipfield_pointer;
					++distance;
				}
			}

			return distance;
		}
	}; // hive_iterator





	// Reverse iterators:

	template <bool is_const_r>
	class hive_reverse_iterator
	{
	private:
		typedef typename hive::group_pointer_type 		group_pointer_type;
		typedef typename hive::aligned_pointer_type 	aligned_pointer_type;
		typedef typename hive::skipfield_pointer_type 	skipfield_pointer_type;

	protected:
		iterator current;

	public:
		struct hive_iterator_tag {};
		typedef std::bidirectional_iterator_tag 	iterator_category;
		typedef std::bidirectional_iterator_tag 	iterator_concept;
		typedef iterator 							iterator_type;
		typedef typename hive::value_type 			value_type;
		typedef typename hive::difference_type		difference_type;
		typedef typename std::conditional_t<is_const_r, typename hive::const_pointer, typename hive::pointer>		pointer;
		typedef typename std::conditional_t<is_const_r, typename hive::const_reference, typename hive::reference>	reference;

		friend class hive;

		template <hive_iterator_concept it_type, typename distance_type>
		friend void std::advance(it_type &it, const distance_type distance);

		template <hive_iterator_concept it_type>
		friend it_type std::next(it_type it, const typename std::iterator_traits<it_type>::difference_type distance);

		template <hive_iterator_concept it_type>
		friend it_type std::prev(it_type it, const typename std::iterator_traits<it_type>::difference_type distance);

		template <hive_iterator_concept it_type>
		friend typename std::iterator_traits<it_type>::difference_type std::distance(const it_type first, const it_type last);



		hive_reverse_iterator () noexcept = default;


		hive_reverse_iterator (const hive_reverse_iterator &source) noexcept = default;


		template <bool is_const_rit = is_const_r, class = std::enable_if_t<is_const_rit> >
		hive_reverse_iterator (const hive_reverse_iterator<false> &source) noexcept:
			current(source.current)
		{}


		hive_reverse_iterator (const hive_iterator<is_const_r> &source) noexcept:
			current(source)
		{
			++(*this);
		}


		template <bool is_const_rit = is_const_r, class = std::enable_if_t<is_const_rit> >
		hive_reverse_iterator (const hive_iterator<false> &source) noexcept:
			current(source)
		{
			++(*this);
		}

      
		hive_reverse_iterator (hive_reverse_iterator &&source) noexcept = default;



		template <bool is_const_rit = is_const_r, class = std::enable_if_t<is_const_rit> >
		hive_reverse_iterator (hive_reverse_iterator<false> &&source) noexcept:
			current(std::move(source.current))
		{}



		hive_reverse_iterator& operator = (const hive_iterator<is_const_r> &source) noexcept
		{
			current = source;
			++(*this);
			return *this;
		}

      
		template <bool is_const_rit = is_const_r, class = std::enable_if_t<is_const_rit> >
		hive_reverse_iterator& operator = (const hive_iterator<false> &source) noexcept
		{
			current = source;
			++(*this);
			return *this;
		}

      
		hive_reverse_iterator& operator = (const hive_reverse_iterator &source) noexcept = default;


		template <bool is_const_rit = is_const_r, class = std::enable_if_t<is_const_rit> >
		hive_reverse_iterator& operator = (const hive_reverse_iterator<false> &source) noexcept
		{
			current = source.current;
			return *this;
		}


		hive_reverse_iterator& operator = (hive_reverse_iterator &&source) noexcept = default;


		template <bool is_const_rit = is_const_r, class = std::enable_if_t<is_const_rit> >
		hive_reverse_iterator& operator = (hive_reverse_iterator<false> &&source) noexcept
		{
			assert(&source != this);
			current = std::move(source.current);
			return *this;
		}



		bool operator == (const hive_reverse_iterator &rh) const noexcept
		{
			return (current == rh.current);
		}



		bool operator == (const hive_reverse_iterator<!is_const_r> &rh) const noexcept
		{
			return (current == rh.current);
		}



		bool operator != (const hive_reverse_iterator &rh) const noexcept
		{
			return (current != rh.current);
		}



		bool operator != (const hive_reverse_iterator<!is_const_r> &rh) const noexcept
		{
			return (current != rh.current);
		}



		reference operator * () const noexcept
		{
			return *pointer_cast<pointer>(current.element_pointer);
		}



		pointer operator -> () const noexcept
		{
			return pointer_cast<pointer>(current.element_pointer);
		}



		// In this case we have to redefine the algorithm, rather than using the internal iterator's -- operator, in order for the reverse_iterator to be allowed to reach rend() ie. begin_iterator - 1
		hive_reverse_iterator & operator ++ ()
		{
			group_pointer_type &group_pointer = current.group_pointer;
			aligned_pointer_type &element_pointer = current.element_pointer;
			skipfield_pointer_type &skipfield_pointer = current.skipfield_pointer;

			assert(group_pointer != nullptr);

			if (--skipfield_pointer >= group_pointer->skipfield)
			{
				element_pointer -= static_cast<size_type>(*skipfield_pointer) + 1u;
				if ((skipfield_pointer -= *skipfield_pointer) >= group_pointer->skipfield) return *this;
			}

			if (group_pointer->previous_group != nullptr)
			{
				group_pointer = group_pointer->previous_group;
				const skipfield_pointer_type skipfield = group_pointer->skipfield + group_pointer->capacity - 1;
				const skipfield_type skip = *skipfield;
				element_pointer = (to_aligned_pointer(group_pointer->skipfield) - 1) - skip;
				skipfield_pointer = skipfield - skip;
			}
			else // bound to rend()
			{
				--element_pointer;
			}

			return *this;
		}



		hive_reverse_iterator operator ++ (int)
		{
			const hive_reverse_iterator copy(*this);
			++*this;
			return copy;
		}



		hive_reverse_iterator & operator -- ()
		{
			++current;
			return *this;
		}



		hive_reverse_iterator operator -- (int)
		{
			const hive_reverse_iterator copy(*this);
			++current;
			return copy;
		}



		hive_iterator<is_const_r> base() const noexcept
		{
			return (current.group_pointer != nullptr) ? ++(hive_iterator<is_const_r>(current)) : hive_iterator<is_const_r>(nullptr, nullptr, nullptr);
		}



		template <bool is_const_it>
		bool operator > (const hive_reverse_iterator<is_const_it> &rh) const noexcept
		{
			return (rh.current > current);
		}



		template <bool is_const_it>
		bool operator < (const hive_reverse_iterator<is_const_it> &rh) const noexcept
		{
			return (current > rh.current);
		}



		template <bool is_const_it>
		bool operator >= (const hive_reverse_iterator<is_const_it> &rh) const noexcept
		{
			return !(current > rh.current);
		}



		template <bool is_const_it>
		bool operator <= (const hive_reverse_iterator<is_const_it> &rh) const noexcept
		{
			return !(rh.current > current);
		}



		template <bool is_const_it>
		std::strong_ordering operator <=> (const hive_reverse_iterator<is_const_it> &rh) const noexcept
		{
			return (rh.current <=> current);
		}



	private:
		// Used by rend(), etc:
		hive_reverse_iterator(const group_pointer_type group_p, const aligned_pointer_type element_p, const skipfield_pointer_type skipfield_p) noexcept: current(group_p, element_p, skipfield_p) {}



		// distance implementation:

 		difference_type distance(const hive_reverse_iterator &last) const
 		{
 			return last.current.distance(current);
 		}



		// Advance for reverse_iterator and const_reverse_iterator - this needs to be implemented slightly differently to forward-iterator's advance, as current needs to be able to reach rend() (ie. begin() - 1) and to be bounded by rbegin():
		void advance(difference_type distance)
		{
			group_pointer_type &group_pointer = current.group_pointer;
			aligned_pointer_type &element_pointer = current.element_pointer;
			skipfield_pointer_type &skipfield_pointer = current.skipfield_pointer;

			assert(element_pointer != nullptr);

			if (distance > 0)
			{
				if (group_pointer->previous_group == nullptr && element_pointer == to_aligned_pointer(group_pointer->elements) - 1) return; // Check if we're already at rend()

				if (group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max())
				{
					const difference_type distance_from_beginning = element_pointer - to_aligned_pointer(group_pointer->elements);

					if (distance <= distance_from_beginning)
					{
						element_pointer -= distance;
						skipfield_pointer -= distance;
						return;
					}
					else if (group_pointer->previous_group == nullptr) // Either we've reached rend() or gone beyond it, so bound to rend()
					{
						element_pointer = to_aligned_pointer(group_pointer->elements) - 1;
						skipfield_pointer = group_pointer->skipfield - 1;
						return;
					}
					else
					{
						distance -= distance_from_beginning;
					}
				}
				else
				{
					const skipfield_pointer_type beginning_point = group_pointer->skipfield + *(group_pointer->skipfield);

					while(skipfield_pointer != beginning_point)
					{
						skipfield_pointer -= *--skipfield_pointer;

						if (--distance == 0)
						{
							element_pointer = to_aligned_pointer(group_pointer->elements) + (skipfield_pointer - group_pointer->skipfield);
							return;
						}
					}

					if (group_pointer->previous_group == nullptr)
					{
						element_pointer = to_aligned_pointer(group_pointer->elements) - 1; // If we've reached rend(), bound to that
						skipfield_pointer = group_pointer->skipfield - 1;
						return;
					}
				}

				group_pointer = group_pointer->previous_group;


				// Intermediary groups - at the start of this code block and the subsequent block, the position of the iterator is assumed to be the first non-erased element in the next group:
				while(static_cast<difference_type>(group_pointer->size) < distance)
				{
					if (group_pointer->previous_group == nullptr) // bound to rend()
					{
						element_pointer = to_aligned_pointer(group_pointer->elements) - 1;
						skipfield_pointer = group_pointer->skipfield - 1;
						return;
					}

					distance -= static_cast<difference_type>(group_pointer->size);
					group_pointer = group_pointer->previous_group;
				}


				// Final group (if not already reached)
				if (static_cast<difference_type>(group_pointer->size) == distance)
				{
					element_pointer = to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield);
					skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);
					return;
				}
				else if (group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max())
				{
					element_pointer = (to_aligned_pointer(group_pointer->elements) + group_pointer->size) - distance;
					skipfield_pointer = (group_pointer->skipfield + group_pointer->size) - distance;
					return;
				}
				else
				{
					skipfield_pointer = group_pointer->skipfield + group_pointer->capacity;

					do
					{
						skipfield_pointer -= *--skipfield_pointer;
					} while(--distance != 0);

					element_pointer = to_aligned_pointer(group_pointer->elements) + (skipfield_pointer - group_pointer->skipfield);
					return;
				}
			}
			else if (distance < 0)
			{
				if (group_pointer->next_group == nullptr && (element_pointer == (to_aligned_pointer(group_pointer->skipfield) - 1) - *(group_pointer->skipfield + (to_aligned_pointer(group_pointer->skipfield) - to_aligned_pointer(group_pointer->elements)) - 1))) // Check if we're already at rbegin()
				{
					return;
				}

				if (element_pointer != to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield)) // ie. != first non-erased element in group
				{
					if (group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max()) // ie. if there are no erasures in the group
					{
						const difference_type distance_from_end = to_aligned_pointer(group_pointer->skipfield) - element_pointer;

						if (distance < distance_from_end)
						{
							element_pointer += distance;
							skipfield_pointer += distance;
							return;
						}
						else if (group_pointer->next_group == nullptr) // either we've reached end() or gone beyond it, so bound to back of block
						{
							element_pointer += distance_from_end - 1;
							skipfield_pointer += distance_from_end - 1;
							return;
						}
						else
						{
							distance -= distance_from_end;
						}
					}
					else
					{
						const skipfield_pointer_type endpoint = skipfield_pointer + (to_aligned_pointer(group_pointer->skipfield) - element_pointer);

						while(true)
						{
							skipfield_pointer += *++skipfield_pointer;
							--distance;

							if (skipfield_pointer == endpoint)
							{
								break;
							}
							else if (distance == 0)
							{
								element_pointer = to_aligned_pointer(group_pointer->elements) + (skipfield_pointer - group_pointer->skipfield);
								return;
							}
						}

						if (group_pointer->next_group == nullptr) return;
					}

					group_pointer = group_pointer->next_group;

					if (distance == 0)
					{
						element_pointer = to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield);
						skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);
						return;
					}
				}


				// Intermediary groups:
				while(static_cast<difference_type>(group_pointer->size) <= distance)
				{
					if (group_pointer->next_group == nullptr) // bound to last element slot in block
					{
						skipfield_pointer = group_pointer->skipfield + group_pointer->capacity - 1;
						element_pointer = (to_aligned_pointer(group_pointer->skipfield) - 1) - *skipfield_pointer;
						skipfield_pointer -= *skipfield_pointer;
						return;
					}
					else if ((distance -= group_pointer->size) == 0)
					{
						group_pointer = group_pointer->next_group;
						element_pointer = to_aligned_pointer(group_pointer->elements) + *(group_pointer->skipfield);
						skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);
						return;
					}
					else
					{
						group_pointer = group_pointer->next_group;
					}
				}


				// Final group (if not already reached):
				if (group_pointer->free_list_head == std::numeric_limits<skipfield_type>::max())
				{
					element_pointer = to_aligned_pointer(group_pointer->elements) + distance;
					skipfield_pointer = group_pointer->skipfield + distance;
					return;
				}
				else // we already know size > distance from previous loop - so it's safe to ignore endpoint check condition while incrementing:
				{
					skipfield_pointer = group_pointer->skipfield + *(group_pointer->skipfield);

					do
					{
						skipfield_pointer += *++skipfield_pointer;
					} while(--distance != 0);

					element_pointer = to_aligned_pointer(group_pointer->elements) + (skipfield_pointer - group_pointer->skipfield);
					return;
				}

				return;
			}
		}

	}; // hive_reverse_iterator


}; // hive



// Used by std::erase_if() overload below:
template<class element_type>
struct hive_eq_to
{
	const element_type &value;

	explicit hive_eq_to(const element_type &store_value) noexcept:
		value(store_value)
	{}

	bool operator() (const element_type &compare_value) const noexcept
	{
		return value == compare_value;
	}
};



} // plf namespace




namespace std
{

	template <class element_type, class allocator_type>
	void swap (plf::hive<element_type, allocator_type> &a, plf::hive<element_type, allocator_type> &b) noexcept(std::allocator_traits<allocator_type>::propagate_on_container_swap::value || std::allocator_traits<allocator_type>::is_always_equal::value)
	{
		a.swap(b);
	}



	template <class element_type, class allocator_type, class predicate_function>
	typename plf::hive<element_type, allocator_type>::size_type erase_if(plf::hive<element_type, allocator_type> &container, predicate_function predicate)
	{
		typedef typename plf::hive<element_type, allocator_type> hive;
		typedef typename hive::const_iterator 	const_iterator;
		typedef typename hive::size_type 		size_type;
		size_type count = 0;
		const const_iterator end = container.cend();

		for (const_iterator current = container.cbegin(); current != end; ++current)
		{
			if (predicate(*current))
			{
				const size_type original_count = ++count;
				const_iterator last = current;

				while(++last != end && predicate(*last))
				{
					++count;
				}

				if (count != original_count)
				{
					current = container.erase(current, last); // optimised range-erase
				}
				else
				{
					current = container.erase(current);
				}

				if (last == end) break;
			}
		}

		return count;
	}



	template <class element_type, class allocator_type>
	typename plf::hive<element_type, allocator_type>::size_type erase(plf::hive<element_type, allocator_type> &container, const element_type &value)
	{
		return erase_if(container, plf::hive_eq_to<element_type>(value));
	}



	// std::reverse_iterator overload, to allow use of hive with ranges and make_reverse_iterator primarily:
	template <plf::hive_iterator_concept it_type>
	class reverse_iterator<it_type> : public it_type::reverse_type
	{
	public:
		typedef typename it_type::reverse_type rit;
		using rit::rit;
	};

} // namespace std


#undef PLF_EXCEPTIONS_SUPPORT

#if defined(_MSC_VER) && !defined(__clang__) && !defined(__GNUC__)
	#pragma warning ( pop )
#endif

#endif // PLF_HIVE_H
