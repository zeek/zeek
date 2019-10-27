// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <type_traits>
#include <utility>

// These forward declarations only exist to enable ADL for the Ref and Unref
// functions.

struct IntrusivePtrDummy;

void Ref(IntrusivePtrDummy*);

void Unref(IntrusivePtrDummy*);

// An intrusive, reference counting smart pointer implementation.
template <class T>
class IntrusivePtr {
public:
	// -- member types

	using pointer = T*;

	using const_pointer = const T*;

	using element_type = T;

	using reference = T&;

	using const_reference = const T&;

	// -- constructors, destructors, and assignment operators

	constexpr IntrusivePtr() noexcept : ptr_(nullptr)
		{
		// nop
		}

	constexpr IntrusivePtr(std::nullptr_t) noexcept : IntrusivePtr()
		{
		// nop
		}

	IntrusivePtr(pointer raw_ptr, bool add_ref) noexcept
		{
		setPtr(raw_ptr, add_ref);
		}

	IntrusivePtr(IntrusivePtr&& other) noexcept : ptr_(other.detach())
		{
		// nop
		}

	IntrusivePtr(const IntrusivePtr& other) noexcept
		{
		setPtr(other.get(), true);
		}

	template <class U, class = std::enable_if_t<std::is_convertible_v<U*, T*>>>
	IntrusivePtr(IntrusivePtr<U> other) noexcept : ptr_(other.detach())
		{
		// nop
		}

	~IntrusivePtr()
		{
		if (ptr_)
			Unref(ptr_);
		}

	void swap(IntrusivePtr& other) noexcept
		{
		std::swap(ptr_, other.ptr_);
		}

	// Returns the raw pointer without modifying the reference count and sets
	// this to `nullptr`.
	pointer release() noexcept
		{
		auto result = ptr_;
		if (result)
			ptr_ = nullptr;
		return result;
		}

	void reset(pointer new_value = nullptr, bool add_ref = true) noexcept
		{
		auto old = ptr_;
		setPtr(new_value, add_ref);
		if (old)
			Unref(old);
		}

	IntrusivePtr& operator=(IntrusivePtr other) noexcept
		{
		swap(other);
		return *this;
		}

	pointer get() const noexcept
		{
		return ptr_;
		}

	pointer operator->() const noexcept
		{
		return ptr_;
		}

	reference operator*() const noexcept
		{
		return *ptr_;
		}

	bool operator!() const noexcept
		{
		return !ptr_;
		}

	explicit operator bool() const noexcept
		{
		return ptr_ != nullptr;
		}

private:
	void setPtr(pointer raw_ptr, bool add_ref) noexcept
		{
		ptr_ = raw_ptr;
		if ( raw_ptr && add_ref )
			Ref(raw_ptr);
		}

	pointer ptr_;
};

// Convenience function for creating intrusive pointers.
template <class T, class... Ts>
IntrusivePtr<T> makeCounted(Ts&&... args)
	{
	// Assumes that objects start with a reference count of 1!
	return {new T(std::forward<Ts>(args)...), false};
	}

// -- comparison to nullptr ----------------------------------------------------

template <class T>
bool operator==(const IntrusivePtr<T>& x, std::nullptr_t) {
  return !x;
}

template <class T>
bool operator==(std::nullptr_t, const IntrusivePtr<T>& x) {
  return !x;
}

template <class T>
bool operator!=(const IntrusivePtr<T>& x, std::nullptr_t) {
  return static_cast<bool>(x);
}

template <class T>
bool operator!=(std::nullptr_t, const IntrusivePtr<T>& x) {
  return static_cast<bool>(x);
}

// -- comparison to raw pointer ------------------------------------------------

template <class T>
bool operator==(const IntrusivePtr<T>& x, const T* y) {
  return x.get() == y;
}

template <class T>
bool operator==(const T* x, const IntrusivePtr<T>& y) {
  return x == y.get();
}

template <class T>
bool operator!=(const IntrusivePtr<T>& x, const T* y) {
  return x.get() != y;
}

template <class T>
bool operator!=(const T* x, const IntrusivePtr<T>& y) {
  return x != y.get();
}

template <class T>
bool operator<(const IntrusivePtr<T>& x, const T* y)
	{
	return x.get() < y;
	}

template <class T>
bool operator<(const T* x, const IntrusivePtr<T>& y)
	{
	return x < y.get();
	}

// -- comparison to intrusive pointer ------------------------------------------

// Using trailing return type and decltype() here removes this function from
// overload resolution if the two pointers types are not comparable (SFINAE).
template <class T, class U>
auto operator==(const IntrusivePtr<T>& x, const IntrusivePtr<U>& y)
-> decltype(x.get() == y.get())
	{
	return x.get() == y.get();
	}

template <class T, class U>
auto operator!=(const IntrusivePtr<T>& x, const IntrusivePtr<U>& y)
-> decltype(x.get() != y.get())
	{
	return x.get() != y.get();
	}

template <class T>
auto operator<(const IntrusivePtr<T>& x, const IntrusivePtr<T>& y)
-> decltype(x.get() < y.get())
	{
	return x.get() < y.get();
	}

