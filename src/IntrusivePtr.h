// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <type_traits>
#include <utility>

/**
 * An intrusive, reference counting smart pointer implementation. Much like
 * @c std::shared_ptr, this smart pointer models shared ownership of an object
 * through a pointer. Several @c IntrusivePtr instances may point to the same
 * object.
 *
 * The @c IntrusivePtr requires two free functions associated to @c T that must
 * be available via argument-dependent lookup: @c Ref and @c Unref. The former
 * increments the reference by one whenever a new owner participates in the
 * lifetime of the shared object and the latter decrements the reference count
 * by one. Once the reference count reaches zero, @c Unref also is responsible
 * for destroying the shared object.
 *
 * The @c IntrusivePtr works with any type that offers the two free functions,
 * but most notably is designed to work with @c BroObj and its subtypes.
 *
 * The same object may get managed via @c IntrusivePtr in one part of the
 * code base while another part of the program manages it manually by passing
 * raw pointers and calling @c Ref and @c Unref explicitly. However, new code
 * should use a smart pointer whenever possible to reduce boilerplate code and
 * increase robustness of the code (in particular w.r.t. exceptions).
 */
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

	constexpr IntrusivePtr() noexcept = default;

	constexpr IntrusivePtr(std::nullptr_t) noexcept : IntrusivePtr()
		{
		// nop
		}

	/**
	 * Constructs a new intrusive pointer for managing the lifetime of the object
	 * pointed to by @c raw_ptr.
	 * @param raw_ptr Pointer to the shared object.
	 * @param add_ref Denotes whether the reference count of the object shall be
	 *                increased during construction.
	 */
	IntrusivePtr(pointer raw_ptr, bool add_ref) noexcept
		{
		setPtr(raw_ptr, add_ref);
		}

	IntrusivePtr(IntrusivePtr&& other) noexcept : ptr_(other.release())
		{
		// nop
		}

	IntrusivePtr(const IntrusivePtr& other) noexcept
		{
		setPtr(other.get(), true);
		}

	template <class U, class = std::enable_if_t<std::is_convertible_v<U*, T*>>>
	IntrusivePtr(IntrusivePtr<U> other) noexcept : ptr_(other.release())
		{
		// nop
		}

	~IntrusivePtr()
		{
		if ( ptr_ )
			Unref(ptr_);
		}

	void swap(IntrusivePtr& other) noexcept
		{
		std::swap(ptr_, other.ptr_);
		}

	/**
	 * Detaches an object from the automated lifetime management and sets this
	 * intrusive pointer to @c nullptr.
	 * @returns the raw pointer without modifying the reference count.
	 */
	pointer release() noexcept
		{
		auto result = ptr_;
		if ( result )
			ptr_ = nullptr;
		return result;
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

	pointer ptr_ = nullptr;
};

/**
 * Convenience function for creating a reference counted object and wrapping it
 * into an intrusive pointers.
 * @param args Arguments for constructing the shared object of type @c T.
 * @returns an @c IntrusivePtr pointing to the new object.
 * @note This function assumes that any @c T starts with a reference count of 1.
 * @relates IntrusivePtr
 */
template <class T, class... Ts>
IntrusivePtr<T> make_intrusive(Ts&&... args)
	{
	// Assumes that objects start with a reference count of 1!
	return {new T(std::forward<Ts>(args)...), false};
	}

// -- comparison to nullptr ----------------------------------------------------

/**
 * @relates IntrusivePtr
 */
template <class T>
bool operator==(const IntrusivePtr<T>& x, std::nullptr_t) {
  return !x;
}

/**
 * @relates IntrusivePtr
 */
template <class T>
bool operator==(std::nullptr_t, const IntrusivePtr<T>& x) {
  return !x;
}

/**
 * @relates IntrusivePtr
 */
template <class T>
bool operator!=(const IntrusivePtr<T>& x, std::nullptr_t) {
  return static_cast<bool>(x);
}

/**
 * @relates IntrusivePtr
 */
template <class T>
bool operator!=(std::nullptr_t, const IntrusivePtr<T>& x) {
  return static_cast<bool>(x);
}

// -- comparison to raw pointer ------------------------------------------------

/**
 * @relates IntrusivePtr
 */
template <class T>
bool operator==(const IntrusivePtr<T>& x, const T* y) {
  return x.get() == y;
}

/**
 * @relates IntrusivePtr
 */
template <class T>
bool operator==(const T* x, const IntrusivePtr<T>& y) {
  return x == y.get();
}

/**
 * @relates IntrusivePtr
 */
template <class T>
bool operator!=(const IntrusivePtr<T>& x, const T* y) {
  return x.get() != y;
}

/**
 * @relates IntrusivePtr
 */
template <class T>
bool operator!=(const T* x, const IntrusivePtr<T>& y) {
  return x != y.get();
}

// -- comparison to intrusive pointer ------------------------------------------

// Using trailing return type and decltype() here removes this function from
// overload resolution if the two pointers types are not comparable (SFINAE).

/**
 * @relates IntrusivePtr
 */
template <class T, class U>
auto operator==(const IntrusivePtr<T>& x, const IntrusivePtr<U>& y)
-> decltype(x.get() == y.get())
	{
	return x.get() == y.get();
	}

/**
 * @relates IntrusivePtr
 */
template <class T, class U>
auto operator!=(const IntrusivePtr<T>& x, const IntrusivePtr<U>& y)
-> decltype(x.get() != y.get())
	{
	return x.get() != y.get();
	}

