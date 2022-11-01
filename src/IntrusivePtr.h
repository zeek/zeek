// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <functional>
#include <type_traits>
#include <utility>

#include "Obj.h"

namespace zeek
	{

/**
 * A tag class for the #IntrusivePtr constructor which means: adopt
 * the reference from the caller.
 */
struct AdoptRef
	{
	};

/**
 * A tag class for the #IntrusivePtr constructor which means: create a
 * new reference to the object.
 */
struct NewRef
	{
	};

/**
 * This has to be forward declared and known here in order for us to be able
 * cast this in the `Unref` function.
 */
class OpaqueVal;

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
 * but most notably is designed to work with @c Obj and its subtypes.
 *
 * The same object may get managed via @c IntrusivePtr in one part of the
 * code base while another part of the program manages it manually by passing
 * raw pointers and calling @c Ref and @c Unref explicitly. However, new code
 * should use a smart pointer whenever possible to reduce boilerplate code and
 * increase robustness of the code (in particular w.r.t. exceptions).
 */
template <class T> class IntrusivePtr
	{
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
	 *
	 * This overload adopts the existing reference from the caller.
	 *
	 * @param raw_ptr Pointer to the shared object.
	 */
	constexpr IntrusivePtr(AdoptRef, pointer raw_ptr) noexcept : ptr_(raw_ptr) { }

	/**
	 * Constructs a new intrusive pointer for managing the lifetime of the object
	 * pointed to by @c raw_ptr.
	 *
	 * This overload adds a new reference.
	 *
	 * @param raw_ptr Pointer to the shared object.
	 */
	IntrusivePtr(NewRef, pointer raw_ptr) noexcept : ptr_(raw_ptr)
		{
		if ( ptr_ )
			Ref(ptr_);
		}

	IntrusivePtr(IntrusivePtr&& other) noexcept : ptr_(other.release())
		{
		// nop
		}

	IntrusivePtr(const IntrusivePtr& other) noexcept : IntrusivePtr(NewRef{}, other.get()) { }

	template <class U, class = std::enable_if_t<std::is_convertible_v<U*, T*>>>
	IntrusivePtr(IntrusivePtr<U> other) noexcept : ptr_(other.release())
		{
		// nop
		}

	~IntrusivePtr()
		{
		if ( ptr_ )
			{
			// Specializing `OpaqueVal` as MSVC compiler does not detect it
			// inheriting from `zeek::Obj` so we have to do that manually.
			if constexpr ( std::is_same_v<T, OpaqueVal> )
				Unref(reinterpret_cast<zeek::Obj*>(ptr_));
			else
				Unref(ptr_);
			}
		}

	void swap(IntrusivePtr& other) noexcept { std::swap(ptr_, other.ptr_); }

	friend void swap(IntrusivePtr& a, IntrusivePtr& b) noexcept
		{
		using std::swap;
		swap(a.ptr_, b.ptr_);
		}

	/**
	 * Detaches an object from the automated lifetime management and sets this
	 * intrusive pointer to @c nullptr.
	 * @returns the raw pointer without modifying the reference count.
	 */
	pointer release() noexcept { return std::exchange(ptr_, nullptr); }

	IntrusivePtr& operator=(const IntrusivePtr& other) noexcept
		{
		IntrusivePtr tmp{other};
		swap(tmp);
		return *this;
		}

	IntrusivePtr& operator=(IntrusivePtr&& other) noexcept
		{
		swap(other);
		return *this;
		}

	IntrusivePtr& operator=(std::nullptr_t) noexcept
		{
		if ( ptr_ )
			{
			Unref(ptr_);
			ptr_ = nullptr;
			}
		return *this;
		}

	pointer get() const noexcept { return ptr_; }

	pointer operator->() const noexcept { return ptr_; }

	reference operator*() const noexcept { return *ptr_; }

	bool operator!() const noexcept { return ! ptr_; }

	explicit operator bool() const noexcept { return ptr_ != nullptr; }

private:
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
template <class T, class... Ts> IntrusivePtr<T> make_intrusive(Ts&&... args)
	{
	// Assumes that objects start with a reference count of 1!
	return {AdoptRef{}, new T(std::forward<Ts>(args)...)};
	}

/**
 * Casts an @c IntrusivePtr object to another by way of static_cast on
 * the underlying pointer.
 * @param p  The pointer of type @c U to cast to another type, @c T.
 * @return  The pointer, as cast to type @c T.
 */
template <class T, class U> IntrusivePtr<T> cast_intrusive(IntrusivePtr<U> p) noexcept
	{
	return {AdoptRef{}, static_cast<T*>(p.release())};
	}

// -- comparison to nullptr ----------------------------------------------------

/**
 * @relates IntrusivePtr
 */
template <class T> bool operator==(const zeek::IntrusivePtr<T>& x, std::nullptr_t)
	{
	return ! x;
	}

/**
 * @relates IntrusivePtr
 */
template <class T> bool operator==(std::nullptr_t, const zeek::IntrusivePtr<T>& x)
	{
	return ! x;
	}

/**
 * @relates IntrusivePtr
 */
template <class T> bool operator!=(const zeek::IntrusivePtr<T>& x, std::nullptr_t)
	{
	return static_cast<bool>(x);
	}

/**
 * @relates IntrusivePtr
 */
template <class T> bool operator!=(std::nullptr_t, const zeek::IntrusivePtr<T>& x)
	{
	return static_cast<bool>(x);
	}

// -- comparison to raw pointer ------------------------------------------------

/**
 * @relates IntrusivePtr
 */
template <class T> bool operator==(const zeek::IntrusivePtr<T>& x, const T* y)
	{
	return x.get() == y;
	}

/**
 * @relates IntrusivePtr
 */
template <class T> bool operator==(const T* x, const zeek::IntrusivePtr<T>& y)
	{
	return x == y.get();
	}

/**
 * @relates IntrusivePtr
 */
template <class T> bool operator!=(const zeek::IntrusivePtr<T>& x, const T* y)
	{
	return x.get() != y;
	}

/**
 * @relates IntrusivePtr
 */
template <class T> bool operator!=(const T* x, const zeek::IntrusivePtr<T>& y)
	{
	return x != y.get();
	}

// -- comparison to intrusive pointer ------------------------------------------

// Using trailing return type and decltype() here removes this function from
// overload resolution if the two pointers types are not comparable (SFINAE).

/**
 * @relates IntrusivePtr
 */
template <class T, class U>
auto operator==(const zeek::IntrusivePtr<T>& x, const zeek::IntrusivePtr<U>& y)
	-> decltype(x.get() == y.get())
	{
	return x.get() == y.get();
	}

/**
 * @relates IntrusivePtr
 */
template <class T, class U>
auto operator!=(const zeek::IntrusivePtr<T>& x, const zeek::IntrusivePtr<U>& y)
	-> decltype(x.get() != y.get())
	{
	return x.get() != y.get();
	}

	} // namespace zeek

// -- hashing ------------------------------------------------

namespace std
	{
template <class T> struct hash<zeek::IntrusivePtr<T>>
	{
	// Hash of intrusive pointer is the same as hash of the raw pointer it holds.
	size_t operator()(const zeek::IntrusivePtr<T>& v) const noexcept
		{
		return std::hash<T*>{}(v.get());
		}
	};
	}
