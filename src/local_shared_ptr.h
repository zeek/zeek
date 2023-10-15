#pragma once

#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared_object.hpp>

namespace zeek::detail
	{
template <class T> using local_shared_ptr = boost::local_shared_ptr<T>;

template <class T, class... Args> local_shared_ptr<T> make_local_shared(Args&&... args)
	{
	T* obj = new T(std::forward<Args>(args)...);
	return local_shared_ptr<T>(obj);
	// return boost::make_local_shared<T>(std::forward<Args>(args)...);
	}

	}
