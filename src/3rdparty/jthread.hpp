// Copied from https://github.com/josuttis/jthread,
// used under CC-BY-4.0.

// -----------------------------------------------------
// cooperative interruptable and joining thread:
// -----------------------------------------------------
#ifndef JTHREAD_HPP
#define JTHREAD_HPP

#include <functional> // for invoke()
#include <future>
#include <iostream> // for debugging output
#include <thread>
#include <type_traits>

#include "stop_token.hpp"

namespace nonstd {

//*****************************************
//* class jthread
//* - joining std::thread with signaling stop/end support
//*****************************************
class jthread {
public:
    //*****************************************
    //* standardized API:
    //*****************************************
    // - cover full API of std::thread
    //   to be able to switch from std::thread to std::jthread

    // types are those from std::thread:
    using id = ::std::thread::id;
    using native_handle_type = ::std::thread::native_handle_type;

    // construct/copy/destroy:
    jthread() noexcept;
    // template <typename F, typename... Args> explicit jthread(F&& f, Args&&... args);
    //  THE constructor that starts the thread:
    //  - NOTE: does SFINAE out copy constructor semantics
    template<typename Callable, typename... Args,
             typename = ::std::enable_if_t<! ::std::is_same_v<::std::decay_t<Callable>, jthread>>>
    explicit jthread(Callable&& cb, Args&&... args);
    ~jthread();

    jthread(const jthread&) = delete;
    jthread(jthread&&) noexcept = default;
    jthread& operator=(const jthread&) = delete;
    jthread& operator=(jthread&&) noexcept;

    // members:
    void swap(jthread&) noexcept;
    bool joinable() const noexcept;
    void join();
    void detach();

    id get_id() const noexcept;
    native_handle_type native_handle();

    // static members:
    static unsigned hardware_concurrency() noexcept { return ::std::thread::hardware_concurrency(); };

    //*****************************************
    // - supplementary API:
    //   - for the calling thread:
    [[nodiscard]] stop_source get_stop_source() noexcept;
    [[nodiscard]] stop_token get_stop_token() const noexcept;
    bool request_stop() noexcept { return get_stop_source().request_stop(); }


    //*****************************************
    //* implementation:
    //*****************************************

private:
    //*** API for the starting thread:
    stop_source _stopSource; // stop_source for started thread
    ::std::thread _thread{}; // started thread (if any)
};


//**********************************************************************

//*****************************************
//* implementation of class jthread
//*****************************************

// default constructor:
inline jthread::jthread() noexcept : _stopSource{nostopstate} {}

// THE constructor that starts the thread:
// - NOTE: declaration does SFINAE out copy constructor semantics
template<typename Callable, typename... Args, typename>
inline jthread::jthread(Callable&& cb, Args&&... args)
    : _stopSource{}, // initialize stop_source
      _thread{
          [](stop_token st, auto&& cb, auto&&... args) { // called lambda in the thread
              // perform tasks of the thread:
              if constexpr ( std::is_invocable_v<Callable, stop_token, Args...> ) {
                  // pass the stop_token as first argument to the started thread:
                  ::std::invoke(::std::forward<decltype(cb)>(cb), std::move(st),
                                ::std::forward<decltype(args)>(args)...);
              }
              else {
                  // started thread does not expect a stop token:
                  ::std::invoke(::std::forward<decltype(cb)>(cb), ::std::forward<decltype(args)>(args)...);
              }
          },
          _stopSource.get_token(),      // not captured due to possible races if immediately set
          ::std::forward<Callable>(cb), // pass callable
          ::std::forward<Args>(args)... // pass arguments for callable
      } {}

// move assignment operator:
inline jthread& jthread::operator=(jthread&& t) noexcept {
    if ( joinable() ) { // if not joined/detached, signal stop and wait for end:
        request_stop();
        join();
    }

    _thread = std::move(t._thread);
    _stopSource = std::move(t._stopSource);
    return *this;
}

// destructor:
inline jthread::~jthread() {
    if ( joinable() ) { // if not joined/detached, signal stop and wait for end:
        request_stop();
        join();
    }
}


// others:
inline bool jthread::joinable() const noexcept { return _thread.joinable(); }
inline void jthread::join() { _thread.join(); }
inline void jthread::detach() { _thread.detach(); }
inline typename jthread::id jthread::get_id() const noexcept { return _thread.get_id(); }
inline typename jthread::native_handle_type jthread::native_handle() { return _thread.native_handle(); }

inline stop_source jthread::get_stop_source() noexcept { return _stopSource; }
inline stop_token jthread::get_stop_token() const noexcept { return _stopSource.get_token(); }

inline void jthread::swap(jthread& t) noexcept {
    std::swap(_stopSource, t._stopSource);
    std::swap(_thread, t._thread);
}


} // namespace nonstd

#endif // JTHREAD_HPP
