use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr::null_mut;
use std::slice;
use std::sync::{Mutex, MutexGuard};

pub(crate) unsafe fn cstr_arg<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }

    // SAFETY: The caller guarantees that `ptr` points to a valid NUL-terminated
    // C string for the duration of this borrow.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    cstr.to_str().ok()
}

pub(crate) unsafe fn cstr_bytes_arg<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }

    // SAFETY: The caller guarantees that `ptr` points to a valid NUL-terminated
    // C string for the duration of this borrow.
    Some(unsafe { CStr::from_ptr(ptr) }.to_bytes())
}

pub(crate) unsafe fn slice_arg<'a, T>(ptr: *const T, len: usize) -> Option<&'a [T]> {
    if ptr.is_null() {
        if len == 0 {
            return Some(&[]);
        }

        return None;
    }

    // SAFETY: The caller guarantees that `ptr` references `len` initialized
    // elements for the duration of this borrow.
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

pub(crate) unsafe fn mut_slice_arg<'a, T>(ptr: *mut T, len: usize) -> Option<&'a mut [T]> {
    if ptr.is_null() {
        if len == 0 {
            return Some(&mut []);
        }

        return None;
    }

    // SAFETY: The caller guarantees that `ptr` references `len` initialized
    // elements and that the resulting mutable borrow is unique.
    Some(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

pub(crate) unsafe fn handle_ref<'a, T>(ptr: *const T) -> Option<&'a T> {
    // SAFETY: The caller guarantees that `ptr`, if non-null, points to a valid
    // instance for the duration of the returned borrow.
    unsafe { ptr.as_ref() }
}

pub(crate) unsafe fn handle_mut<'a, T>(ptr: *mut T) -> Option<&'a mut T> {
    // SAFETY: The caller guarantees that `ptr`, if non-null, points to a valid
    // uniquely borrowed instance for the duration of the returned borrow.
    unsafe { ptr.as_mut() }
}

pub(crate) unsafe fn free_boxed<T>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }

    // SAFETY: The caller guarantees that `ptr` was produced by `Box::into_raw`
    // exactly once and has not already been freed.
    drop(unsafe { Box::from_raw(ptr) });
}

pub(crate) fn into_c_string_ptr(bytes: Vec<u8>) -> *mut c_char {
    CString::new(bytes).map_or_else(|_| null_mut(), CString::into_raw)
}

pub(crate) unsafe fn free_c_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }

    // SAFETY: The caller guarantees that `ptr` was produced by `CString::into_raw`
    // exactly once and has not already been freed.
    drop(unsafe { CString::from_raw(ptr) });
}

pub(crate) fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
