#[inline(never)]
#[cfg_attr(
        any(test, feature = "pre"),
        pre::pre(valid_ptr(us, r)),
        pre::pre("`us` points to a single allocated object of initialized `u8` values that is valid for `us_len` bytes"),
        pre::pre(us_len <= isize::MAX as usize),
        pre::pre(valid_ptr(them, r)),
        pre::pre("`them` points to a single allocated object of initialized `u8` values that is valid for `them_len` bytes"),
        pre::pre(them_len <= isize::MAX as usize)
    )]
pub unsafe fn timing_attack_proof_cmp(us: *const u8, us_len: usize, them: *const u8, them_len: usize) -> bool {
    if us_len != them_len {
        return false;
    }

    let mut result: u8 = 0;

    for i in 0..us_len {
        let us_val = {
            #[cfg_attr(
                    any(test, feature = "pre"),
                    forward(impl pre::std::const_pointer),
                    assure(
                        "the starting and the resulting pointer are in bounds of the same allocated object",
                        reason = "the offset is at most `us_len` bytes and the object at `us` is valid for `us_len` bytes"
                    ),
                    assure(
                        "the computed offset, in bytes, does not overflow an `isize`",
                        reason = "`us_len <= `isize::MAX as usize`"
                    ),
                    assure(
                        "performing the offset does not result in overflow",
                        reason = "a single allocation does not rely on overflow to index all elements and `i as isize >= 0`"
                    )
                )]
            #[allow(clippy::ptr_offset_with_cast)]
            let ptr = us.offset(i as isize);
            #[cfg_attr(
                any(test, feature = "pre"),
                forward(pre),
                assure(
                    valid_ptr(src, r),
                    reason = "`ptr` is constructed from a valid pointer above with an offset that still fits the allocation"
                ),
                assure(
                    proper_align(src),
                    reason = "`T` is `u8`, which has an alignment of `1`, which every pointer has"
                ),
                assure(
                    "`src` points to a properly initialized value of type `T`",
                    reason = "`ptr` points to the object as `us`, which contains initialized `u8` values"
                ),
                assure("`T` is `Copy` or the value at `*src` isn't used after this call", reason = "`u8: Copy`")
            )]
            std::ptr::read_volatile(ptr)
        };
        let them_val = {
            #[cfg_attr(
                    any(test, feature = "pre"),
                    forward(impl pre::std::const_pointer),
                    assure(
                        "the starting and the resulting pointer are in bounds of the same allocated object",
                        reason = "the offset is at most `them_len == us_len` bytes and the object at `them` is valid for `them_len` bytes"
                    ),
                    assure(
                        "the computed offset, in bytes, does not overflow an `isize`",
                        reason = "`them_len == us_len <= `isize::MAX as usize`"
                    ),
                    assure(
                        "performing the offset does not result in overflow",
                        reason = "a single allocation does not rely on overflow to index all elements and `i as isize >= 0`"
                    )
                )]
            #[allow(clippy::ptr_offset_with_cast)]
            let ptr = them.offset(i as isize);
            #[cfg_attr(
                any(test, feature = "pre"),
                forward(pre),
                assure(
                    valid_ptr(src, r),
                    reason = "`ptr` is constructed from a valid pointer above with an offset that still fits the allocation"
                ),
                assure(
                    proper_align(src),
                    reason = "`T` is `u8`, which has an alignment of `1`, which every pointer has"
                ),
                assure(
                    "`src` points to a properly initialized value of type `T`",
                    reason = "`ptr` points to the object as `them`, which contains initialized `u8` values"
                ),
                assure("`T` is `Copy` or the value at `*src` isn't used after this call", reason = "`u8: Copy`")
            )]
            std::ptr::read_volatile(ptr)
        };
        result |= us_val ^ them_val;
    }

    result == 0
}

#[cfg(unix)]
pub mod memlock {
    extern crate libc;

    pub fn mlock<T: Sized>(cont: *mut T, count: usize) {
        let byte_num = count * std::mem::size_of::<T>();
        unsafe {
            let ptr = cont as *mut libc::c_void;
            libc::mlock(ptr, byte_num);
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(ptr, byte_num, libc::MADV_NOCORE);
            #[cfg(target_os = "linux")]
            libc::madvise(ptr, byte_num, libc::MADV_DONTDUMP);
        }
    }

    pub fn munlock<T: Sized>(cont: *mut T, count: usize) {
        let byte_num = count * std::mem::size_of::<T>();
        unsafe {
            let ptr = cont as *mut libc::c_void;
            libc::munlock(ptr, byte_num);
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            libc::madvise(ptr, byte_num, libc::MADV_CORE);
            #[cfg(target_os = "linux")]
            libc::madvise(ptr, byte_num, libc::MADV_DODUMP);
        }
    }
}

#[cfg(not(unix))]
pub mod memlock {
    pub fn mlock<T: Sized>(_cont: *mut T, _count: usize) {}

    pub fn munlock<T: Sized>(_cont: *mut T, _count: usize) {}
}
