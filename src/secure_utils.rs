#[cfg(unix)]
pub mod memlock {
    extern crate libc;

    pub fn mlock<T>(cont: *mut T, count: usize) {
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

    pub fn munlock<T>(cont: *mut T, count: usize) {
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
    pub fn mlock<T>(_cont: *mut T, _count: usize) {}

    pub fn munlock<T>(_cont: *mut T, _count: usize) {}
}
