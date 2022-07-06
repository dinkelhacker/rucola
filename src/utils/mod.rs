pub trait UsizeCast {
    fn u32(self) -> u32;
    fn u64(self) -> u64;
    fn i64(self) -> i64;
}

impl UsizeCast for usize {
    fn u32(self) -> u32 {
        return self as u32;
    }
    fn u64(self) -> u64 {
        return self as u64;
    }
    fn i64(self) -> i64 {
        return self as i64;
    }
}
