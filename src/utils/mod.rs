pub trait Cast<T> {
    fn cast(self) -> T;
}

impl Cast<u8> for u32 {
    fn cast(self) -> u8 {
        return self as u8;
    }
}

impl Cast<u8> for u64 {
    fn cast(self) -> u8 {
        return self as u8;
    }
}
