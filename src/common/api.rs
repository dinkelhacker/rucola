use crate::common::{Success, Error};

pub trait StreamingAPI: DefaultInit + SingleInputUpdate + SingleOutputFinish {}

pub trait DefaultInit {
    fn init(&mut self) -> Result<Success, Error>;
}

pub trait SingleInputUpdate {
    fn update(&mut self, input: &[u8]) -> Result<Success, Error>;
}

pub trait SingleOutputFinish {
    fn finish(&mut self, output: &mut [u8]) -> Result<Success, Error>;
}
