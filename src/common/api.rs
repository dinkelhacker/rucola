pub trait StreamingAPI: DefaultInit + SingleInputUpdate + SingleOutputFinish {}

pub trait DefaultInit {
    fn init(&mut self);
}

pub trait SingleInputUpdate {
    fn update(&mut self, input: &[u8]);
}

pub trait SingleOutputFinish {
    fn finish(&mut self, output: &mut [u8]);
}
