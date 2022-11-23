pub mod api;

#[derive(Debug, PartialEq)]
pub enum Error {
    Err,
}

#[derive(Debug, PartialEq)]
pub enum Success {
    OK,
    Again,
}
