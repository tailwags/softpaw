pub mod codec;
pub mod message;

#[cfg(feature = "tracing")]
pub(crate) use tracing;

#[cfg(not(feature = "tracing"))]
#[allow(unused)]
pub(crate) mod tracing {
    macro_rules! debug {
        ($($tt:tt)*) => {};
    }

    pub(crate) use debug;
}
