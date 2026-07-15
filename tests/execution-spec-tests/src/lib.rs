//! Execution-spec compliance test harness for OpenVM's REVM crypto provider.
//!
//! OpenVM's k256 recovery uses guest-only intrinsics, so native runs use REVM's ecrecover
//! implementation while exercising OpenVM's other precompile implementations.
