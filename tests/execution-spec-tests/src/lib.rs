//! Execution-spec compliance test harness for OpenVM's REVM crypto provider.
//!
//! OpenVM's k256 recovery uses guest-only intrinsics, so native runs use host k256
//! implementations while exercising OpenVM's other precompile implementations.
