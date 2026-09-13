//! Shared curve-decoding errors.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    FieldElementInvalid,
    PointNotOnCurve,
    PointNotInSubgroup,
}
