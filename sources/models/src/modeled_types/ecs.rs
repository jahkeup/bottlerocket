use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
// Just need serde's Error in scope to get its trait methods
use serde::de::Error as _;
use snafu::ensure;
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::fmt;
use std::ops::Deref;
use super::error;

/// ECSAttributeKey represents a string that contains a valid ECS attribute key.  It stores
/// the original string and makes it accessible through standard traits.
// https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Attribute.html
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ECSAttributeKey {
    inner: String,
}


// The name of the attribute. Up to 128 letters (uppercase and lowercase), numbers, hyphens,
// underscores, and periods are allowed.
lazy_static! {
    pub(crate) static ref ECS_ATTRIBUTE_KEY: Regex = Regex::new(
        r"(?x)^
       [a-zA-Z0-9-_\./]{1,128}
   $"
    )
    .unwrap();
}

impl TryFrom<&str> for ECSAttributeKey {
    type Error = error::Error;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        ensure!(
            ECS_ATTRIBUTE_KEY.is_match(input),
            error::BigPattern {
                thing: "ECS attribute key",
                input
            }
        );
        Ok(ECSAttributeKey {
            inner: input.to_string(),
        })
    }
}

string_impls_for!(ECSAttributeKey, "ECSAttributeKey");

#[cfg(test)]
mod test_ecs_attribute_key {
    use super::ECSAttributeKey;
    use std::convert::TryFrom;

    #[test]
    fn good_keys() {
        for ok in &[
            "a",
            "alphabetical",
            "1234567890",
            "with-dash",
            "have.period/slash",
            "have_underscore_too",
            &"a".repeat(128),
            ".leadingperiod",
            "trailingperiod.",
        ] {
            ECSAttributeKey::try_from(*ok).unwrap();
        }
    }

    #[test]
    fn bad_keys() {
        for err in &[
            "",
            &"a".repeat(129),
            "@",
            "$",
            "%",
            ":",
            "no spaces allowed",
        ] {
            ECSAttributeKey::try_from(*err).unwrap_err();
        }
    }
}

// =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

/// ECSAttributeValue represents a string that contains a valid ECS attribute value.  It stores
/// the original string and makes it accessible through standard traits.
// https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_Attribute.html
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ECSAttributeValue {
    inner: String,
}


// The value of the attribute. Up to 128 letters (uppercase and lowercase), numbers, hyphens,
// underscores, periods, at signs (@), forward slashes, colons, and spaces are allowed.
lazy_static! {
    pub(crate) static ref ECS_ATTRIBUTE_VALUE: Regex = Regex::new(
        r"(?x)^
       [a-zA-Z0-9-_\\.@/:] # at least one non-space
       (
         (?-x)([a-zA-Z0-9-_\\.@/: ]{0,126})?(?x) # spaces allowed
         [a-zA-Z0-9-_\\.@/:] # end with non-space
       )?
   $"
    )
    .unwrap();
}

impl TryFrom<&str> for ECSAttributeValue {
    type Error = error::Error;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        ensure!(
            ECS_ATTRIBUTE_VALUE.is_match(input),
            error::BigPattern {
                thing: "ECS attribute value",
                input
            }
        );
        Ok(ECSAttributeValue {
            inner: input.to_string(),
        })
    }
}

string_impls_for!(ECSAttributeValue, "ECSAttributeValue");

#[cfg(test)]
mod test_ecs_attribute_value {
    use super::ECSAttributeValue;
    use std::convert::TryFrom;

    #[test]
    fn good_keys() {
        for ok in &[
            "a",
            "alphabetical",
            "1234567890",
            "with-dash",
            "have.period/slash",
            "have_underscore_too",
            "with spaces in between",
            &"a".repeat(128),
            ".leadingperiod",
            "trailingperiod.",
            "@ and : allowed too",
        ] {
            ECSAttributeValue::try_from(*ok).unwrap();
        }
    }

    #[test]
    fn bad_keys() {
        for err in &[
            "",
            &"a".repeat(129),
            "$",
            "%",
            " leading space",
            "trailing space ",
        ] {
            ECSAttributeValue::try_from(*err).unwrap_err();
        }
    }
}