use chrono::{NaiveDateTime, TimeZone, Utc};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::chain::{Encoder, Packer};

#[derive(Copy, Clone, Default, PartialEq, Serialize, Deserialize, Debug)]
pub struct TimePoint {
    /// elapsed in microseconds
    pub elapsed: u64,
}

impl FromStr for TimePoint {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TimePoint::from_timestamp(s)
    }
}

impl TimePoint {
    pub fn from_timestamp(t: &str) -> Result<Self, String> {
        //2023-12-16T16:17:47.500
        let naive_date_time = NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%.f");

        if naive_date_time.is_err() {
            return Err(String::from("Failed to parse datetime ")
                + naive_date_time.err().unwrap().to_string().as_str());
        }
        let date_time = Utc.from_utc_datetime(&naive_date_time.unwrap());

        Ok(Self {
            elapsed: (date_time.timestamp_millis() * 1000) as u64,
        })
    }


    pub fn to_string(&self) -> Option<String> {
        let seconds = self.elapsed / 1000;
        let milliseconds = self.elapsed % 1000;

        Utc.timestamp_millis_opt(seconds as i64)
            .single() // Handle LocalResult correctly
            .map(|dt| format!("{}.{}", dt.format("%Y-%m-%dT%H:%M:%S"), milliseconds))
    }
}

impl Packer for TimePoint {
    fn size(&self) -> usize {
        8
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        self.elapsed.pack(enc)
    }

    fn unpack(&mut self, raw: &[u8]) -> usize {
        assert!(
            raw.len() >= self.size(),
            "TimePoint.unpack: buffer overflow!"
        );
        self.elapsed.unpack(raw)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct TimePointSec {
    pub seconds: u32,
}

impl FromStr for TimePointSec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        TimePointSec::from_timestamp(s)
    }
}

impl TimePointSec {
    pub fn new(seconds: u32) -> Self {
        Self { seconds }
    }

    pub fn seconds(&self) -> u32 {
        self.seconds
    }

    pub fn from_timestamp(t: &str) -> Result<Self, String> {
        let naive_dt = NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S")
            .map_err(|_e| "Failed to parse datetime")?;

        Ok(Self { seconds: naive_dt.and_utc().timestamp() as u32 })
    }

    pub fn to_string(&self) -> Option<String> {
        Utc.timestamp_opt(self.seconds as i64, 0)
            .single() // Handle LocalResult by taking the single valid option
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string()) // Format the datetime if valid
    }
}

impl Packer for TimePointSec {
    fn size(&self) -> usize {
        4
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        self.seconds.pack(enc)
    }

    fn unpack(&mut self, raw: &[u8]) -> usize {
        assert!(
            raw.len() >= self.size(),
            "TimePointSec.unpack: buffer overflow!"
        );
        self.seconds.unpack(raw)
    }
}

pub(crate) fn deserialize_timepoint<'de, D>(deserializer: D) -> Result<TimePoint, D::Error>
where
    D: Deserializer<'de>,
{
    struct TimePointVisitor;

    impl de::Visitor<'_> for TimePointVisitor {
        type Value = TimePoint;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string representing a datetime")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            TimePoint::from_timestamp(value).map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_str(TimePointVisitor)
}

pub(crate) fn deserialize_optional_timepoint<'de, D>(
    deserializer: D,
) -> Result<Option<TimePoint>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptionalTimePointVisitor;

    impl de::Visitor<'_> for OptionalTimePointVisitor {
        type Value = Option<TimePoint>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an optional string representing a datetime or null")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            TimePoint::from_timestamp(value)
                .map(Some)
                .map_err(de::Error::custom)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    // Updated to handle null values directly
    deserializer.deserialize_any(OptionalTimePointVisitor)
}

const BLOCK_INTERVAL_MS: u64 = 500;
const BLOCK_TIMESTAMP_EPOCH_MS: u64 = 946684800000; // 2000-01-01T00:00:00Z

#[derive(Copy, Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlockTimestamp {
    pub slot: u32,
}

impl BlockTimestamp {
    pub fn new(slot: u32) -> Self {
        Self { slot }
    }

    pub fn maximum() -> Self {
        Self { slot: 0xFFFF }
    }

    pub fn min() -> Self {
        Self { slot: 0 }
    }

    pub fn next(&self) -> Self {
        Self { slot: self.slot.saturating_add(1) }
    }

    pub fn from_time_point(tp: TimePoint) -> Self {
        Self { slot: ((tp.elapsed - BLOCK_TIMESTAMP_EPOCH_MS) / BLOCK_INTERVAL_MS) as u32 }
    }

    pub fn from_time_point_sec(tp: TimePointSec) -> Self {
        let ms = (tp.seconds * 1000) as u64;
        Self { slot: ((ms - BLOCK_TIMESTAMP_EPOCH_MS) / BLOCK_INTERVAL_MS) as u32 }
    }

    pub fn to_time_point(&self) -> TimePoint {
        let millis = self.slot as u64 * BLOCK_INTERVAL_MS + BLOCK_TIMESTAMP_EPOCH_MS;
        TimePoint { elapsed: millis }
    }

    pub fn to_time_point_sec(&self) -> TimePointSec {
        let seconds = (self.slot as u64 * BLOCK_INTERVAL_MS + BLOCK_TIMESTAMP_EPOCH_MS / 1000) as u32;
        TimePointSec { seconds }
    }

    pub fn from_timestamp(s: &String) -> Result<Self, String> {
        Ok(BlockTimestamp::from_time_point_sec(TimePointSec::from_str(s)?))
    }
    pub fn to_string(&self) -> Option<String> {
        Utc.timestamp_opt(self.to_time_point_sec().seconds as i64, 0)
            .single() // Handle LocalResult by taking the single valid option
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string()) // Format the datetime if valid
    }
}

impl Packer for BlockTimestamp {
    fn size(&self) -> usize {
        4
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        self.slot.pack(enc)
    }

    fn unpack(&mut self, raw: &[u8]) -> usize {
        self.slot.unpack(raw)
    }
}
