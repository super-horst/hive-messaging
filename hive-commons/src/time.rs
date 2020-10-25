use crate::CommonError;

#[cfg(not(feature = "web"))]
pub fn now() -> Result<u64, CommonError> {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| CommonError::TimeError {
            message: "Unable to get system time".to_string(),
            cause: e,
        })
}

#[cfg(feature = "web")]
pub fn now() -> Result<u64, CommonError> {
    use js_sys::Date;

    Ok(Date::new_0().get_time() as u64)
}
