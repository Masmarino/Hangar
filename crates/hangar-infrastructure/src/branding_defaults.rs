//! Fallback logo/favicon when an operator hasn't uploaded their own, compiled into the binary via `include_bytes!`.

pub const DEFAULT_LOGO_BYTES: &[u8] = include_bytes!("../assets/hangar-logo.png");
pub const DEFAULT_LOGO_CONTENT_TYPE: &str = "image/png";

pub const DEFAULT_FAVICON_BYTES: &[u8] = include_bytes!("../assets/hangar-favicon.ico");
pub const DEFAULT_FAVICON_CONTENT_TYPE: &str = "image/x-icon";
