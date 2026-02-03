//! TURN message types and error codes

/// TURN error codes (RFC 5766)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnErrorCode {
    /// 400 Bad Request
    BadRequest = 400,
    /// 401 Unauthorized
    Unauthorized = 401,
    /// 403 Forbidden
    Forbidden = 403,
    /// 420 Unknown Attribute
    UnknownAttribute = 420,
    /// 437 Allocation Mismatch
    AllocationMismatch = 437,
    /// 438 Stale Nonce
    StaleNonce = 438,
    /// 441 Wrong Credentials
    WrongCredentials = 441,
    /// 442 Unsupported Transport Protocol
    UnsupportedTransport = 442,
    /// 486 Allocation Quota Reached
    AllocationQuotaReached = 486,
    /// 500 Server Error
    ServerError = 500,
    /// 508 Insufficient Capacity
    InsufficientCapacity = 508,
}

impl TurnErrorCode {
    /// Get the error reason phrase
    pub fn reason(&self) -> &'static str {
        match self {
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::UnknownAttribute => "Unknown Attribute",
            Self::AllocationMismatch => "Allocation Mismatch",
            Self::StaleNonce => "Stale Nonce",
            Self::WrongCredentials => "Wrong Credentials",
            Self::UnsupportedTransport => "Unsupported Transport Protocol",
            Self::AllocationQuotaReached => "Allocation Quota Reached",
            Self::ServerError => "Server Error",
            Self::InsufficientCapacity => "Insufficient Capacity",
        }
    }
}

/// TURN error
#[derive(Debug)]
pub struct TurnError {
    pub code: TurnErrorCode,
    pub message: Option<String>,
}

impl TurnError {
    pub fn new(code: TurnErrorCode) -> Self {
        Self {
            code,
            message: None,
        }
    }

    pub fn with_message(code: TurnErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: Some(message.into()),
        }
    }
}

impl std::fmt::Display for TurnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code as u16, self.code.reason())?;
        if let Some(ref msg) = self.message {
            write!(f, ": {}", msg)?;
        }
        Ok(())
    }
}

impl std::error::Error for TurnError {}
