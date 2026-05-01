//! Boot status and typed error mapping.
//!
//! Boot code runs before the kernel has full diagnostics, so failures are
//! compact, stable, and suitable for early-console or handoff reporting.

/// Stable status values for boot-facing APIs.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// Input data was malformed or internally inconsistent.
    InvalidArgument = 1,
    /// A required object was absent.
    NotFound = 2,
    /// The firmware, target, or feature set is unsupported.
    Unsupported = 3,
    /// Integrity or measurement validation failed.
    IntegrityError = 4,
    /// A bounded table or ring buffer is full.
    CapacityExceeded = 5,
    /// The boot operation cannot proceed in the current state.
    Busy = 6,
    /// An internal invariant failed.
    Internal = 0xffff_ffff,
}

impl BootStatus {
    /// Returns `true` when the status represents success.
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// Internal boot error taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootError {
    /// A general argument validation check failed.
    InvalidArgument,
    /// A boot manifest line or key/value pair is malformed.
    InvalidManifest,
    /// The boot manifest contained a key this skeleton does not own.
    UnknownManifestKey,
    /// A manifest or handoff did not name a kernel image.
    MissingKernelImage,
    /// A kernel entry point was absent or outside the image range.
    MissingEntryPoint,
    /// Image length, entry, or address metadata is invalid.
    InvalidImage,
    /// A memory map is missing.
    MemoryMapEmpty,
    /// A memory range has zero length or overflows.
    InvalidMemoryRegion,
    /// Memory ranges overlap.
    MemoryRegionOverlap,
    /// A bounded table or ring buffer is full.
    CapacityExceeded,
    /// UEFI descriptor metadata is invalid.
    InvalidUefiDescriptor,
    /// UEFI boot services cannot be exited with the provided state.
    InvalidBootServicesState,
    /// Firmware target or feature set is unsupported.
    UnsupportedFirmware,
    /// Early console was used before initialization.
    EarlyConsoleNotReady,
    /// Boot phases were completed out of order.
    PhaseOutOfOrder,
    /// Reserved bits were set in a public flag field.
    ReservedBits,
    /// A checksum or measurement comparison failed.
    IntegrityMismatch,
    /// Handoff data is incomplete.
    HandoffIncomplete,
    /// An internal invariant failed.
    Internal,
}

impl BootError {
    /// Maps a typed error to a stable boot status.
    pub const fn status(self) -> BootStatus {
        match self {
            Self::InvalidArgument
            | Self::InvalidManifest
            | Self::UnknownManifestKey
            | Self::MissingEntryPoint
            | Self::InvalidImage
            | Self::InvalidMemoryRegion
            | Self::MemoryRegionOverlap
            | Self::InvalidUefiDescriptor
            | Self::ReservedBits
            | Self::HandoffIncomplete => BootStatus::InvalidArgument,
            Self::MissingKernelImage | Self::MemoryMapEmpty => BootStatus::NotFound,
            Self::UnsupportedFirmware => BootStatus::Unsupported,
            Self::IntegrityMismatch => BootStatus::IntegrityError,
            Self::CapacityExceeded => BootStatus::CapacityExceeded,
            Self::InvalidBootServicesState | Self::EarlyConsoleNotReady | Self::PhaseOutOfOrder => {
                BootStatus::Busy
            }
            Self::Internal => BootStatus::Internal,
        }
    }

    /// Stable reason label for early-console and handoff diagnostics.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidManifest => "invalid_manifest",
            Self::UnknownManifestKey => "unknown_manifest_key",
            Self::MissingKernelImage => "missing_kernel_image",
            Self::MissingEntryPoint => "missing_entry_point",
            Self::InvalidImage => "invalid_image",
            Self::MemoryMapEmpty => "memory_map_empty",
            Self::InvalidMemoryRegion => "invalid_memory_region",
            Self::MemoryRegionOverlap => "memory_region_overlap",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::InvalidUefiDescriptor => "invalid_uefi_descriptor",
            Self::InvalidBootServicesState => "invalid_boot_services_state",
            Self::UnsupportedFirmware => "unsupported_firmware",
            Self::EarlyConsoleNotReady => "early_console_not_ready",
            Self::PhaseOutOfOrder => "phase_out_of_order",
            Self::ReservedBits => "reserved_bits",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::HandoffIncomplete => "handoff_incomplete",
            Self::Internal => "internal",
        }
    }
}

impl From<BootError> for BootStatus {
    fn from(error: BootError) -> Self {
        error.status()
    }
}

/// Result alias used by boot APIs.
pub type BootResult<T> = Result<T, BootError>;
