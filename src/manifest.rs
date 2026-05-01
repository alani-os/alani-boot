//! Boot manifest parser and validation.
//!
//! The manifest format is intentionally small for MVK host tests: `key=value`
//! lines, `#` comments, and fixed keys for kernel, init, config, profile, and
//! secure-boot intent. The parser borrows string slices and performs no heap
//! allocation, so the crate remains usable in no_std builds.

use crate::error::{BootError, BootResult};

/// Maximum unowned configuration key/value entries retained from a manifest.
pub const MAX_MANIFEST_CONFIG_ENTRIES: usize = 16;

/// Component image classes named by the boot manifest.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestImageKind {
    /// Kernel image.
    Kernel,
    /// Initial userspace/runtime image.
    Init,
    /// Configuration blob.
    Config,
    /// Policy bundle.
    Policy,
}

/// Boot profile selected by manifest or configuration.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootProfile {
    /// Smallest MVK profile.
    Minimal,
    /// Developer profile with diagnostics and mocks enabled.
    Development,
    /// Recovery profile.
    Recovery,
    /// Host-test profile.
    Test,
}

impl BootProfile {
    /// Parses a manifest profile value.
    pub fn parse(value: &str) -> BootResult<Self> {
        match value {
            "minimal" | "mvk" => Ok(Self::Minimal),
            "development" | "dev" => Ok(Self::Development),
            "recovery" => Ok(Self::Recovery),
            "test" | "host-test" => Ok(Self::Test),
            _ => Err(BootError::InvalidManifest),
        }
    }

    /// Stable manifest value for this profile.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Development => "development",
            Self::Recovery => "recovery",
            Self::Test => "test",
        }
    }
}

/// Per-image manifest metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestImage<'a> {
    /// Image kind.
    pub kind: ManifestImageKind,
    /// Boot-medium path or URI.
    pub path: Option<&'a str>,
    /// Physical load address selected by the bootloader.
    pub load_address: u64,
    /// Image length in bytes.
    pub length: u64,
    /// Entry point address. Required for the kernel image.
    pub entry: u64,
    /// Stub checksum value owned by build/release tooling.
    pub checksum: u64,
    /// Reserved image flags. Unknown bits are rejected.
    pub flags: u32,
}

impl<'a> ManifestImage<'a> {
    /// Creates an empty image descriptor for `kind`.
    pub const fn empty(kind: ManifestImageKind) -> Self {
        Self {
            kind,
            path: None,
            load_address: 0,
            length: 0,
            entry: 0,
            checksum: 0,
            flags: 0,
        }
    }

    /// Returns `true` when the image path and length are present.
    pub const fn is_present(self) -> bool {
        self.path.is_some() && self.length != 0
    }

    /// Returns the exclusive loaded-image end address.
    pub const fn end(self) -> Option<u64> {
        self.load_address.checked_add(self.length)
    }

    /// Returns `true` when `entry` points inside this image.
    pub const fn contains_entry(self) -> bool {
        if let Some(end) = self.end() {
            self.entry >= self.load_address && self.entry < end
        } else {
            false
        }
    }
}

/// Arbitrary manifest configuration pair preserved for later config handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestConfigEntry<'a> {
    /// Key after the `config.` prefix.
    pub key: &'a str,
    /// Raw value.
    pub value: &'a str,
}

/// Borrowed boot manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootManifest<'a> {
    /// Kernel image metadata.
    pub kernel: ManifestImage<'a>,
    /// Optional init/runtime image metadata.
    pub init: ManifestImage<'a>,
    /// Optional config blob metadata.
    pub config: ManifestImage<'a>,
    /// Optional policy bundle metadata.
    pub policy: ManifestImage<'a>,
    /// Selected boot profile.
    pub profile: BootProfile,
    /// Whether the boot profile expects secure-boot measurements.
    pub require_secure_boot: bool,
    /// Whether mock devices are allowed in this profile.
    pub allow_mocks: bool,
    /// Optional early console backend name.
    pub console: Option<&'a str>,
    /// Additional config key/value entries.
    config_entries: [Option<ManifestConfigEntry<'a>>; MAX_MANIFEST_CONFIG_ENTRIES],
    config_len: usize,
}

impl<'a> BootManifest<'a> {
    /// Creates an empty manifest with safe defaults.
    pub const fn empty() -> Self {
        Self {
            kernel: ManifestImage::empty(ManifestImageKind::Kernel),
            init: ManifestImage::empty(ManifestImageKind::Init),
            config: ManifestImage::empty(ManifestImageKind::Config),
            policy: ManifestImage::empty(ManifestImageKind::Policy),
            profile: BootProfile::Minimal,
            require_secure_boot: false,
            allow_mocks: false,
            console: None,
            config_entries: [None; MAX_MANIFEST_CONFIG_ENTRIES],
            config_len: 0,
        }
    }

    /// Parses a borrowed key/value manifest.
    pub fn parse(input: &'a str) -> BootResult<Self> {
        let mut manifest = Self::empty();

        for raw_line in input.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(BootError::InvalidManifest)?;
            manifest.set(key.trim(), value.trim())?;
        }

        manifest.validate()?;
        Ok(manifest)
    }

    /// Returns preserved `config.*` entries.
    pub fn config_entries(&self) -> &[Option<ManifestConfigEntry<'a>>] {
        &self.config_entries[..self.config_len]
    }

    /// Validates image and profile invariants.
    pub fn validate(&self) -> BootResult<()> {
        if !self.kernel.is_present() {
            return Err(BootError::MissingKernelImage);
        }
        if self.kernel.load_address == 0 || self.kernel.end().is_none() {
            return Err(BootError::InvalidImage);
        }
        if self.kernel.entry == 0 || !self.kernel.contains_entry() {
            return Err(BootError::MissingEntryPoint);
        }
        validate_image_flags(self.kernel.flags)?;

        for image in [self.init, self.config, self.policy] {
            if image.path.is_some() || image.length != 0 || image.load_address != 0 {
                if !image.is_present() || image.end().is_none() {
                    return Err(BootError::InvalidImage);
                }
                validate_image_flags(image.flags)?;
            }
        }

        if self.require_secure_boot && self.kernel.checksum == 0 {
            return Err(BootError::IntegrityMismatch);
        }
        Ok(())
    }

    fn set(&mut self, key: &'a str, value: &'a str) -> BootResult<()> {
        match key {
            "kernel.path" => self.kernel.path = non_empty(value)?,
            "kernel.load_address" | "kernel.addr" => self.kernel.load_address = parse_u64(value)?,
            "kernel.length" | "kernel.size" => self.kernel.length = parse_u64(value)?,
            "kernel.entry" => self.kernel.entry = parse_u64(value)?,
            "kernel.checksum" => self.kernel.checksum = parse_u64(value)?,
            "kernel.flags" => self.kernel.flags = parse_u32(value)?,
            "init.path" => self.init.path = non_empty(value)?,
            "init.load_address" | "init.addr" => self.init.load_address = parse_u64(value)?,
            "init.length" | "init.size" => self.init.length = parse_u64(value)?,
            "init.entry" => self.init.entry = parse_u64(value)?,
            "init.checksum" => self.init.checksum = parse_u64(value)?,
            "init.flags" => self.init.flags = parse_u32(value)?,
            "config.path" => self.config.path = non_empty(value)?,
            "config.load_address" | "config.addr" => self.config.load_address = parse_u64(value)?,
            "config.length" | "config.size" => self.config.length = parse_u64(value)?,
            "config.checksum" => self.config.checksum = parse_u64(value)?,
            "policy.path" => self.policy.path = non_empty(value)?,
            "policy.load_address" | "policy.addr" => self.policy.load_address = parse_u64(value)?,
            "policy.length" | "policy.size" => self.policy.length = parse_u64(value)?,
            "policy.checksum" => self.policy.checksum = parse_u64(value)?,
            "profile" | "boot.profile" => self.profile = BootProfile::parse(value)?,
            "require_secure_boot" | "secure_boot.required" => {
                self.require_secure_boot = parse_bool(value)?
            }
            "allow_mocks" | "mocks.allowed" => self.allow_mocks = parse_bool(value)?,
            "console" | "console.backend" => self.console = non_empty(value)?,
            _ if key.starts_with("config.") => self.push_config_entry(&key[7..], value)?,
            _ => return Err(BootError::UnknownManifestKey),
        }
        Ok(())
    }

    fn push_config_entry(&mut self, key: &'a str, value: &'a str) -> BootResult<()> {
        if key.is_empty() {
            return Err(BootError::InvalidManifest);
        }
        if self.config_len == MAX_MANIFEST_CONFIG_ENTRIES {
            return Err(BootError::CapacityExceeded);
        }
        self.config_entries[self.config_len] = Some(ManifestConfigEntry { key, value });
        self.config_len += 1;
        Ok(())
    }
}

fn strip_comment(line: &str) -> &str {
    match line.split_once('#') {
        Some((prefix, _)) => prefix,
        None => line,
    }
}

fn non_empty(value: &str) -> BootResult<Option<&str>> {
    if value.is_empty() {
        Err(BootError::InvalidManifest)
    } else {
        Ok(Some(value))
    }
}

fn parse_u64(value: &str) -> BootResult<u64> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|_| BootError::InvalidManifest)
    } else {
        value.parse::<u64>().map_err(|_| BootError::InvalidManifest)
    }
}

fn parse_u32(value: &str) -> BootResult<u32> {
    let parsed = parse_u64(value)?;
    u32::try_from(parsed).map_err(|_| BootError::InvalidManifest)
}

fn parse_bool(value: &str) -> BootResult<bool> {
    match value {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(BootError::InvalidManifest),
    }
}

fn validate_image_flags(flags: u32) -> BootResult<()> {
    const KNOWN_IMAGE_FLAGS: u32 = 0;
    if flags & !KNOWN_IMAGE_FLAGS == 0 {
        Ok(())
    } else {
        Err(BootError::ReservedBits)
    }
}
