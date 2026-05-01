//! Kernel handoff structures built by UEFI or emulator boot paths.
//!
//! Handoff data uses fixed-size, integer-only structures where possible so the
//! eventual bootloader/kernel ABI can be audited for layout stability.

use crate::error::{BootError, BootResult};

/// Maximum memory regions transferred to the kernel.
pub const MAX_HANDOFF_MEMORY_REGIONS: usize = 128;

/// Maximum measurement records transferred to the kernel.
pub const MAX_BOOT_MEASUREMENTS: usize = 16;

/// Handoff magic value: ASCII-ish `ALANBOOT` in little-endian form.
pub const HANDOFF_MAGIC: u64 = 0x544f_4f42_4e41_4c41;

/// Kernel handoff ABI version.
pub const HANDOFF_VERSION: HandoffVersion = HandoffVersion {
    major: 0,
    minor: 1,
    patch: 0,
    flags: 0,
};

/// Handoff ABI version.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffVersion {
    /// Major version. Incompatible layout changes require a bump.
    pub major: u16,
    /// Minor version. Compatible additions require a bump.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
    /// Reserved flags.
    pub flags: u16,
}

/// Initial boot target.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootTarget {
    /// x86_64 under UEFI.
    X86_64Uefi = 1,
    /// x86_64 under QEMU/emulator flow.
    X86_64Qemu = 2,
    /// RISC-V placeholder target.
    Riscv64Reserved = 3,
    /// Host-mode test target.
    HostTest = 0xffff,
}

/// Source that produced the handoff.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootSource {
    /// UEFI boot services path.
    Uefi = 1,
    /// Emulator or simulator path.
    Emulator = 2,
    /// Host-mode tests.
    HostTest = 0xffff,
}

/// Memory region kind transferred to the kernel.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffMemoryKind {
    /// Usable RAM after boot reservations.
    Usable = 1,
    /// Reserved firmware or unknown memory.
    Reserved = 2,
    /// Bootloader-owned data needed during early kernel setup.
    Bootloader = 3,
    /// Loaded kernel image.
    KernelImage = 4,
    /// Loaded init/runtime image.
    InitImage = 5,
    /// Loaded config or policy blob.
    Config = 6,
    /// Framebuffer memory.
    Framebuffer = 7,
    /// Memory-mapped device IO.
    Mmio = 8,
    /// ACPI tables.
    Acpi = 9,
    /// UEFI runtime services.
    RuntimeServices = 10,
    /// Defective memory.
    BadMemory = 11,
}

/// Memory permission and attribute bits.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryAttributes {
    bits: u64,
}

impl MemoryAttributes {
    /// Region can be read.
    pub const READ: Self = Self { bits: 1 << 0 };
    /// Region can be written.
    pub const WRITE: Self = Self { bits: 1 << 1 };
    /// Region can be executed.
    pub const EXECUTE: Self = Self { bits: 1 << 2 };
    /// Region is usable by userspace after kernel setup.
    pub const USER: Self = Self { bits: 1 << 3 };
    /// Region is device/MMIO memory.
    pub const DEVICE: Self = Self { bits: 1 << 4 };
    /// Region is persistent across warm reboot or firmware handoff.
    pub const RUNTIME: Self = Self { bits: 1 << 5 };

    /// Empty attribute set.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Constructs attributes from known raw bits.
    pub const fn from_bits(bits: u64) -> BootResult<Self> {
        if bits & !Self::known_bits() == 0 {
            Ok(Self { bits })
        } else {
            Err(BootError::ReservedBits)
        }
    }

    /// All known attribute bits.
    pub const fn known_bits() -> u64 {
        Self::READ.bits
            | Self::WRITE.bits
            | Self::EXECUTE.bits
            | Self::USER.bits
            | Self::DEVICE.bits
            | Self::RUNTIME.bits
    }

    /// Raw bits.
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Returns a union of two attribute sets.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Returns `true` when all bits in `other` are present.
    pub const fn contains(self, other: Self) -> bool {
        self.bits & other.bits == other.bits
    }
}

/// One memory region in the boot handoff.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffMemoryRegion {
    /// Physical start address.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
    /// Region kind.
    pub kind: HandoffMemoryKind,
    /// Reserved alignment field.
    pub reserved: u16,
    /// Region attribute bits.
    pub attributes: u64,
}

impl HandoffMemoryRegion {
    /// Empty sentinel.
    pub const EMPTY: Self = Self {
        start: 0,
        length: 0,
        kind: HandoffMemoryKind::Reserved,
        reserved: 0,
        attributes: 0,
    };

    /// Creates a validated region.
    pub const fn new(
        start: u64,
        length: u64,
        kind: HandoffMemoryKind,
        attributes: MemoryAttributes,
    ) -> BootResult<Self> {
        if length == 0 || start.checked_add(length).is_none() {
            return Err(BootError::InvalidMemoryRegion);
        }
        Ok(Self {
            start,
            length,
            kind,
            reserved: 0,
            attributes: attributes.bits(),
        })
    }

    /// Exclusive end address.
    pub const fn end(self) -> u64 {
        self.start + self.length
    }

    /// Returns `true` when this region overlaps `other`.
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

/// Fixed-capacity handoff memory map.
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoffMemoryMap {
    entries: [HandoffMemoryRegion; MAX_HANDOFF_MEMORY_REGIONS],
    len: u32,
}

impl HandoffMemoryMap {
    /// Creates an empty handoff memory map.
    pub const fn new() -> Self {
        Self {
            entries: [HandoffMemoryRegion::EMPTY; MAX_HANDOFF_MEMORY_REGIONS],
            len: 0,
        }
    }

    /// Number of active entries.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` when no entries are present.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Active entries.
    pub fn entries(&self) -> &[HandoffMemoryRegion] {
        &self.entries[..self.len()]
    }

    /// Adds a non-overlapping memory region.
    pub fn push(&mut self, region: HandoffMemoryRegion) -> BootResult<()> {
        if self.len() == MAX_HANDOFF_MEMORY_REGIONS {
            return Err(BootError::CapacityExceeded);
        }
        if self.entries().iter().any(|entry| entry.overlaps(region)) {
            return Err(BootError::MemoryRegionOverlap);
        }
        self.entries[self.len()] = region;
        self.len += 1;
        Ok(())
    }

    /// Totals bytes by region kind.
    pub fn total_by_kind(&self, kind: HandoffMemoryKind) -> u64 {
        self.entries()
            .iter()
            .filter(|entry| entry.kind == kind)
            .map(|entry| entry.length)
            .sum()
    }
}

impl Default for HandoffMemoryMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Image class in the boot handoff.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffImageKind {
    /// No image.
    None = 0,
    /// Kernel image.
    Kernel = 1,
    /// Init/runtime image.
    Init = 2,
    /// Configuration blob.
    Config = 3,
    /// Policy bundle.
    Policy = 4,
}

/// Loaded image metadata transferred to the kernel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandoffImage {
    /// Image kind.
    pub kind: HandoffImageKind,
    /// Reserved alignment field.
    pub reserved: u16,
    /// Physical load address.
    pub physical_start: u64,
    /// Optional virtual address chosen by boot code.
    pub virtual_start: u64,
    /// Image length in bytes.
    pub length: u64,
    /// Entry point for executable images.
    pub entry: u64,
    /// Stub checksum value from release tooling.
    pub checksum: u64,
    /// Reserved image flags.
    pub flags: u32,
}

impl HandoffImage {
    /// Empty image sentinel.
    pub const EMPTY: Self = Self {
        kind: HandoffImageKind::None,
        reserved: 0,
        physical_start: 0,
        virtual_start: 0,
        length: 0,
        entry: 0,
        checksum: 0,
        flags: 0,
    };

    /// Creates a loaded image descriptor.
    pub const fn new(
        kind: HandoffImageKind,
        physical_start: u64,
        length: u64,
        entry: u64,
        checksum: u64,
    ) -> BootResult<Self> {
        if matches!(kind, HandoffImageKind::None)
            || physical_start == 0
            || length == 0
            || physical_start.checked_add(length).is_none()
        {
            return Err(BootError::InvalidImage);
        }
        Ok(Self {
            kind,
            reserved: 0,
            physical_start,
            virtual_start: 0,
            length,
            entry,
            checksum,
            flags: 0,
        })
    }

    /// Exclusive image end address.
    pub const fn end(self) -> Option<u64> {
        self.physical_start.checked_add(self.length)
    }

    /// Returns `true` when this image has valid address metadata.
    pub const fn is_present(self) -> bool {
        !matches!(self.kind, HandoffImageKind::None) && self.length != 0
    }

    /// Returns `true` when the entry point is inside the image.
    pub const fn contains_entry(self) -> bool {
        if let Some(end) = self.end() {
            self.entry >= self.physical_start && self.entry < end
        } else {
            false
        }
    }
}

/// Framebuffer format.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramebufferFormat {
    /// No framebuffer.
    None = 0,
    /// 32-bit RGB.
    Rgb32 = 1,
    /// 32-bit BGR.
    Bgr32 = 2,
}

/// Framebuffer descriptor for early kernel diagnostics.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferInfo {
    /// Physical framebuffer base.
    pub base: u64,
    /// Total framebuffer byte length.
    pub length: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per scanline.
    pub stride: u32,
    /// Pixel format.
    pub format: FramebufferFormat,
    /// Reserved alignment field.
    pub reserved: u16,
}

impl FramebufferInfo {
    /// Empty framebuffer descriptor.
    pub const EMPTY: Self = Self {
        base: 0,
        length: 0,
        width: 0,
        height: 0,
        stride: 0,
        format: FramebufferFormat::None,
        reserved: 0,
    };
}

/// ACPI table pointers discovered by firmware.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcpiInfo {
    /// RSDP physical address, or zero when absent.
    pub rsdp_physical: u64,
}

impl AcpiInfo {
    /// Empty ACPI descriptor.
    pub const EMPTY: Self = Self { rsdp_physical: 0 };
}

/// CPU feature bits expected by the kernel bootstrap.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CpuFeatureSet {
    bits: u64,
}

impl CpuFeatureSet {
    /// Long mode.
    pub const LONG_MODE: Self = Self { bits: 1 << 0 };
    /// NX bit.
    pub const NX: Self = Self { bits: 1 << 1 };
    /// SSE2.
    pub const SSE2: Self = Self { bits: 1 << 2 };
    /// Local APIC.
    pub const APIC: Self = Self { bits: 1 << 3 };
    /// XSAVE.
    pub const XSAVE: Self = Self { bits: 1 << 4 };

    /// Empty feature set.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Required features for the x86_64 MVK path.
    pub const fn x86_64_mvk_required() -> Self {
        Self::LONG_MODE
            .union(Self::NX)
            .union(Self::SSE2)
            .union(Self::APIC)
    }

    /// Raw feature bits.
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Returns a union of two feature sets.
    pub const fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Returns `true` when all bits in `required` are present.
    pub const fn contains_all(self, required: Self) -> bool {
        self.bits & required.bits == required.bits
    }
}

/// Measurement algorithm identifier.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeasurementAlgorithm {
    /// No algorithm. Used for empty slots.
    None = 0,
    /// SHA-256 digest supplied by release or firmware tooling.
    Sha256 = 1,
}

/// Component measured by the boot path.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeasurementComponent {
    /// Empty slot.
    None = 0,
    /// Bootloader image.
    Bootloader = 1,
    /// Kernel image.
    Kernel = 2,
    /// Init/runtime image.
    Init = 3,
    /// Policy bundle.
    Policy = 4,
    /// Configuration blob.
    Config = 5,
}

/// One fixed-size boot measurement record.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeasurementRecord {
    /// Measured component.
    pub component: MeasurementComponent,
    /// Digest algorithm.
    pub algorithm: MeasurementAlgorithm,
    /// Digest length in bytes.
    pub digest_len: u16,
    /// Reserved alignment field.
    pub reserved: u16,
    /// Digest bytes. Unused bytes must be zero.
    pub digest: [u8; 32],
}

impl MeasurementRecord {
    /// Empty measurement slot.
    pub const EMPTY: Self = Self {
        component: MeasurementComponent::None,
        algorithm: MeasurementAlgorithm::None,
        digest_len: 0,
        reserved: 0,
        digest: [0; 32],
    };

    /// Creates a SHA-256 measurement record.
    pub const fn sha256(component: MeasurementComponent, digest: [u8; 32]) -> Self {
        Self {
            component,
            algorithm: MeasurementAlgorithm::Sha256,
            digest_len: 32,
            reserved: 0,
            digest,
        }
    }
}

/// Fixed-capacity measurement set.
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementSet {
    records: [MeasurementRecord; MAX_BOOT_MEASUREMENTS],
    len: u32,
}

impl MeasurementSet {
    /// Creates an empty measurement set.
    pub const fn new() -> Self {
        Self {
            records: [MeasurementRecord::EMPTY; MAX_BOOT_MEASUREMENTS],
            len: 0,
        }
    }

    /// Number of active records.
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` when no records are present.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Active records.
    pub fn records(&self) -> &[MeasurementRecord] {
        &self.records[..self.len()]
    }

    /// Adds one measurement record.
    pub fn push(&mut self, record: MeasurementRecord) -> BootResult<()> {
        if self.len() == MAX_BOOT_MEASUREMENTS {
            return Err(BootError::CapacityExceeded);
        }
        if matches!(record.component, MeasurementComponent::None)
            || matches!(record.algorithm, MeasurementAlgorithm::None)
        {
            return Err(BootError::InvalidArgument);
        }
        self.records[self.len()] = record;
        self.len += 1;
        Ok(())
    }
}

impl Default for MeasurementSet {
    fn default() -> Self {
        Self::new()
    }
}

/// ABI-safe boot handoff object.
#[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootHandoff {
    /// Magic value.
    pub magic: u64,
    /// Handoff layout version.
    pub version: HandoffVersion,
    /// Target architecture and boot mode.
    pub target: BootTarget,
    /// Handoff source.
    pub source: BootSource,
    /// Reserved boot flags.
    pub flags: u32,
    /// Preserved memory map.
    pub memory_map: HandoffMemoryMap,
    /// Kernel image metadata.
    pub kernel_image: HandoffImage,
    /// Optional init image metadata.
    pub init_image: HandoffImage,
    /// Optional config blob metadata.
    pub config_blob: HandoffImage,
    /// Optional policy bundle metadata.
    pub policy_bundle: HandoffImage,
    /// Framebuffer metadata.
    pub framebuffer: FramebufferInfo,
    /// ACPI metadata.
    pub acpi: AcpiInfo,
    /// CPU features detected by platform code.
    pub cpu_features: CpuFeatureSet,
    /// Boot measurements.
    pub measurements: MeasurementSet,
}

impl BootHandoff {
    /// Creates a blank handoff for `target` and `source`.
    pub const fn new(target: BootTarget, source: BootSource) -> Self {
        Self {
            magic: HANDOFF_MAGIC,
            version: HANDOFF_VERSION,
            target,
            source,
            flags: 0,
            memory_map: HandoffMemoryMap::new(),
            kernel_image: HandoffImage::EMPTY,
            init_image: HandoffImage::EMPTY,
            config_blob: HandoffImage::EMPTY,
            policy_bundle: HandoffImage::EMPTY,
            framebuffer: FramebufferInfo::EMPTY,
            acpi: AcpiInfo::EMPTY,
            cpu_features: CpuFeatureSet::empty(),
            measurements: MeasurementSet::new(),
        }
    }

    /// Validates handoff invariants before entering the kernel.
    pub fn validate(&self) -> BootResult<()> {
        if self.magic != HANDOFF_MAGIC || self.version.major != HANDOFF_VERSION.major {
            return Err(BootError::HandoffIncomplete);
        }
        if self.memory_map.is_empty() {
            return Err(BootError::MemoryMapEmpty);
        }
        if self.kernel_image.kind != HandoffImageKind::Kernel || !self.kernel_image.is_present() {
            return Err(BootError::MissingKernelImage);
        }
        if !self.kernel_image.contains_entry() {
            return Err(BootError::MissingEntryPoint);
        }
        if matches!(self.target, BootTarget::X86_64Uefi | BootTarget::X86_64Qemu)
            && !self
                .cpu_features
                .contains_all(CpuFeatureSet::x86_64_mvk_required())
        {
            return Err(BootError::UnsupportedFirmware);
        }
        Ok(())
    }
}

/// Fluent builder for boot handoff construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootHandoffBuilder {
    handoff: BootHandoff,
}

impl BootHandoffBuilder {
    /// Creates a builder for `target` and `source`.
    pub const fn new(target: BootTarget, source: BootSource) -> Self {
        Self {
            handoff: BootHandoff::new(target, source),
        }
    }

    /// Adds a memory region.
    pub fn memory_region(mut self, region: HandoffMemoryRegion) -> BootResult<Self> {
        self.handoff.memory_map.push(region)?;
        Ok(self)
    }

    /// Sets the kernel image.
    pub const fn kernel_image(mut self, image: HandoffImage) -> Self {
        self.handoff.kernel_image = image;
        self
    }

    /// Sets the optional init image.
    pub const fn init_image(mut self, image: HandoffImage) -> Self {
        self.handoff.init_image = image;
        self
    }

    /// Sets the optional config blob.
    pub const fn config_blob(mut self, image: HandoffImage) -> Self {
        self.handoff.config_blob = image;
        self
    }

    /// Sets the optional policy bundle.
    pub const fn policy_bundle(mut self, image: HandoffImage) -> Self {
        self.handoff.policy_bundle = image;
        self
    }

    /// Sets framebuffer metadata.
    pub const fn framebuffer(mut self, info: FramebufferInfo) -> Self {
        self.handoff.framebuffer = info;
        self
    }

    /// Sets ACPI metadata.
    pub const fn acpi(mut self, info: AcpiInfo) -> Self {
        self.handoff.acpi = info;
        self
    }

    /// Sets detected CPU features.
    pub const fn cpu_features(mut self, features: CpuFeatureSet) -> Self {
        self.handoff.cpu_features = features;
        self
    }

    /// Adds a boot measurement.
    pub fn measurement(mut self, record: MeasurementRecord) -> BootResult<Self> {
        self.handoff.measurements.push(record)?;
        Ok(self)
    }

    /// Returns the validated handoff.
    pub fn build(self) -> BootResult<BootHandoff> {
        self.handoff.validate()?;
        Ok(self.handoff)
    }
}
