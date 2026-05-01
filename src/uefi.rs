//! UEFI and emulator boot-path abstractions.
//!
//! This module does not call firmware directly. It models UEFI data captured by
//! platform-specific code and converts it into handoff-safe structures for host
//! tests and future QEMU boot work.

use core::mem::size_of;

use crate::error::{BootError, BootResult};
use crate::handoff::{HandoffMemoryKind, HandoffMemoryMap, HandoffMemoryRegion, MemoryAttributes};

/// UEFI page size.
pub const UEFI_PAGE_SIZE: u64 = 4096;

/// Maximum UEFI memory descriptors retained in host-mode tests.
pub const MAX_UEFI_MEMORY_DESCRIPTORS: usize = 128;

/// UEFI memory type subset used by the boot skeleton.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UefiMemoryType {
    /// Unusable descriptor.
    Reserved = 0,
    /// Loader executable code.
    LoaderCode = 1,
    /// Loader data.
    LoaderData = 2,
    /// Boot services code.
    BootServicesCode = 3,
    /// Boot services data.
    BootServicesData = 4,
    /// Runtime services code.
    RuntimeServicesCode = 5,
    /// Runtime services data.
    RuntimeServicesData = 6,
    /// Conventional memory.
    Conventional = 7,
    /// Unusable memory.
    Unusable = 8,
    /// ACPI reclaimable memory.
    AcpiReclaim = 9,
    /// ACPI NVS memory.
    AcpiNvs = 10,
    /// Memory-mapped IO.
    MemoryMappedIo = 11,
    /// Memory-mapped IO port space.
    MemoryMappedIoPortSpace = 12,
    /// PAL code.
    PalCode = 13,
    /// Persistent memory.
    PersistentMemory = 14,
}

/// UEFI memory attributes represented as a compact bitset.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UefiMemoryAttributes {
    bits: u64,
}

impl UefiMemoryAttributes {
    /// Region supports write-back caching.
    pub const WRITE_BACK: Self = Self { bits: 1 << 0 };
    /// Region is executable.
    pub const EXECUTE: Self = Self { bits: 1 << 1 };
    /// Region is runtime-services memory.
    pub const RUNTIME: Self = Self { bits: 1 << 2 };

    /// Empty attribute set.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Raw attribute bits.
    pub const fn bits(self) -> u64 {
        self.bits
    }

    /// Returns the union of two attribute sets.
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

/// One UEFI memory descriptor captured from firmware.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UefiMemoryDescriptor {
    /// UEFI memory type.
    pub memory_type: UefiMemoryType,
    /// Reserved alignment field.
    pub reserved: u32,
    /// Physical start address.
    pub physical_start: u64,
    /// Runtime virtual start address.
    pub virtual_start: u64,
    /// Number of 4 KiB pages.
    pub number_of_pages: u64,
    /// Attribute bits.
    pub attributes: UefiMemoryAttributes,
}

impl UefiMemoryDescriptor {
    /// Empty descriptor.
    pub const EMPTY: Self = Self {
        memory_type: UefiMemoryType::Reserved,
        reserved: 0,
        physical_start: 0,
        virtual_start: 0,
        number_of_pages: 0,
        attributes: UefiMemoryAttributes::empty(),
    };

    /// Creates a descriptor after basic validation.
    pub fn new(
        memory_type: UefiMemoryType,
        physical_start: u64,
        number_of_pages: u64,
        attributes: UefiMemoryAttributes,
    ) -> BootResult<Self> {
        let length = number_of_pages
            .checked_mul(UEFI_PAGE_SIZE)
            .ok_or(BootError::InvalidUefiDescriptor)?;
        if number_of_pages == 0 || physical_start.checked_add(length).is_none() {
            return Err(BootError::InvalidUefiDescriptor);
        }
        Ok(Self {
            memory_type,
            reserved: 0,
            physical_start,
            virtual_start: 0,
            number_of_pages,
            attributes,
        })
    }

    /// Descriptor length in bytes.
    pub const fn byte_len(self) -> Option<u64> {
        self.number_of_pages.checked_mul(UEFI_PAGE_SIZE)
    }

    /// Exclusive end address.
    pub const fn end(self) -> Option<u64> {
        if let Some(len) = self.byte_len() {
            self.physical_start.checked_add(len)
        } else {
            None
        }
    }

    /// Converts this descriptor into a kernel handoff memory region.
    pub fn to_handoff_region(self) -> BootResult<HandoffMemoryRegion> {
        let length = self.byte_len().ok_or(BootError::InvalidUefiDescriptor)?;
        let (kind, attributes) = match self.memory_type {
            UefiMemoryType::Conventional => (
                HandoffMemoryKind::Usable,
                MemoryAttributes::READ.union(MemoryAttributes::WRITE),
            ),
            UefiMemoryType::LoaderCode => (
                HandoffMemoryKind::KernelImage,
                MemoryAttributes::READ.union(MemoryAttributes::EXECUTE),
            ),
            UefiMemoryType::LoaderData
            | UefiMemoryType::BootServicesCode
            | UefiMemoryType::BootServicesData => (
                HandoffMemoryKind::Bootloader,
                MemoryAttributes::READ.union(MemoryAttributes::WRITE),
            ),
            UefiMemoryType::RuntimeServicesCode | UefiMemoryType::RuntimeServicesData => (
                HandoffMemoryKind::RuntimeServices,
                MemoryAttributes::READ
                    .union(MemoryAttributes::WRITE)
                    .union(MemoryAttributes::RUNTIME),
            ),
            UefiMemoryType::AcpiReclaim | UefiMemoryType::AcpiNvs => (
                HandoffMemoryKind::Acpi,
                MemoryAttributes::READ.union(MemoryAttributes::RUNTIME),
            ),
            UefiMemoryType::MemoryMappedIo | UefiMemoryType::MemoryMappedIoPortSpace => (
                HandoffMemoryKind::Mmio,
                MemoryAttributes::READ
                    .union(MemoryAttributes::WRITE)
                    .union(MemoryAttributes::DEVICE),
            ),
            UefiMemoryType::Unusable => (HandoffMemoryKind::BadMemory, MemoryAttributes::empty()),
            UefiMemoryType::PersistentMemory => (
                HandoffMemoryKind::Reserved,
                MemoryAttributes::READ.union(MemoryAttributes::WRITE),
            ),
            UefiMemoryType::Reserved | UefiMemoryType::PalCode => {
                (HandoffMemoryKind::Reserved, MemoryAttributes::empty())
            }
        };
        HandoffMemoryRegion::new(self.physical_start, length, kind, attributes)
    }
}

/// Bounded UEFI memory map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UefiMemoryMap {
    descriptors: [UefiMemoryDescriptor; MAX_UEFI_MEMORY_DESCRIPTORS],
    len: usize,
}

impl UefiMemoryMap {
    /// Creates an empty UEFI memory map.
    pub const fn new() -> Self {
        Self {
            descriptors: [UefiMemoryDescriptor::EMPTY; MAX_UEFI_MEMORY_DESCRIPTORS],
            len: 0,
        }
    }

    /// Number of active descriptors.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no descriptors are present.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Active descriptors.
    pub fn descriptors(&self) -> &[UefiMemoryDescriptor] {
        &self.descriptors[..self.len]
    }

    /// Adds a descriptor, rejecting overlaps and capacity overflow.
    pub fn push(&mut self, descriptor: UefiMemoryDescriptor) -> BootResult<()> {
        if self.len == MAX_UEFI_MEMORY_DESCRIPTORS {
            return Err(BootError::CapacityExceeded);
        }
        let descriptor_end = descriptor.end().ok_or(BootError::InvalidUefiDescriptor)?;
        for existing in self.descriptors() {
            let existing_end = existing.end().ok_or(BootError::InvalidUefiDescriptor)?;
            if descriptor.physical_start < existing_end && existing.physical_start < descriptor_end
            {
                return Err(BootError::MemoryRegionOverlap);
            }
        }
        self.descriptors[self.len] = descriptor;
        self.len += 1;
        Ok(())
    }

    /// Converts this map into the kernel handoff memory map.
    pub fn to_handoff_memory_map(&self) -> BootResult<HandoffMemoryMap> {
        if self.is_empty() {
            return Err(BootError::MemoryMapEmpty);
        }
        let mut map = HandoffMemoryMap::new();
        for descriptor in self.descriptors() {
            map.push(descriptor.to_handoff_region()?)?;
        }
        Ok(map)
    }
}

impl Default for UefiMemoryMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Captured UEFI boot-services state needed to exit boot services.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootServicesState {
    /// Whether boot services are still active.
    pub active: bool,
    /// Memory map key returned by firmware.
    pub map_key: u64,
    /// Descriptor size returned by firmware.
    pub descriptor_size: usize,
    /// Descriptor version returned by firmware.
    pub descriptor_version: u32,
}

impl BootServicesState {
    /// Creates active boot-services state.
    pub const fn active(map_key: u64, descriptor_size: usize, descriptor_version: u32) -> Self {
        Self {
            active: true,
            map_key,
            descriptor_size,
            descriptor_version,
        }
    }

    /// Validates the captured boot-services state.
    pub fn validate(self) -> BootResult<()> {
        if !self.active || self.map_key == 0 {
            return Err(BootError::InvalidBootServicesState);
        }
        if self.descriptor_size < size_of::<UefiMemoryDescriptor>() || self.descriptor_version == 0
        {
            return Err(BootError::InvalidUefiDescriptor);
        }
        Ok(())
    }
}

/// Planned `ExitBootServices` operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitBootServicesPlan {
    /// Captured boot-services state.
    pub state: BootServicesState,
    /// Memory map captured with `state.map_key`.
    pub memory_map: UefiMemoryMap,
}

impl ExitBootServicesPlan {
    /// Creates a plan and validates firmware metadata.
    pub fn new(state: BootServicesState, memory_map: UefiMemoryMap) -> BootResult<Self> {
        state.validate()?;
        if memory_map.is_empty() {
            return Err(BootError::MemoryMapEmpty);
        }
        Ok(Self { state, memory_map })
    }

    /// Returns the handoff memory map that should be preserved after exit.
    pub fn handoff_memory_map(&self) -> BootResult<HandoffMemoryMap> {
        self.memory_map.to_handoff_memory_map()
    }
}

/// UEFI image handle captured as an opaque integer.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UefiImageHandle(pub u64);

/// UEFI system table pointer captured as an opaque integer.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UefiSystemTable(pub u64);

/// Firmware identity metadata safe for diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareInfo<'a> {
    /// Firmware vendor string when available.
    pub vendor: &'a str,
    /// Firmware revision.
    pub revision: u32,
}

impl<'a> FirmwareInfo<'a> {
    /// Returns `true` when the firmware metadata is usable for diagnostics.
    pub const fn is_present(self) -> bool {
        !self.vendor.is_empty()
    }
}
