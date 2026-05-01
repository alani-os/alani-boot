#![cfg_attr(not(feature = "std"), no_std)]

//! UEFI and emulator boot handoff skeleton for the Alani MVK.
//!
//! The crate stays dependency-free while `alani-abi`, `alani-platform`, and
//! `alani-config` stabilize. It provides no-std-friendly contracts for boot
//! manifest parsing, UEFI memory-map capture, early console diagnostics, and
//! kernel handoff construction.

pub mod early_console;
pub mod error;
pub mod handoff;
pub mod manifest;
pub mod uefi;

use early_console::{ConsoleSeverity, EarlyConsole, EarlyConsoleConfig};
use error::{BootError, BootResult};
use handoff::{
    BootHandoff, BootHandoffBuilder, BootSource, BootTarget, CpuFeatureSet, HandoffImage,
    HandoffImageKind, HandoffMemoryMap, MeasurementRecord,
};
use manifest::BootManifest;
use uefi::UefiMemoryMap;

/// Repository name.
pub const REPOSITORY: &str = "alani-boot";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this skeleton.
pub const MODULES: &[&str] = &["early_console", "error", "handoff", "manifest", "uefi"];

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Deterministic boot phases from firmware entry through kernel entry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootPhase {
    /// Firmware or emulator entered the bootloader.
    FirmwareEntry,
    /// Early console configured.
    EarlyConsole,
    /// Boot manifest parsed and validated.
    ManifestLoad,
    /// Kernel and optional images loaded.
    ImageLoad,
    /// Firmware memory map captured and translated.
    MemoryMap,
    /// UEFI boot services exited.
    ExitBootServices,
    /// CPU features validated.
    CpuValidation,
    /// Handoff object built and validated.
    HandoffBuild,
    /// Control transferred to the kernel entry point.
    KernelEntry,
}

impl BootPhase {
    /// Stable phase name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::FirmwareEntry => "firmware_entry",
            Self::EarlyConsole => "early_console",
            Self::ManifestLoad => "manifest_load",
            Self::ImageLoad => "image_load",
            Self::MemoryMap => "memory_map",
            Self::ExitBootServices => "exit_boot_services",
            Self::CpuValidation => "cpu_validation",
            Self::HandoffBuild => "handoff_build",
            Self::KernelEntry => "kernel_entry",
        }
    }
}

/// Number of deterministic boot phases.
pub const BOOT_PHASE_COUNT: usize = 9;

/// Normative boot phase order for host-mode verification.
pub const BOOT_SEQUENCE: [BootPhase; BOOT_PHASE_COUNT] = [
    BootPhase::FirmwareEntry,
    BootPhase::EarlyConsole,
    BootPhase::ManifestLoad,
    BootPhase::ImageLoad,
    BootPhase::MemoryMap,
    BootPhase::ExitBootServices,
    BootPhase::CpuValidation,
    BootPhase::HandoffBuild,
    BootPhase::KernelEntry,
];

/// Boot phase progress tracker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootSequence {
    completed: [bool; BOOT_PHASE_COUNT],
    next_index: usize,
}

impl BootSequence {
    /// Creates a tracker with no completed phases.
    pub const fn new() -> Self {
        Self {
            completed: [false; BOOT_PHASE_COUNT],
            next_index: 0,
        }
    }

    /// Returns the next expected phase.
    pub fn next_expected(&self) -> Option<BootPhase> {
        BOOT_SEQUENCE.get(self.next_index).copied()
    }

    /// Marks a phase complete, rejecting out-of-order transitions.
    pub fn complete(&mut self, phase: BootPhase) -> BootResult<()> {
        let expected = self.next_expected().ok_or(BootError::PhaseOutOfOrder)?;
        if expected != phase {
            return Err(BootError::PhaseOutOfOrder);
        }
        self.completed[self.next_index] = true;
        self.next_index += 1;
        Ok(())
    }

    /// Returns `true` when all boot phases have completed.
    pub const fn is_complete(&self) -> bool {
        self.next_index == BOOT_PHASE_COUNT
    }

    /// Number of completed phases.
    pub const fn completed_count(&self) -> usize {
        self.next_index
    }
}

impl Default for BootSequence {
    fn default() -> Self {
        Self::new()
    }
}

/// Host-mode boot coordinator used by tests and simulators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootCoordinator {
    /// Deterministic phase tracker.
    pub sequence: BootSequence,
    /// Early console event ring.
    pub console: EarlyConsole,
}

impl BootCoordinator {
    /// Creates a new boot coordinator.
    pub const fn new() -> Self {
        Self {
            sequence: BootSequence::new(),
            console: EarlyConsole::new(),
        }
    }

    /// Completes a phase and records an early-console event.
    pub fn complete_phase(&mut self, phase: BootPhase) -> BootResult<()> {
        self.sequence.complete(phase)?;
        if self.console.is_initialized() {
            self.console
                .record(phase, ConsoleSeverity::Info, phase.name())?;
        }
        Ok(())
    }

    /// Initializes the early console in the required phase order.
    pub fn initialize_console(&mut self, config: EarlyConsoleConfig) -> BootResult<()> {
        self.complete_phase(BootPhase::FirmwareEntry)?;
        self.console.initialize(config)?;
        self.complete_phase(BootPhase::EarlyConsole)
    }
}

impl Default for BootCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a validated handoff from a parsed manifest and captured memory map.
pub fn build_handoff_from_manifest(
    manifest: &BootManifest<'_>,
    memory_map: HandoffMemoryMap,
    target: BootTarget,
    source: BootSource,
    cpu_features: CpuFeatureSet,
    measurement: Option<MeasurementRecord>,
) -> BootResult<BootHandoff> {
    manifest.validate()?;
    if memory_map.is_empty() {
        return Err(BootError::MemoryMapEmpty);
    }

    let kernel = HandoffImage::new(
        HandoffImageKind::Kernel,
        manifest.kernel.load_address,
        manifest.kernel.length,
        manifest.kernel.entry,
        manifest.kernel.checksum,
    )?;

    let mut builder = BootHandoffBuilder::new(target, source)
        .kernel_image(kernel)
        .cpu_features(cpu_features);

    for region in memory_map.entries() {
        builder = builder.memory_region(*region)?;
    }

    if manifest.init.is_present() {
        builder = builder.init_image(HandoffImage::new(
            HandoffImageKind::Init,
            manifest.init.load_address,
            manifest.init.length,
            manifest.init.entry,
            manifest.init.checksum,
        )?);
    }

    if manifest.config.is_present() {
        builder = builder.config_blob(HandoffImage::new(
            HandoffImageKind::Config,
            manifest.config.load_address,
            manifest.config.length,
            manifest.config.entry,
            manifest.config.checksum,
        )?);
    }

    if manifest.policy.is_present() {
        builder = builder.policy_bundle(HandoffImage::new(
            HandoffImageKind::Policy,
            manifest.policy.load_address,
            manifest.policy.length,
            manifest.policy.entry,
            manifest.policy.checksum,
        )?);
    }

    if let Some(record) = measurement {
        builder = builder.measurement(record)?;
    }

    builder.build()
}

/// Builds a validated handoff from a parsed manifest and UEFI memory map.
pub fn build_uefi_handoff_from_manifest(
    manifest: &BootManifest<'_>,
    uefi_memory_map: &UefiMemoryMap,
    target: BootTarget,
    cpu_features: CpuFeatureSet,
    measurement: Option<MeasurementRecord>,
) -> BootResult<BootHandoff> {
    build_handoff_from_manifest(
        manifest,
        uefi_memory_map.to_handoff_memory_map()?,
        target,
        BootSource::Uefi,
        cpu_features,
        measurement,
    )
}
