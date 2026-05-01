use alani_boot::early_console::{
    ConsoleDataClass, ConsoleSeverity, EarlyConsole, EarlyConsoleConfig, REDACTED_MESSAGE,
};
use alani_boot::error::{BootError, BootStatus};
use alani_boot::handoff::{
    BootSource, BootTarget, CpuFeatureSet, HandoffImage, HandoffImageKind, HandoffMemoryKind,
    HandoffMemoryMap, HandoffMemoryRegion, MeasurementComponent, MeasurementRecord,
    MemoryAttributes,
};
use alani_boot::manifest::{BootManifest, BootProfile};
use alani_boot::uefi::{
    BootServicesState, ExitBootServicesPlan, UefiMemoryAttributes, UefiMemoryDescriptor,
    UefiMemoryMap, UefiMemoryType,
};
use alani_boot::{build_handoff_from_manifest, BootCoordinator, BootPhase, BootSequence};

const VALID_MANIFEST: &str = r#"
kernel.path=/boot/alani-kernel
kernel.load_address=0x100000
kernel.length=0x200000
kernel.entry=0x101000
kernel.checksum=0xfeed
init.path=/boot/alani-init
init.load_address=0x400000
init.length=0x10000
profile=development
allow_mocks=true
console=serial
config.audit=enabled
"#;

#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_boot::repository_name(), "alani-boot");
    assert!(alani_boot::module_names().contains(&"handoff"));
    assert!(alani_boot::module_names().contains(&"manifest"));
}

#[test]
fn manifest_parser_extracts_kernel_and_profile() {
    let manifest = BootManifest::parse(VALID_MANIFEST).unwrap();
    assert_eq!(manifest.kernel.path, Some("/boot/alani-kernel"));
    assert_eq!(manifest.kernel.load_address, 0x100000);
    assert_eq!(manifest.kernel.entry, 0x101000);
    assert_eq!(manifest.profile, BootProfile::Development);
    assert!(manifest.allow_mocks);
    assert_eq!(manifest.config_entries().len(), 1);
}

#[test]
fn manifest_requires_kernel_image() {
    let error = BootManifest::parse("profile=minimal\n").unwrap_err();
    assert_eq!(error, BootError::MissingKernelImage);
    assert_eq!(BootStatus::from(error), BootStatus::NotFound);
}

#[test]
fn manifest_rejects_kernel_entry_outside_image() {
    let error = BootManifest::parse(
        "kernel.path=/boot/kernel\nkernel.load_address=0x100000\nkernel.length=0x1000\nkernel.entry=0x200000\n",
    )
    .unwrap_err();
    assert_eq!(error, BootError::MissingEntryPoint);
}

#[test]
fn early_console_redacts_sensitive_events() {
    let mut console = EarlyConsole::new();
    assert_eq!(
        console
            .record(BootPhase::FirmwareEntry, ConsoleSeverity::Info, "too early")
            .unwrap_err(),
        BootError::EarlyConsoleNotReady
    );

    console.initialize(EarlyConsoleConfig::SERIAL_COM1).unwrap();
    console
        .record_classified(
            BootPhase::ManifestLoad,
            ConsoleSeverity::Warning,
            ConsoleDataClass::Secret,
            "policy-token",
        )
        .unwrap();
    assert_eq!(console.last().unwrap().message, REDACTED_MESSAGE);
}

#[test]
fn boot_sequence_enforces_phase_order() {
    let mut sequence = BootSequence::new();
    assert_eq!(
        sequence.complete(BootPhase::ManifestLoad).unwrap_err(),
        BootError::PhaseOutOfOrder
    );
    for phase in alani_boot::BOOT_SEQUENCE {
        sequence.complete(phase).unwrap();
    }
    assert!(sequence.is_complete());
}

#[test]
fn coordinator_initializes_console_and_records_phase() {
    let mut coordinator = BootCoordinator::new();
    coordinator
        .initialize_console(EarlyConsoleConfig::SERIAL_COM1)
        .unwrap();
    assert!(coordinator.console.is_initialized());
    assert_eq!(
        coordinator.console.last().unwrap().phase,
        BootPhase::EarlyConsole
    );
}

#[test]
fn uefi_memory_map_translates_to_handoff_regions() {
    let mut map = UefiMemoryMap::new();
    map.push(
        UefiMemoryDescriptor::new(
            UefiMemoryType::Conventional,
            0x100000,
            16,
            UefiMemoryAttributes::WRITE_BACK,
        )
        .unwrap(),
    )
    .unwrap();
    map.push(
        UefiMemoryDescriptor::new(
            UefiMemoryType::MemoryMappedIo,
            0xfec00000,
            1,
            UefiMemoryAttributes::empty(),
        )
        .unwrap(),
    )
    .unwrap();

    let handoff_map = map.to_handoff_memory_map().unwrap();
    assert_eq!(handoff_map.len(), 2);
    assert_eq!(
        handoff_map.total_by_kind(HandoffMemoryKind::Usable),
        16 * alani_boot::uefi::UEFI_PAGE_SIZE
    );
    assert_eq!(handoff_map.entries()[1].kind, HandoffMemoryKind::Mmio);
}

#[test]
fn uefi_memory_map_rejects_overlap() {
    let mut map = UefiMemoryMap::new();
    map.push(
        UefiMemoryDescriptor::new(
            UefiMemoryType::Conventional,
            0x100000,
            4,
            UefiMemoryAttributes::empty(),
        )
        .unwrap(),
    )
    .unwrap();
    let error = map
        .push(
            UefiMemoryDescriptor::new(
                UefiMemoryType::BootServicesData,
                0x102000,
                4,
                UefiMemoryAttributes::empty(),
            )
            .unwrap(),
        )
        .unwrap_err();
    assert_eq!(error, BootError::MemoryRegionOverlap);
}

#[test]
fn exit_boot_services_plan_validates_map_key_and_descriptor_size() {
    let state = BootServicesState::active(0, core::mem::size_of::<UefiMemoryDescriptor>(), 1);
    assert_eq!(
        state.validate().unwrap_err(),
        BootError::InvalidBootServicesState
    );

    let state = BootServicesState::active(1, 8, 1);
    assert_eq!(
        state.validate().unwrap_err(),
        BootError::InvalidUefiDescriptor
    );
}

#[test]
fn handoff_builder_requires_kernel_memory_and_cpu_features() {
    let kernel = HandoffImage::new(
        HandoffImageKind::Kernel,
        0x100000,
        0x200000,
        0x101000,
        0xfeed,
    )
    .unwrap();
    let error =
        alani_boot::handoff::BootHandoffBuilder::new(BootTarget::X86_64Uefi, BootSource::Uefi)
            .kernel_image(kernel)
            .build()
            .unwrap_err();
    assert_eq!(error, BootError::MemoryMapEmpty);
}

#[test]
fn build_handoff_from_manifest_produces_valid_handoff() {
    let manifest = BootManifest::parse(VALID_MANIFEST).unwrap();
    let mut map = HandoffMemoryMap::new();
    map.push(
        HandoffMemoryRegion::new(
            0x100000,
            0x200000,
            HandoffMemoryKind::KernelImage,
            MemoryAttributes::READ.union(MemoryAttributes::EXECUTE),
        )
        .unwrap(),
    )
    .unwrap();
    map.push(
        HandoffMemoryRegion::new(
            0x400000,
            0x10000,
            HandoffMemoryKind::InitImage,
            MemoryAttributes::READ,
        )
        .unwrap(),
    )
    .unwrap();

    let handoff = build_handoff_from_manifest(
        &manifest,
        map,
        BootTarget::HostTest,
        BootSource::HostTest,
        CpuFeatureSet::empty(),
        Some(MeasurementRecord::sha256(
            MeasurementComponent::Kernel,
            [7; 32],
        )),
    )
    .unwrap();

    assert_eq!(handoff.kernel_image.entry, 0x101000);
    assert_eq!(handoff.init_image.kind, HandoffImageKind::Init);
    assert_eq!(handoff.measurements.len(), 1);
}

#[test]
fn x86_handoff_requires_minimum_cpu_features() {
    let manifest = BootManifest::parse(VALID_MANIFEST).unwrap();
    let mut map = HandoffMemoryMap::new();
    map.push(
        HandoffMemoryRegion::new(
            0x100000,
            0x200000,
            HandoffMemoryKind::KernelImage,
            MemoryAttributes::READ.union(MemoryAttributes::EXECUTE),
        )
        .unwrap(),
    )
    .unwrap();

    let error = build_handoff_from_manifest(
        &manifest,
        map,
        BootTarget::X86_64Uefi,
        BootSource::Uefi,
        CpuFeatureSet::empty(),
        None,
    )
    .unwrap_err();
    assert_eq!(error, BootError::UnsupportedFirmware);
}

#[test]
fn exit_boot_services_plan_returns_handoff_map() {
    let mut map = UefiMemoryMap::new();
    map.push(
        UefiMemoryDescriptor::new(
            UefiMemoryType::Conventional,
            0x100000,
            1,
            UefiMemoryAttributes::empty(),
        )
        .unwrap(),
    )
    .unwrap();

    let plan = ExitBootServicesPlan::new(
        BootServicesState::active(1, core::mem::size_of::<UefiMemoryDescriptor>(), 1),
        map,
    )
    .unwrap();
    assert_eq!(plan.handoff_memory_map().unwrap().len(), 1);
}
