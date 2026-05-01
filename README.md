# alani-boot

UEFI and emulator boot handoff logic, kernel image metadata, boot manifest parsing, and early console support.

| Field | Value |
|---|---|
| Status | Experimental MVK skeleton |
| Tier | MVK required |
| Owner | Platform team |
| Aliases | None |
| Architectural dependencies | `alani-abi`, `alani-platform`, `alani-config` |

## Quick Start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
cargo check --no-default-features
cargo clippy --all-features -- -D warnings
```

## Scope

This crate is intentionally dependency-free while sibling repository APIs stabilize. It implements no-std-friendly host-mode contracts for:

- deterministic boot phase tracking from firmware entry through kernel entry;
- borrowed `key=value` boot manifest parsing with kernel, init, config, policy, profile, console, and secure-boot intent fields;
- UEFI memory descriptor capture, validation, overlap rejection, and translation into kernel handoff memory regions;
- `ExitBootServices` planning metadata, including map key and descriptor-size validation;
- ABI-shaped boot handoff data for memory maps, image metadata, framebuffer, ACPI, CPU features, and measurement records;
- early console configuration, structured event retention, and default redaction for sensitive or secret messages.

## Layout

```text
src/
  early_console.rs  early console config and structured event ring
  error.rs          boot status and typed errors
  handoff.rs        kernel handoff ABI-shaped structures and builder
  lib.rs            boot phases, coordinator, and handoff assembly helpers
  manifest.rs       borrowed boot manifest parser and validator
  uefi.rs           UEFI memory map and boot-services models
tests/
  smoke.rs          host-mode conformance and negative tests
```

## Specification Traceability

The first API surface is mapped to `alani-spec/docs/repositories/alani-boot.md`, Doc 01, Doc 02, Doc 05, Doc 06, Doc 11, Doc 16, Doc 17, Doc 19, Doc 42, Doc 43, and `docs/assets/boot_sequence.mmd`.

Path dependencies remain out of `Cargo.toml` until `alani-abi`, `alani-platform`, and `alani-config` publish stable public APIs, as required by the repository metadata contract.
