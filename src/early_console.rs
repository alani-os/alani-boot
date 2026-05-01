//! Early console configuration and structured boot event ring.
//!
//! Before the kernel owns observability, boot code records compact structured
//! events. Sensitive and secret messages are redacted by default.

use crate::error::{BootError, BootResult};
use crate::BootPhase;

/// Maximum events retained before kernel audit/observability handoff.
pub const MAX_EARLY_CONSOLE_EVENTS: usize = 128;

/// Redacted message stored for sensitive or secret data.
pub const REDACTED_MESSAGE: &str = "[redacted]";

/// Early console backend.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleBackend {
    /// No console.
    None,
    /// Serial port only.
    Serial,
    /// Framebuffer only.
    Framebuffer,
    /// Serial and framebuffer.
    SerialAndFramebuffer,
}

/// Serial console settings.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SerialConsole {
    /// IO port base, commonly `0x3f8` on x86_64 QEMU.
    pub io_base: u16,
    /// Baud rate.
    pub baud_rate: u32,
}

impl SerialConsole {
    /// QEMU-compatible COM1 serial console.
    pub const COM1_115200: Self = Self {
        io_base: 0x3f8,
        baud_rate: 115_200,
    };
}

/// Early framebuffer console settings.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FramebufferConsole {
    /// Physical framebuffer base.
    pub base: u64,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes per scanline.
    pub stride: u32,
}

/// Early console configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EarlyConsoleConfig {
    /// Backend selection.
    pub backend: ConsoleBackend,
    /// Serial configuration.
    pub serial: Option<SerialConsole>,
    /// Framebuffer configuration.
    pub framebuffer: Option<FramebufferConsole>,
}

impl EarlyConsoleConfig {
    /// Disabled console.
    pub const DISABLED: Self = Self {
        backend: ConsoleBackend::None,
        serial: None,
        framebuffer: None,
    };

    /// Serial-only COM1 console.
    pub const SERIAL_COM1: Self = Self {
        backend: ConsoleBackend::Serial,
        serial: Some(SerialConsole::COM1_115200),
        framebuffer: None,
    };

    /// Validates backend-specific fields.
    pub const fn validate(self) -> BootResult<()> {
        match self.backend {
            ConsoleBackend::None => Ok(()),
            ConsoleBackend::Serial => {
                if self.serial.is_some() {
                    Ok(())
                } else {
                    Err(BootError::InvalidArgument)
                }
            }
            ConsoleBackend::Framebuffer => {
                if self.framebuffer.is_some() {
                    Ok(())
                } else {
                    Err(BootError::InvalidArgument)
                }
            }
            ConsoleBackend::SerialAndFramebuffer => {
                if self.serial.is_some() && self.framebuffer.is_some() {
                    Ok(())
                } else {
                    Err(BootError::InvalidArgument)
                }
            }
        }
    }
}

/// Event severity for early boot diagnostics.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleSeverity {
    /// Verbose debug event.
    Debug,
    /// Informational event.
    Info,
    /// Recoverable warning.
    Warning,
    /// Error that may prevent boot.
    Error,
    /// Fatal condition.
    Fatal,
}

/// Data classification for an early-console message.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleDataClass {
    /// Safe for public logs.
    Public,
    /// Operational metadata.
    Operational,
    /// Sensitive content that should be redacted.
    Sensitive,
    /// Secret content that must be redacted.
    Secret,
}

/// One structured early-console event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleEvent {
    /// Monotonic sequence assigned by the event ring.
    pub sequence: u64,
    /// Boot phase associated with the event.
    pub phase: BootPhase,
    /// Event severity.
    pub severity: ConsoleSeverity,
    /// Data classification.
    pub data_class: ConsoleDataClass,
    /// Redacted or public message.
    pub message: &'static str,
}

impl ConsoleEvent {
    /// Empty event used to initialize the ring.
    pub const EMPTY: Self = Self {
        sequence: 0,
        phase: BootPhase::FirmwareEntry,
        severity: ConsoleSeverity::Debug,
        data_class: ConsoleDataClass::Public,
        message: "",
    };
}

/// Minimal writer trait for platform-specific serial/framebuffer adapters.
pub trait EarlyConsoleWriter {
    /// Writes a string to the target backend.
    fn write_str(&mut self, text: &str);
}

/// Bounded early-console ring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EarlyConsole {
    config: EarlyConsoleConfig,
    initialized: bool,
    events: [ConsoleEvent; MAX_EARLY_CONSOLE_EVENTS],
    cursor: usize,
    count: usize,
    next_sequence: u64,
}

impl EarlyConsole {
    /// Creates a disabled console with an empty event ring.
    pub const fn new() -> Self {
        Self {
            config: EarlyConsoleConfig::DISABLED,
            initialized: false,
            events: [ConsoleEvent::EMPTY; MAX_EARLY_CONSOLE_EVENTS],
            cursor: 0,
            count: 0,
            next_sequence: 1,
        }
    }

    /// Initializes the early console.
    pub fn initialize(&mut self, config: EarlyConsoleConfig) -> BootResult<()> {
        config.validate()?;
        self.config = config;
        self.initialized = true;
        Ok(())
    }

    /// Returns `true` once the console is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the active configuration.
    pub const fn config(&self) -> EarlyConsoleConfig {
        self.config
    }

    /// Number of retained events.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no events are retained.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Records a public or operational event.
    pub fn record(
        &mut self,
        phase: BootPhase,
        severity: ConsoleSeverity,
        message: &'static str,
    ) -> BootResult<()> {
        self.record_classified(phase, severity, ConsoleDataClass::Operational, message)
    }

    /// Records an event with explicit data classification.
    pub fn record_classified(
        &mut self,
        phase: BootPhase,
        severity: ConsoleSeverity,
        data_class: ConsoleDataClass,
        message: &'static str,
    ) -> BootResult<()> {
        if !self.initialized {
            return Err(BootError::EarlyConsoleNotReady);
        }
        let message = match data_class {
            ConsoleDataClass::Sensitive | ConsoleDataClass::Secret => REDACTED_MESSAGE,
            ConsoleDataClass::Public | ConsoleDataClass::Operational => message,
        };
        self.append(ConsoleEvent {
            sequence: 0,
            phase,
            severity,
            data_class,
            message,
        });
        Ok(())
    }

    /// Writes the latest event to a platform writer.
    pub fn emit_last_to<W: EarlyConsoleWriter>(&self, writer: &mut W) -> BootResult<()> {
        let event = self.last().ok_or(BootError::InvalidArgument)?;
        writer.write_str(event.message);
        Ok(())
    }

    /// Returns the latest event.
    pub fn last(&self) -> Option<ConsoleEvent> {
        if self.count == 0 {
            return None;
        }
        let index = if self.cursor == 0 {
            MAX_EARLY_CONSOLE_EVENTS - 1
        } else {
            self.cursor - 1
        };
        Some(self.events[index])
    }

    /// Returns an event by chronological index among retained entries.
    pub fn get(&self, index: usize) -> Option<ConsoleEvent> {
        if index >= self.count {
            return None;
        }
        let oldest = if self.count == MAX_EARLY_CONSOLE_EVENTS {
            self.cursor
        } else {
            0
        };
        Some(self.events[(oldest + index) % MAX_EARLY_CONSOLE_EVENTS])
    }

    fn append(&mut self, mut event: ConsoleEvent) {
        event.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.events[self.cursor] = event;
        self.cursor = (self.cursor + 1) % MAX_EARLY_CONSOLE_EVENTS;
        if self.count < MAX_EARLY_CONSOLE_EVENTS {
            self.count += 1;
        }
    }
}

impl Default for EarlyConsole {
    fn default() -> Self {
        Self::new()
    }
}
