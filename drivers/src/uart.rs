/*++

Licensed under the Apache-2.0 license.

File Name:

    uart.rs

Abstract:

    File contains API for accessing the UART

--*/

use core::{fmt, ptr};

/// Caliptra UART
#[derive(Default)]
pub struct Uart {}

impl Uart {
    /// Create an instance of Caliptra UART
    pub fn new() -> Self {
        Self {}
    }

    /// Write the string to UART
    ///
    /// # Arguments
    ///
    /// `str` - String to write to UART
    pub fn write(&mut self, str: &str) {
        for byte in str.bytes() {
            match byte {
                0x20..=0x7e | b'\n' | b'\t' => self.write_byte(byte),
                _ => self.write_byte(0xfe),
            }
        }
    }

    /// Write the byte to UART
    ///
    /// # Arguments
    ///
    /// `byte` - Byte to write to UART
    pub fn write_byte(&mut self, byte: u8) {
        // TODO: cleanup after final UART RTL definition is in place
        const STDOUT: *mut u32 = 0x3003_00A8 as *mut u32;
        unsafe {
            ptr::write_volatile(STDOUT, byte as u32);
        }
    }
}

impl fmt::Write for Uart {
    /// Writes a [`char`] into this writer, returning whether the write succeeded.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s);
        Ok(())
    }
}
