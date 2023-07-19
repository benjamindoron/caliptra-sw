// Licensed under the Apache-2.0 license

#![no_main]

use libfuzzer_sys::fuzz_target;

mod image_verify_fuzz_harness;
use caliptra_drivers::ResetReason::*;
use image_verify_fuzz_harness::harness_unstructured;

fuzz_target!(|data: &[u8]| {
    harness_unstructured(ColdReset, data);
});
