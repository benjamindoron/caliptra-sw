// Licensed under the Apache-2.0 license

use afl::fuzz;

mod image_verify_fuzz_harness;
use caliptra_drivers::ResetReason::*;
use image_verify_fuzz_harness::harness_unstructured;

fn main() {
    fuzz!(|data: &[u8]| {
        harness_unstructured(UpdateReset, data);
    });
}
