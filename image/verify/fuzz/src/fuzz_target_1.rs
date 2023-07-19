// Licensed under the Apache-2.0 license

#![cfg_attr(feature = "libfuzzer-sys", no_main)]

#[cfg(all(not(feature = "libfuzzer-sys"), not(feature = "afl")))]
compile_error!("Either feature \"libfuzzer-sys\" or \"afl\" must be enabled!");

#[cfg(feature = "libfuzzer-sys")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "afl")]
use afl::fuzz;

mod fuzz_target_common;
use caliptra_drivers::ResetReason::*;
use caliptra_image_types::ImageManifest;
use fuzz_target_common::{harness_unstructured, harness_structured};

// cargo-fuzz target
#[cfg(all(feature = "libfuzzer-sys", not(feature = "struct-aware")))]
fuzz_target!(|data: &[u8]| {
    harness_unstructured(ColdReset, data);
});

#[cfg(all(feature = "libfuzzer-sys", feature = "struct-aware"))]
fuzz_target!(|data: ImageManifest| {
    harness_structured(ColdReset, data);
});

// cargo-afl target
#[cfg(all(feature = "afl", not(feature = "struct-aware")))]
fn main() {
    fuzz!(|data: &[u8]| {
        harness_unstructured(ColdReset, data);
    });
}

#[cfg(all(feature = "afl", feature = "struct-aware"))]
fn main() {
    fuzz!(|data: ImageManifest| {
        harness_structured(ColdReset, data);
    });
}
