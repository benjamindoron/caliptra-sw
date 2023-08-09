// Licensed under the Apache-2.0 license

#![cfg_attr(feature = "libfuzzer-sys", no_main)]

#[cfg(all(not(feature = "libfuzzer-sys"), not(feature = "afl")))]
compile_error!("Either feature \"libfuzzer-sys\" or \"afl\" must be enabled!");

#[cfg(feature = "libfuzzer-sys")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "afl")]
use afl::fuzz;

#[cfg(not(feature = "struct-aware"))]
use std::mem::size_of;

use caliptra_drivers::Lms;
mod sha256;
use sha256::Sha256SoftwareDriver;

// For consistency with the ROM, use its type definitions
use caliptra_image_types::{ImageLmsPublicKey, ImageLmsSignature};

#[cfg(feature = "struct-aware")]
#[derive(arbitrary::Arbitrary, Debug)]
struct StructuredInput<'a> {
    pub_key: ImageLmsPublicKey,
    sig: ImageLmsSignature,
    input: &'a [u8],
}

#[cfg(feature = "struct-aware")]
fn harness_structured(args: StructuredInput) {
    let _result = Lms::default().verify_lms_signature(&mut Sha256SoftwareDriver::new(), args.input, &args.pub_key, &args.sig);
}

#[cfg(not(feature = "struct-aware"))]
fn harness_unstructured(data: &[u8]) {
    let pub_key: &ImageLmsPublicKey;
    let sig: &ImageLmsSignature;
    let input: &[u8];

    if data.len() < (size_of::<ImageLmsPublicKey>() + size_of::<ImageLmsSignature>()) {
        return;
    }

    // The corpus is seeded with (pub_key, sig, input), so parse the data in this order
    let input_start = data.len() - (size_of::<ImageLmsPublicKey>() + size_of::<ImageLmsSignature>());
    unsafe {
        pub_key = &*(data.as_ptr() as *const ImageLmsPublicKey);
        sig = &*(data[size_of::<ImageLmsPublicKey>()..].as_ptr() as *const ImageLmsSignature);
        input = &data[input_start..];
    }

    let _result = Lms::default().verify_lms_signature(&mut Sha256SoftwareDriver::new(), input, pub_key, sig);
}

// cargo-fuzz target
#[cfg(all(feature = "libfuzzer-sys", not(feature = "struct-aware")))]
fuzz_target!(|data: &[u8]| {
    harness_unstructured(data);
});

#[cfg(all(feature = "libfuzzer-sys", feature = "struct-aware"))]
fuzz_target!(|data: StructuredInput| {
    harness_structured(data);
});

// cargo-afl target
#[cfg(all(feature = "afl", not(feature = "struct-aware")))]
fn main() {
    fuzz!(|data: &[u8]| {
        harness_unstructured(data);
    });
}

#[cfg(all(feature = "afl", feature = "struct-aware"))]
fn main() {
    fuzz!(|data: StructuredInput| {
        harness_structured(data);
    });
}
