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

use caliptra_drivers::{Lms, Sha256SoftwareDriver};
use caliptra_lms_types::{LmsPublicKey, LmsSignature};

pub const SHA256_DIGEST_WORD_SIZE: usize = 8;
// TODO: When using SHA256_DIGEST_WORD_SIZE, these tend to accompany?
pub const LOCAL_P: usize = 34;
pub const LOCAL_H: usize = 5;

#[cfg(feature = "struct-aware")]
#[derive(arbitrary::Arbitrary, Debug)]
struct StructuredInput<'a> {
    pub_key: LmsPublicKey<SHA256_DIGEST_WORD_SIZE>,
    sig: LmsSignature<SHA256_DIGEST_WORD_SIZE, LOCAL_P, LOCAL_H>,
    input: &'a [u8],
}

#[cfg(feature = "struct-aware")]
fn harness_structured(args: StructuredInput) {
    let _result = Lms::default().verify_lms_signature(&mut Sha256SoftwareDriver::new(), args.input, &args.pub_key, &args.sig);
}

#[cfg(not(feature = "struct-aware"))]
fn harness_unstructured(data: &[u8]) {
    let pub_key: &LmsPublicKey<SHA256_DIGEST_WORD_SIZE>;
    let sig: &LmsSignature<SHA256_DIGEST_WORD_SIZE, LOCAL_P, LOCAL_H>;
    let input: &[u8];

    if data.len() < (size_of::<LmsPublicKey<SHA256_DIGEST_WORD_SIZE>>() + size_of::<LmsSignature<SHA256_DIGEST_WORD_SIZE, LOCAL_P, LOCAL_H>>()) {
        return;
    }

    // TODO: The corpus may be seeded with (pub_key, sig), so parse the data as these first
    let input_start = data.len() - (size_of::<LmsPublicKey<SHA256_DIGEST_WORD_SIZE>>() + size_of::<LmsSignature<SHA256_DIGEST_WORD_SIZE, LOCAL_P, LOCAL_H>>());
    unsafe {
        pub_key = &*(data.as_ptr() as *const LmsPublicKey<SHA256_DIGEST_WORD_SIZE>);
        sig = &*(data[size_of::<LmsPublicKey<SHA256_DIGEST_WORD_SIZE>>()..].as_ptr() as *const LmsSignature<SHA256_DIGEST_WORD_SIZE, LOCAL_P, LOCAL_H>);
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
