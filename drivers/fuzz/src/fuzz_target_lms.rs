// Licensed under the Apache-2.0 license

#![cfg_attr(feature = "libfuzzer-sys", no_main)]

#[cfg(all(not(feature = "libfuzzer-sys"), not(feature = "afl")))]
compile_error!("Either feature \"libfuzzer-sys\" or \"afl\" must be enabled!");

#[cfg(feature = "libfuzzer-sys")]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "afl")]
use afl::fuzz;

use std::mem::size_of;

use caliptra_drivers::{Lms, Sha256SoftwareDriver};
use caliptra_lms_types::{LmsPublicKey, LmsSignature};

pub const SHA256_DIGEST_WORD_SIZE: usize = 8;
// TODO: When using SHA256_DIGEST_WORD_SIZE, these will accompany?
pub const LOCAL_P: usize = 34;
pub const LOCAL_H: usize = 5;

fn harness(data: &[u8]) {
    let input: &[u8];
    let pub_key: &LmsPublicKey<SHA256_DIGEST_WORD_SIZE>;
    let sig: &LmsSignature<SHA256_DIGEST_WORD_SIZE, LOCAL_P, LOCAL_H>;

    // Note that this is a large minimum, but working in theory
    if data.len() < (size_of::<LmsPublicKey<SHA256_DIGEST_WORD_SIZE>>() + size_of::<LmsSignature<SHA256_DIGEST_WORD_SIZE, LOCAL_P, LOCAL_H>>()) {
        return;
    }

    // TODO: Alternatively, use structure-aware fuzzing, input comprising arguments
    unsafe {
        input = &data[(size_of::<LmsPublicKey<SHA256_DIGEST_WORD_SIZE>>() + size_of::<LmsSignature<SHA256_DIGEST_WORD_SIZE, LOCAL_P, LOCAL_H>>())..];
        pub_key = &*(data.as_ptr() as *const LmsPublicKey<SHA256_DIGEST_WORD_SIZE>);
        sig = &*(data[size_of::<LmsPublicKey<SHA256_DIGEST_WORD_SIZE>>()] as *const LmsSignature<SHA256_DIGEST_WORD_SIZE, LOCAL_P, LOCAL_H>);
    }

    let _result = Lms::default().verify_lms_signature(&mut Sha256SoftwareDriver::new(), input, pub_key, sig);
}

// cargo-fuzz target
#[cfg(feature = "libfuzzer-sys")]
fuzz_target!(|data: &[u8]| {
    harness(data);
});

// cargo-afl target
#[cfg(feature = "afl")]
fn main() {
    fuzz!(|data: &[u8]| {
        harness(data);
    });
}
