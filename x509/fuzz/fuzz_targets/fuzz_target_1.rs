// Licensed under the Apache-2.0 license

#![no_main]

use libfuzzer_sys::fuzz_target;

mod x509_fuzz_harness;
use x509_fuzz_harness::harness;

fuzz_target!(|data: &[u8]| {
    harness(data);
});
