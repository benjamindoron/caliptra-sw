// Licensed under the Apache-2.0 license

use afl::fuzz;

mod x509_fuzz_harness;
use x509_fuzz_harness::harness;

fn main() {
    fuzz!(|data: &[u8]| {
        harness(data);
    });
}
