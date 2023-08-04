// Licensed under the Apache-2.0 license

use std::mem::size_of;

use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature};
use openssl::x509::X509;

pub fn harness(data: &[u8]) {
    let tbs: &[u8];
    let sig: &Ecdsa384Signature;

    if data.len() < size_of::<Ecdsa384Signature>() {
        return;
    }

    unsafe {
        tbs = &data[size_of::<Ecdsa384Signature>()..];
        sig = &*(data.as_ptr() as *const Ecdsa384Signature);
    }

    let builder = Ecdsa384CertBuilder::new(tbs, sig).unwrap();
    let mut buf = vec![0u8; builder.len()];
    if builder.build(&mut buf) == None {
        return;
    }

    // NB: This assumes that if x509 is returned, it is valid.
    // - Currently, that's not the case. This *will* panic.
    let cert = X509::from_der(&buf).unwrap();
    //assert!(cert.unwrap().verify(issuer_key.priv_key()).unwrap());
}
