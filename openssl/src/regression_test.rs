use std::fs::File;
use std::io::Write;

use crate::ec::{Asn1Flag, EcGroup, EcKey};
use crate::hash::MessageDigest;
use crate::nid::Nid;
use crate::pkey::{self, PKey};
use crate::stack::Stack;
use crate::x509::extension::SubjectAlternativeName;
use crate::x509::{X509Req, X509ReqBuilder, X509};

fn ec_group(nid: Nid) -> EcGroup {
    let mut g = EcGroup::from_curve_name(nid).expect("EcGroup");
    // this is required for openssl 1.0.x (but not 1.1.x)
    g.set_asn1_flag(Asn1Flag::NAMED_CURVE);
    g
}

fn create_csr(pkey: &PKey<pkey::Private>, domains: &[&str]) -> X509Req {
    //
    // the csr builder
    let mut req_bld = X509ReqBuilder::new().expect("X509ReqBuilder");

    // set private/public key in builder
    req_bld.set_pubkey(pkey).expect("set_pubkey");

    // set all domains as alt names
    let mut stack = Stack::new().expect("Stack::new");
    let ctx = req_bld.x509v3_context(None);
    let as_lst = domains
        .iter()
        .map(|&e| format!("DNS:{}", e))
        .collect::<Vec<_>>()
        .join(",");
    let as_lst = as_lst[4..].to_string();
    let mut an = SubjectAlternativeName::new();
    an.dns(&as_lst);
    let ext = an.build(&ctx).expect("SubjectAlternativeName::build");
    stack.push(ext).expect("Stack::push");
    req_bld.add_extensions(&stack).expect("add_extensions");

    // sign it
    req_bld
        .sign(pkey, MessageDigest::sha256())
        .expect("csr_sign");
    // the csr
    req_bld.build()
}

#[test]
fn x509_extension_to_der_full() {
    let builder = X509::builder().unwrap();

    let group = ec_group(Nid::SECP384R1);
    let pri_key_ec = EcKey::generate(&group).expect("EcKey");
    let pkey = PKey::from_ec_key(pri_key_ec).expect("from_ec_key");

    let csr = create_csr(&pkey, &["*.example.com", "example.com"]);

    let csr_der = csr.to_der().expect("to_der()");
    let mut file = File::create("csr.der").unwrap();
    file.write_all(&csr_der).unwrap();
}
