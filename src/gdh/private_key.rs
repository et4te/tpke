use rust_pbc::{Element, ElementPP, Group, Pairing};

use gdh::share::EncryptedShare;

pub struct PrivateKey {
    pub l: u32,
    pub k: u32,
    pub sk: Element,
    pub i: u32,
}

impl PrivateKey {
    pub fn decrypt_share(&self, pairing: &Pairing, uvw: &EncryptedShare) -> Element {
        let mut pp = ElementPP::new();

        // u_i = u ^ self.sk
        let mut u_i = Element::new(Group::G1, pairing);
        pp.init(&uvw.u);
        pp.pow_zn(&mut u_i, &self.sk);
        u_i
    }
}
