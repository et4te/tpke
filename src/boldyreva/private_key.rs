use rust_pbc::{Element, ElementPP, Group, Pairing};

use boldyreva::signature::Signature;

pub struct PrivateKey {
    pub l: u32,
    pub k: u32,
    pub sk: Element,
    pub i: u32,
}

impl PrivateKey {
    pub fn sign(&mut self, pairing: &Pairing, h: &Element) -> Signature {
        let mut pp = ElementPP::new();

        // r = h ^ self.sk
        let mut r = Element::new(Group::G1, pairing);
        pp.init(&h);
        pp.pow_zn(&mut r, &mut self.sk);
        r
    }
}
