use rust_pbc::Element;

// A share is an element in G1
pub type Share = Element;

// An encrypted share in G1
pub struct EncryptedShare {
    pub u: Element,
    pub v: Vec<u8>,
    pub w: Element,
}

impl EncryptedShare {
    pub fn new(u: Element, v: Vec<u8>, w: Element) -> EncryptedShare {
        EncryptedShare { u: u, v: v, w: w }
    }
}
