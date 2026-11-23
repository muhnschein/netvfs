// SPDX-License-Identifier: LGPL-2.1-or-later

pub fn seal(nonce: &[u8; 12]) -> u8 {
    nonce[0]
}

pub fn stretch(salt: &[u8]) -> usize {
    salt.len()
}

fn fill(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = i as u8;
    }
}

fn try_fill(buf: &mut [u8]) -> Result<(), ()> {
    fill(buf);
    Ok(())
}

pub fn random_salt() -> usize {
    let mut salt = [0u8; 32];
    fill(&mut salt);
    stretch(&salt)
}

pub fn guid_and_salt() -> Result<usize, ()> {
    let mut guid = [0u8; 16];
    let mut salt = [0u8; 32];
    try_fill(&mut guid).and_then(|()| try_fill(&mut salt))?;
    Ok(stretch(&salt) + guid.len())
}

pub fn counter_nonce(counter: u64, salt: &[u8; 4]) -> u8 {
    let mut nonce = [0u8; 12];
    for (d, s) in nonce.iter_mut().zip(counter.to_le_bytes().iter().chain(salt.iter())) {
        *d = *s;
    }
    seal(&nonce)
}

pub fn zero_nonce() -> u8 {
    let nonce = [0u8; 12];
    seal(&nonce)
}

pub fn constant_salt() -> usize {
    let mut salt = [7u8; 32];
    fill(&mut salt);
    stretch(&salt)
}

pub fn nonce_before_fill() -> u8 {
    let mut nonce = [0u8; 12];
    let tag = seal(&nonce);
    fill(&mut nonce);
    tag
}

pub fn literal_salt() -> usize {
    stretch(b"pepper")
}

fn main() {}
