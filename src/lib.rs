extern crate byteorder;

use std::fmt;
use std::error;
use byteorder::{ByteOrder, LittleEndian};

pub struct GostKey(pub [u32; 8]);

#[derive(Debug, PartialEq, Eq)]
pub enum GostError {
    NotDivisorOf8,
    DifferentLength,
}

impl fmt::Display for GostError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;
        write!(f, "{}", self.description())
        /*match *self {
            GostError::NotDivisorOf8 => write!(f, "source data length must be divisor of 8"),
        }*/
    }
}

impl error::Error for GostError {
    fn description(&self) -> &str {
        match *self {
            GostError::NotDivisorOf8 => "source data length must be divisor of 8",
            GostError::DifferentLength => "source and destination have different lengths",
        }
    }
}

#[allow(dead_code)]
const SBOX: [[u8; 16]; 8] = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];


#[allow(dead_code)]
#[inline]
fn __magma_round_slow(l: &mut u32, r: &mut u32, key: u32) {
    let t = l.overflowing_add(key).0;
    let mut x: u32 = 0;

    for i in 0..8 {
        x ^= (SBOX[i][((t >> i * 4) & 0xf) as usize] as u32) << 4 * i;
    }
    *r ^= x.rotate_left(11);
}

mod table;

fn __magma_round(l: &mut u32, r: &mut u32, key: u32) {
    let t = l.overflowing_add(key).0 as usize;

    for i in 0..4 {
        *r ^= table::SBOX_LONG[256 * i + ((t >> 8 * i) & 0xff)];
    }
}

pub fn magma_round(l: &mut u32, r: &mut u32, key: u32) {
    __magma_round(l, r, key);
    std::mem::swap(l, r);
}

#[inline]
fn forward_cycle(l: &mut u32, r: &mut u32, key: &GostKey) {
    for i in 0..4 {
        __magma_round(l, r, key.0[2 * i    ]);
        __magma_round(r, l, key.0[2 * i + 1]);
    }
}

#[inline]
fn backward_cycle(l: &mut u32, r: &mut u32, key: &GostKey) {
    for i in 0..4 {
        __magma_round(l, r, key.0[7 - 2 * i]);
        __magma_round(r, l, key.0[6 - 2 * i]);
    }
}

#[inline]
fn __magma_encrypt_block(l: &mut u32, r: &mut u32, key: &GostKey) {
    forward_cycle(l, r, key);
    forward_cycle(l, r, key);
    forward_cycle(l, r, key);
    backward_cycle(l, r, key);
}

pub fn magma_encrypt_block(block: u64, key: &GostKey) -> u64 {
    let mut l: u32 = (block & std::u32::MAX as u64) as u32;
    let mut r: u32 = (block >> 32) as u32;
    __magma_encrypt_block(&mut l, &mut r, key);
    r as u64 | ((l as u64) << 32)
}

#[inline]
fn __magma_decrypt_block(l: &mut u32, r: &mut u32, key: &GostKey) {
    forward_cycle(l, r, key);
    backward_cycle(l, r, key);
    backward_cycle(l, r, key);
    backward_cycle(l, r, key);
}

pub fn magma_decrypt_block(block: u64, key: &GostKey) -> u64 {
    let mut l: u32 = (block & std::u32::MAX as u64) as u32;
    let mut r: u32 = (block >> 32) as u32;
    __magma_decrypt_block(&mut l, &mut r, key);
    r as u64 | ((l as u64) << 32)
}

pub fn magma_encrypt_ecb(src: &[u8], dst: &mut [u8], key: &GostKey) -> Result<(), GostError> {
    if src.len() % 8 != 0 { return Err(GostError::NotDivisorOf8) }
    if src.len() != dst.len() { return Err(GostError::DifferentLength) }
    let len = src.len() / 8;

    for i in 0..len {
        LittleEndian::write_u64(
            &mut dst[8*i..8*(i+1)],
            magma_encrypt_block(LittleEndian::read_u64(&src[8*i..8*(i+1)]), key)
        );
    }

    Ok(())
}

pub fn magma_decrypt_ecb(src: &[u8], dst: &mut [u8], key: &GostKey) -> Result<(), GostError> {
    if src.len() % 8 != 0 { return Err(GostError::NotDivisorOf8) }
    if src.len() != dst.len() { return Err(GostError::DifferentLength) }

    let len = src.len() / 8;

    for i in 0..len {
        LittleEndian::write_u64(
            &mut dst[8*i..8*(i+1)],
            magma_decrypt_block(LittleEndian::read_u64(&src[8*i..8*(i+1)]), key)
        );
    }

    Ok(())
}

pub fn magma_encrypt_gamma(src: &[u8], dst: &mut [u8], key: &GostKey, iv: u32) -> Result<(), GostError> {
    if src.len() != dst.len() { return Err(GostError::DifferentLength) }
    
    let len = src.len();

    let mut ctr = (iv as u64) << 32;

    for i in 0..len / 8 {
        let gamma = magma_encrypt_block(ctr, key);
        ctr += 1;
        LittleEndian::write_u64(
            &mut dst[8*i..8*(i+1)],
            LittleEndian::read_u64(&src[8*i..8*(i+1)]) ^ gamma
        );
    }
    if len % 8 > 0 {
        let rest = len % 8;
        let gamma = magma_encrypt_block(ctr, key);
        let t = LittleEndian::read_uint(&src[len / 8 * 8..], rest);
        let enc = (t ^ gamma) & ((1u64 << rest * 8) - 1);
        LittleEndian::write_uint(&mut dst[len / 8 * 8..], enc, rest);
    }
    Ok(())
}

pub fn magma_decrypt_gamma(src: &[u8], dst: &mut [u8], key: &GostKey, iv: u32) -> Result<(), GostError> {
    magma_encrypt_gamma(src, dst, key, iv)
}
