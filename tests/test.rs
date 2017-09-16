extern crate magma;

#[allow(non_upper_case_globals)]
const key: &magma::GostKey = &magma::GostKey ([
    0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
    0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
]);

#[allow(non_upper_case_globals)]
const text: [u8; 32] = [
    0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
    0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
    0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
    0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89,
];

#[allow(non_upper_case_globals)]
const ecb_text: [u8; 32] = [
    0xa0, 0x72, 0xf3, 0x94, 0x04, 0x3f, 0x07, 0x2b,
    0x48, 0x6e, 0x55, 0xd3, 0x15, 0xe7, 0x70, 0xde,
    0x1e, 0xbc, 0xcf, 0xea, 0xe9, 0xd9, 0xd8, 0x11,
    0xfb, 0x7e, 0xc6, 0x96, 0x09, 0x26, 0x68, 0x7c,
];

#[test]
fn test_round() {
    let mut l: u32 = 0x76543210;
    let mut r: u32 = 0xfedcba98;
    let iter_key = 0xffeeddcc;
    magma::magma_round(&mut l, &mut r, iter_key);
    assert_eq!(l, 0x28da3b14);
    assert_eq!(r, 0x76543210);
}

#[test]
fn test_block_encrypt() {
    assert_eq!(magma::magma_encrypt_block(0xfedcba9876543210, key), 0x4ee901e5c2d8ca3d);
}

#[test]
fn test_block_decrypt() {
    assert_eq!(magma::magma_decrypt_block(0x4ee901e5c2d8ca3d, key), 0xfedcba9876543210);
}

#[test]
fn test_ecb_encrypt() {
    let mut buf = [0u8; 32];
    assert_eq!(magma::magma_encrypt_ecb(&text, &mut buf, key), Ok(()));
    assert_eq!(buf, ecb_text);
    assert_eq!(magma::magma_encrypt_ecb(&text[1..], &mut buf[1..], key), Err(magma::GostError::NotDivisorOf8));
    assert_eq!(magma::magma_encrypt_ecb(&text[8..], &mut buf, key), Err(magma::GostError::DifferentLength));
}

#[test]
fn test_ecb_decrypt() {
    let mut buf = [0u8; 32];
    assert_eq!(magma::magma_decrypt_ecb(&ecb_text, &mut buf, key), Ok(()));
    assert_eq!(buf, text);
    assert_eq!(magma::magma_decrypt_ecb(&ecb_text[1..], &mut buf[1..], key), Err(magma::GostError::NotDivisorOf8));
    assert_eq!(magma::magma_decrypt_ecb(&ecb_text[8..], &mut buf, key), Err(magma::GostError::DifferentLength));
}
