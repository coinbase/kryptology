//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

use bls_sigs_ref::BLSSignaturePop;
use miracl_core::{
    bls12381::{
        big::BIG, ecp::ECP, ecp2::ECP2, rom::MODULUS,
    }
};
use pairing_plus::{
    CurveProjective,
    bls12_381::{
        Fr, G1, G2,
    },
    hash_to_field::BaseFromRO,
    serdes::SerDes,
};
use rand::prelude::*;
use serious::Encoding;
use serde::Deserialize;
use sha2::digest::generic_array::GenericArray;
use structopt::StructOpt;
use std::{
    fs::File,
    io::{self, Read, Cursor},
    path::PathBuf,
};

fn main() {
    let args = CliArgs::from_args();

    match args {
        CliArgs::Generate { number } => generate(number),
        CliArgs::PublicKey { keys } => pubkey(keys),
        CliArgs::Sign { number , data} => sign(number, data),
        CliArgs::Verify { keys } => verify(keys),
    }
}

fn generate(number: usize) {
    let mut rng = thread_rng();
    print!("[");
    let mut sep = "";
    for _ in 0..number {

        let mut buf = [0u8; 48];
        rng.fill_bytes(&mut buf);
        // let mut sk = buf;
        let fr = Fr::from_okm(GenericArray::from_slice(&buf));
        let mut pk = G1::one();
        pk.mul_assign(fr);

        pk.serialize(&mut buf.as_mut(), true).unwrap();
        print!("{}\"{}\"", sep, hex::encode(buf));
        sep = ",";

        // Miracl expects 48 bytes for secret key even though the top 16 bytes are zeros
        // sk = [0u8; 48];
        // fr.serialize(&mut sk[16..].as_mut(), true).unwrap();
        // let s = BIG::frombytes(&sk[..]);
        // let x = _compress_g1(g1mul(&ECP::generator(), &s));
        //
        // println!("Miracl = {}", hex::encode(x));
    }
    print!("]");
}

/// Compress to BLS12-381 standard vs ANSI X9.62
fn _compress_g1(pk: ECP) -> [u8; 48] {
    let mut x = [0u8; 48];
    pk.getx().tobytes(&mut x);
    if pk.is_infinity() {
        // Set the second-most significant bit to indicate this point
        // is at infinity.
        x[0] |= 1 << 6;
    } else {
        let m = BIG { w: MODULUS };
        let mut negy = BIG::new();
        negy.add(&BIG::modneg(&pk.gety(), &m));
        negy.rmod(&m);
        negy.norm();
        // Set the third most significant bit if the correct y-coordinate
        // is lexicographically largest.
        if BIG::comp(&pk.gety(), &negy) == 1 {
            x[0] |= 1 << 5;
        }
    }
    // Set highest bit to distinguish this as a compressed element.
    x[0] |= 1 << 7;
    x
}

fn _compress_g2(sig: ECP2) -> [u8; 96] {
    let mut x = [0u8; 96];
    sig.getx().geta().tobytes(&mut x[..48]);
    sig.getx().getb().tobytes(&mut x[48..]);
    if sig.is_infinity() {
        // Set the second-most significant bit to indicate this point
        // is at infinity.
        x[0] |= 1 << 6;
    } else {
        let mut negy = sig.clone();
        negy.neg();

        // Set the third most significant bit if the correct y-coordinate
        // is lexicographically largest.
        negy.sub(&sig);

        if negy.gety().sign() > 0 {
            x[0] |= 1 << 5;
        }
    }
    // Set highest bit to distinguish this as a compressed element.
    x[0] |= 1 << 7;
    x
}

fn pubkey(keys: String) {
    let res = read_input(&keys).unwrap();

    for pubkey in serde_json::from_slice::<Vec<String>>(&res).unwrap() {
        let res = hex::decode(&pubkey);
        if res.is_err() {
            println!("Invalid hex format {}", res.unwrap_err());
            continue;
        }
        let mut key = res.unwrap();
        let mut cur = Cursor::new(key.as_slice());
        print!("ZCash  {} - ", pubkey);
        let res = G1::deserialize(&mut cur, true);

        if let Err(e) = res {
            println!("fail - {}", e);
        } else {
            println!("pass");
        }

        let res = _uncompress_g1(key.as_mut_slice());

        print!("Miracl {} - ", pubkey);
        if let Err(e) = res {
            println!("fail - {}", e);
        } else {
            println!("pass");
        }
    }
}

fn _uncompress_g1(d: &[u8]) -> Result<ECP, String> {
    if d.len() != 48 {
        return Err("Invalid length".to_string());
    }

    if d[0] & 0x80 != 0x80 {
        return Err("Expected compressed point".to_string());
    }

    // Expect point at infinity
    if d[0] & 0x40 == 0x40 {
        return if !d.iter().skip(1).all(|b| *b == 0) {
            Err("Expected point at infinity but found another point".to_string())
        } else {
            Ok(ECP::new())
        }
    }

    let s = d[0] & 0x20;
    // Unset top bits
    let mut dd = [0u8; 48];
    dd.copy_from_slice(d);
    dd[0] &= 0x1F;
    let x = BIG::frombytes(&dd);
    Ok(ECP::new_bigint(&x, s as isize))
}

fn _uncompress_g2(d: &[u8]) -> Result<ECP2, String> {
    if d.len() != 96 {
        return Err("Invalid length".to_string());
    }

    if d[0] & 0x80 != 0x80 {
        return Err("Expected compressed point".to_string());
    }

    // Expect point at infinity
    if d[0] & 0x40 == 0x40 {
        return if !d.iter().skip(1).all(|b| *b == 0) {
            Err("Expected point at infinity but found another point".to_string())
        } else {
            Ok(ECP2::new())
        }
    }

    let s = d[0] & 0x20;
    let mut dd = [0u8; 97];
    dd[1..].copy_from_slice(d);
    dd[1] &= 0x1F;
    // Unset top bits
    dd[0] = if s > 0 { 0x3 } else { 0x2 };
    Ok(ECP2::frombytes(&dd))
}

fn sign(number: usize, data: String) {
    let mut rng = thread_rng();
    let bytes = data.as_bytes();
    let mut sep = "";
    print!("[");
    for _ in 0..number {
        let mut buf = [0u8; 48];
        rng.fill_bytes(&mut buf);
        let fr = Fr::from_okm(GenericArray::from_slice(&buf));
        let mut pk = G1::one();
        pk.mul_assign(fr);

        let mut pubkey = [0u8; 48];
        pk.serialize(&mut pubkey.as_mut(), true).unwrap();

        let signature = G2::sign(fr, bytes);
        let mut sig = [0u8; 96];
        signature.serialize(&mut sig.as_mut(), true).unwrap();

        print!("{}{{", sep);
        print!(r#""data":"{}","#, data);
        print!(r#""public_key":"{}","#, Encoding::encode(pubkey, Encoding::LowHex).into_string());
        print!(r#""signature":"{}""#, Encoding::encode(sig, Encoding::LowHex).into_string());
        print!("}}");
        sep = ",";
    }
    print!("]");
}

fn verify(keys: String) {
    let res = read_input(&keys).unwrap();

    for req in serde_json::from_slice::<Vec<VerifyRequest>>(&res).unwrap() {
        let pubkey = Encoding::decode(&req.public_key, Encoding::LowHex).unwrap();
        let sig = Encoding::decode(&req.signature, Encoding::LowHex).unwrap();
        let mut cur = Cursor::new(pubkey.as_slice());
        let verkey = G1::deserialize(&mut cur, true).unwrap();
        cur = Cursor::new(sig.as_slice());
        let signature = G2::deserialize(&mut cur, true).unwrap();

        print!("ZCash  {} - ", req.public_key);
        if G2::verify(verkey, signature, req.data.as_bytes()) {
            println!("pass");
        } else {
            println!("fail");
        }
    }
}

#[derive(Debug, StructOpt)]
enum CliArgs {
    Generate {
        #[structopt(short, long)]
        number: usize,
    },
    PublicKey {
        #[structopt(name = "KEYS")]
        keys: String,
    },
    Sign {
        #[structopt(short, long)]
        number: usize,
        #[structopt(short, long)]
        data: String,
    },
    Verify {
        #[structopt(name = "KEYS")]
        keys: String,
    }
}

#[derive(Deserialize)]
struct VerifyRequest {
    data: String,
    public_key: String,
    signature: String
}

fn read_input(value: &str) -> Result<Vec<u8>, String> {
    if !value.is_empty() {
        match get_file(value) {
            Some(file) => {
                match File::open(file.as_path()) {
                    Ok(mut f) => {
                        Ok(read_stream(&mut f))
                    },
                    Err(_) => {
                        Err(format!("Unable to read file {}", file.to_str().unwrap()))
                    }
                }
            }
            None => {
                Ok(value.as_bytes().to_vec())
            }
        }
    } else {
        let mut f = io::stdin();
        Ok(read_stream(&mut f))
    }
}

fn read_stream<R: Read>(f: &mut R) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];

    let mut read = f.read(&mut buffer);
    while read.is_ok() {
        let n = read.unwrap();

        if n == 0 {
            break;
        }

        bytes.extend_from_slice(&buffer[..n]);

        read = f.read(&mut buffer);
    }

    bytes
}

fn get_file(name: &str) -> Option<PathBuf> {
    if name.len() > 256 {
        // too long to be a file
        return None;
    }
    let mut file = PathBuf::new();
    file.push(name);
    if file.as_path().is_file() {
        let metadata = file
            .as_path()
            .symlink_metadata()
            .expect("symlink_metadata call failed");
        if metadata.file_type().is_symlink() {
            if let Ok(f) = file.as_path().read_link() {
                file = f
            } else {
                return None;
            }
        }
        Some(file)
    } else {
        None
    }
}


// fn from_encoding(src: &str) -> Result<Encoding, std::io::Error> {
//    Encoding::parse(src).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
// }

// fn hash_to_g2(d: &[u8]) -> ECP2 {
//     const DST: &'static str = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
//     let y = <G2 as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(d.as_ref(), DST);
//     let mut d = [0u8; 193];
//     d[0] = 0x4;
//     y.serialize(&mut d[1..].as_mut(), false);
//     ECP2::frombytes(&d)
// }

// fn ceil(a: usize, b: usize) -> usize {
//     (a-1)/b+1
// }
//
// fn hash_to_field(hash: usize, hlen: usize, u: &mut [FP2], dst: &[u8], m: &[u8], ctr: usize) {
//     let q = BIG { w: MODULUS };
//     let el = ceil(q.nbits()+AESKEY*16, 8);
//
//     let mut okm = [0u8; 512];
//     let mut fd = [0u8; 256];
//     xmd_expand(hash, hlen, &mut okm, el*ctr, &dst, &m);
//     u[0] = FP2::new_fps(
//         &FP::new_big(&DBIG::frombytes(&okm[0..el]).dmod(&q)),
//         &FP::new_big(&DBIG::frombytes(&okm[el..(2*el)]).dmod(&q))
//     );
//     u[1] = FP2::new_fps(
//         &FP::new_big(&DBIG::frombytes(&okm[(2*el)..(3*el)]).dmod(&q)),
//         &FP::new_big(&DBIG::frombytes(&okm[(3*el)..]).dmod(&q))
//     );
// }
//
// fn hash_to_ecp2(m: &[u8]) -> ECP2 {
//     let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
//     let mut u = [FP2::new(); 2];
//     hash_to_field(hmac::MC_SHA2, ecp::HASH_TYPE, &mut u, &dst[..], m, 2);
//
//     let mut p = ECP2::map2point(&u[0]);
//     let q = ECP2::map2point(&u[1]);
//     p.add(&q);
//     p.cfp();
//     p.affine();
//     p
// }