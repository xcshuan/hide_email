// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::vec::Vec;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{ckb_constants::Source, debug, high_level::load_witness_args};

use crate::error::Error;

use ark_bn254::{Bn254 as E, Fr};
use ark_ff::bytes::FromBytes;
use ark_serialize::*;
use zkp_groth16::{prepare_verifying_key, verify_proof, Proof, VerifyKey};

pub fn transform_public_input_flatten(input: &[u8]) -> Vec<Fr> {
    input
        .chunks(32)
        .map(|bytes| {
            Fr::read(&bytes[..]).expect("pack hash as field element")
        })
        .collect()
}

pub fn main() -> Result<(), Error> {
    let witness = load_witness_args(0, Source::GroupInput)?;

    // 存放证明
    let lock_type = witness.lock();
    // 存放verify_key
    let input_type = witness.input_type();
    // 存放公共输入
    let output_type = witness.output_type();

    debug!("1");
    if let (Some(proof_bytes), Some(vk_bytes), Some(public_input)) = (
        lock_type.to_opt(),
        input_type.to_opt(),
        output_type.to_opt(),
    ) {
        debug!("2");
        let vk2 = VerifyKey::<E>::deserialize(vk_bytes.raw_data().as_ref()).unwrap();
        let proof2 = Proof::<E>::deserialize(proof_bytes.raw_data().as_ref()).unwrap();
        let pvk2 = prepare_verifying_key(&vk2);
        debug!("3");
        let res = verify_proof(
            &pvk2,
            &proof2,
            &transform_public_input_flatten(&public_input.raw_data()),
        )
        .ok();
        debug!("4");
        if let Some(res) = res {
            if res {
                return Ok(());
            }
        }
    }

    Err(Error::Encoding)
}
