use substring::{params, utils::generate_circuit_instance};

use super::*;
use ark_bn254::Bn254 as E;
use ark_serialize::*;
use ark_std::test_rng;
use ckb_groth16::{
    create_random_proof, generate_random_parameters, verifier::prepare_verifying_key, verify_proof,
    Proof, VerifyKey,
};
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use std::time::Instant;

const MAX_CYCLES: u64 = 1_000_000_000_000;

#[test]
fn test_verify() {
    // deploy contract
    let mut context = Context::default();
    let email_contract_bin: Bytes = Loader::default().load_binary("hide_email");
    let email_out_point = context.deploy_cell(email_contract_bin);

    // prepare scripts
    let type_script = context
        .build_script(&email_out_point, Bytes::default())
        .expect("script");

    println!("hash_type: {}", type_script.hash_type().as_bytes()[0]);

    let type_script_dep = CellDep::new_builder().out_point(email_out_point).build();

    let always_success_bin = ALWAYS_SUCCESS.clone();
    let always_success_out_point = context.deploy_cell(always_success_bin);

    // prepare scripts
    let lock_script = context
        .build_script(&always_success_out_point, Bytes::from(vec![41]))
        .expect("script");
    let lock_script_dep = CellDep::new_builder()
        .out_point(always_success_out_point)
        .build();

    let rng = &mut test_rng();

    let padding = "0"; // must be single char, or else fill it to MAX_HASH_PREIMAGE_LENGTH
    let secret = "christian.schneider@androidloves.me";
    let mut padding_message = "from:Christian Schneider Christian Schneider Christian Schneider <christian.schneider@androidloves.me>\r\nsubject:this is a test mail\r\ndate:Sat, 14 Mar 2020 21:48:57 +0100\r\nmessage-id:<4c2828df-2dae-74ff-2fa7-e6ac36100341@androidloves.me>\r\nto:mail@kmille.wtf\r\ncontent-type:text/plain; charset=utf-8; format=flowed\r\ncontent-transfer-encoding:7bit\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=androidloves.me; s=2019022801; t=1584218937; h=from:from:reply-to:subject:subject:date:date:message-id:message-id: to:to:cc:content-type:content-type: content-transfer-encoding:content-transfer-encoding; bh=aeLbTnlUQQv2UFEWKHeiL5Q0NjOwj4ktNSInk8rN/P0=; b=".to_string();
    padding_message
        .push_str(&*padding.repeat(params::MAX_HASH_PREIMAGE_LENGTH - padding_message.len()));

    let (c, public_input) = generate_circuit_instance(secret.to_string(), padding_message);

    println!("[Groth16] Begin");
    let s_start = Instant::now();
    let params = generate_random_parameters::<E, _, _>(c.clone(), rng).unwrap();
    let s_time = s_start.elapsed();
    println!("[Groth16] Setup : {:?}", s_time);

    let mut vk_bytes = Vec::new();
    params.vk.serialize(&mut vk_bytes).unwrap();
    println!("[Groth16] VerifyKey length : {}", vk_bytes.len());

    // Prepare the verification key (for proof verification)
    let pvk = prepare_verifying_key(&params.vk);
    println!("pvk:{}", pvk.gamma_abc_g1.len());

    let p_start = Instant::now();
    let proof = create_random_proof(&params, c, rng).unwrap();
    let p_time = p_start.elapsed();
    println!("[Groth16] Prove : {:?}", p_time);

    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();
    println!("[Groth16] Proof : {}", proof_bytes.len());

    let v_start = Instant::now();
    assert!(verify_proof(&pvk, &proof, &public_input).unwrap());
    println!("[Groth16] Verify : {:?}", v_start.elapsed());

    let vk2 = VerifyKey::<E>::deserialize(&vk_bytes[..]).unwrap();
    let proof2 = Proof::<E>::deserialize(&proof_bytes[..]).unwrap();
    let pvk2 = prepare_verifying_key(&vk2);
    assert!(verify_proof(&pvk2, &proof2, &public_input).unwrap());

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .type_(Some(type_script.clone()).pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity(500u64.pack())
        .type_(Some(type_script.clone()).pack())
        .lock(lock_script.clone())
        .build()];

    let v_start = Instant::now();
    let public_input_flatten = serialize_public_input(public_input);
    println!(
        "[Groth16] Public Input Flatten : {}",
        public_input_flatten.len()
    );
    let public_input = transform_public_input_flatten(&public_input_flatten);
    assert!(verify_proof(&pvk2, &proof2, &public_input,).unwrap());
    let v_time = v_start.elapsed();
    println!("[Groth16] Second Verify : {:?}", v_time);

    let witness = WitnessArgsBuilder::default()
        .lock(Some(Bytes::from(proof_bytes)).pack())
        .input_type(Some(Bytes::from(vk_bytes)).pack())
        .output_type(Some(Bytes::from(public_input_flatten)).pack())
        .build();

    let witness = witness.as_bytes().pack();

    println!("witness len: {}", witness.len());
    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .output_data(Bytes::new().pack())
        .cell_dep(lock_script_dep)
        .cell_dep(type_script_dep)
        .witness(witness)
        .build();

    println!("tx len: {}", &tx.data().as_bytes().len());
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");

    println!("consume cycles: {}", cycles);
}
