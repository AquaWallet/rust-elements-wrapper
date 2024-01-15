use std::ffi::{c_char, CStr, CString};
use std::str::FromStr;
use elements::bitcoin::hashes::{ripemd160};
use elements::hashes::Hash;
use elements::hex::{FromHex, ToHex};
use elements::opcodes::Ordinary::OP_IF;
use elements::{opcodes, Script, script};
use elements::hashes::serde_macros::serde_details::SerdeHash;
use elements::script::{Builder, Instruction};
use elements::secp256k1_zkp::PublicKey;
use hex::decode;
use serde::Serialize;

#[no_mangle]
pub extern fn reconstruct_swap_script(
    preimage_hash: *const c_char,
    claim_public_key: *const c_char,
    refund_public_key: *const c_char,
    timeout_block_height: u32,
) -> *mut c_char {
    let preimage_hash_string = unsafe { CStr::from_ptr(preimage_hash).to_str().unwrap().trim() };
    let claim_public_key_string = unsafe { CStr::from_ptr(claim_public_key).to_str().unwrap().trim() };
    let refund_public_key_string = unsafe { CStr::from_ptr(refund_public_key).to_str().unwrap().trim() };

    let claim_public_key = PublicKey::from_str(claim_public_key_string).unwrap().serialize();
    let refund_public_key = PublicKey::from_str(refund_public_key_string).unwrap().serialize();
    let preimage_hash_ripemd = ripemd160::Hash::hash(decode(&preimage_hash_string).unwrap().as_slice()).to_byte_array();

    let script = Builder::new()
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(&preimage_hash_ripemd)
        .push_opcode(opcodes::all::OP_EQUAL)
        .push_opcode(opcodes::all::OP_IF)
        .push_slice(&claim_public_key)
        .push_opcode(opcodes::all::OP_ELSE)
        .push_int(timeout_block_height as i64)
        .push_opcode(opcodes::all::OP_CLTV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(&refund_public_key)
        .push_opcode(opcodes::all::OP_ENDIF)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();

    return CString::new(script.to_hex().to_owned()).unwrap().into_raw();
}

#[no_mangle]
pub extern fn extract_claim_public_key(comparison_script: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(comparison_script).to_str().unwrap().trim() };
    let script = elements::script::Script::from_hex(c_str);

    let binding = script.unwrap();
    let mut iter = binding.instructions();
    let mut found_op_if = false;
    while let Some(instruction) = iter.next() {
        let ins = instruction.unwrap();
        if ins.op() != None {
            if (ins.op().unwrap() == elements::opcodes::All::from(OP_IF as u8)) {
                found_op_if = true;
                continue;
            }
        }
        if (found_op_if) {
            found_op_if = false;
            let claim_public_key = PublicKey::from_slice(ins.push_bytes().unwrap()).unwrap().to_hex();
            return CString::new(claim_public_key.to_owned()).unwrap().into_raw();
        }
    }
    return CString::new("").unwrap().into_raw();
}
#[no_mangle]
pub extern fn rust_cstr_free(s: *mut c_char) {
    unsafe {
        if s.is_null() { return; }
        CString::from_raw(s)
    };
}