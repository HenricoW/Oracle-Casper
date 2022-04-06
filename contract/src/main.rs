#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

// We need to explicitly import the std alloc crate and `alloc::string::String` as we're in a
// `no_std` environment.
extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
// use hex;
use casper_contract::{
    contract_api::{
        runtime::{self, get_caller},
        storage::{self, dictionary_get, dictionary_put},
    },
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::{
    CLType, CLTyped, EntryPoint, EntryPointAccess, EntryPointType, EntryPoints, Parameter, U512,
};
// use vrf::openssl::{CipherSuite, ECVRF};
// use vrf::VRF;

const DICT_NAME: &str = "hash_results";
// const SEED: &[u8] = b"this is the seed";
// struct Vrf_Result<'a> {
//     seed: &'a str,
//     hash: Vec<u8>,
//     pi: Vec<u8>,
//     nonce: U512,
// }

// fn add_result(pi: Vec<u8>, hash: Vec<u8>, seed: &str) {
//     let dictionary_uref = match runtime::get_key(DICT_NAME) {
//         Some(uref_key) => uref_key.into_uref().unwrap_or_revert(),
//         None => storage::new_dictionary(DICT_NAME).unwrap_or_revert(),
//     };

//     // let pi: Vec<u8> = runtime::get_named_arg("pi");
//     // let hash: Vec<u8> = runtime::get_named_arg("hash");
//     // let seed: &str = runtime::get_named_arg("seed");

//     // check if valid combo

//     // store hash
//     dictionary_put(dictionary_uref, seed, hash);

// }

#[no_mangle]
pub extern "C" fn generate() {
    // let mut vrf = ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI).unwrap();

    // let secret_key = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    let start_str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    // let public_key = vrf.derive_public_key(&secret_key).unwrap();
    
    // let pi = vrf.prove(&secret_key, &SEED).unwrap();
    // let hash = vrf.proof_to_hash(&pi).unwrap();
    let hash = start_str.to_string();

    // temporarily
    let dictionary_uref = match runtime::get_key(&DICT_NAME) {
        Some(uref_key) => uref_key.into_uref().unwrap_or_revert(),
        None => storage::new_dictionary(&DICT_NAME).unwrap_or_revert(),
    };

    dictionary_put(dictionary_uref, "this is the seed", hash);
    // temporarily
}

#[no_mangle]
pub extern "C" fn call() {
    let mut entry_points = EntryPoints::new();

    entry_points.add_entry_point(EntryPoint::new(
        "generate", 
        Vec::new(), 
        CLType::Unit, 
        EntryPointAccess::Public, 
        EntryPointType::Contract));

    let (contract_hash, _version) = storage::new_contract(
        entry_points,
        None,
        Some("contract_package_hash".to_string()),
        Some("access_token".to_string()),
    );
    runtime::put_key("oracle_contract", contract_hash.into());
    runtime::put_key("oracle_contract_wrapped", storage::new_uref(contract_hash).into());
}

