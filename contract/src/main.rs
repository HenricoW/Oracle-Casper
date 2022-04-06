#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

// We need to explicitly import the std alloc crate and `alloc::string::String` as we're in a
// `no_std` environment.
extern crate alloc;

use alloc::string::{ToString};
use alloc::vec::Vec;
use casper_contract::{
    contract_api::{
        // runtime::{self, get_caller},
        runtime,
        storage::{self, dictionary_put},
    },
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::{
    CLType, EntryPoint, EntryPointAccess, EntryPointType, EntryPoints,
};

const CONTRACT_HASH_KEY: &str = "oracle_contract";
const CONTRACT_HASH_WRAPPED_KEY: &str = "oracle_contract_wrapped";
const DICTIONARY_NAME: &str = "hash_results";
const SEED: &str = "this is the seed";

#[no_mangle]
pub extern "C" fn generate() {
    let start_str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

    let hash = start_str.to_string();

    let dictionary_uref = match runtime::get_key(&DICTIONARY_NAME) {
        Some(uref_key) => uref_key.into_uref().unwrap_or_revert(),
        None => storage::new_dictionary(&DICTIONARY_NAME).unwrap_or_revert(),
    };

    dictionary_put(dictionary_uref, SEED, hash);
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
    runtime::put_key(CONTRACT_HASH_KEY, contract_hash.into());
    runtime::put_key(CONTRACT_HASH_WRAPPED_KEY, storage::new_uref(contract_hash).into());
}

