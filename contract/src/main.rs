#![no_std]
#![no_main]

#[cfg(not(target_arch = "wasm32"))]
compile_error!("target arch should be wasm32: compile with '--target wasm32-unknown-unknown'");

// We need to explicitly import the std alloc crate and `alloc::string::String` as we're in a
// `no_std` environment.
extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{ToString, String};
use alloc::vec::Vec;
use casper_contract::{
    contract_api::{
        runtime::{self, get_caller},
        storage::{self, dictionary_put, dictionary_get},
    },
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_types::{
    CLType, EntryPoint, EntryPointAccess, EntryPointType, EntryPoints, U128, Key,
    api_error::ApiError,
};
use casper_types_derive::{CLTyped, FromBytes, ToBytes};

const CONTRACT_HASH_KEY: &str = "oracle_contract";
const CONTRACT_HASH_WRAPPED_KEY: &str = "oracle_contract_wrapped";
const DICTIONARY_NAME: &str = "hash_results";
const SEED: &str = "this is the seed";

const PROVIDER_DICT: &str = "provider_dictionary";
const NUM_OF_PROVIDERS: &str = "num_of_providers";

#[derive(CLTyped, ToBytes, FromBytes)]
struct Provider {
    is_provider: bool,
    provider_id: u32,
    pending_balance: U128,
}

#[no_mangle]
pub extern "C" fn reg_init() {
    let dict_ref = storage::new_dictionary(&DICTIONARY_NAME).unwrap_or_revert();
    dictionary_put(dict_ref, NUM_OF_PROVIDERS, 0_u32);
}

#[no_mangle]
pub extern "C" fn register() {

    let dictionary_uref = match runtime::get_key(&DICTIONARY_NAME) {
        Some(uref_key) => uref_key.into_uref().unwrap_or_revert(),
        None => {
            let dict_ref = storage::new_dictionary(&DICTIONARY_NAME).unwrap_or_revert();
            dictionary_put(dict_ref, NUM_OF_PROVIDERS, 0_u32);
            dict_ref
        },
    };

    let mut prov_count: u32 = dictionary_get(dictionary_uref, NUM_OF_PROVIDERS)
        .unwrap_or_revert_with(ApiError::MissingKey)
        .unwrap_or_revert_with(ApiError::ValueNotFound);

    prov_count += 1;
    dictionary_put(dictionary_uref, NUM_OF_PROVIDERS, prov_count);


    // let prov_count_uref = runtime::get_key(&NUM_OF_PROVIDERS)
    //     .unwrap_or_revert_with(ApiError::MissingKey)
    //     .into_uref()
    //     .unwrap_or_revert_with(ApiError::UnexpectedKeyVariant);

    // let mut provider_count: u32 = storage::read(prov_count_uref)
    //     .unwrap_or_revert_with(ApiError::Read)
    //     .unwrap_or_revert_with(ApiError::ValueNotFound);

    // storage::add(prov_count_uref, 1);
    // provider_count += 1;

    // storage::write(prov_count_uref, provider_count);

    // let provider_obj = Provider{
    //     is_provider: true,
    //     provider_id: provider_count,
    //     pending_balance: U128::from(0_u128),
    // };

    // dictionary_put(dictionary_uref, &get_caller().to_string(), provider_obj);
    // dictionary_put(dictionary_uref, NUM_OF_PROVIDERS, 4_u32);
}

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
    // runtime::put_key(NUM_OF_PROVIDERS, storage::new_uref(0_u32).into());
    
    // create contract key map
    // let mut contract_named_keys: BTreeMap<String, Key> = BTreeMap::new();
    
    // initialize & add number of providers
    // let num_prov_uref = storage::new_uref(3_u32);
    // let num_prov_key = String::from(NUM_OF_PROVIDERS);
    // contract_named_keys.insert(num_prov_key, num_prov_uref.into());

    // let dictionary_uref = match runtime::get_key(&DICTIONARY_NAME) {
    //     Some(uref_key) => uref_key.into_uref().unwrap_or_revert(),
    //     None => storage::new_dictionary(&DICTIONARY_NAME).unwrap_or_revert(),
    // };

    // dictionary_put(dictionary_uref, NUM_OF_PROVIDERS, 3_u32);

    // specify public entry points
    let mut entry_points = EntryPoints::new();
    entry_points.add_entry_point(EntryPoint::new(
        "generate", 
        Vec::new(), 
        CLType::Unit, 
        EntryPointAccess::Public, 
        EntryPointType::Contract));

    entry_points.add_entry_point(EntryPoint::new(
        "register", 
        Vec::new(), 
        CLType::Unit, 
        EntryPointAccess::Public,
        EntryPointType::Contract));

    entry_points.add_entry_point(EntryPoint::new(
        "reg_init", 
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

