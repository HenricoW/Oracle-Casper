use std::path::PathBuf;

use casper_engine_test_support::{
    DeployItemBuilder, ExecuteRequestBuilder, InMemoryWasmTestBuilder, WasmTestBuilder, ARG_AMOUNT,
    DEFAULT_ACCOUNT_ADDR, DEFAULT_PAYMENT, DEFAULT_RUN_GENESIS_REQUEST,
};

use casper_execution_engine::storage::global_state::in_memory::InMemoryGlobalState;
use casper_types::bytesrepr::{FromBytes, ToBytes};
use casper_types::system::mint;
use casper_types::{account::AccountHash, runtime_args, PublicKey, RuntimeArgs, SecretKey, U512};
use casper_types::{CLTyped, Key, StoredValue, HashAddr};

pub struct Contract {
    pub builder: WasmTestBuilder<InMemoryGlobalState>,
    pub account_addr: AccountHash,
}
const CONTRACT_HASH_KEY: &str = "oracle_contract";
const CONTRACT_HASH_WRAPPED_KEY: &str = "oracle_contract_wrapped";
const DICTIONARY_NAME: &str = "hash_results";
const GENERATE_EP: &str = "generate";
const SEED: &str = "this is the seed";

impl Contract {
    pub fn deploy() -> Contract {
        // create new key pair
        let public_key: PublicKey =
            PublicKey::from(&SecretKey::ed25519_from_bytes([1u8; 32]).unwrap());

        let account_addr = AccountHash::from(&public_key);

        // spin up local dev env & fund account
        let mut builder = InMemoryWasmTestBuilder::default();
        builder.run_genesis(&DEFAULT_RUN_GENESIS_REQUEST).commit();

        let fund_my_account_request = {
            let deploy_item = DeployItemBuilder::new()
                .with_address(*DEFAULT_ACCOUNT_ADDR)
                .with_authorization_keys(&[*DEFAULT_ACCOUNT_ADDR])
                .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
                .with_transfer_args(runtime_args! {
                    mint::ARG_AMOUNT => U512::from(30_000_000_000_000_u64),
                    mint::ARG_TARGET => public_key,
                    mint::ARG_ID => <Option::<u64>>::None
                })
                .with_deploy_hash([1; 32])
                .build();

            ExecuteRequestBuilder::from_deploy_item(deploy_item).build()
        };
        builder
            .exec(fund_my_account_request)
            .expect_success()
            .commit();

        // contract deploy
        let code = PathBuf::from("main.wasm");
        let args = runtime_args! {};
        let deploy = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_session_code(code, args)
            .with_address(account_addr)
            .with_authorization_keys(&[account_addr])
            .build();
        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy).build();
        builder.exec(execute_request).expect_success().commit();

        Self {
            builder,
            account_addr,
        }
    }

    /// Function that handles the creation and running of sessions.
    pub fn call(&mut self, contract: &str, method: &str, args: RuntimeArgs, deploy: [u8; 32]) {
        let deploy = DeployItemBuilder::new()
            .with_empty_payment_bytes(runtime_args! {ARG_AMOUNT => *DEFAULT_PAYMENT})
            .with_stored_session_named_key(contract, method, args)
            .with_address(self.account_addr)
            .with_deploy_hash(deploy)
            .with_authorization_keys(&[self.account_addr])
            .build();
        let execute_request = ExecuteRequestBuilder::from_deploy_item(deploy).build();
        self.builder.exec(execute_request).expect_success().commit();
    }

    pub fn query<T: CLTyped + FromBytes + ToBytes>(&self, key_name: &str) -> T {
        self.builder
            .query(
                None,
                Key::Account(self.account_addr),
                &[key_name.to_string()],
            )
            .expect("should be stored value.")
            .as_cl_value()
            .expect("should be cl value.")
            .clone()
            .into_t()
            .expect("should be string.")
    }

    pub fn query_dictionary_value<T: CLTyped + FromBytes>(
        &self,
        key: &str,
    ) -> T {
        let contract_hash : HashAddr = self.query(CONTRACT_HASH_WRAPPED_KEY);

        query_dictionary_item(&self.builder, Key::Hash(contract_hash), Some(DICTIONARY_NAME.to_string()), key)
            .expect("should be stored value.")
            .as_cl_value()
            .expect("should be cl value.")
            .clone()
            .into_t()
            .expect("Wrong type in query result.")
    }

}

pub fn query_dictionary_item(
    builder: &InMemoryWasmTestBuilder,
    key: Key,
    dictionary_name: Option<String>,
    dictionary_item_key: &str,
) -> Result<StoredValue, String> {
    let empty_path = vec![];
    let dictionary_key_bytes = dictionary_item_key.as_bytes();
    let address = match key {
        Key::Account(_) | Key::Hash(_) => {
            if let Some(name) = dictionary_name {
                let stored_value = builder.query(None, key, &[])?;

                let named_keys = match &stored_value {
                    StoredValue::Account(account) => account.named_keys(),
                    StoredValue::Contract(contract) => contract.named_keys(),
                    _ => {
                        return Err(
                            "Provided base key is neither an account nor a contract".to_string()
                        )
                    }
                };

                let dictionary_uref = named_keys
                    .get(&name)
                    .and_then(Key::as_uref)
                    .ok_or_else(|| "No dictionary uref was found in named keys".to_string())?;

                Key::dictionary(*dictionary_uref, dictionary_key_bytes)
            } else {
                return Err("No dictionary name was provided".to_string());
            }
        }
        Key::URef(uref) => Key::dictionary(uref, dictionary_key_bytes),
        Key::Dictionary(address) => Key::Dictionary(address),
        _ => return Err("Unsupported key type for a query to a dictionary item".to_string()),
    };
    builder.query(None, address, &empty_path)
}


#[test]
fn test_deploy() {
    let mut contract = Contract::deploy();

    // set value
    contract.call(
        CONTRACT_HASH_KEY,
        GENERATE_EP,
        runtime_args! {},
        [2u8; 32],
    );

    // get value
    let value: String = contract.query_dictionary_value(SEED);
    assert_eq!(value, "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721".to_string());
}