#![cfg_attr(not(feature = "mock"), no_std)]
#![feature(proc_macro_hygiene)]
extern crate ontio_std as ostd;
use ostd::abi::{Sink, Source, EventBuilder};
use ostd::prelude::*;
use ostd::runtime::{address, check_witness, contract_migrate, input, ret, sha256, caller, entry_address};
use ostd::contract::{eth, neo};
use ostd::types::U256;
use ostd::database::{get, put};

const VERIFYHERDERANDEXECUTETX_ID: [u8; 4] = [0xa4, 0xe3, 0x20, 0xdb];

const KEY_ADMIN: &[u8] = b"1";
const KEY_CHAIN_ID: &[u8] = b"2";
const EVM_CCM_CONTRACT: &[u8] = b"3";
const FROM_CHAIN_TX: &[u8] = b"4";
const INCREASED_INDEX: &[u8] = b"5";
const MAKE_TX_PARAM_HASH: &[u8] = b"6";

fn initialize(admin: &Address) -> bool {
    assert!(get_admin().is_zero(), "has inited");
    assert!(check_witness(admin), "check admin signature failed");
    put(KEY_ADMIN, admin);
    true
}

fn get_admin() -> Address {
    get(KEY_ADMIN).unwrap_or_default()
}

fn set_chain_id(chain_id: U128) -> bool {
    assert!(check_witness(&get_admin()), "check admin signature failed");
    put(KEY_CHAIN_ID, chain_id);
    true
}

fn get_chain_id() -> U128 {
    get(KEY_CHAIN_ID).unwrap_or_default()
}

fn set_evm_ccm_contract(ccm: &Address) -> bool {
    assert!(check_witness(&get_admin()), "check admin signature failed");
    put(EVM_CCM_CONTRACT, ccm);
    true
}

fn get_evm_ccm_contract() -> Address {
    get(EVM_CCM_CONTRACT).unwrap_or_default()
}

fn verify_header_and_execute_tx(raw_header: &[u8], raw_seal: &[u8], accont_proof: &[u8], storage_proof: &[u8], raw_cross_tx: &[u8]) -> bool {
    let this = address();
    let res = eth::evm_invoke(&this, &get_evm_ccm_contract(), gen_verify_header_and_execute_tx_data(raw_header, raw_seal, accont_proof, storage_proof, raw_cross_tx).as_slice());
    assert!(!res.is_empty(), "invalid evm invoke return");
    let mut source = Source::new(res.as_slice());
    // parse response
    let zion_tx_hash = source.read_bytes().unwrap();
    let from_chain_id: u64 = source.read().unwrap();
    let from_chain_id = U128::new(from_chain_id as u128);
    let source_tx_hash = source.read_bytes().unwrap();
    let cross_chain_id = source.read_bytes().unwrap();
    let from_contract = source.read_bytes().unwrap();
    let to_chain_id: u64 = source.read().unwrap();
    let to_chain_id = U128::new(to_chain_id as u128);
    let to_contract = source.read_bytes().unwrap();
    let method = source.read_bytes().unwrap();
    let args = source.read_bytes().unwrap();

    // check & put tx exection information
    assert!(!from_chain_tx_exist(cross_chain_id), "the transaction has been executed!");
    put_from_chain_tx(cross_chain_id);
    assert!(to_chain_id == get_chain_id(), "This Tx is not aiming at this network!");

    // call lock proxy contract
    assert!((to_contract.len() == 20), "to contract address is not 20 length!");
    let mut to_contract_addr = [0; 20];
    to_contract_addr[..].copy_from_slice(to_contract[..].as_ref());
    let lock_proxy_contract_addr = &Address::new(to_contract_addr);
    neo::call_contract(&lock_proxy_contract_addr, (method, args, from_contract, from_chain_id));

    // notify event
    EventBuilder::new()
    .string("verifyToOntProof")
    .bytearray(zion_tx_hash)
    .bytearray(source_tx_hash)
    .number(from_chain_id)
    .bytearray(to_contract)
    .notify();

    true
}

fn gen_verify_header_and_execute_tx_data(raw_header: &[u8], raw_seal: &[u8], accont_proof: &[u8], storage_proof: &[u8], raw_cross_tx: &[u8]) -> Vec<u8> {
    let offset1 = 5*32;
    let offset2 = offset1 + 32 + ((raw_header.len() - 1)/32 + 1)*32;
    let offset3 = offset2 + 32 + ((raw_seal.len() - 1)/32 + 1)*32;
    let offset4 = offset3 + 32 + ((accont_proof.len() - 1)/32 + 1)*32;
    let offset5 = offset4 + 32 + ((storage_proof.len() - 1)/32 + 1)*32;
    [VERIFYHERDERANDEXECUTETX_ID.as_ref(), 
    U256::from(offset1 as u128).to_be_bytes().as_ref(), 
    U256::from(offset2 as u128).to_be_bytes().as_ref(), 
    U256::from(offset3 as u128).to_be_bytes().as_ref(), 
    U256::from(offset4 as u128).to_be_bytes().as_ref(), 
    U256::from(offset5 as u128).to_be_bytes().as_ref(), 
    U256::from(raw_header.len() as u128).to_be_bytes().as_ref(), format_bytes(raw_header).as_ref(), 
    U256::from(raw_seal.len() as u128).to_be_bytes().as_ref(), format_bytes(raw_seal).as_ref(), 
    U256::from(accont_proof.len() as u128).to_be_bytes().as_ref(), format_bytes(accont_proof).as_ref(), 
    U256::from(storage_proof.len() as u128).to_be_bytes().as_ref(), format_bytes(storage_proof).as_ref(), 
    U256::from(raw_cross_tx.len() as u128).to_be_bytes().as_ref(), format_bytes(raw_cross_tx).as_ref()].concat()
}

fn format_bytes(b: &[u8]) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    let n = (b.len() - 1)/32;
    res = [res.as_slice(), b[..n*32].as_ref()].concat();
    let mut temp = [0; 32];
    temp[..b.len()-n*32].copy_from_slice(b[n*32..].as_ref());
    res = [res.as_slice(), temp.as_ref()].concat();
    res
}

fn put_from_chain_tx(tx_hash: &[u8]) {
    put(FROM_CHAIN_TX, tx_hash);
}

fn from_chain_tx_exist(tx_hash: &[u8]) -> bool {
    let res: Vec<u8> = get(FROM_CHAIN_TX).unwrap_or_default();
    tx_hash == res.as_slice()
}

fn increased_index() -> U128 {
    let res = get(INCREASED_INDEX).unwrap_or_default();
    put(INCREASED_INDEX, res + 1);
    res
}

fn get_make_tx_param_hash(key: &[u8]) -> Vec<u8> {
    get([MAKE_TX_PARAM_HASH, key].concat()).unwrap()
}

fn put_make_tx_param_hash(key: &[u8], hash: &[u8]) {
    put([MAKE_TX_PARAM_HASH, key].concat(), hash);
}

fn cross_chain(to_chain_id: U128, to_proxy_hash: &[u8], method: &[u8], args: &[u8]) -> bool {
    let this = address();
    let index = increased_index();
    let param_tx_hash = U256::from(index).to_be_bytes();
    let cross_chain_id = sha256([this.as_bytes(), param_tx_hash.as_ref()].concat());

    let offset1 = 7*32;
    let offset2 = offset1 + 32*2;
    let offset3 = offset2 + 32*2;
    let offset4 = offset3 + 32*2;
    let offset5 = offset4 + 32*2;
    let offset6 = offset5 + 32 + ((method.len() - 1)/32 + 1)*32;
    let make_tx_param = 
    [U256::from(offset1 as u128).to_be_bytes().as_ref(), 
    U256::from(offset2 as u128).to_be_bytes().as_ref(), 
    U256::from(offset3 as u128).to_be_bytes().as_ref(), 
    U256::from(to_chain_id).to_be_bytes().as_ref(), 
    U256::from(offset4 as u128).to_be_bytes().as_ref(), 
    U256::from(offset5 as u128).to_be_bytes().as_ref(), 
    U256::from(offset6 as u128).to_be_bytes().as_ref(), 
    U256::from(param_tx_hash.len() as u128).to_be_bytes().as_ref(), param_tx_hash.as_ref(), 
    U256::from(cross_chain_id.as_bytes().len() as u128).to_be_bytes().as_ref(), cross_chain_id.as_bytes(),  
    U256::from(caller().as_bytes().len() as u128).to_be_bytes().as_ref(), format_bytes(caller().as_bytes()).as_ref(), 
    U256::from(to_proxy_hash.len() as u128).to_be_bytes().as_ref(), format_bytes(to_proxy_hash).as_ref(), 
    U256::from(method.len() as u128).to_be_bytes().as_ref(), format_bytes(method).as_ref(), 
    U256::from(args.len() as u128).to_be_bytes().as_ref(), format_bytes(args).as_ref(), 
    ].concat();

    let make_tx_param_hash = sha256(make_tx_param.as_slice());

    put_make_tx_param_hash(param_tx_hash.as_ref(), make_tx_param_hash.as_bytes());

    // notify event
    EventBuilder::new()
    .string("cross_chain")
    .address(entry_address().as_ref())
    .bytearray(param_tx_hash.as_ref())
    .address(caller().as_ref())
    .number(to_chain_id)
    .bytearray(to_proxy_hash)
    .bytearray(make_tx_param.as_slice())
    .notify();

    true
}

fn migrate(
    code: &[u8], vm_type: u32, name: &str, version: &str, author: &str, email: &str, desc: &str,
) -> bool {
    assert!(check_witness(&get_admin()), "check admin signature failed");
    let new_addr = contract_migrate(code, vm_type, name, version, author, email, desc);
    assert!(!new_addr.is_zero());
    true
}

#[no_mangle]
pub fn invoke() {
    let input = input();
    let mut source = Source::new(&input);
    let action = source.read().unwrap();
    let mut sink = Sink::new(12);
    match action {
        "initialize" => {
            let admin = source.read().unwrap();
            sink.write(initialize(admin))
        }
        "getAdmin" => {
            sink.write(get_admin());
        }
        "setChainId" => {
            let chain_id = source.read().unwrap();
            sink.write(set_chain_id(chain_id));
        }
        "getChainId" => {
            sink.write(get_chain_id());
        }
        "setEvmCcmContract" => {
            let addr = source.read().unwrap();
            sink.write(set_evm_ccm_contract(addr))
        }
        "getEvmCcmContract" => {
            sink.write(get_evm_ccm_contract());
        }
        "crossChain" => {
            let (to_chain_id, to_proxy_hash, method, args) = source.read().unwrap();
            sink.write(cross_chain(to_chain_id, to_proxy_hash, method, args));
        }
        "getMakeTxParamHash" => {
            let key = source.read().unwrap();
            sink.write(get_make_tx_param_hash(key))
        }
        "verifyHeaderAndExecuteTx" => {
            let (raw_header, raw_seal, accont_proof, storage_proof, raw_cross_tx) =
                source.read().unwrap();
            sink.write(verify_header_and_execute_tx(
                raw_header,
                raw_seal,
                accont_proof,
                storage_proof,
                raw_cross_tx,
            ));
        }
        "migrate" => {
            let (code, vm_type, name, version, author, email, desc) = source.read().unwrap();
            let vm_type: U128 = vm_type;
            sink.write(migrate(code, vm_type.raw() as u32, name, version, author, email, desc));
        }
        _ => panic!("unsupported action!"),
    }
    ret(sink.bytes())
}
