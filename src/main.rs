use pallet_mining::OnChainPayload;
use substrate_api_client::{
    compose_extrinsic, Api, UncheckedExtrinsicV4, XtStatus, sp_runtime::app_crypto::Pair
};
use parity_scale_codec::Encode;
use impl_serde::serialize::from_hex;
use sp_core::sr25519;
use log::info;
use std::time::SystemTime;
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct InputInfo {
    pub version: u16,
    pub did_pk: String,
    pub proof: String,
    pub pubkey: String,
    pub secret_seed: String,
    pub url: String
}

#[derive(Debug)]
pub struct HeartbeatParam {
    payload: OnChainPayload,
    pubkey: [u8; 32],
    signature: [u8; 64],
    url: String
}

pub fn load_info_config() -> Result<InputInfo, String> {
    let content = match std::fs::read_to_string("config.toml") {
        Ok(content) => content,
        Err(e) => return Err(e.to_string()),
    };
    match toml::from_str::<InputInfo>(&content) {
        Ok(config) => Ok(config),
        Err(_) => Err("failed to load config".into()),
    }
}

pub fn keep_online() {
    env_logger::init();
    loop {
        let heart_param = prepare_params();
        info!("get param: {:?}", heart_param);
        let api = Api::<sr25519::Pair>::new(heart_param.url).expect("create api failed");
        let xt_d: UncheckedExtrinsicV4<_> =
            compose_extrinsic!(api, "Mining", "im_online", heart_param.payload, heart_param.pubkey, heart_param.signature);
        api.send_extrinsic(xt_d.hex_encode(), XtStatus::InBlock)
            .expect("submit tx failed")
            .expect("tx on chain failed");

        info!("submit im_online successfully: {:?}", SystemTime::now());
        std::thread::sleep(std::time::Duration::from_secs(6));
    }
}

fn prepare_params() -> HeartbeatParam {
    let info = match load_info_config() {
        Ok(info) => info,
        Err(_) => panic!("read config filed")
    };

    info!("Info from config:{:?}", info);

    let did = pallet_facility::DIdentity {
        version: info.version,
        pk: from_hex(&info.did_pk).unwrap()
    };
    let proof = from_hex(&info.proof).unwrap();
    let payload = pallet_mining::OnChainPayload {
        did: did.clone(),
        proof: proof.clone(),
    };
    let signature = sign_payload(info.secret_seed, payload.clone());
    let tmp = from_hex(&info.pubkey).unwrap();
    let mut pubkey = [0u8; 32];
    for i in 0..tmp.len() {
        pubkey[i] = tmp[i];
    }
    let param = HeartbeatParam {
        payload,
        pubkey,
        signature,
        url: info.url
    };
    param
}

fn sign_payload(raw_seed: String, payload: OnChainPayload) -> [u8; 64] {
    let seed = from_hex(raw_seed.as_str()).unwrap();
    let pair = sp_core::sr25519::Pair::from_seed_slice(&seed[..]).unwrap();
    let tmp = hex::encode(payload.encode());
    let data = tmp.as_str().as_bytes();
    let signature = pair.sign(data);
    *signature.as_ref()
}

fn main() {
    keep_online();
}
