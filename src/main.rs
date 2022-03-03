use pallet_mining::OnChainPayload;
use substrate_api_client::{
    compose_extrinsic, Api, UncheckedExtrinsicV4, XtStatus, sp_runtime::app_crypto::Pair
};
use parity_scale_codec::Encode;
use sp_keyring::AccountKeyring;
use impl_serde::serialize::from_hex;
use sp_core::sr25519;

#[derive(Debug)]
pub struct HeartbeatParam {
    payload: OnChainPayload,
    pubkey: [u8; 32],
    signature: [u8; 64]
}

pub struct Client {
    pub url: String,
    pub singer: sp_core::sr25519::Pair,
}


pub fn keep_online() {
    loop {
        println!("start submit im-online");
        let client = Client {
            url: String::from("ws://127.0.0.1:9944"),
            singer: AccountKeyring::Alice.pair(),
        };

        let api = Api::<sr25519::Pair>::new(client.url.clone()).expect("create api failed");
        // .map(|api| api.set_signer(client.singer))
        // .expect("api create failed");
        if let Some(_signer) = api.signer.clone() {
            println!("signer exist");
        } else {
            println!("no signer");
            let heart_param = prepare_params();
            println!("get param: {:?}", heart_param);

            let xt_d: UncheckedExtrinsicV4<_> =
                compose_extrinsic!(api, "Mining", "im_online", heart_param.payload, heart_param.pubkey, heart_param.signature);

            api.send_extrinsic(xt_d.hex_encode(), XtStatus::InBlock)
                .expect("submit tx failed")
                .expect("tx on chain failed");

            println!("submit im_online successfully");
            std::thread::sleep(std::time::Duration::from_secs(6));
        }
    }
}

fn prepare_params() -> HeartbeatParam {
    const PK_HEX:&str = "0x6b74fb5ed2ffb08de0f539bd2e437c3ba018f266201eaa3254a5919092fa4093";
    let did = pallet_facility::DIdentity {
        version: 1,
        pk: from_hex(PK_HEX).unwrap()
    };
    // let report = pallet_facility::AttestationReport::default();
    let proof = from_hex(PK_HEX).unwrap();
    let payload = pallet_mining::OnChainPayload {
        did: did.clone(),
        proof: proof.clone(),
    };
    let signature = sign_payload(payload.clone());
    // const PUBLIC:&str = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    let pubkey: [u8; 32] = [212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133, 76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125];
    // let signature = from_hex("0x4c4552e055ee2d9d43ff1ca6126e29cee211bcccec512934c10f85f78663e50dac786fd1f327ca7f5c9c9b78092a398a51b3ae6c46f00c7c353b17146f8e7b8f").unwrap();
    // let signature: [u8; 64] = [76, 69, 82, 224, 85, 238, 45, 157, 67, 255, 28, 166, 18, 110, 41, 206, 226, 17, 188, 204, 236, 81, 41, 52, 193, 15, 133, 247, 134, 99, 229, 13, 172, 120, 111, 209, 243, 39, 202, 127, 92, 156, 155, 120, 9, 42, 57, 138, 81, 179, 174, 108, 70, 240, 12, 124, 53, 59, 23, 20, 111, 142, 123, 143];
    let param = HeartbeatParam {
        payload,
        pubkey,
        signature
    };
    param
}

fn sign_payload(payload: OnChainPayload) -> [u8; 64] {
    let pair = AccountKeyring::Alice.pair();
    let tmp = hex::encode(payload.encode());
    let data = tmp.as_str().as_bytes();
    let signature = pair.sign(data);
    *signature.as_ref()
}

fn main() {
    keep_online();
}
