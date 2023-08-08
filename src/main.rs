use axum::body::Bytes;
use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
use engine::{
    Action, AuthKey, CreateSession, CreateUser, Deposit, FillMode, PlaceOrder, Side, UserId,
};
use rand::rngs::OsRng;
use rand::RngCore;
use rust_decimal::Decimal;
use std::error::Error;

use secp256k1::ecdsa::Signature as SecpSignature;
use secp256k1::hashes::sha256;
use secp256k1::rand::rngs::OsRng as SecpOsRng;
use secp256k1::{generate_keypair, Message, PublicKey, Secp256k1, SecretKey};

static DST: &[u8; 43] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const BLS_KP: [u8; 32] = [
    3, 118, 174, 92, 14, 103, 242, 117, 13, 95, 249, 119, 162, 53, 137, 254, 196, 67, 211, 26, 172,
    153, 203, 101, 244, 167, 41, 198, 17, 106, 96, 201,
];
const KP: [u8; 64] = [
    215, 32, 70, 91, 16, 212, 79, 152, 140, 226, 28, 13, 233, 13, 184, 26, 213, 38, 85, 118, 22,
    198, 105, 245, 182, 253, 31, 164, 253, 66, 141, 125, 155, 204, 19, 198, 247, 194, 7, 134, 124,
    152, 25, 183, 165, 185, 226, 126, 58, 121, 57, 39, 82, 195, 176, 21, 12, 48, 203, 227, 132, 64,
    139, 62,
];

const SECP_KP: [u8; 32] = [
    183, 167, 2, 149, 245, 111, 120, 156, 78, 139, 150, 18, 153, 170, 237, 91, 172, 226, 30, 197,
    25, 214, 74, 124, 132, 93, 187, 254, 195, 85, 220, 251,
];

async fn send_action_blst(
    action: Action,
    keypair: &blst::min_sig::SecretKey,
) -> Result<(), Box<dyn Error>> {
    let msg_encoded = action.encode();
    let sig = keypair.sign(&msg_encoded[..], DST, &[]);
    let msg_bytes = Bytes::from(msg_encoded);
    let sig_bytes = Bytes::from(sig.to_bytes().to_vec());
    let x = [msg_bytes, sig_bytes].concat();
    let client = reqwest::Client::new();
    let len = x.len();
    let res = client
        .post("http://localhost:3000/action")
        .body(x)
        .send()
        .await?;
    println!(
        "Bytes size: {}, Action: {:?} - Result: {:?}",
        len,
        action,
        res.text().await?
    );
    Ok(())
}

async fn send_action_ed25119(action: Action, keypair: &Keypair) -> Result<(), Box<dyn Error>> {
    let msg_encoded = action.encode();
    let signature = keypair.sign(&msg_encoded[..]);
    let msg_bytes = Bytes::from(msg_encoded);
    let sig_bytes = Bytes::from(signature.to_bytes().to_vec());
    let x = [msg_bytes, sig_bytes].concat();
    let client = reqwest::Client::new();
    let len = x.len();
    let res = client
        .post("http://localhost:3000/action")
        .body(x)
        .send()
        .await?;
    println!(
        "Size: {}, Action: {:?} - Result: {:?}",
        len,
        action,
        res.text().await?
    );
    Ok(())
}

async fn send_action_secp(action: Action, keypair: &SecretKey) -> Result<(), Box<dyn Error>> {
    let secp = Secp256k1::new();
    let msg_encoded = action.encode();
    let message = Message::from_hashed_data::<sha256::Hash>(&msg_encoded);
    let sig = secp.sign_ecdsa(&message, &keypair);
    let msg_bytes = Bytes::from(msg_encoded);
    let bytes_sig = sig.serialize_compact();
    let sig_bytes = Bytes::copy_from_slice(&bytes_sig[..]);
    let x = [msg_bytes, sig_bytes].concat();
    let client = reqwest::Client::new();
    let len = x.len();
    let res = client
        .post("http://localhost:3000/action")
        .body(x)
        .send()
        .await?;
    println!(
        "Size: {}, Action: {:?} - Result: {:?}",
        len,
        action,
        res.text().await?
    );
    /*
    let (action, size) = Action::decode(&x[..]).unwrap();
    println!("Action: {:?} :: {}", action, size);
    match action {
        Action::CreateUser(CreateUser { auth_key }) => match auth_key {
            AuthKey::Secp256k1(key) => {
                let public_key = PublicKey::from_slice(&key[..]).unwrap();
                let sig = SecpSignature::from_compact(&x[size..]).unwrap();
                let message = Message::from_hashed_data::<sha256::Hash>(&x[..size]);
                assert!(secp.verify_ecdsa(&message, &sig, &public_key).is_ok());
                println!("Success");
            }
            _ => todo!(),
        },
        _ => todo!(),
    }
    */
    Ok(())
}

async fn registration() -> Result<(), Box<dyn Error>> {
    let keypair = get_keypair_ed25119(false);
    let public_key = keypair.public.to_bytes();
    // println!("Raw key bytes: {:?}", public_key);
    // let keypair: Keypair = Keypair::generate(&mut csprng);
    let msg = Action::CreateUser(CreateUser {
        auth_key: AuthKey::Ed25119(public_key),
    });

    let msg_encoded = msg.encode();
    let signature = keypair.sign(&msg_encoded[..]);
    let msg_bytes = Bytes::from(msg_encoded);
    let sig_bytes = Bytes::from(signature.to_bytes().to_vec());
    let x = [msg_bytes, sig_bytes].concat();

    let len = x.len();
    /*
    let msg_decoded: (Action, usize) =
        bincode::decode_from_slice(&x[..], bincode::config::standard()).unwrap();
    let sig = Signature::from_bytes(&x[msg_decoded.1..])
        .unwrap()
        .to_bytes();
    */
    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:3000/action")
        .body(x)
        .send()
        .await?;

    println!("len: {}, Registration: {:?}", len, res.text().await?);
    Ok(())
}

async fn deposit(user_id: UserId) -> Result<(), Box<dyn Error>> {
    let keypair = get_keypair_ed25119(false);
    let public_key = keypair.public.to_bytes();
    let msg = Action::Deposit(Deposit {
        user_id,
        collateral_id: 0,
        amount: rust_decimal::Decimal::from_f64_retain(1e9).unwrap(),
    });

    let msg_encoded = msg.encode();
    let signature = keypair.sign(&msg_encoded[..]);
    let msg_bytes = Bytes::from(msg_encoded);
    let sig_bytes = Bytes::from(signature.to_bytes().to_vec());
    let x = [msg_bytes, sig_bytes].concat();

    /*
    let msg_decoded: (Action, usize) =
        bincode::decode_from_slice(&x[..], bincode::config::standard()).unwrap();

    let sig = Signature::from_bytes(&x[msg_decoded.1..])
        .unwrap()
        .to_bytes();
    */

    let len = x.len();
    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:3000/action")
        .body(x)
        .send()
        .await?;

    println!("Size: {}, Registration: {:?}", len, res.text().await?);
    Ok(())
}

fn get_keypair_ed25119(random: bool) -> Keypair {
    match random {
        true => {
            let mut csprng = OsRng {};
            Keypair::generate(&mut csprng)
        }
        false => Keypair::from_bytes(&KP).unwrap(),
    }
}

fn get_keypair_secp(random: bool) -> SecretKey {
    match random {
        true => {
            let secp = Secp256k1::new();
            let mut rng = SecpOsRng {};
            let (seckey, _pubkey) = secp.generate_keypair(&mut rng);
            seckey
        }
        false => SecretKey::from_slice(&SECP_KP[..]).unwrap(),
    }
}

fn get_keypair_bls(random: bool) -> blst::min_sig::SecretKey {
    match random {
        true => {
            let mut rng = rand::thread_rng();
            let mut ikm = [0u8; 32];
            rng.fill_bytes(&mut ikm);
            blst::min_sig::SecretKey::key_gen(&ikm, &[]).unwrap()
        }
        false => blst::min_sig::SecretKey::from_bytes(&BLS_KP).unwrap(),
    }
}

/*
async fn place_order(user_id: i32) -> Result<(), Box<dyn Error>> {
    let keypair = get_keypair_ed25119(false);
    let sk = get_keypair_bls(false);
    let price = 100_000i64;
    let msg = Action::PlaceOrder(PlaceOrderParams {
        market_id: 0,
        user_id,
        side: Side::Bid,
        price: Some(price.into()),
        size: Decimal::ONE,
        fill_mode: FillMode::Limit,
        reduce_only: false,
    });

    let msg_encoded = bincode::encode_to_vec(msg.clone(), bincode::config::standard()).unwrap();
    let sig = sk.sign(&msg_encoded[..], DST, &[]);
    let msg_bytes = Bytes::from(msg_encoded);
    let sig_bytes = Bytes::from(sig.to_bytes().to_vec());
    let x = [msg_bytes, sig_bytes].concat();
    let (action, size): (Action, usize) =
        bincode::decode_from_slice(&x[..], bincode::config::standard()).unwrap();
    let signature = blst::min_sig::Signature::from_bytes(&x[size..]).unwrap();
    println!("size: {}", size);
    println!("Bytes {:?}", &x[..]);
    println!("Sig bytes {:?}", &x[size..]);
    println!("Sig {:?}", signature);
    let client = reqwest::Client::new();
    let res = client
        .post("http://localhost:3000/action")
        .body(x)
        .send()
        .await?;
    println!("Place Order: {:?}", res.text().await?);
    Ok(())
}
*/

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keypair = get_keypair_ed25119(false);
    let sk = get_keypair_bls(false);
    let pk = sk.sk_to_pk();

    send_action_ed25119(
        Action::CreateUser(CreateUser {
            auth_key: AuthKey::Ed25119(keypair.public.to_bytes()),
        }),
        &keypair,
    )
    .await?;
    send_action_ed25119(
        Action::Deposit(Deposit {
            user_id: 0,
            collateral_id: 0,
            amount: rust_decimal::Decimal::from_f64_retain(1e9).unwrap(),
        }),
        &keypair,
    )
    .await?;
    send_action_ed25119(
        Action::CreateSession(CreateSession {
            user_id: 0,
            blst_key: pk.to_bytes(),
            expiry_timestamp: 0,
        }),
        &keypair,
    )
    .await?;

    send_action_blst(
        Action::PlaceOrder(PlaceOrder {
            user_id: 0,
            market_id: 0,
            side: Side::Bid,
            price: Some(Decimal::ONE),
            size: Decimal::ONE,
            fill_mode: FillMode::Limit,
            is_reduce_only: false,
        }),
        &sk,
    )
    .await?;
    /*
    let secp = Secp256k1::new();
    let secret = get_keypair_secp(false);
    let public_key = secret.public_key(&secp).serialize();
    send_action_secp(
        Action::CreateUser(CreateUser {
            auth_key: AuthKey::Secp256k1(public_key),
        }),
        &secret,
    )
    .await?;
    send_action_secp(
        Action::CreateSession(CreateSession {
            user_id: 0,
            blst_key: pk.to_bytes(),
        }),
        &secret,
    )
    .await?;
    */

    Ok(())
}
