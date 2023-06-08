use bincode::{Decode, Encode};
use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use rayon::{prelude::*, ThreadPool};
use std::sync::mpsc;

#[derive(Encode, Decode, Debug)]
struct Payload {
    signature: [u8; Signature::BYTE_SIZE],
    message_encoded: Vec<u8>,
}

#[derive(Debug, Clone, Encode, Decode)]
pub enum Action {
    CreateUser { user_id: u64 },
}

fn main() {
    let PAR_THREAD_POOL: ThreadPool = rayon::ThreadPoolBuilder::new()
        .num_threads(20)
        .build()
        .unwrap();

    let (tx, rx) = mpsc::channel();
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);

    // Imagine loop here for recv.
    let count: u64 = 100;
    use std::time::{Duration, Instant};

    let start = Instant::now();
    for i in 0..count {
        let msg = Action::CreateUser { user_id: i };
        let msg_encoded = bincode::encode_to_vec(msg.clone(), bincode::config::standard()).unwrap();
        let signature = keypair.sign(&msg_encoded[..]);
        let payload = Payload {
            signature: signature.to_bytes(),
            message_encoded: msg_encoded,
        };
        let serialized_payload =
            bincode::encode_to_vec(payload, bincode::config::standard()).unwrap();
        let duration = start.elapsed();

        let t = tx.clone();

        PAR_THREAD_POOL.spawn(move || {
            let deserialized_payload: (Payload, usize) =
                bincode::decode_from_slice(&serialized_payload[..], bincode::config::standard())
                    .unwrap();

            let payload_sig = Signature::from_bytes(&deserialized_payload.0.signature).unwrap();

            keypair
                .public
                .verify(&deserialized_payload.0.message_encoded[..], &payload_sig)
                .unwrap();

            let action: (Action, usize) = bincode::decode_from_slice(
                &deserialized_payload.0.message_encoded[..],
                bincode::config::standard(),
            )
            .unwrap();

            t.send((deserialized_payload.0, action.0)).unwrap();
        });
    }

    let duration = start.elapsed();
    println!("Time elapsed is: {:?}", duration);

    let mut counter = 0;
    while let Ok((_payload, action)) = rx.recv() {
        println!("{:?}", action);
        counter += 1;
        if counter == count {
            break;
        }
    }
}
