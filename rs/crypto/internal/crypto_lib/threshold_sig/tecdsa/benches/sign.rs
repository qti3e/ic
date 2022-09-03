use criterion::*;
use rand::Rng;
use ic_crypto_internal_threshold_sig_ecdsa::*;
use ic_types::Randomness;

mod test_utils {
    include!("../tests/test_utils.rs");
}

use test_utils::*;

/// Setup the signature protocol execution.
fn setup_protocol(threshold: usize, nodes: usize) -> SignatureProtocolExecution {
    let number_of_dealings_corrupted = threshold;

    let mut rng = rand::thread_rng();
    let random_seed = Seed::from_rng(&mut rng);

    let setup = SignatureProtocolSetup::new(
        EccCurveType::K256,
        nodes,
        threshold,
        number_of_dealings_corrupted,
        random_seed,
    )
        .unwrap();

    let signed_message = rng.gen::<[u8; 32]>().to_vec();
    let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);

    SignatureProtocolExecution::new(
        setup.clone(),
        signed_message.clone(),
        random_beacon,
        derivation_path.clone(),
    )
}

fn bench_ecdsa_threshold(c: &mut Criterion, threshold: usize, nodes: usize) {
    let proto = setup_protocol(threshold, nodes);
    let shares = proto.generate_shares().unwrap();

    let mut group = c.benchmark_group(format!("ecdsa({}, {})", threshold, nodes));
    group
        .sample_size(100)
        .sampling_mode(SamplingMode::Flat);

    group.bench_function("generate_shares_and_verify", |b| {
        b.iter(|| proto.generate_shares().unwrap());
    });

    group.bench_function("combine_shares", |b| {
        b.iter(|| {
            proto.generate_signature(&shares).unwrap();
        })
    });

    group.bench_with_input(
        "verify_signature",
        &proto.generate_signature(&shares).unwrap(),
        |b, sig| {
            b.iter(|| {
                proto.verify_signature(&sig).unwrap();
            })
        });
}

fn ecdsa(c: &mut Criterion) {
    bench_ecdsa_threshold(c, 3, 10);
    bench_ecdsa_threshold(c, 11, 29);
}

criterion_group!(benches, ecdsa);
criterion_main!(benches);
