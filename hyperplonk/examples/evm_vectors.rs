use std::io::Write;
use std::path::PathBuf;

use p3_air::{Air, AirBuilder, BaseAir, BaseAirWithPublicValues};
use p3_hyperplonk::evm_codec::{
    Challenge, Challenger, Compress, Dft, FieldHash, MerkleJsonMetrics, Pcs, Val,
    count_merkle_digests_in_proof, effective_digest_bytes_for_v3_security_bits,
    encode_calldata_verify_bytes, encode_proof_blob_v3, hex_prefixed,
    render_json_payload_with_metrics_and_merkle,
};
use p3_hyperplonk::{HyperPlonkConfig, ProverInput, VerifierInput, keygen, prove, verify};
use p3_koala_bear::GenericPoseidon2LinearLayersKoalaBear;
use p3_poseidon2_air::{RoundConstants, generate_trace_rows, num_cols};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use whir_p3::metrics::{reset_hash_counters, snapshot_hash_counters};

type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;

const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = 3;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 20;
const SECURITY_LEVEL: usize = 100;

pub struct Poseidon2Air(
    p3_poseidon2_air::Poseidon2Air<
        Val,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
);

impl BaseAir<Val> for Poseidon2Air {
    fn width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }
}

impl BaseAirWithPublicValues<Val> for Poseidon2Air {}

impl<AB: AirBuilder<F = Val>> Air<AB> for Poseidon2Air {
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputFormat {
    Json,
    Calldata,
}

struct CliArgs {
    format: OutputFormat,
    out: Option<PathBuf>,
    pretty: bool,
}

impl CliArgs {
    fn parse() -> Result<Self, String> {
        let mut format = OutputFormat::Json;
        let mut out = None;
        let mut pretty = false;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--format" => {
                    let Some(value) = args.next() else {
                        return Err(format!("missing value for --format\n{}", Self::usage()));
                    };
                    format = match value.as_str() {
                        "json" => OutputFormat::Json,
                        "calldata" => OutputFormat::Calldata,
                        _ => {
                            return Err(format!(
                                "unsupported format '{value}', expected 'json' or 'calldata'\n{}",
                                Self::usage()
                            ));
                        }
                    };
                }
                "--out" => {
                    let Some(value) = args.next() else {
                        return Err(format!("missing value for --out\n{}", Self::usage()));
                    };
                    out = Some(PathBuf::from(value));
                }
                "--pretty" => {
                    pretty = true;
                }
                "-h" | "--help" => {
                    return Err(Self::usage().to_string());
                }
                _ => {
                    return Err(format!("unknown argument '{arg}'\n{}", Self::usage()));
                }
            }
        }

        Ok(Self {
            format,
            out,
            pretty,
        })
    }

    const fn usage() -> &'static str {
        concat!(
            "Usage: cargo run --example evm_vectors -- [OPTIONS]\n\n",
            "Options:\n",
            "  --format <json|calldata>   Output format (default: json)\n",
            "  --out <path>               Write output to file (default: stdout)\n",
            "  --pretty                   Pretty-print JSON output\n",
            "  -h, --help                 Show this help\n",
        )
    }
}

fn run() -> Result<(), String> {
    let cli = match CliArgs::parse() {
        Ok(cli) => cli,
        Err(err) => {
            if err == CliArgs::usage() {
                print!("{err}");
                return Ok(());
            }
            return Err(err);
        }
    };

    let mut rng = StdRng::seed_from_u64(0);

    let config = {
        let dft = Dft::default();
        let pow_bits = 20;
        let whir_params = ProtocolParameters {
            security_level: SECURITY_LEVEL,
            pow_bits,
            folding_factor: FoldingFactor::Constant(4),
            merkle_hash: FieldHash::for_security_bits(SECURITY_LEVEL),
            merkle_compress: Compress::for_security_bits(SECURITY_LEVEL),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
            rs_domain_initial_reduction_factor: 3,
        };
        HyperPlonkConfig::<_, Challenge, _>::new(
            Pcs::new(dft, whir_params),
            Challenger::from_hasher(Vec::new(), p3_keccak::Keccak256Hash),
        )
    };

    let round_constants = RoundConstants::from_rng(&mut rng);
    let make_air = || Poseidon2Air(p3_poseidon2_air::Poseidon2Air::new(round_constants.clone()));
    let air = make_air();
    let (vk, pk) = keygen([&air]);

    let log_b = 15;
    let trace = generate_trace_rows::<
        _,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(
        (0..1 << log_b).map(|_| rng.random()).collect(),
        &round_constants,
        0,
    );

    let prover_inputs = vec![ProverInput::new(make_air(), Vec::new(), trace)];
    let public_inputs = prover_inputs
        .iter()
        .map(|input| input.public_values.clone())
        .collect::<Vec<_>>();
    reset_hash_counters();
    let proof = prove(&config, &pk, prover_inputs);
    let hash_counts_prover = snapshot_hash_counters();

    let verifier_inputs = public_inputs
        .iter()
        .cloned()
        .map(|public_values| VerifierInput::new(make_air(), public_values))
        .collect::<Vec<_>>();
    reset_hash_counters();
    verify(&config, &vk, verifier_inputs, &proof)
        .map_err(|err| format!("generated proof failed verification: {err:?}"))?;
    let hash_counts_verifier = snapshot_hash_counters();

    let masked_digest_bytes = effective_digest_bytes_for_v3_security_bits(SECURITY_LEVEL);
    let masked_digest_bits = masked_digest_bytes.saturating_mul(8);
    let total_merkle_digest_count = count_merkle_digests_in_proof(&proof);
    let proof_blob = encode_proof_blob_v3(&public_inputs, &proof, masked_digest_bytes);
    let calldata = encode_calldata_verify_bytes(&proof_blob);

    let output = match cli.format {
        OutputFormat::Json => render_json_payload_with_metrics_and_merkle(
            &proof_blob,
            &calldata,
            hash_counts_prover.into(),
            hash_counts_verifier.into(),
            MerkleJsonMetrics {
                masked_digest_bytes,
                masked_digest_bits,
                total_merkle_digest_count,
            },
            cli.pretty,
        ),
        OutputFormat::Calldata => hex_prefixed(&calldata),
    };

    match cli.out {
        Some(path) => {
            std::fs::write(&path, output.as_bytes())
                .map_err(|err| format!("failed to write output to '{}': {err}", path.display()))?;
        }
        None => {
            let mut stdout = std::io::stdout();
            stdout
                .write_all(output.as_bytes())
                .map_err(|err| format!("failed to write output to stdout: {err}"))?;
            if cli.format == OutputFormat::Calldata {
                stdout
                    .write_all(b"\n")
                    .map_err(|err| format!("failed to write newline: {err}"))?;
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
