use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::crh::{
    poseidon::{constraints::CRHGadget, CRH as PoseidonCRH},
    CRHScheme, CRHSchemeGadget,
};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_groth16::{Groth16, ProvingKey};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use wasm_bindgen::prelude::*;

#[derive(Clone)]
pub struct PhiIdentityCircuit {
    pub kai_signature: Fr,
    pub expected_user_phikey: Fr,
    pub poseidon_config: PoseidonConfig<Fr>,
}

impl ConstraintSynthesizer<Fr> for PhiIdentityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let private_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(self.kai_signature))?;
        let public_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.expected_user_phikey))?;

        let params_var =
            <CRHGadget<Fr> as CRHSchemeGadget<PoseidonCRH<Fr>, Fr>>::ParametersVar::new_constant(
                cs,
                &self.poseidon_config,
            )?;

        let hash_var = CRHGadget::<Fr>::evaluate(&params_var, &[private_var])?;
        hash_var.enforce_equal(&public_var)?;

        Ok(())
    }
}

#[wasm_bindgen]
pub async fn generate_proof(
    kai_sig_hex: String,
    salt: String,
    phi_key_b64: String,
) -> Result<String, JsValue> {
    use ark_ff::PrimeField;

    let kai_sig_bytes = hex::decode(kai_sig_hex)
        .map_err(|e| JsValue::from_str(&format!("hex decode failed: {e}")))?;
    let phi_key_bytes = base64::decode(phi_key_b64)
        .map_err(|e| JsValue::from_str(&format!("base64 decode failed: {e}")))?;

    let kai_sig = Fr::from_le_bytes_mod_order(&kai_sig_bytes);
    let phi_key = Fr::from_le_bytes_mod_order(&phi_key_bytes);

    // 🛠️ Fix: convert &[u8; N] → &[u8]
    let pk_bytes = &include_bytes!("../zk-keys/proving.key")[..];
    let config_bytes = &include_bytes!("../zk-keys/poseidon.params")[..];

    let proving_key: ProvingKey<Bls12_381> = CanonicalDeserialize::deserialize_compressed(pk_bytes)
        .map_err(|e| JsValue::from_str(&format!("proving_key deserialize failed: {e}")))?;
    let poseidon_config: PoseidonConfig<Fr> = CanonicalDeserialize::deserialize_compressed(config_bytes)
        .map_err(|e| JsValue::from_str(&format!("poseidon config deserialize failed: {e}")))?;

    let circuit = PhiIdentityCircuit {
        kai_signature: kai_sig,
        expected_user_phikey: phi_key,
        poseidon_config,
    };

    let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
        circuit,
        &proving_key,
        &mut ark_std::test_rng(),
    )
    .map_err(|e| JsValue::from_str(&format!("proof generation failed: {e}")))?;

    let mut buf = vec![];
    proof.serialize_compressed(&mut buf)
        .map_err(|e| JsValue::from_str(&format!("proof serialize failed: {e}")))?;

    Ok(base64::encode(buf))
}
