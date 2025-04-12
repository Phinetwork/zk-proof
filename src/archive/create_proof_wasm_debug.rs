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

/// 📜 ZK circuit: Poseidon(kai_signature) == expected_user_phikey
#[derive(Clone)]
pub struct PhiIdentityCircuit {
    pub kai_signature: Fr,
    pub expected_user_phikey: Fr,
    pub poseidon_config: PoseidonConfig<Fr>,
}

impl ConstraintSynthesizer<Fr> for PhiIdentityCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
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

/// 🧬 WASM-compatible proof generation
#[wasm_bindgen]
pub fn create_proof_wasm(
    kai_sig_bytes: &[u8],
    user_phikey_bytes: &[u8],
    proving_key_bytes: &[u8],
    poseidon_params_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let kai_sig: Fr = CanonicalDeserialize::deserialize_compressed(kai_sig_bytes)
        .map_err(|e| JsValue::from_str(&format!("kai_sig deserialize error: {:?}", e)))?;
    let user_phikey: Fr = CanonicalDeserialize::deserialize_compressed(user_phikey_bytes)
        .map_err(|e| JsValue::from_str(&format!("user_phikey deserialize error: {:?}", e)))?;
    let proving_key: ProvingKey<Bls12_381> =
        CanonicalDeserialize::deserialize_compressed(proving_key_bytes)
            .map_err(|e| JsValue::from_str(&format!("proving_key deserialize error: {:?}", e)))?;
    let poseidon_config: PoseidonConfig<Fr> =
        CanonicalDeserialize::deserialize_compressed(poseidon_params_bytes)
            .map_err(|e| JsValue::from_str(&format!("poseidon params deserialize error: {:?}", e)))?;

    let circuit = PhiIdentityCircuit {
        kai_signature: kai_sig,
        expected_user_phikey: user_phikey,
        poseidon_config,
    };

    let proof = Groth16::<Bls12_381>::create_random_proof_with_reduction(
        circuit,
        &proving_key,
        &mut ark_std::test_rng(),
    )
    .map_err(|e| JsValue::from_str(&format!("Proof generation error: {:?}", e)))?;

    let mut proof_bytes = vec![];
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("proof serialize error: {:?}", e)))?;

    Ok(proof_bytes)
}
