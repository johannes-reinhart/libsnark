/** @file
*****************************************************************************

Implementation of interfaces for LegoGro16 SNARK with State-Consistency

*****************************************************************************/

#ifndef SC_LEGO_GRO16_TCC_
#define SC_LEGO_GRO16_TCC_

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/sc_legogro16.hpp>
#include <libff/common/utils.hpp>

namespace libsnark {

template<typename ppT>
bool sc_lego_gro16_proving_key<ppT>::operator==(const sc_lego_gro16_proving_key<ppT> &other) const
{
    return (this->pk_lego_gro16 == other.pk_lego_gro16 &&
            this->commitment_key == other.commitment_key);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const sc_lego_gro16_proving_key<ppT> &pk)
{
    out << pk.pk_lego_gro16 << OUTPUT_NEWLINE;
    out << pk.commitment_key << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, sc_lego_gro16_proving_key<ppT> &pk)
{
    in >> pk.pk_lego_gro16;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.commitment_key;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}


template<typename ppT>
bool sc_lego_gro16_proof<ppT>::operator==(const sc_lego_gro16_proof<ppT> &other) const
{
    return (this->proof == other.proof &&
            this->commitment == other.commitment);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const sc_lego_gro16_proof<ppT> &proof)
{
    out << proof.proof << OUTPUT_NEWLINE;
    out << proof.commitment << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, sc_lego_gro16_proof<ppT> &proof)
{
    in >> proof.proof;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.commitment;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}



template <typename ppT>
sc_lego_gro16_keypair<ppT> sc_lego_gro16_generator(const lego_gro16_constraint_system<ppT> &cs, const lego_gro16_assignment<ppT> &initial_state)
{
    libff::enter_block("Call to sc_lego_gro16_generator");

    sc_lego_gro16_proof<ppT> initial_proof;
    sc_lego_gro16_prover_state<ppT> initial_prover_state;

    pedersen_commitment_key<ppT> ck = pedersen_commitment_generator<ppT>(cs.commitment_size);
    pedersen_commitment_pair<ppT> cp0 = pedersen_commitment_commit<ppT>(ck, initial_state);
    lego_gro16_keypair<ppT> keypair = lego_gro16_generator<ppT>(ck, cs);
    libff::leave_block("Call to sc_lego_gro16_generator");

    sc_lego_gro16_proving_key<ppT> pk(std::move(keypair.pk), std::move(ck));

    initial_prover_state.cp = cp0;
    initial_proof.commitment = cp0.commitment;

    return sc_lego_gro16_keypair<ppT>(std::move(pk), std::move(keypair.vk), std::move(initial_proof), std::move(initial_prover_state));
}

template <typename ppT>
sc_lego_gro16_proof<ppT> sc_lego_gro16_prover(const sc_lego_gro16_proving_key<ppT> &pk,
                                              const lego_gro16_constraint_system<ppT> &constraint_system,
                                              const lego_gro16_primary_input<ppT> &primary_input,
                                              const lego_gro16_assignment<ppT> &state_assignment_old,
                                              const lego_gro16_assignment<ppT> &state_assignment_new,
                                              const lego_gro16_assignment<ppT> &witness_assignment,
                                              sc_lego_gro16_prover_state<ppT> &prover_state)
{
    r1cs_variable_assignment<libff::Fr<ppT>> auxiliary_input(state_assignment_old);
    auxiliary_input.insert(auxiliary_input.end(), state_assignment_new.begin(), state_assignment_new.end());
    auxiliary_input.insert(auxiliary_input.end(), witness_assignment.begin(), witness_assignment.end());

    libff::enter_block("Call to sc_lego_gro16_prover");
    pedersen_commitment_pair<ppT> cp = pedersen_commitment_commit<ppT>(pk.commitment_key, state_assignment_new);

    lego_gro16_proof<ppT> legogro_proof = lego_gro16_prover<ppT>(pk.pk_lego_gro16,
                                                       constraint_system,
                                                       primary_input,
                                                       {prover_state.cp.commitment, cp.commitment},
                                                       {prover_state.cp.opening, cp.opening},
                                                       auxiliary_input);

    libff::leave_block("Call to sc_lego_gro16_prover");

    sc_lego_gro16_proof<ppT> proof = sc_lego_gro16_proof<ppT>(std::move(legogro_proof), std::move(cp.commitment));
    prover_state.cp = cp;

    return proof;
}

template<typename ppT>
sc_lego_gro16_processed_verification_key<ppT> sc_lego_gro16_verifier_process_vk(const sc_lego_gro16_verification_key<ppT> &vk)
{
    return lego_gro16_verifier_process_vk(vk);
}

template <typename ppT>
bool sc_lego_gro16_online_verifier_weak_IC(const sc_lego_gro16_processed_verification_key<ppT> &vk,
                                            const lego_gro16_primary_input<ppT> &primary_input,
                                            const sc_lego_gro16_proof<ppT> &proof,
                                            const sc_lego_gro16_proof<ppT> &proof_previous)
{
    bool result;
    libff::enter_block("Call to sc_lego_gro16_online_verifier_weak_IC");
    result = lego_gro16_online_verifier_weak_IC(vk, primary_input, {proof_previous.commitment, proof.commitment}, proof.proof);
    libff::leave_block("Call to sc_lego_gro16_online_verifier_weak_IC");

    return result;
}

template<typename ppT>
bool sc_lego_gro16_verifier_weak_IC(const sc_lego_gro16_verification_key<ppT> &vk,
                                    const lego_gro16_primary_input<ppT> &primary_input,
                                    const sc_lego_gro16_proof<ppT> &proof,
                                    const sc_lego_gro16_proof<ppT> &proof_previous)
{
    libff::enter_block("Call to sc_lego_gro16_verifier_weak_IC");
    sc_lego_gro16_processed_verification_key<ppT> pvk = sc_lego_gro16_verifier_process_vk<ppT>(vk);
    bool result = sc_lego_gro16_online_verifier_weak_IC<ppT>(pvk, primary_input, proof, proof_previous);
    libff::leave_block("Call to sc_lego_gro16_verifier_weak_IC");
    return result;
}

template<typename ppT>
bool sc_lego_gro16_online_verifier_strong_IC(const sc_lego_gro16_processed_verification_key<ppT> &vk,
                                             const lego_gro16_primary_input<ppT> &primary_input,
                                             const sc_lego_gro16_proof<ppT> &proof,
                                             const sc_lego_gro16_proof<ppT> &proof_previous)
{
    bool result;
    libff::enter_block("Call to sc_lego_gro16_online_verifier_strong_IC");
    result = lego_gro16_online_verifier_strong_IC(vk, primary_input, {proof_previous.commitment, proof.commitment}, proof.proof);
    libff::leave_block("Call to sc_lego_gro16_online_verifier_strong_IC");
    return result;
}

template<typename ppT>
bool sc_lego_gro16_verifier_strong_IC(const sc_lego_gro16_verification_key<ppT> &vk,
                                      const lego_gro16_primary_input<ppT> &primary_input,
                                      const sc_lego_gro16_proof<ppT> &proof,
                                      const sc_lego_gro16_proof<ppT> &proof_previous)
{
    libff::enter_block("Call to sc_lego_gro16_verifier_strong_IC");
    sc_lego_gro16_processed_verification_key<ppT> pvk = sc_lego_gro16_verifier_process_vk<ppT>(vk);
    bool result = sc_lego_gro16_online_verifier_strong_IC<ppT>(pvk, primary_input, proof, proof_previous);
    libff::leave_block("Call to sc_lego_gro16_verifier_strong_IC");
    return result;
}



} // libsnark
#endif // SC_LEGO_GRO16_TCC_
