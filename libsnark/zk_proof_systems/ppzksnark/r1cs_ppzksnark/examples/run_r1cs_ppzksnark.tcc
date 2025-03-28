/** @file
 *****************************************************************************

 Implementation of functionality that runs the R1CS ppzkSNARK for
 a given R1CS example.

 See run_r1cs_ppzksnark.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_R1CS_PPZKSNARK_TCC_
#define RUN_R1CS_PPZKSNARK_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace libsnark {

template<typename ppT>
typename std::enable_if<ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::print_header("R1CS ppzkSNARK Affine Verifier");
    const bool answer = r1cs_ppzksnark_affine_verifier_weak_IC<ppT>(vk, primary_input, proof);
    assert(answer == expected_answer);
}

template<typename ppT>
typename std::enable_if<!ppT::has_affine_pairing, void>::type
test_affine_verifier(const r1cs_ppzksnark_verification_key<ppT> &vk,
                     const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                     const r1cs_ppzksnark_proof<ppT> &proof,
                     const bool expected_answer)
{
    libff::UNUSED(vk, primary_input, proof, expected_answer);
    libff::print_header("R1CS ppzkSNARK Affine Verifier");
    printf("Affine verifier is not supported; not testing anything.\n");
}

/**
 * The code below provides an example of all stages of running a R1CS ppzkSNARK.
 *
 * Of course, in a real-life scenario, we would have three distinct entities,
 * mangled into one in the demonstration below. The three entities are as follows.
 * (1) The "generator", which runs the ppzkSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_ppzksnark(const r1cs_example<libff::Fr<ppT> > &example,
                        const bool test_serialization)
{
    r1cs_example<libff::Fr<ppT> > example_copy(example);
    libff::enter_block("Call to run_r1cs_ppzksnark");

    libff::print_header("R1CS ppzkSNARK Generator");
    r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(example_copy.constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_ppzksnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_ppzksnark_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<r1cs_ppzksnark_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    libff::print_header("R1CS ppzkSNARK Prover");
    r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, example_copy.constraint_system,example_copy.primary_input, example_copy.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<r1cs_ppzksnark_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("R1CS ppzkSNARK Verifier");
    const bool ans = r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example_copy.primary_input, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS ppzkSNARK Online Verifier");
    const bool ans2 = r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example_copy.primary_input, proof);
    assert(ans == ans2);

    test_affine_verifier<ppT>(keypair.vk, example_copy.primary_input, proof, ans);

    libff::leave_block("Call to run_r1cs_ppzksnark");

    return (ans && ans2);
}

} // libsnark

#endif // RUN_R1CS_PPZKSNARK_TCC_
