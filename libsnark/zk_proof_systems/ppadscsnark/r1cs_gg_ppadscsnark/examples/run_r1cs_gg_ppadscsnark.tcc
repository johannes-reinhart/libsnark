/** @file
 *****************************************************************************

 Implementation of functionality that runs the R1CS GG-ppADSCSNARK for
 a given R1CS example.

 See run_r1cs_gg_ppadscsnark.hpp .

 *****************************************************************************/

#ifndef RUN_R1CS_GG_PPADSCSNARK_TCC_
#define RUN_R1CS_GG_PPADSCSNARK_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppadscsnark/r1cs_gg_ppadscsnark.hpp>
#include <libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.hpp>

namespace libsnark {


/**
 * The code below provides an example of all stages of running a R1CS GG-ppADSCSNARK.
 *
 * Of course, in a real-life scenario, we would have four distinct entities,
 * mangled into one in the demonstration below. The four entities are as follows.
 * (1) The "generator", which runs the ppSNARK generator on input a given
 *     constraint system CS to create a proving and a verification key for CS.
 * (2) The "authenticator", which authenticates private input values
 * (3) The "prover", which runs the ppSNARK prover on input the proving key,
 *     a primary input for CS, and an auxiliary input for CS.
 * (4) The "verifier", which runs the ppSNARK verifier on input the verification key,
 *     a primary input for CS, and a proof.
 */
template<typename ppT>
bool run_r1cs_gg_ppadscsnark(r1cs_adsc_example<libff::Fr<ppT>> &example,
                             size_t private_input_size,
                             size_t state_size,
                             size_t iterations,
                             const bool test_serialization)
{
    libff::enter_block("Call to run_r1cs_gg_ppadscsnark");

    libff::enter_block("Call to r1cs_to_r1cs_adsc");
    r1cs_gg_ppadscsnark_constraint_system<ppT> constraint_system = r1cs_to_r1cs_adsc(std::move(example.constraint_system), private_input_size, state_size);
    libff::leave_block("Call to r1cs_to_r1cs_adsc");

    // Check that constraint system is satisfied within each iteration
    for(size_t t = 0; t < iterations; ++t){
        r1cs_variable_assignment<libff::Fr<ppT>> auxiliary_input(example.private_input[t]);
        auxiliary_input.insert(auxiliary_input.end(), example.state_assignment[t].begin(), example.state_assignment[t].end());
        auxiliary_input.insert(auxiliary_input.end(), example.state_assignment[t+1].begin(), example.state_assignment[t+1].end());
        auxiliary_input.insert(auxiliary_input.end(), example.witness_assignment[t].begin(), example.witness_assignment[t].end());
        assert(constraint_system.is_satisfied(example.primary_input[t], auxiliary_input));
    }

    libff::print_header("R1CS GG-ppADSCSNARK Generator");
    r1cs_gg_ppadscsnark_keypair<ppT> keypair = r1cs_gg_ppadscsnark_generator<ppT>(constraint_system, example.state_assignment[0]);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    r1cs_gg_ppadscsnark_processed_verification_key<ppT> pvk = r1cs_gg_ppadscsnark_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<r1cs_gg_ppadscsnark_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<r1cs_gg_ppadscsnark_verification_key<ppT> >(keypair.vk);
        for(size_t i = 0; i < keypair.aks.size(); ++i){
            keypair.aks[i] = libff::reserialize<r1cs_gg_ppadscsnark_authentication_key<ppT> >(keypair.aks[i]);
        }
        pvk = libff::reserialize<r1cs_gg_ppadscsnark_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    r1cs_gg_ppadscsnark_proof<ppT> previous_proof = keypair.initial_proof;
    bool result = true;
    for(size_t t = 0; t < iterations; ++t) {
        libff::print_header("R1CS GG-ppADSCSNARK Authenticator");
        authentication_tags<ppT> tags = r1cs_gg_ppadscsnark_authenticate(keypair.aks[0], constraint_system.primary_input_size + 1, t, example.private_input[t]);

        if (test_serialization)
        {
            libff::enter_block("Test serialization of authentication tags");
            tags = libff::reserialize<authentication_tags<ppT> >(tags);
            libff::leave_block("Test serialization of authentication tags");
        }

        libff::print_header("R1CS GG-ppADSCSNARK Prover");
        r1cs_variable_assignment<libff::Fr<ppT>> auxiliary_input(example.private_input[t]);
        auxiliary_input.insert(auxiliary_input.end(), example.state_assignment[t].begin(), example.state_assignment[t].end());
        auxiliary_input.insert(auxiliary_input.end(), example.state_assignment[t+1].begin(), example.state_assignment[t+1].end());
        auxiliary_input.insert(auxiliary_input.end(), example.witness_assignment[t].begin(), example.witness_assignment[t].end());
        r1cs_gg_ppadscsnark_proof<ppT> proof = r1cs_gg_ppadscsnark_prover<ppT>(keypair.pk,
                                                                           constraint_system,
                                                                           example.primary_input[t],
                                                                           auxiliary_input,
                                                                           tags);
        printf("\n"); libff::print_indent(); libff::print_mem("after prover");

        if (test_serialization)
        {
            libff::enter_block("Test serialization of proof");
            proof = libff::reserialize<r1cs_gg_ppadscsnark_proof<ppT> >(proof);
            libff::leave_block("Test serialization of proof");
        }

        libff::print_header("R1CS GG-ppADSCSNARK Verifier");
        const bool ans = r1cs_gg_ppadscsnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input[t], proof, previous_proof, t);
        printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
        printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

        libff::print_header("R1CS GG-ppADSCSNARK Online Verifier");
    #ifndef NDEBUG
        const bool ans2 = r1cs_gg_ppadscsnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input[t], proof, previous_proof, t);
    #endif
        assert(ans == ans2);
        previous_proof = proof;
        result = result && ans;
        if (!result){
            return result;
        }
    }


    libff::leave_block("Call to run_r1cs_gg_ppadscsnark");

    return result;
}

} // libsnark

#endif // RUN_R1CS_GG_PPADSCSNARK_TCC_
