/** @file
*****************************************************************************

Implementation of functionality of commitment-carrying Groth16


*****************************************************************************/

#ifndef CC_GRO16_TCC_
#define CC_GRO16_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

namespace libsnark {

template<typename ppT>
bool cc_gro16_proving_key<ppT>::operator==(const cc_gro16_proving_key<ppT> &other) const
{
    return (this->alpha_g1 == other.alpha_g1 &&
            this->beta_g1 == other.beta_g1 &&
            this->beta_g2 == other.beta_g2 &&
            this->delta_g1 == other.delta_g1 &&
            this->delta_g2 == other.delta_g2 &&
            this->eta_over_gamma_g1 == other.eta_over_gamma_g1 &&
            this->eta_over_delta_g1 == other.eta_over_delta_g1 &&
            this->gamma_ABC_commitment_g1 == other.gamma_ABC_commitment_g1 &&
            this->A_query == other.A_query &&
            this->B_query == other.B_query &&
            this->H_query == other.H_query &&
            this->L_query == other.L_query
            );
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_proving_key<ppT> &pk)
{
    out << pk.alpha_g1 << OUTPUT_NEWLINE;
    out << pk.beta_g1 << OUTPUT_NEWLINE;
    out << pk.beta_g2 << OUTPUT_NEWLINE;
    out << pk.delta_g1 << OUTPUT_NEWLINE;
    out << pk.delta_g2 << OUTPUT_NEWLINE;
    out << pk.eta_over_gamma_g1 << OUTPUT_NEWLINE;
    out << pk.eta_over_delta_g1 << OUTPUT_NEWLINE;
    out << pk.gamma_ABC_commitment_g1 << OUTPUT_NEWLINE;
    out << pk.A_query;
    out << pk.B_query;
    out << pk.H_query;
    out << pk.L_query;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_proving_key<ppT> &pk)
{
    in >> pk.alpha_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.beta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.eta_over_gamma_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.eta_over_delta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.gamma_ABC_commitment_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.A_query;
    in >> pk.B_query;
    in >> pk.H_query;
    in >> pk.L_query;

    return in;
}

template<typename ppT>
bool cc_gro16_verification_key<ppT>::operator==(const cc_gro16_verification_key<ppT> &other) const
{
    return (this->alpha_g1_beta_g2 == other.alpha_g1_beta_g2 &&
            this->gamma_g2 == other.gamma_g2 &&
            this->delta_g2 == other.delta_g2 &&
            this->gamma_ABC_g1 == other.gamma_ABC_g1);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_verification_key<ppT> &vk)
{
    out << vk.alpha_g1_beta_g2 << OUTPUT_NEWLINE;
    out << vk.gamma_g2 << OUTPUT_NEWLINE;
    out << vk.delta_g2 << OUTPUT_NEWLINE;
    out << vk.gamma_ABC_g1 << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_verification_key<ppT> &vk)
{
    in >> vk.alpha_g1_beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.gamma_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.delta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.gamma_ABC_g1;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool cc_gro16_processed_verification_key<ppT>::operator==(const cc_gro16_processed_verification_key<ppT> &other) const
{
    return (this->vk_alpha_g1_beta_g2 == other.vk_alpha_g1_beta_g2 &&
            this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
            this->vk_delta_g2_precomp == other.vk_delta_g2_precomp &&
            this->gamma_ABC_g1 == other.gamma_ABC_g1);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_processed_verification_key<ppT> &pvk)
{
    out << pvk.vk_alpha_g1_beta_g2 << OUTPUT_NEWLINE;
    out << pvk.vk_gamma_g2_precomp << OUTPUT_NEWLINE;
    out << pvk.vk_delta_g2_precomp << OUTPUT_NEWLINE;
    out << pvk.gamma_ABC_g1 << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_processed_verification_key<ppT> &pvk)
{
    in >> pvk.vk_alpha_g1_beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.vk_gamma_g2_precomp;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.vk_delta_g2_precomp;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.gamma_ABC_g1;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool cc_gro16_proof<ppT>::operator==(const cc_gro16_proof<ppT> &other) const
{
    return (this->g_A == other.g_A &&
            this->g_B == other.g_B &&
            this->g_C == other.g_C);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_proof<ppT> &proof)
{
    out << proof.g_A << OUTPUT_NEWLINE;
    out << proof.g_B << OUTPUT_NEWLINE;
    out << proof.g_C << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_proof<ppT> &proof)
{
    in >> proof.g_A;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.g_B;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.g_C;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
bool cc_gro16_ccproof<ppT>::operator==(const cc_gro16_ccproof<ppT> &other) const
{
    return (this->proof == other.proof &&
            this->commitment == other.commitment &&
            this->opening == other.opening);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_ccproof<ppT> &ccproof)
{
    out << ccproof.proof << OUTPUT_NEWLINE;
    out << ccproof.commitment << OUTPUT_NEWLINE;
    out << ccproof.opening << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_ccproof<ppT> &ccproof)
{
    in >> ccproof.proof;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ccproof.commitment;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ccproof.opening;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
cc_gro16_verification_key<ppT> cc_gro16_verification_key<ppT>::dummy_verification_key(const size_t input_size)
{
    cc_gro16_verification_key<ppT> result;
    result.alpha_g1_beta_g2 = libff::Fr<ppT>::random_element() * libff::GT<ppT>::random_element();
    result.gamma_g2 = libff::G2<ppT>::random_element();
    result.delta_g2 = libff::G2<ppT>::random_element();

    libff::G1<ppT> base = libff::G1<ppT>::random_element();
    libff::G1_vector<ppT> v;
    for (size_t i = 0; i < input_size; ++i)
    {
        v.emplace_back(libff::G1<ppT>::random_element());
    }

    result.gamma_ABC_g1 = accumulation_vector<libff::G1<ppT> >(std::move(base), std::move(v));

    return result;
}

template <typename ppT>
cc_gro16_keypair<ppT> cc_gro16_generator(const cc_gro16_constraint_system<ppT> &r1cs)
{
    libff::enter_block("Call to cc_gro16_generator");

    /* Make the B_query "lighter" if possible */
    //r1cs.swap_AB_if_beneficial();
    // Do this in r1cs_to_r1cs_cc

    /* Generate secret randomness */
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> beta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> gamma = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> eta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> gamma_inverse = gamma.inverse();
    const libff::Fr<ppT> delta_inverse = delta.inverse();
    const libff::Fr<ppT> eta_over_gamma = eta*gamma_inverse;
    const libff::Fr<ppT> eta_over_delta = eta*delta_inverse;

    /* A quadratic arithmetic program evaluated at t. */
    qap_instance_evaluation<libff::Fr<ppT> > qap = r1cs_to_qap_instance_map_with_evaluation(r1cs, t);

    if(!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("* QAP number of variables: %zu\n", qap.num_variables());
        libff::print_indent();
        printf("* QAP pre degree: %zu\n", r1cs.constraints.size());
        libff::print_indent();
        printf("* QAP degree: %zu\n", qap.degree());
        libff::print_indent();
        printf("* QAP number of input variables: %zu\n", qap.num_inputs());
    }

    const size_t rwitness_size = qap.num_variables() - qap.num_inputs() - r1cs.commitment_size;
    const size_t input_commitment_size = qap.num_inputs() + r1cs.commitment_size;

    libff::enter_block("Compute query densities");
    size_t non_zero_At = 0;
    size_t non_zero_Bt = 0;
    for (size_t i = 0; i < qap.num_variables() + 1; ++i)
    {
        if (!qap.At[i].is_zero())
        {
            ++non_zero_At;
        }
        if (!qap.Bt[i].is_zero())
        {
            ++non_zero_Bt;
        }
    }
    libff::leave_block("Compute query densities");

    /* qap.{At,Bt,Ct,Ht} are now in unspecified state, but we do not use them later */
    libff::Fr_vector<ppT> At = std::move(qap.At);
    libff::Fr_vector<ppT> Bt = std::move(qap.Bt);
    libff::Fr_vector<ppT> Ct = std::move(qap.Ct);
    libff::Fr_vector<ppT> Ht = std::move(qap.Ht);

    /* The gamma inverse product component: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * gamma^{-1}. */
    libff::enter_block("Compute gamma_ABC for R1CS verification key");
    libff::Fr_vector<ppT> gamma_ABC;
    gamma_ABC.reserve(input_commitment_size);

    const libff::Fr<ppT> gamma_ABC_0 = (beta * At[0] + alpha * Bt[0] + Ct[0]) * gamma_inverse;
    for (size_t i = 1; i < input_commitment_size + 1; ++i)
    {
        gamma_ABC.emplace_back((beta * At[i] + alpha * Bt[i] + Ct[i]) * gamma_inverse);
    }
    libff::leave_block("Compute gamma_ABC for R1CS verification key");

    /* The delta inverse product component: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * delta^{-1}. */
    libff::enter_block("Compute L query for R1CS proving key");
    libff::Fr_vector<ppT> Lt;
    Lt.reserve(rwitness_size);

    const size_t Lt_offset = input_commitment_size + 1;
    for (size_t i = 0; i < rwitness_size; ++i)
    {
        Lt.emplace_back((beta * At[Lt_offset + i] + alpha * Bt[Lt_offset + i] + Ct[Lt_offset + i]) * delta_inverse);
    }
    libff::leave_block("Compute L query for R1CS proving key");

    /**
     * Note that H for Groth's proof system is degree d-2, but the QAP
     * reduction returns coefficients for degree d polynomial H (in
     * style of PGHR-type proof systems)
     */
    Ht.resize(Ht.size() - 2);

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Generating G1 MSM window table");
    const libff::G1<ppT> g1_generator = libff::G1<ppT>::random_element();
    const size_t g1_scalar_count = non_zero_At + non_zero_Bt + qap.num_variables();
    const size_t g1_scalar_size = libff::Fr<ppT>::ceil_size_in_bits();
    const size_t g1_window_size = libff::get_exp_window_size<libff::G1<ppT> >(g1_scalar_count);

    if(!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("* G1 window: %zu\n", g1_window_size);
    }
    libff::window_table<libff::G1<ppT> > g1_table = libff::get_window_table(g1_scalar_size, g1_window_size, g1_generator);
    libff::leave_block("Generating G1 MSM window table");

    libff::enter_block("Generating G2 MSM window table");
    const libff::G2<ppT> G2_gen = libff::G2<ppT>::random_element();
    const size_t g2_scalar_count = non_zero_Bt;
    const size_t g2_scalar_size = libff::Fr<ppT>::ceil_size_in_bits();
    size_t g2_window_size = libff::get_exp_window_size<libff::G2<ppT> >(g2_scalar_count);

    if(!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("* G2 window: %zu\n", g2_window_size);
    }
    libff::window_table<libff::G2<ppT> > g2_table = libff::get_window_table(g2_scalar_size, g2_window_size, G2_gen);
    libff::leave_block("Generating G2 MSM window table");

    libff::enter_block("Generate R1CS proving key");
    libff::G1<ppT> alpha_g1 = alpha * g1_generator;
    libff::G1<ppT> beta_g1 = beta * g1_generator;
    libff::G2<ppT> beta_g2 = beta * G2_gen;
    libff::G1<ppT> delta_g1 = delta * g1_generator;
    libff::G2<ppT> delta_g2 = delta * G2_gen;
    libff::G1<ppT> eta_over_delta_g1 = eta_over_delta * g1_generator;
    libff::G1<ppT> eta_over_gamma_g1 = eta_over_gamma * g1_generator;

    libff::enter_block("Generate queries");
    libff::enter_block("Compute the A-query", false);
    libff::G1_vector<ppT> A_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, At);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(A_query);
#endif
    libff::leave_block("Compute the A-query", false);

    libff::enter_block("Compute the B-query", false);
    knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > B_query = kc_batch_exp(libff::Fr<ppT>::ceil_size_in_bits(), g2_window_size, g1_window_size, g2_table, g1_table, libff::Fr<ppT>::one(), libff::Fr<ppT>::one(), Bt, chunks);
    // NOTE: if USE_MIXED_ADDITION is defined,
    // kc_batch_exp will convert its output to special form internally
    libff::leave_block("Compute the B-query", false);

    libff::enter_block("Compute the H-query", false);
    libff::G1_vector<ppT> H_query = batch_exp_with_coeff(g1_scalar_size, g1_window_size, g1_table, qap.Zt * delta_inverse, Ht);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(H_query);
#endif
    libff::leave_block("Compute the H-query", false);

    libff::enter_block("Compute the L-query", false);
    libff::G1_vector<ppT> L_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, Lt);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(L_query);
#endif
    libff::leave_block("Compute the L-query", false);
    libff::leave_block("Generate queries");

    libff::leave_block("Generate R1CS proving key");

    libff::enter_block("Generate R1CS verification key");
    libff::GT<ppT> alpha_g1_beta_g2 = ppT::reduced_pairing(alpha_g1, beta_g2);
    libff::G2<ppT> gamma_g2 = gamma * G2_gen;

    libff::enter_block("Encode gamma_ABC for R1CS verification key");
    libff::G1<ppT> gamma_ABC_g1_0 = gamma_ABC_0 * g1_generator;
    libff::G1_vector<ppT> gamma_ABC_g1_values = batch_exp(g1_scalar_size, g1_window_size, g1_table, gamma_ABC);
    libff::leave_block("Encode gamma_ABC for R1CS verification key");
    libff::leave_block("Generate R1CS verification key");

    libff::leave_block("Call to cc_gro16_generator");

    libff::G1_vector<ppT> gamma_ABC_commitment_g1(gamma_ABC_g1_values.begin() + qap.num_inputs(), gamma_ABC_g1_values.end());
    libff::G1_vector<ppT> gamma_ABC_input_g1(gamma_ABC_g1_values.begin(), gamma_ABC_g1_values.begin() + qap.num_inputs());
    accumulation_vector<libff::G1<ppT> > gamma_ABC_g1(std::move(gamma_ABC_g1_0), std::move(gamma_ABC_input_g1));

    cc_gro16_commitment_key<ppT> ck;
    ck.push_back(eta_over_gamma_g1);
    ck.insert(ck.end(), gamma_ABC_commitment_g1.begin(), gamma_ABC_commitment_g1.end());

    cc_gro16_verification_key<ppT> vk = cc_gro16_verification_key<ppT>(alpha_g1_beta_g2,
                                                                                         gamma_g2,
                                                                                         delta_g2,
                                                                                         gamma_ABC_g1);

    cc_gro16_proving_key<ppT> pk = cc_gro16_proving_key<ppT>(std::move(alpha_g1),
                                                                               std::move(beta_g1),
                                                                               std::move(beta_g2),
                                                                               std::move(delta_g1),
                                                                               std::move(delta_g2),
                                                                               std::move(eta_over_gamma_g1),
                                                                               std::move(eta_over_delta_g1),
                                                                               std::move(gamma_ABC_commitment_g1),
                                                                               std::move(A_query),
                                                                               std::move(B_query),
                                                                               std::move(H_query),
                                                                               std::move(L_query));


    pk.print_size();
    vk.print_size();


    return cc_gro16_keypair<ppT>(std::move(pk), std::move(vk), std::move(ck));
}

template <typename ppT>
cc_gro16_ccproof<ppT> cc_gro16_prover(const cc_gro16_proving_key<ppT> &pk,
                                                      const cc_gro16_constraint_system<ppT> &constraint_system,
                                                      const cc_gro16_primary_input<ppT> &primary_input,
                                                      const cc_gro16_auxiliary_input<ppT> &auxiliary_input)
{
    libff::enter_block("Call to cc_gro16_prover");

#ifdef DEBUG
    assert(constraint_system.is_satisfied(primary_input, auxiliary_input));
#endif

    libff::enter_block("Compute the polynomial H");
    const qap_witness<libff::Fr<ppT> > qap_wit = r1cs_to_qap_witness_map(constraint_system, primary_input, auxiliary_input, libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero());

    /* We are dividing degree 2(d-1) polynomial by degree d polynomial
       and not adding a PGHR-style ZK-patch, so our H is degree d-2 */
    assert(!qap_wit.coefficients_for_H[qap_wit.degree()-2].is_zero());
    assert(qap_wit.coefficients_for_H[qap_wit.degree()-1].is_zero());
    assert(qap_wit.coefficients_for_H[qap_wit.degree()].is_zero());
    libff::leave_block("Compute the polynomial H");

#ifdef DEBUG
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    qap_instance_evaluation<libff::Fr<ppT> > qap_inst = r1cs_to_qap_instance_map_with_evaluation(constraint_system, t);
    assert(qap_inst.is_satisfied(qap_wit));
#endif

    /* Choose two random field elements for prover zero-knowledge. */
    const libff::Fr<ppT> r = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> s = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> nu = libff::Fr<ppT>::random_element();

    //const size_t rwitness_size = qap_wit.num_variables() - qap_wit.num_inputs() - constraint_system.commitment_size;
    const size_t input_commitment_size = qap_wit.num_inputs() + constraint_system.commitment_size;

#ifdef DEBUG
    assert(qap_wit.coefficients_for_ABCs.size() == qap_wit.num_variables());
    assert(pk.A_query.size() == qap_wit.num_variables()+1);
    assert(pk.B_query.domain_size() == qap_wit.num_variables()+1);
    assert(pk.H_query.size() == qap_wit.degree() - 1);
    //assert(pk.L_query.size() == rwitness_size);
    assert(pk.gamma_ABC_commitment_g1.size() == constraint_system.commitment_size);
#endif

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Compute the proof");

    libff::enter_block("Compute evaluation to A-query", false);
    // TODO: sort out indexing
    libff::Fr_vector<ppT> const_padded_assignment(1, libff::Fr<ppT>::one());
    const_padded_assignment.insert(const_padded_assignment.end(), qap_wit.coefficients_for_ABCs.begin(), qap_wit.coefficients_for_ABCs.end());

    libff::G1<ppT> evaluation_At = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                                        libff::Fr<ppT>,
                                                                        libff::multi_exp_method_BDLO12>(
        pk.A_query.begin(),
        pk.A_query.begin() + qap_wit.num_variables() + 1,
        const_padded_assignment.begin(),
        const_padded_assignment.begin() + qap_wit.num_variables() + 1,
        chunks);
    libff::leave_block("Compute evaluation to A-query", false);

    libff::enter_block("Compute evaluation to B-query", false);
    knowledge_commitment<libff::G2<ppT>, libff::G1<ppT> > evaluation_Bt = kc_multi_exp_with_mixed_addition<libff::G2<ppT>,
                                                                                                           libff::G1<ppT>,
                                                                                                           libff::Fr<ppT>,
                                                                                                           libff::multi_exp_method_BDLO12>(
        pk.B_query,
        0,
        qap_wit.num_variables() + 1,
        const_padded_assignment.begin(),
        const_padded_assignment.begin() + qap_wit.num_variables() + 1,
        chunks);
    libff::leave_block("Compute evaluation to B-query", false);

    libff::enter_block("Compute evaluation to H-query", false);
    libff::G1<ppT> evaluation_Ht = libff::multi_exp<libff::G1<ppT>,
                                                    libff::Fr<ppT>,
                                                    libff::multi_exp_method_BDLO12>(
        pk.H_query.begin(),
        pk.H_query.begin() + (qap_wit.degree() - 1),
        qap_wit.coefficients_for_H.begin(),
        qap_wit.coefficients_for_H.begin() + (qap_wit.degree() - 1),
        chunks);
    libff::leave_block("Compute evaluation to H-query", false);

    libff::enter_block("Compute evaluation to L-query", false);
    libff::G1<ppT> evaluation_Lt = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                                        libff::Fr<ppT>,
                                                                        libff::multi_exp_method_BDLO12>(
        pk.L_query.begin(),
        pk.L_query.end(),
        const_padded_assignment.begin() + input_commitment_size + 1,
        const_padded_assignment.begin() + qap_wit.num_variables() + 1,
        chunks);
    libff::leave_block("Compute evaluation to L-query", false);

    libff::enter_block("Compute evaluation to D-query", false);
    libff::G1<ppT> evaluation_Dt = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.gamma_ABC_commitment_g1.begin(),
            pk.gamma_ABC_commitment_g1.end(),
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1,
            const_padded_assignment.begin() + input_commitment_size + 1,
            chunks);
    libff::leave_block("Compute evaluation to D-query", false);

    /* A = alpha + sum_i(a_i*A_i(t)) + r*delta */
    libff::G1<ppT> g1_A = pk.alpha_g1 + evaluation_At + r * pk.delta_g1;

    /* B = beta + sum_i(a_i*B_i(t)) + s*delta */
    libff::G1<ppT> g1_B = pk.beta_g1 + evaluation_Bt.h + s * pk.delta_g1;
    libff::G2<ppT> g2_B = pk.beta_g2 + evaluation_Bt.g + s * pk.delta_g2;

    /* C = sum_i(a_i*((beta*A_i(t) + alpha*B_i(t) + C_i(t)) + H(t)*Z(t))/delta) + A*s + B*r - r*s*delta - nu*eta/delta */
    libff::G1<ppT> g1_C = evaluation_Ht + evaluation_Lt + s *  g1_A + r * g1_B - (r * s) * pk.delta_g1 - nu*pk.eta_over_delta_g1;

    /* D = sum_i(a_i*((beta*A_i(t) + alpha*B_i(t) + C_i(t)) + H(t)*Z(t))/gamma)+ nu*eta/gamma */
    libff::G1<ppT> g1_D = evaluation_Dt + nu*pk.eta_over_gamma_g1;

    libff::leave_block("Compute the proof");

    libff::leave_block("Call to cc_gro16_prover");

    cc_gro16_proof<ppT> proof = cc_gro16_proof<ppT>(std::move(g1_A), std::move(g2_B), std::move(g1_C));

    // D is the commitment, nu is the opening
    cc_gro16_ccproof<ppT> ccproof = cc_gro16_ccproof<ppT>(std::move(proof), std::move(g1_D), nu);
    ccproof.print_size();

    return ccproof;
}

template <typename ppT>
cc_gro16_processed_verification_key<ppT> cc_gro16_verifier_process_vk(const cc_gro16_verification_key<ppT> &vk)
{
    libff::enter_block("Call to cc_gro16_verifier_process_vk");

    cc_gro16_processed_verification_key<ppT> pvk;
    pvk.vk_alpha_g1_beta_g2 = vk.alpha_g1_beta_g2;
    pvk.vk_gamma_g2_precomp = ppT::precompute_G2(vk.gamma_g2);
    pvk.vk_delta_g2_precomp = ppT::precompute_G2(vk.delta_g2);
    pvk.gamma_ABC_g1 = vk.gamma_ABC_g1;

    libff::leave_block("Call to cc_gro16_verifier_process_vk");

    return pvk;
}

template <typename ppT>
bool cc_gro16_online_verifier_weak_IC(const cc_gro16_processed_verification_key<ppT> &pvk,
                                               const cc_gro16_primary_input<ppT> &primary_input,
                                               const cc_gro16_commitment<ppT> &commitment,
                                               const cc_gro16_proof<ppT> &proof)
{
    libff::enter_block("Call to cc_gro16_online_verifier_weak_IC");
    assert(pvk.gamma_ABC_g1.domain_size() >= primary_input.size());

    libff::enter_block("Accumulate input");
    const accumulation_vector<libff::G1<ppT> > accumulated_IC = pvk.gamma_ABC_g1.template accumulate_chunk<libff::Fr<ppT> >(primary_input.begin(), primary_input.end(), 0);
    const libff::G1<ppT> acc = accumulated_IC.first + commitment; // commitment is the D-Part of the proof
    libff::leave_block("Accumulate input");

    bool result = true;

    libff::enter_block("Check if the proof is well-formed");
    if (!proof.is_well_formed())
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("At least one of the proof elements does not lie on the curve.\n");
        }
        result = false;
    }
    libff::leave_block("Check if the proof is well-formed");

    libff::enter_block("Online pairing computations");
    libff::enter_block("Check QAP divisibility");
    const libff::G1_precomp<ppT> proof_g_A_precomp = ppT::precompute_G1(proof.g_A);
    const libff::G2_precomp<ppT> proof_g_B_precomp = ppT::precompute_G2(proof.g_B);
    const libff::G1_precomp<ppT> proof_g_C_precomp = ppT::precompute_G1(proof.g_C);
    const libff::G1_precomp<ppT> acc_precomp = ppT::precompute_G1(acc);

    const libff::Fqk<ppT> QAP1 = ppT::miller_loop(proof_g_A_precomp,  proof_g_B_precomp);
    const libff::Fqk<ppT> QAP2 = ppT::double_miller_loop(
        acc_precomp, pvk.vk_gamma_g2_precomp,
        proof_g_C_precomp, pvk.vk_delta_g2_precomp);
    const libff::GT<ppT> QAP = ppT::final_exponentiation(QAP1 * QAP2.unitary_inverse());

    if (QAP != pvk.vk_alpha_g1_beta_g2)
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("QAP divisibility check failed.\n");
        }
        result = false;
    }
    libff::leave_block("Check QAP divisibility");
    libff::leave_block("Online pairing computations");

    libff::leave_block("Call to cc_gro16_online_verifier_weak_IC");

    return result;
}

template<typename ppT>
bool cc_gro16_verifier_weak_IC(const cc_gro16_verification_key<ppT> &vk,
                                        const cc_gro16_primary_input<ppT> &primary_input,
                                        const cc_gro16_commitment<ppT> &commitment,
                                        const cc_gro16_proof<ppT> &proof)
{
    libff::enter_block("Call to cc_gro16_verifier_weak_IC");
    cc_gro16_processed_verification_key<ppT> pvk = cc_gro16_verifier_process_vk<ppT>(vk);
    bool result = cc_gro16_online_verifier_weak_IC<ppT>(pvk, primary_input, commitment, proof);
    libff::leave_block("Call to cc_gro16_verifier_weak_IC");
    return result;
}

template<typename ppT>
bool cc_gro16_online_verifier_strong_IC(const cc_gro16_processed_verification_key<ppT> &pvk,
                                                 const cc_gro16_primary_input<ppT> &primary_input,
                                                 const cc_gro16_commitment<ppT> &commitment,
                                                 const cc_gro16_proof<ppT> &proof)
{
    bool result = true;
    libff::enter_block("Call to cc_gro16_online_verifier_strong_IC");

    if (pvk.gamma_ABC_g1.domain_size() != primary_input.size())
    {
        libff::print_indent(); printf("Input length differs from expected (got %zu, expected %zu).\n", primary_input.size(), pvk.gamma_ABC_g1.domain_size());
        result = false;
    }
    else
    {
        result = cc_gro16_online_verifier_weak_IC(pvk, primary_input, commitment, proof);
    }

    libff::leave_block("Call to cc_gro16_online_verifier_strong_IC");
    return result;
}

template<typename ppT>
bool cc_gro16_verifier_strong_IC(const cc_gro16_verification_key<ppT> &vk,
                                          const cc_gro16_primary_input<ppT> &primary_input,
                                          const cc_gro16_commitment<ppT> &commitment,
                                          const cc_gro16_proof<ppT> &proof)
{
    libff::enter_block("Call to cc_gro16_verifier_strong_IC");
    cc_gro16_processed_verification_key<ppT> pvk = cc_gro16_verifier_process_vk<ppT>(vk);
    bool result = cc_gro16_online_verifier_strong_IC<ppT>(pvk, primary_input, commitment, proof);
    libff::leave_block("Call to cc_gro16_verifier_strong_IC");
    return result;
}

} // libsnark
#endif // CC_GRO16_TCC_
