/** @file
*****************************************************************************

Implementation of interfaces for a ppADSCSNARK for R1CS.

See r1cs_gg_ppadscsnark.hpp .

*****************************************************************************/

#ifndef R1CS_GG_PPADSCSNARK_TCC_
#define R1CS_GG_PPADSCSNARK_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/prf/prf.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_plain_qap/r1cs_to_plain_qap.hpp>

namespace libsnark {

template<typename ppT>
bool r1cs_gg_ppadscsnark_proving_key<ppT>::operator==(const r1cs_gg_ppadscsnark_proving_key<ppT> &other) const
{
    return (this->alpha_g1 == other.alpha_g1 &&
            this->A_query == other.A_query &&
            this->Pi_state_new_query == other.Pi_state_new_query &&
            this->Qi_state_query == other.Qi_state_query &&
            this->Pi_rws_delta_query == other.Pi_rws_delta_query &&
            this->H_delta_query == other.H_delta_query &&
            this->Pi_rw_zeta_query == other.Pi_rw_zeta_query &&
            this->Pi_priv_input_query == other.Pi_priv_input_query &&
            this->H_zeta_query == other.H_zeta_query &&
            this->beta_g2 == other.beta_g2 &&
            this->B_query == other.B_query
            );
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_proving_key<ppT> &pk)
{
    out << pk.alpha_g1 << OUTPUT_NEWLINE;
    out << pk.beta_g2 << OUTPUT_NEWLINE;

    out << pk.A_query;
    out << pk.Pi_state_new_query;
    out << pk.Qi_state_query;
    out << pk.Pi_rws_delta_query;
    out << pk.H_delta_query;
    out << pk.Pi_rw_zeta_query;
    out << pk.Pi_priv_input_query;
    out << pk.H_zeta_query;
    out << pk.B_query;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_proving_key<ppT> &pk)
{
    in >> pk.alpha_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);

    in >> pk.A_query;
    in >> pk.Pi_state_new_query;
    in >> pk.Qi_state_query;
    in >> pk.Pi_rws_delta_query;
    in >> pk.H_delta_query;
    in >> pk.Pi_rw_zeta_query;
    in >> pk.Pi_priv_input_query;
    in >> pk.H_zeta_query;
    in >> pk.B_query;

    return in;
}

template<typename ppT>
bool r1cs_gg_ppadscsnark_verification_key<ppT>::operator==(const r1cs_gg_ppadscsnark_verification_key<ppT> &other) const
{
    return (this->Pi_statement_query == other.Pi_statement_query &&
            this->alpha_g1_beta_g2 == other.alpha_g1_beta_g2 &&
            this->zeta == other.zeta &&
            this->eta == other.eta &&
            this->delta == other.delta &&
            this->xi == other.xi &&
            this->kappa == other.kappa &&
            this->prfseed2 == other.prfseed2 &&
            this->macsaltaccu_g1 == other.macsaltaccu_g1 &&
            this->one_g1 == other.one_g1,
            this->one_g2 == other.one_g2
            );
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_verification_key<ppT> &vk)
{
    out << vk.Pi_statement_query << OUTPUT_NEWLINE;
    out << vk.alpha_g1_beta_g2 << OUTPUT_NEWLINE;
    out << vk.zeta << OUTPUT_NEWLINE;
    out << vk.eta << OUTPUT_NEWLINE;
    out << vk.delta << OUTPUT_NEWLINE;
    out << vk.xi << OUTPUT_NEWLINE;
    out << vk.kappa << OUTPUT_NEWLINE;
    out << vk.prfseed2 << OUTPUT_NEWLINE;
    out << vk.macsaltaccu_g1 << OUTPUT_NEWLINE;
    out << vk.one_g1 << OUTPUT_NEWLINE;
    out << vk.one_g2 << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_verification_key<ppT> &vk)
{
    in >> vk.Pi_statement_query;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.alpha_g1_beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.zeta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.eta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.delta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.xi;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.kappa;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.prfseed2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.macsaltaccu_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.one_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.one_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
r1cs_gg_ppadscsnark_verification_key<ppT> r1cs_gg_ppadscsnark_verification_key<ppT>::dummy_verification_key(const size_t input_size)
{
    r1cs_gg_ppadscsnark_verification_key<ppT> result;
    result.alpha_g1_beta_g2 = libff::Fr<ppT>::random_element() * libff::GT<ppT>::random_element();
    result.zeta = libff::Fr<ppT>::random_element();
    result.eta = libff::Fr<ppT>::random_element();
    result.delta = libff::Fr<ppT>::random_element();
    result.xi = libff::Fr<ppT>::random_element();
    result.kappa = libff::Fr<ppT>::random_element();
    result.prfseed2 = libff::Fr<ppT>::random_element();
    result.macsaltaccu_g1 = libff::G1<ppT>::random_element();
    result.one_g1 = libff::G1<ppT>::random_element();
    result.one_g2 = libff::G2<ppT>::random_element();

    libff::Fr_vector<ppT> v;
    for (size_t i = 0; i < input_size; ++i)
    {
        v.emplace_back(libff::Fr<ppT>::random_element());
    }

    result.Pi_statement_query = v;

    return result;
}

template<typename ppT>
bool r1cs_gg_ppadscsnark_processed_verification_key<ppT>::operator==(const r1cs_gg_ppadscsnark_processed_verification_key<ppT> &other) const
{
    return (this->Pi_statement_query == other.Pi_statement_query &&
        this->alpha_g1_beta_g2 == other.alpha_g1_beta_g2 &&
        this->zeta == other.delta &&
        this->eta == other.xi &&
        this->delta == other.delta &&
        this->xi == other.xi &&
        this->kappa == other.kappa &&
        this->prfseed2 == other.prfseed2 &&
        this->macsaltaccu_g1 == other.macsaltaccu_g1 &&
        this->one_g1 == other.one_g1 &&
        this->mone_g2_precomp == other.mone_g2_precomp
    );
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk)
{
    out << pvk.Pi_statement_query << OUTPUT_NEWLINE;
    out << pvk.alpha_g1_beta_g2 << OUTPUT_NEWLINE;
    out << pvk.zeta << OUTPUT_NEWLINE;
    out << pvk.eta << OUTPUT_NEWLINE;
    out << pvk.delta << OUTPUT_NEWLINE;
    out << pvk.xi << OUTPUT_NEWLINE;
    out << pvk.kappa << OUTPUT_NEWLINE;
    out << pvk.prfseed2 << OUTPUT_NEWLINE;
    out << pvk.macsaltaccu_g1 << OUTPUT_NEWLINE;
    out << pvk.one_g1 << OUTPUT_NEWLINE;
    out << pvk.mone_g2_precomp << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk)
{
    in >> pvk.Pi_statement_query;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.alpha_g1_beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.zeta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.eta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.delta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.xi;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.kappa;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.prfseed2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.macsaltaccu_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.one_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.mone_g2_precomp;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
bool r1cs_gg_ppadscsnark_authentication_key<ppT>::operator==(const r1cs_gg_ppadscsnark_authentication_key<ppT> &other) const
{
    return (this->prfseed1 == other.prfseed1 &&
    this->prfseed2 == other.prfseed2);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_authentication_key<ppT> &ak)
{
    out << ak.prfseed1 << OUTPUT_NEWLINE;
    out << ak.prfseed2 << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_authentication_key<ppT> &ak)
{
    in >> ak.prfseed1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ak.prfseed2;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool r1cs_gg_ppadscsnark_proof<ppT>::operator==(const r1cs_gg_ppadscsnark_proof<ppT> &other) const
{
    return (this->A_g1 == other.A_g1 &&
            this->C_g1 == other.C_g1 &&
            this->D_g1 == other.D_g1 &&
            this->E_g1 == other.E_g1 &&
            this->F_g1 == other.F_g1 &&
            this->G_g1 == other.G_g1 &&
            this->B_g2 == other.B_g2);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_proof<ppT> &proof)
{
    out << proof.A_g1 << OUTPUT_NEWLINE;
    out << proof.C_g1 << OUTPUT_NEWLINE;
    out << proof.D_g1 << OUTPUT_NEWLINE;
    out << proof.E_g1 << OUTPUT_NEWLINE;
    out << proof.F_g1 << OUTPUT_NEWLINE;
    out << proof.G_g1 << OUTPUT_NEWLINE;
    out << proof.B_g2 << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_proof<ppT> &proof)
{
    in >> proof.A_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.C_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.D_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.E_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.F_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.G_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.B_g2;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}



template <typename ppT>
r1cs_gg_ppadscsnark_keypair<ppT> r1cs_gg_ppadscsnark_generator(const r1cs_gg_ppadscsnark_constraint_system<ppT> &r1cs,
                                                               const r1cs_gg_ppadscsnark_variable_assignment<ppT> &initial_state,
                                                               std::vector<size_t> private_input_blocks)
{
    libff::enter_block("Call to r1cs_gg_ppadscsnark_generator");
    assert(initial_state.size() == r1cs.state_size);

    std::vector<size_t> accumulated_input_block_size;
    if(private_input_blocks.size() == 0)
    {
        // Default case, just one authentication key for entire private-input-block
        accumulated_input_block_size.push_back(r1cs.private_input_size);
    } else
    {
        // Otherwise check, that all inputs are covered
        size_t acc = 0;
        for(size_t i = 0; i < private_input_blocks.size(); ++i){
            assert(private_input_blocks[i] != 0);
            acc += private_input_blocks[i];
            accumulated_input_block_size.push_back(acc);
        }
        assert(acc == r1cs.private_input_size);
    }

    /* Make the B_query "lighter" if possible */
    //r1cs.swap_AB_if_beneficial();
    // This step can be carried out before inputting into the generator (e.g. in r1cs_to_r1cs_ad),
    // as this changes the constraint system -> and the prover needs the same constraint system

    /* Generate secret randomness */
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> beta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> xi = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> eta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> zeta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> kappa = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> prfseed2 = libff::Fr<ppT>::random_element();

    std::vector<libff::Fr<ppT>> prfseed1_v;
    for(size_t i = 0; i < accumulated_input_block_size.size(); ++i)
    {
        prfseed1_v.push_back(libff::Fr<ppT>::random_element());
    }


    const libff::Fr<ppT> xi_inverse = xi.inverse();
    const libff::Fr<ppT> delta_inverse = delta.inverse();
    const libff::Fr<ppT> kappa_over_eta = kappa*eta.inverse();
    const libff::Fr<ppT> zeta_inverse = zeta.inverse();

    /* A quadratic arithmetic program evaluated at t. */
    qap_instance_evaluation<libff::Fr<ppT> > qap = r1cs_to_plain_qap_instance_map_with_evaluation(r1cs, t);

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

    /* The verifier key components for public inputs: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * delta^{-1}. */
    libff::enter_block("Compute Pi_statement query for R1CS verification key");
    libff::Fr_vector<ppT> Pi_statement_t;
    Pi_statement_t.reserve(qap.num_inputs()+1);

    for (size_t i = 0; i < qap.num_inputs() + 1; ++i)
    {
        Pi_statement_t.emplace_back((beta * At[i] + alpha * Bt[i] + Ct[i]));
    }
    libff::leave_block("Compute Pi_statement query for R1CS verification key");

    /* The product component for the new state: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * kappa * eta^{-1}. */
    libff::enter_block("Compute Pi_state_new_query query for R1CS proving key");
    libff::Fr_vector<ppT> Pi_state_new_t;
    Pi_state_new_t.reserve(r1cs.state_size);

    const size_t Pi_state_new_offset = qap.num_inputs() + 1 + r1cs.private_input_size + r1cs.state_size;
    for (size_t i = 0; i < r1cs.state_size; ++i)
    {
        Pi_state_new_t.emplace_back((beta * At[Pi_state_new_offset + i] + alpha * Bt[Pi_state_new_offset + i] + Ct[Pi_state_new_offset + i]) * kappa_over_eta);
    }
    libff::leave_block("Compute Pi_state_new_query query for R1CS proving key");

    /* The product component for the old state: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * zeta^{-1}. */
    libff::enter_block("Compute Qi_state_query query for R1CS proving key");
    libff::Fr_vector<ppT> Qi_state_t;
    Qi_state_t.reserve(r1cs.state_size);

    const size_t Qi_state_old_offset = qap.num_inputs() + 1 + r1cs.private_input_size;
    const size_t Qi_state_new_offset = qap.num_inputs() + 1 + r1cs.private_input_size + r1cs.state_size;
    for (size_t i = 0; i < r1cs.state_size; ++i)
    {
        Qi_state_t.emplace_back((
                                        beta *  (At[Qi_state_old_offset + i] + kappa*At[Qi_state_new_offset + i]) +
                                        alpha * (Bt[Qi_state_old_offset + i] + kappa*Bt[Qi_state_new_offset + i]) +
                                        (Ct[Qi_state_old_offset + i] + kappa*Ct[Qi_state_new_offset + i]) ) * zeta_inverse);
    }
    libff::leave_block("Compute Qi_state_query query for R1CS proving key");

    /* The product component for the remaining witness and delta: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * delta^{-1}. */
    libff::enter_block("Compute Pi_rws_delta_query query for R1CS proving key");
    libff::Fr_vector<ppT> Pi_rws_delta_t;
    Pi_rws_delta_t.reserve(qap.num_variables() - qap.num_inputs() - r1cs.private_input_size - r1cs.state_size);

    const size_t Pi_rws_delta_state_offset = qap.num_inputs() + 1 + r1cs.private_input_size;
    const size_t Pi_rws_delta_rwitness_offset = qap.num_inputs() + 1 + r1cs.private_input_size + 2*r1cs.state_size;
    for (size_t i = 0; i < r1cs.state_size; ++i)
    {
        Pi_rws_delta_t.emplace_back((beta * At[Pi_rws_delta_state_offset + i] + alpha * Bt[Pi_rws_delta_state_offset + i] + Ct[Pi_rws_delta_state_offset + i]) * delta_inverse);
    }
    for (size_t i = 0; i < qap.num_variables() - qap.num_inputs() - r1cs.private_input_size - 2*r1cs.state_size; ++i)
    {
        Pi_rws_delta_t.emplace_back((beta * At[Pi_rws_delta_rwitness_offset + i] + alpha * Bt[Pi_rws_delta_rwitness_offset + i] + Ct[Pi_rws_delta_rwitness_offset + i]) * delta_inverse);
    }
    libff::leave_block("Compute Pi_rws_delta_query query for R1CS proving key");

    /* The product component for the remaining witness and zeta: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * zeta^{-1}. */
    libff::enter_block("Compute Pi_rw_zeta_query query for R1CS proving key");
    libff::Fr_vector<ppT> Pi_rw_zeta_t;
    Pi_rw_zeta_t.reserve(qap.num_variables() - qap.num_inputs() - r1cs.private_input_size - 2*r1cs.state_size);

    const size_t Pi_rw_zeta_offset = qap.num_inputs() + 1 + r1cs.private_input_size + 2*r1cs.state_size;
    for (size_t i = 0; i < qap.num_variables() - qap.num_inputs() - r1cs.private_input_size - 2*r1cs.state_size; ++i)
    {
        Pi_rw_zeta_t.emplace_back((beta * At[Pi_rw_zeta_offset + i] + alpha * Bt[Pi_rw_zeta_offset + i] + Ct[Pi_rw_zeta_offset + i]) * zeta_inverse);
    }
    libff::leave_block("Compute Pi_rw_zeta_query query for R1CS proving key");

    /* The product component for the private input: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * xi^{-1}. */
    libff::enter_block("Compute Pi_priv_input query for R1CS proving key");
    libff::Fr_vector<ppT> Pi_priv_input_t;
    Pi_priv_input_t.reserve(r1cs.private_input_size);

    const size_t Pi_priv_input_query_offset = qap.num_inputs() + 1;
    for (size_t i = 0; i < r1cs.private_input_size; ++i)
    {
        Pi_priv_input_t.emplace_back((beta * At[Pi_priv_input_query_offset + i] + alpha * Bt[Pi_priv_input_query_offset + i] + Ct[Pi_priv_input_query_offset + i]) * xi_inverse);
    }
    libff::leave_block("Compute Pi_priv_input query for R1CS proving key");

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
    libff::G2<ppT> beta_g2 = beta * G2_gen;

    libff::enter_block("Generate queries");
    libff::enter_block("Compute the A-query", false);
    libff::G1_vector<ppT> A_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, At);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(A_query);
#endif
    libff::leave_block("Compute the A-query", false);

    libff::enter_block("Compute the B-query", false);
    libff::G2_vector<ppT> B_query = batch_exp(g2_scalar_size, g2_window_size, g2_table, Bt);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G2<ppT> >(B_query);
#endif

    libff::leave_block("Compute the B-query", false);

    libff::enter_block("Compute the H-query", false);
    libff::G1_vector<ppT> H_delta_query = batch_exp_with_coeff(g1_scalar_size, g1_window_size, g1_table, qap.Zt * delta_inverse, Ht);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(H_delta_query);
#endif
    libff::G1_vector<ppT> H_zeta_query = batch_exp_with_coeff(g1_scalar_size, g1_window_size, g1_table, qap.Zt * zeta_inverse, Ht);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(H_zeta_query);
#endif
    libff::leave_block("Compute the H-query", false);

    libff::enter_block("Compute the Pi_state_new_query", false);
    libff::G1_vector<ppT> Pi_state_new_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, Pi_state_new_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Pi_state_new_query);
#endif
    libff::leave_block("Compute the Pi_state_new_query", false);
    libff::enter_block("Compute the Qi_state_query", false);
    libff::G1_vector<ppT> Qi_state_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, Qi_state_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Qi_state_query);
#endif
    libff::leave_block("Compute the Qi_state_query", false);
    libff::enter_block("Compute the Pi_rws_delta_query", false);
    libff::G1_vector<ppT> Pi_rws_delta_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, Pi_rws_delta_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Pi_rws_delta_query);
#endif
    libff::leave_block("Compute the Pi_rws_delta_query", false);
    libff::enter_block("Compute the Pi_rw_zeta_query", false);
    libff::G1_vector<ppT> Pi_rw_zeta_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, Pi_rw_zeta_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Pi_rw_zeta_query);
#endif
    libff::leave_block("Compute the Pi_rw_zeta_query", false);

    libff::enter_block("Compute the Pi_priv_input-query", false);
    libff::G1_vector<ppT> Pi_priv_input_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, Pi_priv_input_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Pi_priv_input_query);
#endif
    libff::leave_block("Compute the Pi_priv_input-query", false);
    libff::leave_block("Generate queries");

    libff::leave_block("Generate R1CS proving key");

    libff::enter_block("Generate R1CS verification key");
    libff::GT<ppT> alpha_g1_beta_g2 = ppT::reduced_pairing(alpha_g1, beta_g2);


    libff::enter_block("Compute accumulated mac salt");
    libff::Fr<ppT> macsaltaccu = libff::Fr<ppT>(0);
    size_t list_idx = 0;
    for(size_t i = 0; i < r1cs.private_input_size; i++){
        if(i >= accumulated_input_block_size[list_idx]){
            ++list_idx;
        }
        macsaltaccu += prp<libff::Fr<ppT>>(prfseed1_v[list_idx], Pi_priv_input_query_offset + i) * Pi_priv_input_t[i];
    }
    libff::G1<ppT> macsaltaccu_g1 = macsaltaccu * g1_generator;

    libff::leave_block("Compute accumulated mac salt");


    libff::leave_block("Generate R1CS verification key");

    libff::enter_block("Generate initial proof");
    libff::G1<ppT> evaluation_Pi_state_new_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            Pi_state_new_query.begin(),
            Pi_state_new_query.end(),
            initial_state.begin(),
            initial_state.end(),
            chunks);

    libff::leave_block("Generate initial proof");


    libff::leave_block("Call to r1cs_gg_ppadscsnark_generator");


    r1cs_gg_ppadscsnark_verification_key<ppT> vk = r1cs_gg_ppadscsnark_verification_key<ppT>(
                                                                                Pi_statement_t,
                                                                                alpha_g1_beta_g2,
                                                                                zeta,
                                                                                eta,
                                                                                delta,
                                                                                xi,
                                                                                kappa,
                                                                                prfseed2,
                                                                                macsaltaccu_g1,
                                                                                g1_generator,
                                                                                G2_gen);

    r1cs_gg_ppadscsnark_proving_key<ppT> pk = r1cs_gg_ppadscsnark_proving_key<ppT>(std::move(alpha_g1),
                                                                               std::move(A_query),
                                                                               std::move(Pi_state_new_query),
                                                                               std::move(Qi_state_query),
                                                                               std::move(Pi_rws_delta_query),
                                                                               std::move(H_delta_query),
                                                                               std::move(Pi_rw_zeta_query),
                                                                               std::move(Pi_priv_input_query),
                                                                               std::move(H_zeta_query),
                                                                               std::move(beta_g2),
                                                                               std::move(B_query));

    std::vector<r1cs_gg_ppadscsnark_authentication_key<ppT>> aks;
    for(size_t i = 0; i < prfseed1_v.size(); ++i){
        r1cs_gg_ppadscsnark_authentication_key<ppT> ak = r1cs_gg_ppadscsnark_authentication_key<ppT>(prfseed1_v[i], prfseed2);
        ak.print_size();
        aks.push_back(ak);
    }
    r1cs_gg_ppadscsnark_proof<ppT> initial_proof;
    initial_proof.D_g1 = evaluation_Pi_state_new_t;

    pk.print_size();
    vk.print_size();

    return r1cs_gg_ppadscsnark_keypair<ppT>(std::move(pk), std::move(vk), std::move(aks), std::move(initial_proof));
}

template<typename ppT>
libff::Fr<ppT> r1cs_gg_ppadscsnark_authenticate(const r1cs_gg_ppadscsnark_authentication_key<ppT> &ak, size_t label, size_t iteration, libff::Fr<ppT> value)
{
    libff::Fr<ppT> salt, macsecret;
    salt = prp(ak.prfseed1, label);
    macsecret = prp(ak.prfseed2, iteration);
    return salt + macsecret * value;
}

template<typename ppT>
authentication_tags<ppT> r1cs_gg_ppadscsnark_authenticate(const r1cs_gg_ppadscsnark_authentication_key<ppT> &ak, size_t label_start, size_t iteration, std::vector<libff::Fr<ppT>> values)
{
    authentication_tags<ppT> result;
    result.reserve(values.size());
    for(size_t i = 0; i < values.size(); ++i){
        result.push_back(r1cs_gg_ppadscsnark_authenticate(ak, label_start + i, iteration, values[i]));
    }
    return result;
}


template <typename ppT>
r1cs_gg_ppadscsnark_proof<ppT> r1cs_gg_ppadscsnark_prover(const r1cs_gg_ppadscsnark_proving_key<ppT> &pk,
                                                      const r1cs_gg_ppadscsnark_constraint_system<ppT> &constraint_system,
                                                      const r1cs_gg_ppadscsnark_primary_input<ppT> &primary_input,
                                                      const r1cs_gg_ppadscsnark_auxiliary_input<ppT> &auxiliary_input,
                                                      const authentication_tags<ppT> &authentication_tags)
{
    libff::enter_block("Call to r1cs_gg_ppadscsnark_prover");

#ifdef DEBUG
    assert(constraint_system.is_satisfied(primary_input, auxiliary_input));
#endif

    libff::enter_block("Compute the polynomial H");
    const qap_witness<libff::Fr<ppT> > qap_wit = r1cs_to_plain_qap_witness_map(constraint_system, primary_input, auxiliary_input, libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero());

    /* We are dividing degree 2(d-1) polynomial by degree d polynomial
       and not adding a PGHR-style zk-patch, so our H is degree d-2 */
    assert(!qap_wit.coefficients_for_H[qap_wit.degree()-2].is_zero());
    assert(qap_wit.coefficients_for_H[qap_wit.degree()-1].is_zero());
    assert(qap_wit.coefficients_for_H[qap_wit.degree()].is_zero());
    libff::leave_block("Compute the polynomial H");

#ifdef DEBUG
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    qap_instance_evaluation<libff::Fr<ppT> > qap_inst = r1cs_to_plain_qap_instance_map_with_evaluation(constraint_system, t);
    assert(qap_inst.is_satisfied(qap_wit));
#endif

#ifdef DEBUG
    assert(qap_wit.coefficients_for_ABCs.size() == qap_wit.num_variables());
    assert(pk.A_query.size() == qap_wit.num_variables()+1);
    assert(pk.B_query.size() == qap_wit.num_variables()+1);
    assert(pk.H_delta_query.size() == qap_wit.degree() - 1);
    assert(pk.H_zeta_query.size() == qap_wit.degree() - 1);
    assert(pk.Pi_state_new_query.size() == constraint_system.state_size);
    assert(pk.Qi_state_query.size() == constraint_system.state_size);
    assert(pk.Pi_rws_delta_query.size() == qap_wit.num_variables() - qap_wit.num_inputs() - constraint_system.private_input_size - constraint_system.state_size);
    assert(pk.Pi_rw_zeta_query.size() == qap_wit.num_variables() - qap_wit.num_inputs() - constraint_system.private_input_size- 2*constraint_system.state_size);
    assert(pk.Pi_priv_input_query.size() == constraint_system.private_input_size);
    assert(authentication_tags.size() == constraint_system.private_input_size);
#endif

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Compute the proof");

    libff::enter_block("Compute evaluation to A-query", false);
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

    libff::G2<ppT> evaluation_Bt = libff::multi_exp_with_mixed_addition<libff::G2<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.B_query.begin(),
            pk.B_query.begin() + qap_wit.num_variables() + 1,
            const_padded_assignment.begin(),
            const_padded_assignment.begin() + qap_wit.num_variables() + 1,
            chunks);
    libff::leave_block("Compute evaluation to B-query", false);

    libff::enter_block("Compute evaluation to H-query", false);
    libff::G1<ppT> evaluation_H_delta_t = libff::multi_exp<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.H_delta_query.begin(),
            pk.H_delta_query.begin() + (qap_wit.degree() - 1),
            qap_wit.coefficients_for_H.begin(),
            qap_wit.coefficients_for_H.begin() + (qap_wit.degree() - 1),
            chunks);
    libff::G1<ppT> evaluation_H_zeta_t = libff::multi_exp<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.H_zeta_query.begin(),
            pk.H_zeta_query.begin() + (qap_wit.degree() - 1),
            qap_wit.coefficients_for_H.begin(),
            qap_wit.coefficients_for_H.begin() + (qap_wit.degree() - 1),
            chunks);
    libff::leave_block("Compute evaluation to H-query", false);

    libff::enter_block("Compute evaluation to L-query", false);
    libff::G1<ppT> evaluation_Pi_state_new_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.Pi_state_new_query.begin(),
            pk.Pi_state_new_query.end(),
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + constraint_system.state_size,
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + 2*constraint_system.state_size,
            chunks);
    libff::G1<ppT> evaluation_Qi_state_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.Qi_state_query.begin(),
            pk.Qi_state_query.end(),
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size,
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + constraint_system.state_size,
            chunks);
    libff::Fr_vector<ppT> rws_assignment(const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size,
                                         const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + constraint_system.state_size);
    rws_assignment.insert(rws_assignment.end(),
                          const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + 2*constraint_system.state_size,
                          const_padded_assignment.end());
    libff::G1<ppT> evaluation_Pi_rws_delta_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.Pi_rws_delta_query.begin(),
            pk.Pi_rws_delta_query.end(),
            rws_assignment.begin(),
            rws_assignment.end(),
            chunks);
    libff::G1<ppT> evaluation_Pi_rw_zeta_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.Pi_rw_zeta_query.begin(),
            pk.Pi_rw_zeta_query.end(),
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + 2*constraint_system.state_size,
            const_padded_assignment.end(),
            chunks);
    libff::G1<ppT> evaluation_Pi_priv_input_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.Pi_priv_input_query.begin(),
            pk.Pi_priv_input_query.end(),
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1,
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size,
            chunks);
    libff::leave_block("Compute evaluation to L-query", false);

    libff::enter_block("Compute evaluation to Pi_priv_input_tags-query", false);
    libff::G1<ppT> evaluation_Pi_priv_input_tags_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.Pi_priv_input_query.begin(),
            pk.Pi_priv_input_query.end(),
            authentication_tags.begin(),
            authentication_tags.end(),
            chunks);
    libff::leave_block("Compute evaluation to Pi_priv_input_tags-query", false);

    /* A = alpha + sum_i(a_i*A_i(t)) */
    libff::G1<ppT> A_g1 = pk.alpha_g1 + evaluation_At;

    /* B = beta + sum_i(a_i*B_i(t)) */
    libff::G2<ppT> B_g2 = pk.beta_g2 + evaluation_Bt;

    /* C = sum_i(a_i*((beta*A_i(t) + alpha*B_i(t) + C_i(t)) + H(t)*Z(t))/delta) */
    libff::G1<ppT> C_g1 = evaluation_Pi_rws_delta_t + evaluation_H_delta_t;
    libff::G1<ppT> D_g1 = evaluation_Pi_state_new_t;
    libff::G1<ppT> E_g1 = evaluation_Qi_state_t + evaluation_Pi_rw_zeta_t + evaluation_H_zeta_t;
    libff::G1<ppT> F_g1 = evaluation_Pi_priv_input_t;
    libff::G1<ppT> G_g1 = evaluation_Pi_priv_input_tags_t;

    libff::leave_block("Compute the proof");

    libff::leave_block("Call to r1cs_gg_ppadscsnark_prover");

    r1cs_gg_ppadscsnark_proof<ppT> proof = r1cs_gg_ppadscsnark_proof<ppT>(std::move(A_g1),
                                                                      std::move(C_g1),
                                                                      std::move(D_g1),
                                                                      std::move(E_g1),
                                                                      std::move(F_g1),
                                                                      std::move(G_g1),
                                                                      std::move(B_g2));
    proof.print_size();

    return proof;
}

template <typename ppT>
r1cs_gg_ppadscsnark_processed_verification_key<ppT> r1cs_gg_ppadscsnark_verifier_process_vk(const r1cs_gg_ppadscsnark_verification_key<ppT> &vk)
{
    libff::enter_block("Call to r1cs_gg_ppadscsnark_verifier_process_vk");

    r1cs_gg_ppadscsnark_processed_verification_key<ppT> pvk;
    pvk.Pi_statement_query = vk.Pi_statement_query;
    pvk.alpha_g1_beta_g2 = vk.alpha_g1_beta_g2;
    pvk.zeta = vk.zeta;
    pvk.eta = vk.eta;
    pvk.delta = vk.delta;
    pvk.xi = vk.xi;
    pvk.kappa = vk.kappa;
    pvk.prfseed2 = vk.prfseed2;
    pvk.macsaltaccu_g1 = vk.macsaltaccu_g1;
    pvk.one_g1 = vk.one_g1;
    pvk.mone_g2_precomp = ppT::precompute_G2(-vk.one_g2);

    libff::leave_block("Call to r1cs_gg_ppadscsnark_verifier_process_vk");

    return pvk;
}

template <typename ppT>
bool r1cs_gg_ppadscsnark_online_verifier_weak_IC(const r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk,
                                               const r1cs_gg_ppadscsnark_primary_input<ppT> &primary_input,
                                               const r1cs_gg_ppadscsnark_proof<ppT> &proof,
                                               const r1cs_gg_ppadscsnark_proof<ppT> &proof_previous,
                                               size_t iteration)
{
    libff::enter_block("Call to r1cs_gg_ppadscsnark_online_verifier_weak_IC");
    assert(pvk.Pi_statement_query.size() >= primary_input.size()+1);

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif


    libff::enter_block("Accumulate input");
    libff::Fr<ppT> acc_value(pvk.Pi_statement_query[0]);
    for(size_t i = 0; i < primary_input.size(); ++i){
        acc_value += primary_input[i] * pvk.Pi_statement_query[i+1];
    }

    libff::G1_vector<ppT> v_g1({pvk.one_g1, proof.C_g1, proof.D_g1, proof.F_g1});
    libff::Fr_vector<ppT> v_fr({acc_value, pvk.delta, pvk.eta*pvk.kappa.inverse(), pvk.xi});


    libff::G1<ppT> acc = libff::multi_exp<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_bos_coster>(
            v_g1.begin(),
            v_g1.end(),
            v_fr.begin(),
            v_fr.end(),
            chunks);

    libff::leave_block("Accumulate input");

    bool result = true;


    libff::enter_block("Check if the proof is well-formed");
    // we do not check proof_previous, as it has already been checked in the previous iteration
    // we assume, that the proving party stores the proof_previous, so it can be trusted once verified
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
    const libff::G1_precomp<ppT> proof_g_A_precomp = ppT::precompute_G1(proof.A_g1);
    const libff::G2_precomp<ppT> proof_g_B_precomp = ppT::precompute_G2(proof.B_g2);
    const libff::G1_precomp<ppT> acc_precomp = ppT::precompute_G1(acc);

    const libff::Fqk<ppT> QAP1 = ppT::double_miller_loop(proof_g_A_precomp,  proof_g_B_precomp,
                                                         acc_precomp,  pvk.mone_g2_precomp);
    const libff::GT<ppT> QAP = ppT::final_exponentiation(QAP1);

    if (QAP != pvk.alpha_g1_beta_g2)
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("QAP divisibility check failed.\n");
        }
        result = false;
    }
    libff::leave_block("Check QAP divisibility");
    libff::leave_block("Online pairing computations");

    libff::enter_block("Check state consistency");
    libff::G1_vector<ppT> vs_g1({proof.C_g1, proof_previous.D_g1, proof.E_g1});
    libff::Fr_vector<ppT> vs_fr({pvk.delta, pvk.eta, -pvk.zeta});

    libff::G1<ppT> state_check = libff::multi_exp<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_bos_coster>(
            vs_g1.begin(),
            vs_g1.end(),
            vs_fr.begin(),
            vs_fr.end(),
            chunks);

    if (!state_check.is_zero()){
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("State consistency check failed.\n");
        }
        result = false;
    }
    libff::leave_block("Check state consistency");

    libff::enter_block("Check accumulated tags");
    libff::Fr<ppT> macsecret = prp(pvk.prfseed2, iteration);
    if (proof.G_g1 != pvk.macsaltaccu_g1 + macsecret*proof.F_g1){
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("Accumulated tag check failed.\n");
        }
        result = false;
    }
    libff::leave_block("Check accumulated tags");

    libff::leave_block("Call to r1cs_gg_ppadscsnark_online_verifier_weak_IC");

    return result;
}

template<typename ppT>
bool r1cs_gg_ppadscsnark_verifier_weak_IC(const r1cs_gg_ppadscsnark_verification_key<ppT> &vk,
                                        const r1cs_gg_ppadscsnark_primary_input<ppT> &primary_input,
                                        const r1cs_gg_ppadscsnark_proof<ppT> &proof,
                                        const r1cs_gg_ppadscsnark_proof<ppT> &proof_previous,
                                        size_t iteration)
{
    libff::enter_block("Call to r1cs_gg_ppadscsnark_verifier_weak_IC");
    r1cs_gg_ppadscsnark_processed_verification_key<ppT> pvk = r1cs_gg_ppadscsnark_verifier_process_vk<ppT>(vk);
    bool result = r1cs_gg_ppadscsnark_online_verifier_weak_IC<ppT>(pvk, primary_input, proof, proof_previous, iteration);
    libff::leave_block("Call to r1cs_gg_ppadscsnark_verifier_weak_IC");
    return result;
}

template<typename ppT>
bool r1cs_gg_ppadscsnark_online_verifier_strong_IC(const r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk,
                                                 const r1cs_gg_ppadscsnark_primary_input<ppT> &primary_input,
                                                 const r1cs_gg_ppadscsnark_proof<ppT> &proof,
                                                 const r1cs_gg_ppadscsnark_proof<ppT> &proof_previous,
                                                 size_t iteration)
{
    bool result = true;
    libff::enter_block("Call to r1cs_gg_ppadscsnark_online_verifier_strong_IC");

    if (pvk.Pi_statement_query.size()-1 != primary_input.size())
    {
        libff::print_indent(); printf("Input length differs from expected (got %zu, expected %zu).\n", primary_input.size(), pvk.Pi_statement_query.size()-1);
        result = false;
    }
    else
    {
        result = r1cs_gg_ppadscsnark_online_verifier_weak_IC(pvk, primary_input, proof, proof_previous, iteration);
    }

    libff::leave_block("Call to r1cs_gg_ppadscsnark_online_verifier_strong_IC");
    return result;
}

template<typename ppT>
bool r1cs_gg_ppadscsnark_verifier_strong_IC(const r1cs_gg_ppadscsnark_verification_key<ppT> &vk,
                                          const r1cs_gg_ppadscsnark_primary_input<ppT> &primary_input,
                                          const r1cs_gg_ppadscsnark_proof<ppT> &proof,
                                          const r1cs_gg_ppadscsnark_proof<ppT> &proof_previous,
                                          size_t iteration)
{
    libff::enter_block("Call to r1cs_gg_ppadscsnark_verifier_strong_IC");
    r1cs_gg_ppadscsnark_processed_verification_key<ppT> pvk = r1cs_gg_ppadscsnark_verifier_process_vk<ppT>(vk);
    bool result = r1cs_gg_ppadscsnark_online_verifier_strong_IC<ppT>(pvk, primary_input, proof, proof_previous, iteration);
    libff::leave_block("Call to r1cs_gg_ppadscsnark_verifier_strong_IC");
    return result;
}


} // libsnark
#endif // R1CS_GG_PPADSCSNARK_TCC_
