/** @file
 *****************************************************************************

 Implementation of interfaces for a R1CS-to-QAP reduction.

 See r1cs_to_qap.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_TO_QAP_TCC_
#define R1CS_TO_QAP_TCC_

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libfqfft/evaluation_domain/get_evaluation_domain.hpp>

namespace libsnark {

/**
 * Instance map for the R1CS-to-QAP reduction.
 *
 * Namely, given a R1CS constraint system cs, construct a QAP instance for which:
 *   A := (A_0(z),A_1(z),...,A_m(z))
 *   B := (B_0(z),B_1(z),...,B_m(z))
 *   C := (C_0(z),C_1(z),...,C_m(z))
 * where
 *   m = number of variables of the QAP
 * and
 *   each A_i,B_i,C_i is expressed in the Lagrange basis.
 */
template<typename FieldT>
qap_instance<FieldT> r1cs_to_qap_instance_map(const r1cs_constraint_system<FieldT> &cs)
{
    libff::enter_block("Call to r1cs_to_qap_instance_map");

    const std::shared_ptr<libfqfft::evaluation_domain<FieldT> > domain = libfqfft::get_evaluation_domain<FieldT>(cs.num_constraints() + cs.num_inputs() + 1);

    std::vector<std::map<size_t, FieldT> > A_in_Lagrange_basis(cs.num_variables()+1);
    std::vector<std::map<size_t, FieldT> > B_in_Lagrange_basis(cs.num_variables()+1);
    std::vector<std::map<size_t, FieldT> > C_in_Lagrange_basis(cs.num_variables()+1);

    libff::enter_block("Compute polynomials A, B, C in Lagrange basis");
    /**
     * add and process the constraints
     *     input_i * 0 = 0
     * to ensure soundness of input consistency
     */
    for (size_t i = 0; i <= cs.num_inputs(); ++i)
    {
        A_in_Lagrange_basis[i][cs.num_constraints() + i] = FieldT::one();
    }
    /* process all other constraints */
    for (size_t i = 0; i < cs.num_constraints(); ++i)
    {
        auto a = cs.constraints[i].a.getTerms();
        for (size_t j = 0; j < a.size(); ++j)
        {
            A_in_Lagrange_basis[a[j].index][i] += a[j].coeff;
        }

        auto b = cs.constraints[i].b.getTerms();
        for (size_t j = 0; j < cs.constraints[i].b.getTerms().size(); ++j)
        {
            B_in_Lagrange_basis[b[j].index][i] += b[j].coeff;
        }

        auto c = cs.constraints[i].c.getTerms();
        for (size_t j = 0; j < c.size(); ++j)
        {
            C_in_Lagrange_basis[c[j].index][i] += c[j].coeff;
        }
    }
    libff::leave_block("Compute polynomials A, B, C in Lagrange basis");

    libff::leave_block("Call to r1cs_to_qap_instance_map");

    return qap_instance<FieldT>(domain,
                                cs.num_variables(),
                                domain->m,
                                cs.num_inputs(),
                                std::move(A_in_Lagrange_basis),
                                std::move(B_in_Lagrange_basis),
                                std::move(C_in_Lagrange_basis));
}

static unsigned int roundUpToNearestPowerOf2(unsigned int v)
{
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

/**
 * Instance map for the R1CS-to-QAP reduction followed by evaluation of the resulting QAP instance.
 *
 * Namely, given a R1CS constraint system cs and a field element t, construct
 * a QAP instance (evaluated at t) for which:
 *   At := (A_0(t),A_1(t),...,A_m(t))
 *   Bt := (B_0(t),B_1(t),...,B_m(t))
 *   Ct := (C_0(t),C_1(t),...,C_m(t))
 *   Ht := (1,t,t^2,...,t^n)
 *   Zt := Z(t) = "vanishing polynomial of a certain set S, evaluated at t"
 * where
 *   m = number of variables of the QAP
 *   n = degree of the QAP
 */
template<typename FieldT>
qap_instance_evaluation<FieldT> r1cs_to_qap_instance_map_with_evaluation(const r1cs_constraint_system<FieldT> &cs,
                                                                         const FieldT &t)
{
    libff::enter_block("Call to r1cs_to_qap_instance_map_with_evaluation");

    const std::shared_ptr<libfqfft::evaluation_domain<FieldT> > domain = libfqfft::get_evaluation_domain<FieldT>(roundUpToNearestPowerOf2(cs.num_constraints() + cs.num_inputs() + 1));

    std::vector<FieldT> At, Bt, Ct, Ht;

    At.resize(cs.num_variables()+1, FieldT::zero());
    Bt.resize(cs.num_variables()+1, FieldT::zero());
    Ct.resize(cs.num_variables()+1, FieldT::zero());
    Ht.reserve(domain->m+1);

    const FieldT Zt = domain->compute_vanishing_polynomial(t);

    libff::enter_block("Compute evaluations of A, B, C, H at t");
    const std::vector<FieldT> u = domain->evaluate_all_lagrange_polynomials(t);
    /**
     * add and process the constraints
     *     input_i * 0 = 0
     * to ensure soundness of input consistency
     */
    for (size_t i = 0; i <= cs.num_inputs(); ++i)
    {
        At[i] = u[cs.num_constraints() + i];
    }
    /* process all other constraints */
    for (size_t i = 0; i < cs.num_constraints(); ++i)
    {
        auto a = cs.constraints[i]->getA().getTerms();
        for (size_t j = 0; j < a.size(); ++j)
        {
            At[a[j].index] += u[i]*a[j].getCoeff();
        }

        auto b = cs.constraints[i]->getB().getTerms();
        for (size_t j = 0; j < b.size(); ++j)
        {
            Bt[b[j].index] += u[i]*b[j].getCoeff();
        }

        auto c = cs.constraints[i]->getC().getTerms();
        for (size_t j = 0; j < c.size(); ++j)
        {
            Ct[c[j].index] +=u[i]*c[j].getCoeff();
        }
    }

    FieldT ti = FieldT::one();
    for (size_t i = 0; i < domain->m+1; ++i)
    {
        Ht.emplace_back(ti);
        ti *= t;
    }
    libff::leave_block("Compute evaluations of A, B, C, H at t");

    libff::leave_block("Call to r1cs_to_qap_instance_map_with_evaluation");

    return qap_instance_evaluation<FieldT>(domain,
                                           cs.num_variables(),
                                           domain->m,
                                           cs.num_inputs(),
                                           t,
                                           std::move(At),
                                           std::move(Bt),
                                           std::move(Ct),
                                           std::move(Ht),
                                           Zt);
}

/**
 * Witness map for the R1CS-to-QAP reduction.
 *
 * The witness map takes zero knowledge into account when d1,d2,d3 are random.
 *
 * More precisely, compute the coefficients
 *     h_0,h_1,...,h_n
 * of the polynomial
 *     H(z) := (A(z)*B(z)-C(z))/Z(z)
 * where
 *   A(z) := A_0(z) + \sum_{k=1}^{m} w_k A_k(z) + d1 * Z(z)
 *   B(z) := B_0(z) + \sum_{k=1}^{m} w_k B_k(z) + d2 * Z(z)
 *   C(z) := C_0(z) + \sum_{k=1}^{m} w_k C_k(z) + d3 * Z(z)
 *   Z(z) := "vanishing polynomial of set S"
 * and
 *   m = number of variables of the QAP
 *   n = degree of the QAP
 *
 * This is done as follows:
 *  (1) compute evaluations of A,B,C on S = {sigma_1,...,sigma_n}
 *  (2) compute coefficients of A,B,C
 *  (3) compute evaluations of A,B,C on T = "coset of S"
 *  (4) compute evaluation of H on T
 *  (5) compute coefficients of H
 *  (6) patch H to account for d1,d2,d3 (i.e., add coefficients of the polynomial (A d2 + B d1 - d3) + d1*d2*Z )
 *
 * The code below is not as simple as the above high-level description due to
 * some reshuffling to save space.
 */
template<typename FieldT>
void r1cs_to_qap_witness_map(const std::shared_ptr<libfqfft::evaluation_domain<FieldT>> domain,
                             const r1cs_constraint_system<FieldT> &cs,
                             const std::vector<FieldT> &full_variable_assignment,
                             std::vector<FieldT> &aA,
                             std::vector<FieldT> &aB,
                             std::vector<FieldT> &aH)
{
    libff::enter_block("Call to r1cs_to_qap_witness_map");

    libff::enter_block("Compute evaluation of polynomials A, B, C on set S");
    std::vector<FieldT> &aC = aH;
#ifdef MULTICORE
    #pragma omp parallel for
#endif
    for (size_t i = 0; i < cs.num_constraints(); ++i)
    {
        aA[i] = cs.constraints[i]->evaluateA(full_variable_assignment);
        aB[i] = cs.constraints[i]->evaluateB(full_variable_assignment);
        aC[i] = cs.constraints[i]->evaluateC(full_variable_assignment);
    }
    /* account for the additional constraints input_i * 0 = 0 */
    for (size_t i = 0; i <= cs.num_inputs(); ++i)
    {
        aA[i+cs.num_constraints()] = full_variable_assignment[i];
        aB[i+cs.num_constraints()] = FieldT::zero();
        aC[i+cs.num_constraints()] = FieldT::zero();
    }
#ifdef MULTICORE
    #pragma omp parallel for
#endif
    /* zero initialize the remaining coefficients */
    for (size_t i = cs.num_constraints() + cs.num_inputs() + 1; i < domain->m; i++)
    {
        aA[i] = FieldT::zero();
        aB[i] = FieldT::zero();
        aC[i] = FieldT::zero();
    }
    libff::leave_block("Compute evaluation of polynomials A, B, C on set S");

    libff::enter_block("Compute coefficients of polynomial A");
    domain->iFFT(aA);
    libff::leave_block("Compute coefficients of polynomial A");

    libff::enter_block("Compute evaluation of polynomial A on set T");
    domain->cosetFFT(aA, FieldT::multiplicative_generator);
    libff::leave_block("Compute evaluation of polynomial A on set T");

    libff::enter_block("Compute coefficients of polynomial B");
    domain->iFFT(aB);
    libff::leave_block("Compute coefficients of polynomial B");

    libff::enter_block("Compute evaluation of polynomial B on set T");
    domain->cosetFFT(aB, FieldT::multiplicative_generator);
    libff::leave_block("Compute evaluation of polynomial B on set T");

    libff::enter_block("Compute coefficients of polynomial C");
    domain->iFFT(aC);
    libff::leave_block("Compute coefficients of polynomial C");

    libff::enter_block("Compute evaluation of polynomial C on set T");
    domain->cosetFFT(aC, FieldT::multiplicative_generator);
    libff::leave_block("Compute evaluation of polynomial C on set T");

    libff::enter_block("Compute evaluation of polynomial H on set T");
#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t i = 0; i < domain->m; ++i)
    {
        aH[i] = (aA[i] * aB[i]) - aC[i];
    }
    aH[domain->m] = FieldT::zero();

    libff::enter_block("Divide by Z on set T");
    domain->divide_by_Z_on_coset(aH);
    libff::leave_block("Divide by Z on set T");

    libff::leave_block("Compute evaluation of polynomial H on set T");

    libff::enter_block("Compute coefficients of polynomial H");
    domain->icosetFFT(aH, FieldT::multiplicative_generator);
    libff::leave_block("Compute coefficients of polynomial H");

    libff::leave_block("Call to r1cs_to_qap_witness_map");
}

} // libsnark

#endif // R1CS_TO_QAP_TCC_
