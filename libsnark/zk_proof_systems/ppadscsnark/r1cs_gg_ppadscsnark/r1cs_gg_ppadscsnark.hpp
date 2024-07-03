/** @file
*****************************************************************************

Declaration of interfaces for a ppADSCSNARK for R1CS with a security proof
in the generic group (GG) model.

*****************************************************************************/

#ifndef R1CS_GG_PPADSCSNARK_HPP_
#define R1CS_GG_PPADSCSNARK_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppadscsnark/r1cs_gg_ppadscsnark_params.hpp>

namespace libsnark {

/******************************** Proving key ********************************/

template<typename ppT>
class r1cs_gg_ppadscsnark_proving_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_proving_key<ppT> &pk);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_proving_key<ppT> &pk);

/**
 * A proving key for the R1CS GG-ppADSCSNARK.
 */
template<typename ppT>
class r1cs_gg_ppadscsnark_proving_key {
public:
    libff::G1<ppT> alpha_g1;
    libff::G1_vector<ppT> A_query;
    libff::G1_vector<ppT> Pi_state_new_query;
    libff::G1_vector<ppT> Qi_state_query;
    libff::G1_vector<ppT> Pi_rws_delta_query;
    libff::G1_vector<ppT> H_delta_query;
    libff::G1_vector<ppT> Pi_rw_zeta_query;
    libff::G1_vector<ppT> Pi_priv_input_query;
    libff::G1_vector<ppT> H_zeta_query;

    libff::G2<ppT> beta_g2;
    libff::G2_vector<ppT> B_query;

    r1cs_gg_ppadscsnark_proving_key() {};
    r1cs_gg_ppadscsnark_proving_key<ppT>& operator=(const r1cs_gg_ppadscsnark_proving_key<ppT> &other) = default;
    r1cs_gg_ppadscsnark_proving_key(const r1cs_gg_ppadscsnark_proving_key<ppT> &other) = default;
    r1cs_gg_ppadscsnark_proving_key(r1cs_gg_ppadscsnark_proving_key<ppT> &&other) = default;
    r1cs_gg_ppadscsnark_proving_key(libff::G1<ppT> &&alpha_g1,
                                  libff::G1_vector<ppT> &&A_query,
                                  libff::G1_vector<ppT> &&Pi_state_new_query,
                                  libff::G1_vector<ppT> &&Qi_state_query,
                                  libff::G1_vector<ppT> &&Pi_rws_delta_query,
                                  libff::G1_vector<ppT> &&H_delta_query,
                                  libff::G1_vector<ppT> &&Pi_rw_zeta_query,
                                  libff::G1_vector<ppT> &&Pi_priv_input_query,
                                  libff::G1_vector<ppT> &&H_zeta_query,
                                  libff::G2<ppT> &&beta_g2,
                                  libff::G2_vector<ppT> &&B_query) :
        alpha_g1(std::move(alpha_g1)),
        A_query(std::move(A_query)),
        Pi_state_new_query(std::move(Pi_state_new_query)),
        Qi_state_query(std::move(Qi_state_query)),
        Pi_rws_delta_query(std::move(Pi_rws_delta_query)),
        H_delta_query(std::move(H_delta_query)),
        Pi_rw_zeta_query(std::move(Pi_rw_zeta_query)),
        Pi_priv_input_query(std::move(Pi_priv_input_query)),
        H_zeta_query(std::move(H_zeta_query)),
        beta_g2(std::move(beta_g2)),
        B_query(std::move(B_query))
        {};

    size_t G1_size() const
    {
        return 1 + A_query.size() + Pi_state_new_query.size() + Qi_state_query.size() + Pi_rws_delta_query.size() +
                H_delta_query.size() + Pi_rw_zeta_query.size() + Pi_priv_input_query.size() + H_zeta_query.size();
    }

    size_t G2_size() const
    {
        return 1 + B_query.size();
    }

    size_t G1_sparse_size() const
    {
        return G1_size();
    }

    size_t G2_sparse_size() const
    {
        return G2_size();
    }

    size_t size_in_bits() const
    {
        return (G1_size() * libff::G1<ppT>::size_in_bits() + G2_size() * libff::G2<ppT>::size_in_bits());
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in PK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* Non-zero G1 elements in PK: %zu\n", this->G1_sparse_size());
        libff::print_indent(); printf("* G2 elements in PK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* Non-zero G2 elements in PK: %zu\n", this->G2_sparse_size());
        libff::print_indent(); printf("* PK size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const r1cs_gg_ppadscsnark_proving_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_gg_ppadscsnark_proving_key<ppT> &pk);
    friend std::istream& operator>> <ppT>(std::istream &in, r1cs_gg_ppadscsnark_proving_key<ppT> &pk);
};


/******************************* Verification key ****************************/

template<typename ppT>
class r1cs_gg_ppadscsnark_verification_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_verification_key<ppT> &vk);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_verification_key<ppT> &vk);

/**
 * A verification key for the R1CS GG-ppADSCSNARK.
 * The verification key is private, it can only be used in a designated verifier setting
 */
template<typename ppT>
class r1cs_gg_ppadscsnark_verification_key {
public:
    libff::Fr_vector<ppT> Pi_statement_query;
    libff::GT<ppT> alpha_g1_beta_g2;
    libff::Fr<ppT> zeta;
    libff::Fr<ppT> eta;
    libff::Fr<ppT> delta;
    libff::Fr<ppT> xi;
    libff::Fr<ppT> kappa;
    libff::Fr<ppT> prfseed2;
    libff::G1<ppT> macsaltaccu_g1;
    libff::G1<ppT> one_g1;

    libff::G2<ppT> one_g2;


    r1cs_gg_ppadscsnark_verification_key() = default;
    r1cs_gg_ppadscsnark_verification_key(const libff::Fr_vector<ppT> &Pi_statement_query,
                                        const libff::GT<ppT> &alpha_g1_beta_g2,
                                         const libff::Fr<ppT> &zeta,
                                         const libff::Fr<ppT> &eta,
                                        const libff::Fr<ppT> &delta,
                                        const libff::Fr<ppT> &xi,
                                         const libff::Fr<ppT> &kappa,
                                        const libff::Fr<ppT> &prfseed2,
                                        const libff::G1<ppT> &macsaltaccu_g1,
                                       const libff::G1<ppT> &one_g1,
                                        const libff::G2<ppT> &one_g2
                                       ) :
            Pi_statement_query(Pi_statement_query),
            alpha_g1_beta_g2(alpha_g1_beta_g2),
            zeta(zeta),
            eta(eta),
            delta(delta),
            xi(xi),
            kappa(kappa),
            prfseed2(prfseed2),
            macsaltaccu_g1(macsaltaccu_g1),
            one_g1(one_g1),
            one_g2(one_g2)
    {};

    size_t G1_size() const
    {
        return 2;
    }

    size_t G2_size() const
    {
        return 1;
    }

    size_t GT_size() const
    {
        return 1;
    }

    size_t Fr_size() const
    {
        return Pi_statement_query.size() + 6;
    }

    size_t size_in_bits() const
    {
        return (
                G1_size() * libff::G1<ppT>::size_in_bits() +
                G2_size() * libff::G2<ppT>::size_in_bits() +
                GT_size() * libff::GT<ppT>::ceil_size_in_bits() +
                Fr_size() * libff::Fr<ppT>::ceil_size_in_bits()
                );
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in VK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in VK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* GT elements in VK: %zu\n", this->GT_size());
        libff::print_indent(); printf("* Fr elements in VK: %zu\n", this->Fr_size());
        libff::print_indent(); printf("* VK size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const r1cs_gg_ppadscsnark_verification_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_gg_ppadscsnark_verification_key<ppT> &vk);
    friend std::istream& operator>> <ppT>(std::istream &in, r1cs_gg_ppadscsnark_verification_key<ppT> &vk);

    static r1cs_gg_ppadscsnark_verification_key<ppT> dummy_verification_key(const size_t input_size);
};


/************************ Processed verification key *************************/

template<typename ppT>
class r1cs_gg_ppadscsnark_processed_verification_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk);

/**
 * A processed verification key for the R1CS GG-ppADSCSNARK.
 *
 * Compared to a (non-processed) verification key, a processed verification key
 * contains a small constant amount of additional pre-computed information that
 * enables a faster verification time.
 */
template<typename ppT>
class r1cs_gg_ppadscsnark_processed_verification_key {
public:
    libff::Fr_vector<ppT> Pi_statement_query;
    libff::GT<ppT> alpha_g1_beta_g2;
    libff::Fr<ppT> zeta;
    libff::Fr<ppT> eta;
    libff::Fr<ppT> delta;
    libff::Fr<ppT> xi;
    libff::Fr<ppT> kappa;
    libff::Fr<ppT> prfseed2;
    libff::G1<ppT> macsaltaccu_g1;
    libff::G1<ppT> one_g1;

    libff::G2_precomp<ppT> mone_g2_precomp;

    bool operator==(const r1cs_gg_ppadscsnark_processed_verification_key &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk);
    friend std::istream& operator>> <ppT>(std::istream &in, r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk);
};

/******************************* Authentication key ****************************/

template<typename ppT>
class r1cs_gg_ppadscsnark_authentication_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_authentication_key<ppT> &ak);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_authentication_key<ppT> &ak);

/**
* An authentication key for the R1CS GG-ppADSCSNARK.
* The authentication key is private, the prover should not have access to it
*/
template<typename ppT>
class r1cs_gg_ppadscsnark_authentication_key {
public:
    libff::Fr<ppT> prfseed1;
    libff::Fr<ppT> prfseed2;

    r1cs_gg_ppadscsnark_authentication_key() = default;
    r1cs_gg_ppadscsnark_authentication_key( const libff::Fr<ppT> &prfseed1, const libff::Fr<ppT> &prfseed2) :
            prfseed1(prfseed1),
            prfseed2(prfseed2)

    {};

    size_t G1_size() const
    {
        return 0;
    }

    size_t G2_size() const
    {
        return 0;
    }

    size_t GT_size() const
    {
        return 0;
    }

    size_t Fr_size() const
    {
        return 2;
    }

    size_t size_in_bits() const
    {
        return (
                G1_size() * libff::G1<ppT>::size_in_bits() +
                G2_size() * libff::G2<ppT>::size_in_bits() +
                GT_size() * libff::GT<ppT>::ceil_size_in_bits() +
                Fr_size() * libff::Fr<ppT>::ceil_size_in_bits()
        );
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in VK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in VK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* GT elements in VK: %zu\n", this->GT_size());
        libff::print_indent(); printf("* Fr elements in VK: %zu\n", this->Fr_size());
        libff::print_indent(); printf("* AK size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const r1cs_gg_ppadscsnark_authentication_key<ppT> &other) const;

};


/*********************************** Proof ***********************************/

template<typename ppT>
class r1cs_gg_ppadscsnark_proof;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppadscsnark_proof<ppT> &proof);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppadscsnark_proof<ppT> &proof);

/**
 * A proof for the R1CS GG-ppADSCSNARK.
 *
 * While the proof has a structure, externally one merely opaquely produces,
 * serializes/deserializes, and verifies proofs. We only expose some information
 * about the structure for statistics purposes.
 */
template<typename ppT>
class r1cs_gg_ppadscsnark_proof {
public:
    libff::G1<ppT> A_g1;
    libff::G1<ppT> C_g1;
    libff::G1<ppT> D_g1;
    libff::G1<ppT> E_g1;
    libff::G1<ppT> F_g1;
    libff::G1<ppT> G_g1;

    libff::G2<ppT> B_g2;


    r1cs_gg_ppadscsnark_proof()
    {
        // invalid proof with valid curve points
        this->A_g1 = libff::G1<ppT>::one();
        this->C_g1 = libff::G1<ppT>::one();
        this->D_g1 = libff::G1<ppT>::one();
        this->E_g1 = libff::G1<ppT>::one();
        this->F_g1 = libff::G1<ppT>::one();
        this->G_g1 = libff::G1<ppT>::one();

        this->B_g2 = libff::G2<ppT>::one();
    }
    r1cs_gg_ppadscsnark_proof(libff::G1<ppT> &&A_g1,
                            libff::G1<ppT> &&C_g1,
                            libff::G1<ppT> &&D_g1,
                            libff::G1<ppT> &&E_g1,
                            libff::G1<ppT> &&F_g1,
                            libff::G1<ppT> &&G_g1,
                            libff::G2<ppT> &&B_g2) :
        A_g1(std::move(A_g1)),
        C_g1(std::move(C_g1)),
        D_g1(std::move(D_g1)),
        E_g1(std::move(E_g1)),
        F_g1(std::move(F_g1)),
        G_g1(std::move(G_g1)),
        B_g2(std::move(B_g2))
    {};

    size_t G1_size() const
    {
        return 6;
    }

    size_t G2_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits() + G2_size() * libff::G2<ppT>::size_in_bits();
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in proof: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in proof: %zu\n", this->G2_size());
        libff::print_indent(); printf("* Proof size in bits: %zu\n", this->size_in_bits());
    }

    bool is_well_formed() const
    {
        return (A_g1.is_well_formed() &&
                C_g1.is_well_formed() &&
                D_g1.is_well_formed() &&
                E_g1.is_well_formed() &&
                F_g1.is_well_formed() &&
                G_g1.is_well_formed() &&
                B_g2.is_well_formed());
    }

    bool operator==(const r1cs_gg_ppadscsnark_proof<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_gg_ppadscsnark_proof<ppT> &proof);
    friend std::istream& operator>> <ppT>(std::istream &in, r1cs_gg_ppadscsnark_proof<ppT> &proof);
};

/********************************** Key pair *********************************/

/**
 * A key pair (actually key triple) for the R1CS GG-ppADSCSNARK, which consists of a proving key, a verification key,
 * and an authentication key
 */
template<typename ppT>
class r1cs_gg_ppadscsnark_keypair {
public:
    r1cs_gg_ppadscsnark_proving_key<ppT> pk;
    r1cs_gg_ppadscsnark_verification_key<ppT> vk;
    std::vector<r1cs_gg_ppadscsnark_authentication_key<ppT>> aks;
    r1cs_gg_ppadscsnark_proof<ppT> initial_proof;


    r1cs_gg_ppadscsnark_keypair() = default;
    r1cs_gg_ppadscsnark_keypair(const r1cs_gg_ppadscsnark_keypair<ppT> &other) = default;
    r1cs_gg_ppadscsnark_keypair(r1cs_gg_ppadscsnark_proving_key<ppT> &&pk,
                                r1cs_gg_ppadscsnark_verification_key<ppT> &&vk,
                                std::vector<r1cs_gg_ppadscsnark_authentication_key<ppT>> &&aks,
                                r1cs_gg_ppadscsnark_proof<ppT> &&initial_proof) :
            pk(std::move(pk)),
            vk(std::move(vk)),
            aks(std::move(aks)),
            initial_proof(std::move(initial_proof))
    {}

    r1cs_gg_ppadscsnark_keypair(r1cs_gg_ppadscsnark_keypair<ppT> &&other) = default;
};

/***************************** Main algorithms *******************************/

/**
 * A generator algorithm for the R1CS GG-ppADSCSNARK.
 *
 * Given a R1CS constraint system CS, this algorithm produces proving, verification and authentication keys for CS.
 */
template<typename ppT>
r1cs_gg_ppadscsnark_keypair<ppT> r1cs_gg_ppadscsnark_generator(const r1cs_gg_ppadscsnark_constraint_system<ppT> &r1cs,
                                                               const r1cs_gg_ppadscsnark_variable_assignment<ppT> &initial_state,
                                                               std::vector<size_t> private_input_blocks=std::vector<size_t>());

/**
 * An authentication algorithm for the R1CS GG-ppADSCSNARK.
 *
 * Given an input value and a label, this algorithm outputs an authentication tag for the value
 */
template<typename ppT>
libff::Fr<ppT> r1cs_gg_ppadscsnark_authenticate(const r1cs_gg_ppadscsnark_authentication_key<ppT> &ak, size_t label, size_t iteration, libff::Fr<ppT> value);

template<typename ppT>
authentication_tags<ppT> r1cs_gg_ppadscsnark_authenticate(const r1cs_gg_ppadscsnark_authentication_key<ppT> &ak, size_t label_start, size_t iteration, std::vector<libff::Fr<ppT>> values);

/**
 * A prover algorithm for the R1CS GG-ppADSCSNARK.
 *
 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
 * produces a proof (of knowledge) that attests to the following statement:
 *               ``there exists Y such that CS(X,Y)=0''.
 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
 */
template<typename ppT>
r1cs_gg_ppadscsnark_proof<ppT> r1cs_gg_ppadscsnark_prover(const r1cs_gg_ppadscsnark_proving_key<ppT> &pk,
                                                      const r1cs_gg_ppadscsnark_constraint_system<ppT> &constraint_system,
                                                      const r1cs_gg_ppadscsnark_primary_input<ppT> &primary_input,
                                                      const r1cs_gg_ppadscsnark_auxiliary_input<ppT> &auxiliary_input,
                                                      const authentication_tags<ppT> &authentication_tags);

/*
  Below are four variants of verifier algorithm for the R1CS GG-ppADSCSNARK.

  These are the four cases that arise from the following two choices:

  (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
  In the latter case, we call the algorithm an "online verifier".

  (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
  Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
  weak input consistency requires that |primary_input| <= CS.num_inputs (and
  the primary input is implicitly padded with zeros up to length CS.num_inputs).
*/

/**
 * A verifier algorithm for the R1CS GG-ppADSCSNARK that:
 * (1) accepts a non-processed verification key, and
 * (2) has weak input consistency.
 */
template<typename ppT>
bool r1cs_gg_ppadscsnark_verifier_weak_IC(const r1cs_gg_ppadscsnark_verification_key<ppT> &vk,
                                        const r1cs_gg_ppadscsnark_primary_input<ppT> &primary_input,
                                        const r1cs_gg_ppadscsnark_proof<ppT> &proof,
                                        const r1cs_gg_ppadscsnark_proof<ppT> &proof_previous,
                                        size_t iteration);

/**
 * A verifier algorithm for the R1CS GG-ppADSCSNARK that:
 * (1) accepts a non-processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool r1cs_gg_ppadscsnark_verifier_strong_IC(const r1cs_gg_ppadscsnark_verification_key<ppT> &vk,
                                          const r1cs_gg_ppadscsnark_primary_input<ppT> &primary_input,
                                          const r1cs_gg_ppadscsnark_proof<ppT> &proof,
                                          const r1cs_gg_ppadscsnark_proof<ppT> &proof_previous,
                                          size_t iteration);

/**
 * Convert a (non-processed) verification key into a processed verification key.
 */
template<typename ppT>
r1cs_gg_ppadscsnark_processed_verification_key<ppT> r1cs_gg_ppadscsnark_verifier_process_vk(const r1cs_gg_ppadscsnark_verification_key<ppT> &vk);

/**
 * A verifier algorithm for the R1CS GG-ppADSCSNARK that:
 * (1) accepts a processed verification key, and
 * (2) has weak input consistency.
 */
template<typename ppT>
bool r1cs_gg_ppadscsnark_online_verifier_weak_IC(const r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk,
                                               const r1cs_gg_ppadscsnark_primary_input<ppT> &input,
                                               const r1cs_gg_ppadscsnark_proof<ppT> &proof,
                                               const r1cs_gg_ppadscsnark_proof<ppT> &proof_previous,
                                               size_t iteration);

/**
 * A verifier algorithm for the R1CS GG-ppADSCSNARK that:
 * (1) accepts a processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool r1cs_gg_ppadscsnark_online_verifier_strong_IC(const r1cs_gg_ppadscsnark_processed_verification_key<ppT> &pvk,
                                                 const r1cs_gg_ppadscsnark_primary_input<ppT> &primary_input,
                                                 const r1cs_gg_ppadscsnark_proof<ppT> &proof,
                                                 const r1cs_gg_ppadscsnark_proof<ppT> &proof_previous,
                                                 size_t iteration);

/****************************** Miscellaneous ********************************/




} // libsnark

#include <libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppadscsnark/r1cs_gg_ppadscsnark.tcc>

#endif // R1CS_GG_PPADSCSNARK_HPP_
