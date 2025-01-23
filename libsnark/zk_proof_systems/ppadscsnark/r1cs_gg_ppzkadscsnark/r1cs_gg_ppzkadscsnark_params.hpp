/** @file
 *****************************************************************************

 Declaration of public-parameter selector for the R1CS GG-ppZKADSCSNARK.

 *****************************************************************************/

#ifndef R1CS_GG_PPZKADSCSNARK_PARAMS_HPP_
#define R1CS_GG_PPZKADSCSNARK_PARAMS_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp>

namespace libsnark {

/**
 * Below are various template aliases (used for convenience).
 */

template<typename ppT>
using r1cs_gg_ppzkadscsnark_constraint_system = r1cs_adsc_constraint_system<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_primary_input = r1cs_primary_input<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_auxiliary_input = r1cs_auxiliary_input<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_assignment = r1cs_variable_assignment<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_label = libff::Fr<ppT>;

} // libsnark

#endif // R1CS_GG_PPZKADSCSNARK_PARAMS_HPP_
