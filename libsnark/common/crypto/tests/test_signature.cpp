/** @file
 *****************************************************************************
 Test signature routines

 *****************************************************************************/
#include <cassert>
#include <iostream>
#include <iomanip>

#include <libff/common/profiling.hpp>
#include <libff/common/serialization.hpp>
#include "libsnark/common/crypto/signature/eddsa.hpp"


#ifndef NDEBUG

using namespace libsnark;

void test_eddsa_signature(size_t size, bool serialize)
{
    libff::enter_block("Test EDDSA");
    std::vector<uint8_t> data;
    for (size_t i = 0; i < size; ++i){
        data.push_back((uint8_t) i);
    }

    libff::enter_block("generate keys");
    signature_eddsa_keypair keypair = signature_eddsa_generate();
    libff::leave_block("generate keys");


    signature_eddsa_keypair keypair2;

    if (serialize){
        keypair2 = libff::reserialize(keypair);
        assert(keypair2 == keypair);
    } else {
        keypair2 = keypair;
    }
    std::cout << "Keypair size: " << keypair2.size_in_bits() << std::endl;
    std::cout << "Keypair serialized size: " << libff::get_serialized_size(keypair2) << std::endl;

    libff::enter_block("sign");
    signature_eddsa_signature signature = signature_eddsa_sign(keypair2.privkey, data);
    libff::leave_block("sign");

    signature_eddsa_signature signature2;
    if (serialize){
        signature2 = libff::reserialize(signature);
        assert(signature2 == signature);
    } else {
        signature2 = signature;
    }
    std::cout << "Signature size: " << signature2.size_in_bits() << std::endl;
    std::cout << "Signature serialized size: " << libff::get_serialized_size(signature2) << std::endl;

    libff::enter_block("verify");
    bool verifies = signature_eddsa_verify(keypair2.pubkey, signature2, data);
    libff::leave_block("verify");

    assert(verifies);

    libff::leave_block("Test EDDSA");
}


int main()
{
    libff::start_profiling();
    test_eddsa_signature(1000, true);
}
#else // NDEBUG
int main()
{
    printf("All tests here depend on assert() which is disabled by -DNDEBUG. Please recompile and run again.\n");
}
#endif // NDEBUG
