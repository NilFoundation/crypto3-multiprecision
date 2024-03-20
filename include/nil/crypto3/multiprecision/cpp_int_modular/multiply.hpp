///////////////////////////////////////////////////////////////
//  Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
//
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
//  Contains eval_multiply for cpp_int_modular_backend, which does nothing but converts it to cpp_int_backend and does the multiplication.
//

#ifndef CRYPTO3_MP_CPP_INT_MUL_HPP
#define CRYPTO3_MP_CPP_INT_MUL_HPP

#include <boost/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

                // This function should be called only for creation of montgomery and Barett params, no during "normal" execution.
                template<unsigned Bits1, unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR void 
                eval_multiply(cpp_int_modular_backend<Bits1 + Bits2> &result,
                              const cpp_int_modular_backend<Bits1> &a,
                              const cpp_int_modular_backend<Bits2> &b) noexcept {
                    boost::multiprecision::backends::cpp_int_backend<Bits1 + Bits2, Bits1 + Bits2, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked> result_cpp_int; 
// TODO(martun): finish this function, otherwise nothing will work.
                }

                // Just a call to the upper function, similar to operator*=.
                // Caller is responsible for the result to fit in Bits1 bits, we will NOT throw!
                template<unsigned Bits1, unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR void 
                eval_multiply(cpp_int_modular_backend<Bits1> &result,
                              const cpp_int_modular_backend<Bits2> &a) noexcept {
                    cpp_int_modular_backend<Bits1+Bits2> large_result(result);
                    eval_multiply(large_result, result, a);
                    result = large_result;
                }

            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif 
