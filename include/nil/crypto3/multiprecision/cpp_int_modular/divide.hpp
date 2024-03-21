///////////////////////////////////////////////////////////////
//  Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
//
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
//  Contains eval_modulus for cpp_int_modular_backend, which uses conversion to cpp_int_backend to actually apply the operation.
//

#ifndef CRYPTO3_MP_CPP_INT_DIV_HPP
#define CRYPTO3_MP_CPP_INT_DIV_HPP

#include <boost/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

                // This function should be called only for creation of montgomery and Barett params and calculation of inverse,
                // element, not during "normal" execution. We will use conversion to normal boost::cpp_int here and then
                // convert back.
                template<unsigned Bits1, unsigned Bits2, unsigned Bits3>
                inline BOOST_MP_CXX14_CONSTEXPR void 
                eval_modulus(cpp_int_modular_backend<Bits1> &result,
                              const cpp_int_modular_backend<Bits2> &a,
                              const cpp_int_modular_backend<Bits3> &b) noexcept {
                    boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked> result_cpp_int; 
// TODO(martun): finish this function, otherwise nothing will work.
                }

                // Just a call to the upper function, similar to operator*=.
                // Caller is responsible for the result to fit in Bits1 bits, we will NOT throw!
                template<unsigned Bits1, unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR void 
                eval_modulus(cpp_int_modular_backend<Bits1> &result,
                             const cpp_int_modular_backend<Bits2> &a) noexcept {
                    boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked> result_cpp_int; 
                }

                // This function should be called only for creation of montgomery and Barett params and calculation of inverse,
                // element, not during "normal" execution. We will use conversion to normal boost::cpp_int here and then
                // convert back.
                template<unsigned Bits1, unsigned Bits2, unsigned Bits3>
                inline BOOST_MP_CXX14_CONSTEXPR void 
                eval_divide(cpp_int_modular_backend<Bits1> &result,
                              const cpp_int_modular_backend<Bits2> &a,
                              const cpp_int_modular_backend<Bits3> &b) noexcept {
                    boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked> result_cpp_int; 
// TODO(martun): finish this function, otherwise nothing will work.
                }

                // Just a call to the upper function, similar to operator*=.
                // Caller is responsible for the result to fit in Bits1 bits, we will NOT throw!
                template<unsigned Bits1, unsigned Bits2>
                inline BOOST_MP_CXX14_CONSTEXPR void 
                eval_divide(cpp_int_modular_backend<Bits1> &result,
                             const cpp_int_modular_backend<Bits2> &a) noexcept {
                    boost::multiprecision::backends::cpp_int_backend<Bits1, Bits1, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked> result_cpp_int; 
                }
            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_MP_CPP_INT_DIV_HPP
