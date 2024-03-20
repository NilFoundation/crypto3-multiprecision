///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
// Comparison operators for cpp_int_modular_backend:
//
#ifndef CRYPTO3_MP_CPP_INT_COMPARISON_HPP
#define CRYPTO3_MP_CPP_INT_COMPARISON_HPP

#include <boost/multiprecision/detail/constexpr.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

#ifdef BOOST_MSVC
#pragma warning(push)
#pragma warning(disable : 4018 4389 4996)
#endif

                //
                // Start with non-trivial cpp_int's:
                //
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    bool>::type
                    eval_eq(const cpp_int_modular_backend<Bits>& a,
                            const cpp_int_modular_backend<Bits>& b) noexcept {
                    return boost::multiprecision::std_constexpr::equal(a.limbs(), a.limbs() + a.size(), b.limbs());
                }
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR
                    typename std::enable_if<!is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                                            bool>::type
                    eval_eq(const cpp_int_modular_backend<Bits>& a, limb_type b) noexcept {
// TODO(martun): write a test for this function.
                    auto* limbs = a.limbs();
                    if (!std::all_of(limbs, limbs + a.size() - 1, [&](limb_type limb){return limb == 0;}))
                        return false;
                    if (limbs[a.size() - 1] != b)
                        return false;
                    return true;
                }

                template<unsigned Bits >
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    bool>::type
                    eval_lt(const cpp_int_modular_backend<Bits>& a, limb_type b) noexcept {
                    auto* limbs = a.limbs();
                    if (!std::all_of(limbs, limbs + a.size() - 1, [&](limb_type limb){return limb == 0;}))
                        return false;
                    return limbs[a.size() - 1] < b;
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR
                    typename std::enable_if<!is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                                            bool>::type
                    eval_gt(const cpp_int_modular_backend<Bits>& a,
                            limb_type b) noexcept {
                    auto* limbs = a.limbs();
                    if (!std::all_of(limbs, limbs + a.size() - 1, [&](limb_type limb){return limb == 0;}))
                        return true;
                    return *a.limbs() > b;
                }
                
                //
                // And again for trivial cpp_ints:
                //
                template<unsigned Bits, class U>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::detail::is_unsigned<U>::value &&
                        is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    bool>::type
                    eval_eq(const cpp_int_modular_backend<Bits>& a, U b) noexcept {
                    return *a.limbs() == b;
                }
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    bool>::type
                    eval_lt(const cpp_int_modular_backend<Bits>& a, const cpp_int_modular_backend<Bits>& b) noexcept {
                    return *a.limbs() < *b.limbs();
                }
                
                template<unsigned Bits, class U>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::detail::is_unsigned<U>::value &&
                        is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    bool>::type
                    eval_lt(const cpp_int_modular_backend<Bits>& a, U b) noexcept {
                    return *a.limbs() < b;
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    bool>::type
                    eval_gt(const cpp_int_modular_backend<Bits>& a, const cpp_int_modular_backend<Bits>& b) noexcept {
                    return *a.limbs() > *b.limbs();
                }
                template<unsigned Bits, class U>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    boost::multiprecision::detail::is_unsigned<U>::value &&
                        is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value,
                    bool>::type
                    eval_gt(const cpp_int_modular_backend<Bits>& a, U b) noexcept {
                    return *a.limbs() > b;
                }
#ifdef BOOST_MSVC
#pragma warning(pop)
#endif

            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif
