///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
// Comparison operators for cpp_int_modular_backend:
//
#ifndef CRYPTO3_CPP_INT_ADD_HPP
#define CRYPTO3_CPP_INT_ADD_HPP

#include <boost/multiprecision/detail/constexpr.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/add_unsigned.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

                //
                // As above, but for adding a single limb to a non-trivial cpp_int:
                //
                template<class CppInt>
                inline BOOST_MP_CXX14_CONSTEXPR void
                    add_unsigned(CppInt& result,
                                 const CppInt& a,
                                 const limb_type& o) noexcept {
                    // Addition using modular arithmetic.
                    // Nothing fancy, just let uintmax_t take the strain:

                    double_limb_type carry = o;
                    typename CppInt::limb_pointer pr = result.limbs();
                    typename CppInt::const_limb_pointer pa = a.limbs();
                    unsigned i = 0;
                    // Addition with carry until we either run out of digits or carry is zero:
                    for (; carry && (i < result.size()); ++i) {
                        carry += static_cast<double_limb_type>(pa[i]);
#ifdef __MSVC_RUNTIME_CHECKS
                        pr[i] = static_cast<limb_type>(carry & ~static_cast<limb_type>(0));
#else
                        pr[i] = static_cast<limb_type>(carry);
#endif
                        carry >>= CppInt::limb_bits;
                    }
                    // Just copy any remaining digits:
                    if (&a != &result) {
                        boost::multiprecision::std_constexpr::copy(pa + i, pa + a.size(), pr + i);
                    }
                    result.set_carry(carry);
                    result.normalize();
                }

                //
                // And again to subtract a single limb:
                //
                template<class CppInt>
                inline BOOST_MP_CXX14_CONSTEXPR void
                    subtract_unsigned(CppInt& result, const CppInt& a, const limb_type& b) noexcept {
// TODO(martun): check how we need to re-write this, our cppInt has fixed size.
                    // Subtract one limb.
                    // Nothing fancy, just let uintmax_t take the strain:
                    constexpr double_limb_type borrow = static_cast<double_limb_type>(CppInt::max_limb_value) + 1;
                    typename CppInt::limb_pointer pr = result.limbs();
                    typename CppInt::const_limb_pointer pa = a.limbs();
                    if (*pa >= b) {
                        *pr = *pa - b;
                        if (&result != &a) {
                            boost::multiprecision::std_constexpr::copy(pa + 1, pa + a.size(), pr + 1);
                        } else if ((result.size() == 1) && (*pr == 0)) {
                        }
                    } else if (result.size() == 1) {
                        *pr = b - *pa;
                    } else {
                        *pr = static_cast<limb_type>((borrow + *pa) - b);
                        unsigned i = 1;
                        while (!pa[i]) {
                            pr[i] = CppInt::max_limb_value;
                            ++i;
                        }
                        pr[i] = pa[i] - 1;
                        if (&result != &a) {
                            ++i;
                            boost::multiprecision::std_constexpr::copy(pa + i, pa + a.size(), pr + i);
                        }
                        result.normalize();
                    }
                }

                //
                // Now the actual functions called by the front end, all of which forward to one of the above:
                //
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                    eval_add(cpp_int_modular_backend<Bits>& result,
                             const cpp_int_modular_backend<Bits>& o) noexcept {
                    eval_add(result, result, o);
                }
                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_add(cpp_int_modular_backend<Bits>& result,
                             const cpp_int_modular_backend<Bits>& a,
                             const cpp_int_modular_backend<Bits>& b) noexcept {
                    add_unsigned(result, a, b);
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_add(
                        cpp_int_modular_backend<Bits>& result,
                        const limb_type& o) noexcept {
                    add_unsigned(result, result, o);
                }
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                    eval_add(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& a,
                        const limb_type& o) noexcept {
                    add_unsigned(result, a, o);
                }
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_subtract(
                        cpp_int_modular_backend<Bits>& result,
                        const limb_type& o) noexcept {
                    subtract_unsigned(result, result, o);
                }
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::type
                    eval_subtract(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& a,
                        const limb_type& o) noexcept {
                    subtract_unsigned(result, a, o);
                }
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_increment(cpp_int_modular_backend<Bits>&
                                       result) noexcept {
                    constexpr const limb_type one = 1;

                    if ((result.limbs()[0] < cpp_int_modular_backend<Bits>::max_limb_value))
                        ++result.limbs()[0];
                    else
                        eval_add(result, one);
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int_modular<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_decrement(cpp_int_modular_backend<Bits>& result) noexcept {

                    constexpr const limb_type one = 1;

                    if (result.limbs()[0])
                        --result.limbs()[0];
                    else
                        eval_subtract(result, one);
                }
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_subtract(cpp_int_modular_backend<Bits>& result,
                                  const cpp_int_modular_backend<Bits>& o) noexcept {
                    // Martun: this is called from fp.hpp
                    eval_subtract(result, result, o);
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_subtract(cpp_int_modular_backend<Bits>& result,
                                  const cpp_int_modular_backend<Bits>& a,
                                  const cpp_int_modular_backend<Bits>& b
                                ) noexcept {
                    // Martun: this is called from fp.hpp
                    subtract_unsigned(result, a, b);
                }

                //
                // Simple addition and subtraction routine for trivial cpp_int's come last:
                //
                // Simple version for two unsigned arguments:
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_add(cpp_int_modular_backend<Bits>& result,
                             const cpp_int_modular_backend<Bits>& o) noexcept {
                    *result.limbs() += *o.limbs();
                    result.normalize();
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value &&
                    boost::multiprecision::is_unsigned_number<cpp_int_modular_backend<Bits>>::value &&
                    boost::multiprecision::is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_subtract(cpp_int_modular_backend<Bits>& result,
                                  const cpp_int_modular_backend<Bits>& o) noexcept {
                    *result.limbs() -= *o.limbs();
                    result.normalize();
                }
            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif
