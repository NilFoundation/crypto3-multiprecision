///////////////////////////////////////////////////////////////
//  Copyright 2012-2020 John Maddock.
//  Copyright 2020 Madhur Chauhan.
//  Distributed under the Boost Software License, Version 1.0.
//  (See accompanying file LICENSE_1_0.txt or copy at
//   https://www.boost.org/LICENSE_1_0.txt)
//
// Comparison operators for cpp_int_modular_backend:
//
#ifndef CRYPTO3_MP_CPP_INT_MISC_HPP
#define CRYPTO3_MP_CPP_INT_MISC_HPP

#include <boost/multiprecision/detail/constexpr.hpp>
#include <boost/multiprecision/detail/bitscan.hpp>    // lsb etc
#include <boost/integer/common_factor_rt.hpp>               // gcd/lcm
#include <boost/functional/hash_fwd.hpp>
#include <numeric>    // std::gcd

#ifdef BOOST_MSVC
#pragma warning(push)
#pragma warning(disable : 4702)
#pragma warning(disable : 4127)    // conditional expression is constant
#pragma warning(disable : 4146)    // unary minus operator applied to unsigned type, result still unsigned
#endif

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

                template<class T, bool has_limits = std::numeric_limits<T>::is_specialized>
                struct numeric_limits_workaround : public std::numeric_limits<T> { };
                template<class R>
                struct numeric_limits_workaround<R, false> {
                    static constexpr unsigned digits =
                        ~static_cast<R>(0) < 0 ? sizeof(R) * CHAR_BIT - 1 : sizeof(R) * CHAR_BIT;
                    static constexpr R(min)() {
                        return (static_cast<R>(-1) < 0) ? static_cast<R>(1) << digits : 0;
                    }
                    static constexpr R(max)() {
                        return (static_cast<R>(-1) < 0) ? ~(static_cast<R>(1) << digits) : ~static_cast<R>(0);
                    }
                };

                template<class R, unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                        boost::multiprecision::detail::is_integral<R>::value &&
                        !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value, void>::type
                    eval_convert_to(R *result, const cpp_int_modular_backend<Bits> &backend) {

                    BOOST_IF_CONSTEXPR(
                        numeric_limits_workaround<R>::digits <
                        cpp_int_modular_backend<Bits>::limb_bits) {
                        if (boost::multiprecision::detail::is_signed<R>::value &&
                                   boost::multiprecision::detail::is_integral<R>::value && 
                                   static_cast<nil::crypto3::multiprecision::limb_type>(
                                       (std::numeric_limits<R>::max)()) <= backend.limbs()[0]) {
                            *result = (numeric_limits_workaround<R>::max)();
                            return;
                        } else
                            *result = static_cast<R>(backend.limbs()[0]);
                    }
                    else
                        *result = static_cast<R>(backend.limbs()[0]);

                    unsigned shift = cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned i = 1;
                    BOOST_IF_CONSTEXPR(
                        numeric_limits_workaround<R>::digits >
                        cpp_int_modular_backend<Bits>::limb_bits) {
                        while ((i < backend.size()) &&
                               (shift <
                                static_cast<unsigned>(
                                    numeric_limits_workaround<R>::digits -
                                    cpp_int_modular_backend<Bits>::limb_bits))) {
                            *result += static_cast<R>(backend.limbs()[i]) << shift;
                            shift += cpp_int_modular_backend<Bits>::limb_bits;
                            ++i;
                        }
                        //
                        // We have one more limb to extract, but may not need all the bits, so treat this as a special
                        // case:
                        //
                        if (i < backend.size()) {
                            const limb_type mask =
                                numeric_limits_workaround<R>::digits - shift ==
                                        cpp_int_modular_backend<Bits>::
                                            limb_bits ?
                                    ~static_cast<limb_type>(0) :
                                    (static_cast<limb_type>(1u) << (numeric_limits_workaround<R>::digits - shift)) - 1;
                            *result += (static_cast<R>(backend.limbs()[i]) & mask) << shift;
                            if ((static_cast<R>(backend.limbs()[i]) & static_cast<limb_type>(~mask)) ||
                                (i + 1 < backend.size())) {
                                // Overflow:
                                if (boost::multiprecision::detail::is_signed<R>::value)
                                    *result = (numeric_limits_workaround<R>::max)();
                                return;
                            }
                        }
                    }
                    else if (backend.size() > 1) {
                        // Overflow:
                        if (boost::multiprecision::detail::is_signed<R>::value)
                            *result = (numeric_limits_workaround<R>::max)();
                        return;
                    }
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value, bool>::type
                    eval_is_zero(const cpp_int_modular_backend<Bits> &val) noexcept {
                    return !std::all_of(val.limbs(), val.limbs() + val.size(), [&](limb_type limb){return limb == 0;});
                }

                //
                // Get the location of the least-significant-bit:
                //
                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_lsb(const cpp_int_modular_backend<Bits> &a) {

                    using default_ops::eval_get_sign;
                    if (eval_get_sign(a) == 0) {
                        BOOST_THROW_EXCEPTION(std::domain_error("No bits were set in the operand."));
                    }
                    
                    //
                    // Find the index of the least significant limb that is non-zero:
                    //
                    unsigned index = 0;
                    while (!a.limbs()[index] && (index < a.size()))
                        ++index;
                    //
                    // Find the index of the least significant bit within that limb:
                    //
                    unsigned result = boost::multiprecision::detail::find_lsb(a.limbs()[index]);

                    return result +
                           index * cpp_int_modular_backend<Bits>::limb_bits;
                }

                //
                // Get the location of the most-significant-bit:
                //
                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_msb_imp(const cpp_int_modular_backend<Bits> &a) {
                    //
                    // Find the index of the most significant bit that is non-zero:
                    //
// TODO(martun): not this is wrong, we may have 0 limbs.
                    return (a.size() - 1) *
                               cpp_int_modular_backend<Bits>::limb_bits +
                           boost::multiprecision::detail::find_msb(a.limbs()[a.size() - 1]);
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_msb(const cpp_int_modular_backend<Bits> &a) {
                    using default_ops::eval_get_sign;
                    return eval_msb_imp(a);
                }

#ifdef BOOST_GCC
//
// We really shouldn't need to be disabling this warning, but it really does appear to be
// spurious.  The warning appears only when in release mode, and asserts are on.
//
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value,
                    bool>::type
                    eval_bit_test(const cpp_int_modular_backend<Bits> &val,
                                  unsigned index) noexcept {
                    unsigned offset =
                        index / cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned shift =
                        index % cpp_int_modular_backend<Bits>::limb_bits;
                    limb_type mask = shift ? limb_type(1u) << shift : limb_type(1u);
                    if (offset >= val.size())
                        return false;
                    return val.limbs()[offset] & mask ? true : false;
                }

#ifdef BOOST_GCC
#pragma GCC diagnostic pop
#endif

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bit_set(cpp_int_modular_backend<Bits> &val,
                                 unsigned index) {
                    unsigned offset =
                        index / cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned shift =
                        index % cpp_int_modular_backend<Bits>::limb_bits;
                    limb_type mask = shift ? limb_type(1u) << shift : limb_type(1u);
                    if (offset >= val.size()) {
                        unsigned os = val.size();
                        val.resize(offset + 1, offset + 1);
                        if (offset >= val.size())
                            return;    // fixed precision overflow
                        for (unsigned i = os; i <= offset; ++i)
                            val.limbs()[i] = 0;
                    }
                    val.limbs()[offset] |= mask;
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bit_unset(cpp_int_modular_backend<Bits> &val,
                                   unsigned index) noexcept {
                    unsigned offset =
                        index / cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned shift =
                        index % cpp_int_modular_backend<Bits>::limb_bits;
                    limb_type mask = shift ? limb_type(1u) << shift : limb_type(1u);
                    if (offset >= val.size())
                        return;
                    val.limbs()[offset] &= ~mask;
                    val.normalize();
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bit_flip(cpp_int_modular_backend<Bits> &val,
                                  unsigned index) {
                    unsigned offset =
                        index / cpp_int_modular_backend<Bits>::limb_bits;
                    unsigned shift =
                        index % cpp_int_modular_backend<Bits>::limb_bits;
                    limb_type mask = shift ? limb_type(1u) << shift : limb_type(1u);
                    if (offset >= val.size()) {
                        unsigned os = val.size();
                        val.resize(offset + 1, offset + 1);
                        if (offset >= val.size())
                            return;    // fixed precision overflow
                        for (unsigned i = os; i <= offset; ++i)
                            val.limbs()[i] = 0;
                    }
                    val.limbs()[offset] ^= mask;
                    val.normalize();
                }

                template<class R, unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    std::is_convertible<
                        typename cpp_int_modular_backend<Bits>::local_limb_type,
                        R>::value>::type
                    eval_convert_to(R *result, const cpp_int_modular_backend<Bits> &val) {
                    using common_type = typename std::common_type<
                        R,
                        typename cpp_int_modular_backend<Bits>::local_limb_type>::type;
                    BOOST_IF_CONSTEXPR(std::numeric_limits<R>::is_specialized) {
                        if (static_cast<common_type>(*val.limbs()) >
                            static_cast<common_type>((std::numeric_limits<R>::max)())) {
                            *result = boost::multiprecision::detail::is_signed<R>::value &&
                                boost::multiprecision::detail::is_integral<R>::value ?
                                    (std::numeric_limits<R>::max)() :
                                    static_cast<R>(*val.limbs());
                        } else
                            *result = static_cast<R>(*val.limbs());
                    }
                    else *result = static_cast<R>(*val.limbs());
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_lsb(const cpp_int_modular_backend<Bits> &a) {
                    //
                    // Find the index of the least significant bit within that limb:
                    //
                    return boost::multiprecision::detail::find_lsb(*a.limbs());
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_msb_imp(const cpp_int_modular_backend<Bits> &a) {
                    //
                    // Find the index of the least significant bit within that limb:
                    //
                    return boost::multiprecision::detail::find_msb(*a.limbs());
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value, unsigned>::type
                    eval_msb(const cpp_int_modular_backend<Bits> &a) {
                    
                    return eval_msb_imp(a);
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR std::size_t hash_value(
                    const cpp_int_modular_backend<Bits> &val) noexcept {
                    std::size_t result = 0;
                    for (unsigned i = 0; i < val.size(); ++i) {
                        boost::hash_combine(result, val.limbs()[i]);
                    }
                    boost::hash_combine(result, val.sign());
                    return result;
                }

#ifdef BOOST_MSVC
#pragma warning(pop)
#endif

            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif
