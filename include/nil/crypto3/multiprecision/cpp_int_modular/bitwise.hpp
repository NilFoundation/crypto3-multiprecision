///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
// Comparison operators for cpp_int_modular_backend:
//
#ifndef CRYPTO3_MP_CPP_INT_BIT_HPP
#define CRYPTO3_MP_CPP_INT_BIT_HPP

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4319)
#endif

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

                template<class CppInt1, class CppInt2, class Op>
                BOOST_MP_CXX14_CONSTEXPR void bitwise_op(
                    CppInt1& result, const CppInt2& o, Op op) noexcept {
                    //
                    // Both arguments are unsigned types, very simple case handled as a special case.
                    //
                    // First figure out how big the result needs to be and set up some data:
                    //
                    unsigned rs = result.size();
                    unsigned os = o.size();
                    unsigned m(0), x(0);
                    minmax(rs, os, m, x);
                    result.resize(x, x);
                    typename CppInt1::limb_pointer pr = result.limbs();
                    typename CppInt2::const_limb_pointer po = o.limbs();
                    for (unsigned i = rs; i < x; ++i)
                        pr[i] = 0;

                    for (unsigned i = 0; i < os; ++i)
                        pr[i] = op(pr[i], po[i]);
                    for (unsigned i = os; i < x; ++i)
                        pr[i] = op(pr[i], limb_type(0));

                    result.normalize();
                }

                struct bit_and {
                    BOOST_MP_CXX14_CONSTEXPR limb_type operator()(limb_type a, limb_type b) const noexcept {
                        return a & b;
                    }
                };
                struct bit_or {
                    BOOST_MP_CXX14_CONSTEXPR limb_type operator()(limb_type a, limb_type b) const noexcept {
                        return a | b;
                    }
                };
                struct bit_xor {
                    BOOST_MP_CXX14_CONSTEXPR limb_type operator()(limb_type a, limb_type b) const noexcept {
                        return a ^ b;
                    }
                };

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_and(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    bitwise_op(result, o, bit_and());
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_or(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    bitwise_op(result, o, bit_or());
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_xor(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    bitwise_op(result, o, bit_xor());
                }
                //
                // Again for operands which are single limbs:
                //
                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_and(
                        cpp_int_modular_backend<Bits>& result,
                        limb_type l) noexcept {
                    result.limbs()[0] &= l;
                    result.resize(1, 1);
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_or(cpp_int_modular_backend<Bits>& result, limb_type l) noexcept {
                    result.limbs()[0] |= l;
                }

                template<unsigned Bits>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_bitwise_xor(cpp_int_modular_backend<Bits>& result, limb_type l) noexcept {
                    result.limbs()[0] ^= l;
                }

                template<unsigned Bits,
                         class Allocator1>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_unsigned_number<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    !is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_complement(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>&
                            o) noexcept {
                    unsigned os = o.size();
                    result.resize(UINT_MAX, os);
                    for (unsigned i = 0; i < os; ++i)
                        result.limbs()[i] = ~o.limbs()[i];
                    for (unsigned i = os; i < result.size(); ++i)
                        result.limbs()[i] = ~static_cast<limb_type>(0);
                    result.normalize();
                }
#ifndef TVM
                template<class Int>
                inline void left_shift_byte(Int& result, double_limb_type s) {
                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    limb_type shift = static_cast<limb_type>(s % Int::limb_bits);
                    unsigned ors = result.size();
                    if ((ors == 1) && (!*result.limbs()))
                        return;    // shifting zero yields zero.
                    unsigned rs = ors;
                    if (shift && (result.limbs()[ors - 1] >> (Int::limb_bits - shift)))
                        ++rs;    // Most significant limb will overflow when shifted
                    rs += offset;
                    result.resize(rs, rs);
                    rs = result.size();

                    typename Int::limb_pointer pr = result.limbs();

                    if (rs != ors)
                        pr[rs - 1] = 0u;
                    std::size_t bytes = static_cast<std::size_t>(s / CHAR_BIT);
                    std::size_t len = (std::min)(ors * sizeof(limb_type), rs * sizeof(limb_type) - bytes);
                    if (bytes >= rs * sizeof(limb_type))
                        result = static_cast<limb_type>(0u);
                    else {
                        unsigned char* pc = reinterpret_cast<unsigned char*>(pr);
                        std::memmove(pc + bytes, pc, len);
                        std::memset(pc, 0, bytes);
                    }
                }
#endif

                template<class Int>
                inline BOOST_MP_CXX14_CONSTEXPR void left_shift_limb(Int& result, double_limb_type s) {
                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    limb_type shift = static_cast<limb_type>(s % Int::limb_bits);

                    unsigned ors = result.size();
                    if ((ors == 1) && (!*result.limbs()))
                        return;    // shifting zero yields zero.
                    unsigned rs = ors;
                    if (shift && (result.limbs()[ors - 1] >> (Int::limb_bits - shift)))
                        ++rs;    // Most significant limb will overflow when shifted
                    rs += offset;
                    result.resize(rs, rs);

                    typename Int::limb_pointer pr = result.limbs();

                    if (offset > rs) {
                        // The result is shifted past the end of the result:
                        result = static_cast<limb_type>(0);
                        return;
                    }

                    unsigned i = rs - result.size();
                    for (; i < ors; ++i)
                        pr[rs - 1 - i] = pr[ors - 1 - i];
                    for (; i < rs; ++i)
                        pr[rs - 1 - i] = 0;
                }

                template<class Int>
                inline BOOST_MP_CXX14_CONSTEXPR void left_shift_generic(Int& result, double_limb_type s) {
                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    limb_type shift = static_cast<limb_type>(s % Int::limb_bits);

                    unsigned ors = result.size();
                    if ((ors == 1) && (!*result.limbs()))
                        return;    // shifting zero yields zero.
                    unsigned rs = ors;
                    if (shift && (result.limbs()[ors - 1] >> (Int::limb_bits - shift)))
                        ++rs;    // Most significant limb will overflow when shifted
                    rs += offset;
                    result.resize(rs, rs);
                    bool truncated = result.size() != rs;

                    typename Int::limb_pointer pr = result.limbs();

                    if (offset > rs) {
                        // The result is shifted past the end of the result:
                        result = static_cast<limb_type>(0);
                        return;
                    }

                    unsigned i = rs - result.size();
                    // This code only works when shift is non-zero, otherwise we invoke undefined behaviour!
                    BOOST_ASSERT(shift);
                    if (!truncated) {
                        if (rs > ors + offset) {
                            pr[rs - 1 - i] = pr[ors - 1 - i] >> (Int::limb_bits - shift);
                            --rs;
                        } else {
                            pr[rs - 1 - i] = pr[ors - 1 - i] << shift;
                            if (ors > 1)
                                pr[rs - 1 - i] |= pr[ors - 2 - i] >> (Int::limb_bits - shift);
                            ++i;
                        }
                    }
                    for (; rs - i >= 2 + offset; ++i) {
                        pr[rs - 1 - i] = pr[rs - 1 - i - offset] << shift;
                        pr[rs - 1 - i] |= pr[rs - 2 - i - offset] >> (Int::limb_bits - shift);
                    }
                    if (rs - i >= 1 + offset) {
                        pr[rs - 1 - i] = pr[rs - 1 - i - offset] << shift;
                        ++i;
                    }
                    for (; i < rs; ++i)
                        pr[rs - 1 - i] = 0;
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_left_shift(
                        cpp_int_modular_backend<Bits>& result,
                        double_limb_type s) noexcept {
                    is_valid_bitwise_op(result);
                    if (!s)
                        return;

#if BOOST_ENDIAN_LITTLE_BYTE && defined(BOOST_MP_USE_LIMB_SHIFT)
                    constexpr const limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;
                    constexpr const limb_type byte_shift_mask = CHAR_BIT - 1;

                    if ((s & limb_shift_mask) == 0) {
                        left_shift_limb(result, s);
                    }
#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
                    else if ((s & byte_shift_mask) == 0)
#else
                    else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
                    {
                        left_shift_byte(result, s);
                    }
#elif BOOST_ENDIAN_LITTLE_BYTE
                    constexpr const limb_type byte_shift_mask = CHAR_BIT - 1;

#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
                    if ((s & byte_shift_mask) == 0)
#else
                    constexpr limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;
                    if (BOOST_MP_IS_CONST_EVALUATED(s) && ((s & limb_shift_mask) == 0))
                        left_shift_limb(result, s);
                    else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
                    {
                        left_shift_byte(result, s);
                    }
#else
                    constexpr const limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;

                    if ((s & limb_shift_mask) == 0) {
                        left_shift_limb(result, s);
                    }
#endif
                    else {
                        left_shift_generic(result, s);
                    }
                    //
                    // We may have shifted off the end and have leading zeros:
                    //
                    result.normalize();
                }

#ifndef TVM
                template<class Int>
                inline void right_shift_byte(Int& result, double_limb_type s) {
                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    BOOST_ASSERT((s % CHAR_BIT) == 0);
                    unsigned ors = result.size();
                    unsigned rs = ors;
                    if (offset >= rs) {
                        result = limb_type(0);
                        return;
                    }
                    rs -= offset;
                    typename Int::limb_pointer pr = result.limbs();
                    unsigned char* pc = reinterpret_cast<unsigned char*>(pr);
                    limb_type shift = static_cast<limb_type>(s / CHAR_BIT);
                    std::memmove(pc, pc + shift, ors * sizeof(pr[0]) - shift);
                    shift = (sizeof(limb_type) - shift % sizeof(limb_type)) * CHAR_BIT;
                    if (shift < Int::limb_bits) {
                        pr[ors - offset - 1] &= (static_cast<limb_type>(1u) << shift) - 1;
                        if (!pr[ors - offset - 1] && (rs > 1))
                            --rs;
                    }
// TODO(martun): remove this resize, we cannot resize any more.
                    result.resize(rs, rs);
                }
#endif

                template<class Int>
                inline BOOST_MP_CXX14_CONSTEXPR void right_shift_limb(Int& result, double_limb_type s) {
                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    BOOST_ASSERT((s % Int::limb_bits) == 0);
                    unsigned ors = result.size();
                    unsigned rs = ors;
                    if (offset >= rs) {
                        result = limb_type(0);
                        return;
                    }
                    rs -= offset;
                    typename Int::limb_pointer pr = result.limbs();
                    unsigned i = 0;
                    for (; i < rs; ++i)
                        pr[i] = pr[i + offset];
// TODO(martun): remove this resize, we cannot resize any more.
                    result.resize(rs, rs);
                }

                template<class Int>
                inline BOOST_MP_CXX14_CONSTEXPR void right_shift_generic(Int& result, double_limb_type s) {
                    limb_type offset = static_cast<limb_type>(s / Int::limb_bits);
                    limb_type shift = static_cast<limb_type>(s % Int::limb_bits);
                    unsigned ors = result.size();
                    unsigned rs = ors;
                    if (offset >= rs) {
                        result = limb_type(0);
                        return;
                    }
                    rs -= offset;
                    typename Int::limb_pointer pr = result.limbs();
                    if ((pr[ors - 1] >> shift) == 0) {
                        if (--rs == 0) {
                            result = limb_type(0);
                            return;
                        }
                    }
                    unsigned i = 0;

                    // This code only works for non-zero shift, otherwise we invoke undefined behaviour!
                    BOOST_ASSERT(shift);
                    for (; i + offset + 1 < ors; ++i) {
                        pr[i] = pr[i + offset] >> shift;
                        pr[i] |= pr[i + offset + 1] << (Int::limb_bits - shift);
                    }
                    pr[i] = pr[i + offset] >> shift;
                    result.resize(rs, rs);
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<!is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_right_shift(
                        cpp_int_modular_backend<Bits>& result,
                        double_limb_type s) noexcept {
                    is_valid_bitwise_op(result);
                    if (!s)
                        return;

#if BOOST_ENDIAN_LITTLE_BYTE && defined(BOOST_MP_USE_LIMB_SHIFT) && !defined(TVM)
                    constexpr const limb_type limb_shift_mask = cpp_int_modular_backend<Bits>::limb_bits - 1;
                    constexpr const limb_type byte_shift_mask = CHAR_BIT - 1;

                    if ((s & limb_shift_mask) == 0)
                        right_shift_limb(result, s);
#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
                    else if ((s & byte_shift_mask) == 0)
#else
                    else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
                        right_shift_byte(result, s);
#elif BOOST_ENDIAN_LITTLE_BYTE && !defined(TVM)
                    constexpr const limb_type byte_shift_mask = CHAR_BIT - 1;

#ifdef BOOST_MP_NO_CONSTEXPR_DETECTION
                    if ((s & byte_shift_mask) == 0)
#else
                    constexpr limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;
                    if (BOOST_MP_IS_CONST_EVALUATED(s) && ((s & limb_shift_mask) == 0))
                        right_shift_limb(result, s);
                    else if (((s & byte_shift_mask) == 0) && !BOOST_MP_IS_CONST_EVALUATED(s))
#endif
                        right_shift_byte(result, s);
#else
                    constexpr const limb_type limb_shift_mask =
                        cpp_int_modular_backend<Bits>::limb_bits - 1;

                    if ((s & limb_shift_mask) == 0)
                        right_shift_limb(result, s);
#endif
                    else
                        right_shift_generic(result, s);
                }

                //
                // Over again for trivial cpp_int's:
                //
                template<unsigned Bits,
                          class T>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_left_shift(
                        cpp_int_modular_backend<Bits>& result,
                        T s) noexcept {
                    is_valid_bitwise_op(result);
                    *result.limbs() <<= s;
                    result.normalize();
                }

                template<unsigned Bits, class T>
                BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<is_trivial_cpp_int<
                    cpp_int_modular_backend<Bits>>::value>::type
                    eval_right_shift(
                        cpp_int_modular_backend<Bits>& result,
                        T s) noexcept {
                    // Nothing to check here... just make sure we don't invoke undefined behavior:
                    is_valid_bitwise_op(result);
                    *result.limbs() = (static_cast<unsigned>(s) >= sizeof(*result.limbs()) * CHAR_BIT) ?
                                          0 :
                                          (*result.limbs() >> s);
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    is_unsigned_number<cpp_int_modular_backend<Bits>>::value &&
                    is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_complement(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>&
                            o) noexcept {
                    *result.limbs() = ~*o.limbs();
                    result.normalize();
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    is_unsigned_number<cpp_int_modular_backend<Bits>>::value &&
                    is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_bitwise_and(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    *result.limbs() &= *o.limbs();
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    is_unsigned_number<cpp_int_modular_backend<Bits>>::value &&
                    is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_bitwise_or(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    *result.limbs() |= *o.limbs();
                }

                template<unsigned Bits>
                inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value &&
                    is_unsigned_number<cpp_int_modular_backend<Bits>>::value &&
                    is_unsigned_number<cpp_int_modular_backend<Bits>>::value>::
                    type
                    eval_bitwise_xor(
                        cpp_int_modular_backend<Bits>& result,
                        const cpp_int_modular_backend<Bits>& o) noexcept {
                    *result.limbs() ^= *o.limbs();
                }

            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
