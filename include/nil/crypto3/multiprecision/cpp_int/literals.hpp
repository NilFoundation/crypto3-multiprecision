///////////////////////////////////////////////////////////////
//  Copyright 2013 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_MP_CPP_INT_LITERALS_HPP
#define BOOST_MP_CPP_INT_LITERALS_HPP

#include <nil/crypto3/multiprecision/cpp_int/cpp_int_config.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            namespace literals {
                namespace detail {

                    template<char>
                    struct hex_value;
                    template<>
                    struct hex_value<'0'> {
                        static constexpr limb_type value = 0;
                    };
                    template<>
                    struct hex_value<'1'> {
                        static constexpr limb_type value = 1;
                    };
                    template<>
                    struct hex_value<'2'> {
                        static constexpr limb_type value = 2;
                    };
                    template<>
                    struct hex_value<'3'> {
                        static constexpr limb_type value = 3;
                    };
                    template<>
                    struct hex_value<'4'> {
                        static constexpr limb_type value = 4;
                    };
                    template<>
                    struct hex_value<'5'> {
                        static constexpr limb_type value = 5;
                    };
                    template<>
                    struct hex_value<'6'> {
                        static constexpr limb_type value = 6;
                    };
                    template<>
                    struct hex_value<'7'> {
                        static constexpr limb_type value = 7;
                    };
                    template<>
                    struct hex_value<'8'> {
                        static constexpr limb_type value = 8;
                    };
                    template<>
                    struct hex_value<'9'> {
                        static constexpr limb_type value = 9;
                    };
                    template<>
                    struct hex_value<'a'> {
                        static constexpr limb_type value = 10;
                    };
                    template<>
                    struct hex_value<'b'> {
                        static constexpr limb_type value = 11;
                    };
                    template<>
                    struct hex_value<'c'> {
                        static constexpr limb_type value = 12;
                    };
                    template<>
                    struct hex_value<'d'> {
                        static constexpr limb_type value = 13;
                    };
                    template<>
                    struct hex_value<'e'> {
                        static constexpr limb_type value = 14;
                    };
                    template<>
                    struct hex_value<'f'> {
                        static constexpr limb_type value = 15;
                    };
                    template<>
                    struct hex_value<'A'> {
                        static constexpr limb_type value = 10;
                    };
                    template<>
                    struct hex_value<'B'> {
                        static constexpr limb_type value = 11;
                    };
                    template<>
                    struct hex_value<'C'> {
                        static constexpr limb_type value = 12;
                    };
                    template<>
                    struct hex_value<'D'> {
                        static constexpr limb_type value = 13;
                    };
                    template<>
                    struct hex_value<'E'> {
                        static constexpr limb_type value = 14;
                    };
                    template<>
                    struct hex_value<'F'> {
                        static constexpr limb_type value = 15;
                    };

                    template<class Pack, limb_type value>
                    struct combine_value_to_pack;
                    template<limb_type first, limb_type... ARGS, limb_type value>
                    struct combine_value_to_pack<value_pack<first, ARGS...>, value> {
                        using type = value_pack<first | value, ARGS...>;
                    };

                    template<char NextChar, char... CHARS>
                    struct pack_values {
                        static constexpr unsigned chars_per_limb = sizeof(limb_type) * CHAR_BIT / 4;
                        static constexpr unsigned shift = ((sizeof...(CHARS)) % chars_per_limb) * 4;
                        static constexpr limb_type value_to_add =
                            shift ? hex_value<NextChar>::value << shift : hex_value<NextChar>::value;

                        using recursive_packed_type = typename pack_values<CHARS...>::type;
                        using pack_type =
                            typename std::conditional<shift == 0, typename recursive_packed_type::next_type,
                                                      recursive_packed_type>::type;
                        using type = typename combine_value_to_pack<pack_type, value_to_add>::type;
                    };
                    template<char NextChar>
                    struct pack_values<NextChar> {
                        static constexpr limb_type value_to_add = hex_value<NextChar>::value;

                        using type = value_pack<value_to_add>;
                    };

                    template<class T>
                    struct strip_leading_zeros_from_pack;
                    template<limb_type... PACK>
                    struct strip_leading_zeros_from_pack<value_pack<PACK...>> {
                        using type = value_pack<PACK...>;
                    };
                    template<limb_type... PACK>
                    struct strip_leading_zeros_from_pack<value_pack<0u, PACK...>> {
                        using type = typename strip_leading_zeros_from_pack<value_pack<PACK...>>::type;
                    };

                    template<limb_type v, class PACK>
                    struct append_value_to_pack;
                    template<limb_type v, limb_type... PACK>
                    struct append_value_to_pack<v, value_pack<PACK...>> {
                        using type = value_pack<PACK..., v>;
                    };

                    template<class T>
                    struct reverse_value_pack;
                    template<limb_type v, limb_type... VALUES>
                    struct reverse_value_pack<value_pack<v, VALUES...>> {
                        using lead_values = typename reverse_value_pack<value_pack<VALUES...>>::type;
                        using type = typename append_value_to_pack<v, lead_values>::type;
                    };
                    template<limb_type v>
                    struct reverse_value_pack<value_pack<v>> {
                        using type = value_pack<v>;
                    };
                    template<>
                    struct reverse_value_pack<value_pack<>> {
                        using type = value_pack<>;
                    };

                    template<char l1, char l2, char... STR>
                    struct make_packed_value_from_str {
                        static_assert(l1 == '0', "Multi-precision integer literals must be in hexadecimal notation.");
                        static_assert((l2 == 'X') || (l2 == 'x'),
                                      "Multi-precision integer literals must be in hexadecimal notation.");
                        using packed_type = typename pack_values<STR...>::type;
                        using stripped_type = typename strip_leading_zeros_from_pack<packed_type>::type;
                        using type = typename reverse_value_pack<stripped_type>::type;
                    };

                    template<class Pack, class B>
                    struct make_backend_from_pack {
                        static constexpr Pack p = {};
                        static constexpr B value = p;
                    };

                    template<class Pack, class B>
                    constexpr B make_backend_from_pack<Pack, B>::value;

                    template<unsigned Digits>
                    struct signed_cpp_int_literal_result_type {
                        static constexpr unsigned bits = Digits * 4;
                        using backend_type =
                            nil::crypto3::multiprecision::backends::cpp_int_backend<bits, bits, signed_magnitude,
                                                                                    unchecked, void>;
                        using number_type = number<backend_type, et_off>;
                    };

                    template<unsigned Digits>
                    struct unsigned_cpp_int_literal_result_type {
                        static constexpr unsigned bits = Digits * 4;
                        using backend_type =
                            nil::crypto3::multiprecision::backends::cpp_int_backend<bits, bits, unsigned_magnitude,
                                                                                    unchecked, void>;
                        using number_type = number<backend_type, et_off>;
                    };

                }    // namespace detail

                template<char... STR>
                constexpr typename nil::crypto3::multiprecision::literals::detail::signed_cpp_int_literal_result_type<
                    (sizeof...(STR)) - 2>::number_type
                    operator"" _cppi() {
                    using pt = typename nil::crypto3::multiprecision::literals::detail::make_packed_value_from_str<
                        STR...>::type;
                    return nil::crypto3::multiprecision::literals::detail::make_backend_from_pack<
                        pt, typename nil::crypto3::multiprecision::literals::detail::signed_cpp_int_literal_result_type<
                                (sizeof...(STR)) - 2>::backend_type>::value;
                }

                template<char... STR>
                constexpr typename nil::crypto3::multiprecision::literals::detail::unsigned_cpp_int_literal_result_type<
                    (sizeof...(STR)) - 2>::number_type
                    operator"" _cppui() {
                    using pt = typename nil::crypto3::multiprecision::literals::detail::make_packed_value_from_str<
                        STR...>::type;
                    return nil::crypto3::multiprecision::literals::detail::make_backend_from_pack<
                        pt, typename nil::crypto3::multiprecision::literals::detail::
                                unsigned_cpp_int_literal_result_type<(sizeof...(STR)) - 2>::backend_type>::value;
                }

#ifdef __ZKLLVM__
#define BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(Bits)                                                                   \
    inline constexpr const char *                                                                                     \
    operator"" BOOST_JOIN(_cppui, Bits)(const char *val) {                                                            \
        return val;                                                                                                   \
    }

    inline constexpr const char *                                                                                     \
    operator"" BOOST_JOIN(_cppi, Bits)(const char *val) {                                                            \
        return val;                                                                                                   \
    }
#else
#define BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(Bits)                                                                   \
    template<char... STR>                                                                                             \
    constexpr nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::cpp_int_backend<           \
        Bits, Bits, nil::crypto3::multiprecision::signed_magnitude, nil::crypto3::multiprecision::unchecked, void>>   \
        operator"" BOOST_JOIN(_cppi, Bits)() {                                                                        \
        using pt = typename nil::crypto3::multiprecision::literals::detail::make_packed_value_from_str<STR...>::type; \
        return nil::crypto3::multiprecision::literals::detail::make_backend_from_pack<                                \
            pt, nil::crypto3::multiprecision::backends::cpp_int_backend<                                              \
                    Bits, Bits, nil::crypto3::multiprecision::signed_magnitude,                                       \
                    nil::crypto3::multiprecision::unchecked, void>>::value;                                           \
    }                                                                                                                 \
    template<char... STR>                                                                                             \
    constexpr nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::backends::cpp_int_backend<           \
        Bits, Bits, nil::crypto3::multiprecision::unsigned_magnitude, nil::crypto3::multiprecision::unchecked, void>> \
        operator"" BOOST_JOIN(_cppui, Bits)() {                                                                       \
        using pt = typename nil::crypto3::multiprecision::literals::detail::make_packed_value_from_str<STR...>::type; \
        return nil::crypto3::multiprecision::literals::detail::make_backend_from_pack<                                \
            pt, nil::crypto3::multiprecision::backends::cpp_int_backend<                                              \
                    Bits, Bits, nil::crypto3::multiprecision::unsigned_magnitude,                                     \
                    nil::crypto3::multiprecision::unchecked, void>>::value;                                           \
    }
#endif


            }    // namespace literals

            //
            // Overload unary minus operator for constexpr use:
            //
            template<unsigned MinBits, cpp_int_check_type Checked>
            constexpr number<cpp_int_backend<MinBits, MinBits, signed_magnitude, Checked, void>, et_off>
                operator-(const number<cpp_int_backend<MinBits, MinBits, signed_magnitude, Checked, void>, et_off>& a) {
                return cpp_int_backend<MinBits, MinBits, signed_magnitude, Checked, void>(
                    a.backend(), nil::crypto3::multiprecision::literals::detail::make_negate_tag());
            }
            template<unsigned MinBits, cpp_int_check_type Checked>
            constexpr number<cpp_int_backend<MinBits, MinBits, signed_magnitude, Checked, void>, et_off>
                operator-(number<cpp_int_backend<MinBits, MinBits, signed_magnitude, Checked, void>, et_off>&& a) {
                return cpp_int_backend<MinBits, MinBits, signed_magnitude, Checked, void>(
                    static_cast<
                        const number<cpp_int_backend<MinBits, MinBits, signed_magnitude, Checked, void>, et_off>&>(a)
                        .backend(),
                    nil::crypto3::multiprecision::literals::detail::make_negate_tag());
            }

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

// Moved here from algebra. This is a comprehensive list of all bitlengths we use.
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(16)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(17)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(18)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(64)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(92)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(94)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(128)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(130)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(149)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(150)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(151)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(152)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(160)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(163)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(164)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(177)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(178)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(179)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(180)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(181)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(182)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(183)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(191)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(192)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(205)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(206)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(222)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(223)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(224)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(225)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(226)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(239)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(248)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(249)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(250)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(251)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(252)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(253)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(254)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(255)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(263)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(264)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(280)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(281)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(292)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(293)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(294)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(295)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(296)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(297)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(298)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(316)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(319)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(320)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(330)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(331)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(374)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(375)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(376)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(377)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(378)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(379)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(380)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(381)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(384)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(503)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(504)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(507)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(512)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(515)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(516)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(521)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(546)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(577)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(578)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(585)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(595)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(636)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(706)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(707)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(758)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(753)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(759)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(761)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(859)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(860)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(893)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(894)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(913)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(1024)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(1490)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(1536)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(2048)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(2790)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(3072)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(4096)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(4269)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(4314)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(6144)
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(8192)

#endif    // BOOST_MP_CPP_INT_CORE_HPP
