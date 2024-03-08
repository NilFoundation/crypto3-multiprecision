///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. 
//  Copyright 2024 Martun Karapetyan. <martun@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifndef CRYPTO3_CPP_INT_MODULAR_HPP
#define CRYPTO3_CPP_INT_MODULAR_HPP

#ifndef TVM
#include <iostream>
#include <iomanip>
#include <cstdint>

#include <boost/array.hpp>

#include <boost/predef/other/endian.h>
#endif

#include <boost/core/empty_value.hpp>
#include <boost/integer/static_min_max.hpp>

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/detail/integer_ops.hpp>
#include <boost/multiprecision/detail/rebind.hpp>
#include <boost/multiprecision/traits/is_byte_container.hpp>
#include <boost/multiprecision/detail/constexpr.hpp>

#include <boost/multiprecision/cpp_int/checked.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/value_pack.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/cpp_int_modular_config.hpp>

#ifdef __EVM__
// EVM doesn't support exceptions, moreover it always should be compiled with flag `-fno-exceptions`. Therefore,
// keywords `throw`, etc. cannot appear.
#undef BOOST_THROW_EXCEPTION
#define BOOST_THROW_EXCEPTION(...) std::abort()
#endif

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

                using boost::enable_if;
                using namespace boost::multiprecision;
                using namespace boost::multiprecision::detail;
                using namespace boost::multiprecision::backends;

#ifdef BOOST_MSVC
#pragma warning(push)
#pragma warning( \
    disable : 4307)    // integral constant overflow (oveflow is in a branch not taken when it would overflow)
#pragma warning(disable : 4127)    // conditional expression is constant
#pragma warning(disable : 4702)    // Unreachable code (reachability depends on template params)
#endif

                template<unsigned Bits>
                struct cpp_int_modular_backend;

                template<unsigned Bits,
                         bool trivial = false>
                struct cpp_int_modular_base;

            }    // namespace backends
        }  // namespace multiprecision
    } // namespace crypto3
} // namespace nil
 
namespace boost {
    namespace multiprecision {
        namespace detail {

            template<unsigned Bits>
            struct is_byte_container<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>>
                : public boost::false_type { };

                //
                // Traits class determines the maximum and minimum precision values:
                //
                template<class T>
                struct max_precision;

                template<unsigned Bits>
                struct max_precision<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>> {
                    static constexpr const unsigned value = boost::static_unsigned_max<Bits, Bits>::value;
                };

                template<class T>
                struct min_precision;

                template<unsigned Bits>
                struct min_precision<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>> {
                    static constexpr const unsigned value =i boost::static_unsigned_max<Bits, MaxBits>::value;
                };

                //
                // Traits class determines whether the number of bits precision requested could fit in a native type,
                // we call this a "trivial" cpp_int:
                //
                template<class T>
                struct is_trivial_cpp_int {
                    static constexpr const bool value = false;
                };

                template<unsigned Bits>
                struct is_trivial_cpp_int<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>> {
                    using self = nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>;
                    static constexpr const bool value = (max_precision<self>::value <= (sizeof(double_limb_type) * CHAR_BIT));
                };

                template<unsigned Bits>
                struct is_trivial_cpp_int<nil::crypto3::multiprecision::backends::cpp_int_modular_base<Bits, true>> {
                    static constexpr const bool value = true;
                };

            }    // namespace backends
            //
            // Traits class to determine whether a cpp_int_modular_backend is signed or not:
            //
            template<unsigned Bits>
            struct is_unsigned_number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>>
                : public std::integral_constant<bool, true> { };

            namespace backends {
                //
                // Traits class determines whether T should be implicitly convertible to U, or
                // whether the constructor should be made explicit.  The latter happens if we
                // are losing the sign, or have fewer digits precision in the target type:
                //
                template<class T, class U>
                struct is_implicit_cpp_int_conversion;

                template<unsigned Bits, unsigned Bits2>
                struct is_implicit_cpp_int_conversion<
                    nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>,
                    nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits2>> {
                    using t1 = nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>;
                    using t2 = nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits2>;
                    static constexpr const bool value = 
                        (boost::multiprecision::detail::max_precision<t1>::value <= 
                            boost::multiprecision::detail::max_precision<t2>::value);
                };

                //
                // Traits class to determine whether operations on a cpp_int may throw:
                //
                template<class T>
                struct is_non_throwing_cpp_int : public std::integral_constant<bool, false> { };

                template<unsigned Bits>
                struct is_non_throwing_cpp_int<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>>
                    : public std::integral_constant<bool, true> { };

                //
                // Traits class, determines whether the cpp_int is fixed precision or not:
                //
                template<class T>
                struct is_fixed_precision;

                template<unsigned Bits>
                struct is_fixed_precision<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>>
                    : public std::integral_constant<
                          bool,
                          boost::multiprecision::detail::max_precision<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>>::value !=
                              UINT_MAX> { };

                namespace detail {

                    inline BOOST_MP_CXX14_CONSTEXPR void verify_new_size(unsigned new_size,
                                                                         unsigned min_size,
                                                                         const std::integral_constant<int, checked>&) {
                        if (new_size < min_size)
                            BOOST_THROW_EXCEPTION(
                                std::overflow_error("Unable to allocate sufficient storage for the value of the "
                                                    "result: value overflows the maximum allowable magnitude."));
                    }
                    inline BOOST_MP_CXX14_CONSTEXPR void
                        verify_new_size(unsigned /*new_size*/,
                                        unsigned /*min_size*/,
                                        const std::integral_constant<int, unchecked>&) {
                    }

                    template<class U>
                    inline BOOST_MP_CXX14_CONSTEXPR void
                        verify_limb_mask(bool b, U limb, U mask, const std::integral_constant<int, checked>&) {
                        // When we mask out "limb" with "mask", do we loose bits?  If so it's an overflow error:
                        if (b && (limb & ~mask))
                            BOOST_THROW_EXCEPTION(
                                std::overflow_error("Overflow in cpp_int arithmetic: there is insufficient precision "
                                                    "in the target type to hold all of the bits of the result."));
                    }
                    template<class U>
                    inline BOOST_MP_CXX14_CONSTEXPR void
                        verify_limb_mask(bool /*b*/,
                                         U /*limb*/,
                                         U /*mask*/,
                                         const std::integral_constant<int, unchecked>&) {
                    }
                }    // namespace detail
        }    // namespace detail
    } // namespace multiprecision
} // namespace boost

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
                //
                // Now define the various data layouts that are possible.
                // For modular we only use fixed precision (i.e. no allocator), unsigned type with limb-usage count:
                //
                template<unsigned Bits>
                struct cpp_int_modular_base<Bits, false> {
                    using limb_pointer = limb_type*;
                    using const_limb_pointer = const limb_type*;
                    using checked_type = std::integral_constant<int, Checked>;

                    struct scoped_shared_storage {
                        BOOST_MP_CXX14_CONSTEXPR scoped_shared_storage(const cpp_int_modular_base&, unsigned) {
                        }
                        BOOST_MP_CXX14_CONSTEXPR void deallocate(unsigned) {
                        }
                    };
                    //
                    // Interface invariants:
                    //
                    static_assert(Bits > sizeof(double_limb_type) * CHAR_BIT,
                                  "Template parameter Bits is inconsistent with the parameter trivial - did you "
                                  "mistakingly try to override the trivial parameter?");

                public:
                    static constexpr unsigned limb_bits = sizeof(limb_type) * CHAR_BIT;
                    static constexpr limb_type max_limb_value = ~static_cast<limb_type>(0u);
                    static constexpr limb_type sign_bit_mask = static_cast<limb_type>(1u) << (limb_bits - 1);
                    static constexpr unsigned internal_limb_count =
                        Bits / limb_bits + ((Bits % limb_bits) ? 1 : 0);
                    static constexpr limb_type upper_limb_mask =
                        (Bits % limb_bits) ? (limb_type(1) << (Bits % limb_bits)) - 1 : (~limb_type(0));
                    static_assert(internal_limb_count >= 2,
                                  "A fixed precision integer type must have at least 2 limbs");

                private:
                    union data_type {
                        limb_type m_data[internal_limb_count];
                        limb_type m_first_limb;
                        double_limb_type m_double_first_limb;

                        constexpr data_type() {
                        }
                        constexpr data_type(limb_type i) : m_data {i} {
                        }
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                        constexpr data_type(limb_type i, limb_type j) : m_data {i, j} {
                        }
#endif
#if !defined(TVM) && !defined(EVM)
                        constexpr data_type(double_limb_type i) : m_double_first_limb(i) {
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                            if (BOOST_MP_IS_CONST_EVALUATED(m_double_first_limb)) {
                                data_type t(static_cast<limb_type>(i & max_limb_value),
                                            static_cast<limb_type>(i >> limb_bits));
                                *this = t;
                            }
#endif
                        }
#endif // TVM

                        template<limb_type... VALUES>
                        constexpr data_type(literals::detail::value_pack<VALUES...>) : m_data {VALUES...} {
                        }
                    } m_wrapper;
                    limb_type m_limbs;

                    // This is a temporary value which is set when carry has happend during addition.
                    // If this value is true, reduction by modulus must happen next.
                    bool carry = false;

                public:
                    //
                    // Direct construction:
                    //
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(limb_type i) noexcept : m_wrapper(i), m_limbs(1) {
                    }
#ifdef TVM
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(unsigned int i) noexcept :
                        cpp_int_modular_base(static_cast<limb_type>(i)) {
                    }
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(int i) noexcept :
                        cpp_int_modular_base(static_cast<signed_limb_type>(i)) {
                    }
#endif // TVM

#if BOOST_ENDIAN_LITTLE_BYTE && !defined(BOOST_MP_TEST_NO_LE)
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(double_limb_type i) noexcept :
                        m_wrapper(i), m_limbs(i > max_limb_value ? 2 : 1) {
                    }
#endif
                    template<limb_type... VALUES>
                    constexpr cpp_int_modular_base(literals::detail::value_pack<VALUES...> i) :
                        m_wrapper(i), m_limbs(sizeof...(VALUES)) {
                    }
                    constexpr cpp_int_modular_base(literals::detail::value_pack<>) :
                        m_wrapper(static_cast<limb_type>(0u)), m_limbs(1) {
                    }
                    explicit constexpr cpp_int_modular_base(scoped_shared_storage&, unsigned) noexcept :
                        m_wrapper(), m_limbs(1) {
                    }
                    //
                    // Helper functions for getting at our internal data, and manipulating storage:
                    //
                    BOOST_MP_FORCEINLINE constexpr unsigned size() const noexcept {
                        return m_limbs;
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR limb_pointer limbs() noexcept {
                        return m_wrapper.m_data;
                    }
                    BOOST_MP_FORCEINLINE constexpr const_limb_pointer limbs() const noexcept {
                        return m_wrapper.m_data;
                    }
                    BOOST_MP_FORCEINLINE constexpr bool sign() const noexcept {
                        return false;
                    }

                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void normalize() noexcept {
                        limb_pointer p = limbs();
                        detail::verify_limb_mask(m_limbs == internal_limb_count,
                                                 p[internal_limb_count - 1],
                                                 upper_limb_mask,
                                                 checked_type());
                        p[internal_limb_count - 1] &= upper_limb_mask;
                        while ((m_limbs - 1) && !p[m_limbs - 1])
                            --m_limbs;
                    }

                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base() noexcept = default;

                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(const cpp_int_modular_base& o) noexcept :
                        m_wrapper(o.m_wrapper), m_limbs(o.m_limbs) {
                    }

                    // Defaulted functions:
                    //~cpp_int_modular_base() noexcept {}
                    //
                    // These are deprecated in C++20 unless we make them explicit:
                    //
                    BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base& operator=(const cpp_int_modular_base&) = default;

                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void assign(const cpp_int_modular_base& o) noexcept {
                        if (this != &o) {
                            m_limbs = o.m_limbs;
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                            if (BOOST_MP_IS_CONST_EVALUATED(m_limbs)) {
                                for (unsigned i = 0; i < m_limbs; ++i)
                                    limbs()[i] = o.limbs()[i];
                            } else
#endif
                                std::memcpy(limbs(), o.limbs(), o.size() * limb_size);
                        }
                    }

                public:
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void do_swap(cpp_int_modular_base& o) noexcept {
                        for (unsigned i = 0; i < (std::max)(size(), o.size()); ++i)
                            std_constexpr::swap(m_wrapper.m_data[i], o.m_wrapper.m_data[i]);
                        std_constexpr::swap(m_limbs, o.m_limbs);
                    }

                protected:
                    template<class A>
                    BOOST_MP_CXX14_CONSTEXPR void check_in_range(const A&) noexcept {
                    }
                };

                template<unsigned Bits>
                const unsigned cpp_int_modular_base<Bits, false>::limb_bits;
                template<unsigned Bits>
                const limb_type cpp_int_modular_base<Bits, false>::max_limb_value;
                template<unsigned Bits>
                const limb_type cpp_int_modular_base<Bits, false>::sign_bit_mask;
                template<unsigned Bits>
                const unsigned cpp_int_modular_base<Bits, false>::internal_limb_count;

                //
                // Traits classes to figure out a native type with N bits, these vary from boost::uint_t<N> only
                // because some platforms have native integer types longer than boost::long_long_type, "really
                // boost::long_long_type" anyone??
                //
#ifdef __EVM__
                template<unsigned N>
                struct trivial_limb_type {
                    using type = double_limb_type;
                };
#elif !defined(TVM)
                template<unsigned N, bool s>
                struct trivial_limb_type_imp {
                    using type = double_limb_type;
                };

                template<unsigned N>
                struct trivial_limb_type_imp<N, true> {
                    using type = typename boost::uint_t<N>::least;
                };

                template<unsigned N>
                struct trivial_limb_type
                    : public trivial_limb_type_imp<N, N <= sizeof(boost::long_long_type) * CHAR_BIT> { };
#else
                template<unsigned N>
                struct trivial_limb_type {
                    using type = unsigned;
                };
#endif //TVM
                //
                // Backend for unsigned fixed precision (i.e. no allocator) type which will fit entirely inside a
                // "double_limb_type":
                //
                template<unsigned Bits>
                struct cpp_int_modular_base<Bits, true> {
                    using local_limb_type = typename trivial_limb_type<Bits>::type;
                    using limb_pointer = local_limb_type*;
                    using const_limb_pointer = const local_limb_type*;

                    struct scoped_shared_storage {
                        BOOST_MP_CXX14_CONSTEXPR scoped_shared_storage(const cpp_int_modular_base&, unsigned) {
                        }
                        BOOST_MP_CXX14_CONSTEXPR void deallocate(unsigned) {
                        }
                    };

                private:
                    static constexpr unsigned limb_bits = sizeof(local_limb_type) * CHAR_BIT;
                    static constexpr local_limb_type limb_mask =
                        limb_bits != Bits ?
                            static_cast<local_limb_type>(static_cast<local_limb_type>(~local_limb_type(0)) >>
                                                         (limb_bits - Bits)) :
                            static_cast<local_limb_type>(~local_limb_type(0));

                    local_limb_type m_data;

                    using checked_type = std::integral_constant<int, Checked>;

                    //
                    // Interface invariants:
                    //
                    static_assert(Bits <= sizeof(double_limb_type) * CHAR_BIT,
                                  "Template parameter Bits is inconsistent with the parameter trivial - did you "
                                  "mistakingly try to override the trivial parameter?");

                protected:
                    template<class T>
                    BOOST_MP_CXX14_CONSTEXPR
                        typename std::enable_if<!(std::numeric_limits<T>::is_specialized &&
                                                  (std::numeric_limits<T>::digits <= (int)Bits))>::type
                        check_in_range(T val,
                                       const std::integral_constant<int, checked>&,
                                       const std::integral_constant<bool, false>&) {
                        using common_type = typename std::common_type<T, local_limb_type>::type;

                        if (static_cast<common_type>(val) > limb_mask)
                            BOOST_THROW_EXCEPTION(std::range_error(
                                "The argument to a cpp_int constructor exceeded the largest value it can represent."));
                    }
                    template<class T>
                    BOOST_MP_CXX14_CONSTEXPR void check_in_range(T val,
                                                                 const std::integral_constant<int, checked>&,
                                                                 const std::integral_constant<bool, true>&) {
                        using common_type = typename std::common_type<T, local_limb_type>::type;

                        if (static_cast<common_type>(val) > limb_mask)
                            BOOST_THROW_EXCEPTION(std::range_error(
                                "The argument to a cpp_int constructor exceeded the largest value it can represent."));
                        if (val < 0)
                            BOOST_THROW_EXCEPTION(
                                std::range_error("The argument to an unsigned cpp_int constructor was negative."));
                    }
                    template<class T, int C, bool B>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void
                        check_in_range(T,
                                       const std::integral_constant<int, C>&,
                                       const std::integral_constant<bool, B>&) noexcept {
                    }

                    template<class T>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void
                        check_in_range(T val) noexcept(noexcept(std::declval<cpp_int_modular_base>().check_in_range(
                            std::declval<T>(),
                            checked_type(),
                            boost::multiprecision::detail::is_signed<T>()))) {
                        check_in_range(val, checked_type(), boost::multiprecision::detail::is_signed<T>());
                    }

                public:
                    //
                    // Direct construction:
                    //
#ifdef __MSVC_RUNTIME_CHECKS
                    template<class SI>
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(
                        SI i,
                        typename std::enable_if<boost::multiprecision::detail::is_signed<SI>::value &&
                                                boost::multiprecision::detail::is_integral<SI>::value &&
                                                (Checked == unchecked)>::type const* = 0) noexcept :
                        m_data(i < 0 ? (1 + ~static_cast<local_limb_type>(-i & limb_mask)) & limb_mask :
                                       static_cast<local_limb_type>(i & limb_mask)) {
                    }
                    template<class SI>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(
                        SI i,
                        typename std::enable_if<boost::multiprecision::detail::is_signed<SI>::value &&
                                                boost::multiprecision::detail::is_integral<SI>::value &&
                                                (Checked == checked)>::type const* =
                            0) noexcept(noexcept(std::declval<cpp_int_modular_base>().check_in_range(std::declval<SI>()))) :
                        m_data(i < 0 ? 1 + ~static_cast<local_limb_type>(-i & limb_mask) :
                                       static_cast<local_limb_type>(i & limb_mask)) {
                        check_in_range(i);
                    }
                    template<class UI>
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(
                        UI i,
                        typename std::enable_if<boost::multiprecision::detail::is_unsigned<UI>::value &&
                                                (Checked == unchecked)>::type const* = 0) noexcept :
                        m_data(static_cast<local_limb_type>(i & limb_mask)) {
                    }
                    template<class UI>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(
                        UI i,
                        typename std::enable_if<boost::multiprecision::detail::is_unsigned<UI>::value &&
                                                (Checked == checked)>::type const* =
                            0) noexcept(noexcept(std::declval<cpp_int_modular_base>().check_in_range(std::declval<UI>()))) :
                        m_data(static_cast<local_limb_type>(i & limb_mask)) {
                        check_in_range(i);
                    }
#else
                    template<class SI>
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(
                        SI i,
                        typename std::enable_if<boost::multiprecision::detail::is_signed<SI>::value &&
                                                boost::multiprecision::detail::is_integral<SI>::value &&
                                                (Checked == unchecked)>::type const* = 0) noexcept :
                        m_data(i < 0 ? (1 + ~static_cast<local_limb_type>(-i)) & limb_mask :
                                       static_cast<local_limb_type>(i) & limb_mask) {
                    }
                    template<class SI>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(
                        SI i,
                        typename std::enable_if<boost::multiprecision::detail::is_signed<SI>::value &&
                                                boost::multiprecision::detail::is_integral<SI>::value &&
                                                (Checked == checked)>::type const* =
                            0) noexcept(noexcept(std::declval<cpp_int_modular_base>().check_in_range(std::declval<SI>()))) :
                        m_data(i < 0 ? 1 + ~static_cast<local_limb_type>(-i) : static_cast<local_limb_type>(i)) {
                        check_in_range(i);
                    }
                    template<class UI>
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(
                        UI i,
                        typename std::enable_if<boost::multiprecision::detail::is_unsigned<UI>::value &&
                                                (Checked == unchecked)>::type const* = 0) noexcept :
                        m_data(static_cast<local_limb_type>(i) & limb_mask) {
                    }
                    template<class UI>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base(
                        UI i,
                        typename std::enable_if<boost::multiprecision::detail::is_unsigned<UI>::value &&
                                                (Checked == checked)>::type const* =
                            0) noexcept(noexcept(std::declval<cpp_int_modular_base>().check_in_range(std::declval<UI>()))) :
                        m_data(static_cast<local_limb_type>(i)) {
                        check_in_range(i);
                    }
#endif
                    template<class F>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR
                        cpp_int_modular_base(F i,
                                     typename std::enable_if<std::is_floating_point<F>::value>::type const* =
                                         0) noexcept((Checked == unchecked)) :
                        m_data(static_cast<local_limb_type>(std::fabs(i)) & limb_mask) {
                        check_in_range(i);
                        if (i < 0)
                            negate();
                    }
                    constexpr cpp_int_modular_base(literals::detail::value_pack<>) noexcept :
                        m_data(static_cast<local_limb_type>(0u)) {
                    }
                    template<limb_type a>
                    constexpr cpp_int_modular_base(literals::detail::value_pack<a>) noexcept :
                        m_data(static_cast<local_limb_type>(a)) {
                    }
                    template<limb_type a, limb_type b>
                    constexpr cpp_int_modular_base(literals::detail::value_pack<a, b>) noexcept :
                        m_data(static_cast<local_limb_type>(a) | (static_cast<local_limb_type>(b) << bits_per_limb)) {
                    }
                    //
                    // These are deprecated in C++20 unless we make them explicit:
                    //
                    BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_base& operator=(const cpp_int_modular_base&) = default;

                    explicit constexpr cpp_int_modular_base(scoped_shared_storage&, unsigned) noexcept : m_data(0) {
                    }
                    //
                    // Helper functions for getting at our internal data, and manipulating storage:
                    //
                    BOOST_MP_FORCEINLINE constexpr unsigned size() const noexcept {
                        return 1;
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR limb_pointer limbs() noexcept {
                        return &m_data;
                    }
                    BOOST_MP_FORCEINLINE constexpr const_limb_pointer limbs() const noexcept {
                        return &m_data;
                    }
                    BOOST_MP_FORCEINLINE constexpr bool sign() const noexcept {
                        return false;
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void sign(bool b) noexcept((Checked == unchecked)) {
                        if (b)
                            negate();
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void resize(unsigned, unsigned min_size) {
                        boost::multiprecision::backends::detail::verify_new_size(2, min_size, checked_type());
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void normalize() noexcept((Checked == unchecked)) {
                        detail::verify_limb_mask(true, m_data, limb_mask, checked_type());
                        m_data &= limb_mask;
                    }

                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base() noexcept : m_data(0) {
                    }
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_base(const cpp_int_modular_base& o) noexcept : m_data(o.m_data) {
                    }
                    //~cpp_int_modular_base() noexcept {}
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void assign(const cpp_int_modular_base& o) noexcept {
                        m_data = o.m_data;
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void negate() noexcept((Checked == unchecked)) {
                        BOOST_IF_CONSTEXPR(Checked == checked) {
                            BOOST_THROW_EXCEPTION(std::range_error("Attempt to negate an unsigned type."));
                        }
                        m_data = ~m_data;
                        ++m_data;
                    }
                    BOOST_MP_FORCEINLINE constexpr bool isneg() const noexcept {
                        return false;
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void do_swap(cpp_int_modular_base& o) noexcept {
                        std_constexpr::swap(m_data, o.m_data);
                    }
                };
































                //
                // Traits class, lets us know whether type T can be directly converted to the base type,
                // used to enable/disable constructors etc:
                //
                template<class Arg, class Base>
                struct is_allowed_cpp_int_modular_base_conversion
                    : public std::conditional<std::is_same<Arg, limb_type>::value
#ifdef TVM
                                                  || std::is_same<Arg, unsigned int>::value||
                                                  std::is_same<Arg, int>::value
#endif
#if BOOST_ENDIAN_LITTLE_BYTE && !defined(BOOST_MP_TEST_NO_LE)
                                                  || std::is_same<Arg, double_limb_type>::value
#endif
                                                  || literals::detail::is_value_pack<Arg>::value ||
                                                  (is_trivial_cpp_int<Base>::value &&
                                                   boost::multiprecision::detail::is_arithmetic<Arg>::value),
                                              std::integral_constant<bool, true>,
                                              std::integral_constant<bool, false>>::type {
                };

                //
                // Now the actual backend, normalising parameters passed to the base class:
                //
                template<unsigned Bits>
                struct cpp_int_modular_backend
                    : public cpp_int_modular_base<Bits, is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value> {
                    using self_type = cpp_int_modular_backend<Bits>;
                    using base_type = cpp_int_modular_base<Bits, is_trivial_cpp_int<self_type>::value>;
                    using trivial_tag = std::integral_constant<bool, is_trivial_cpp_int<self_type>::value>;
                public:
#ifdef TVM
                    using unsigned_types = std::tuple<unsigned, limb_type, double_limb_type>;
#else

                   using unsigned_types = typename std::conditional<is_trivial_cpp_int<self_type>::value,
                                                                     std::tuple<unsigned char,
                                                                                unsigned short,
                                                                                unsigned,
                                                                                unsigned long,
                                                                                boost::ulong_long_type,
                                                                                double_limb_type>,
                                                                     std::tuple<limb_type, double_limb_type>>::type;
#endif
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_backend() noexcept
                    { }
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_backend(const cpp_int_modular_backend& o) noexcept
                        : base_type(o)
                    { }

                    // rvalue copy:
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_backend(cpp_int_modular_backend&& o) noexcept
                        : base_type(static_cast<base_type&&>(o)) {
                    }
                    template<unsigned Bits2>
                    BOOST_MP_FORCEINLINE BOOST_CXX14_CONSTEXPR cpp_int_modular_backend(
                        cpp_int_modular_backend<Bits2>&& o,
                        typename std::enable_if<
                            is_implicit_cpp_int_conversion<cpp_int_modular_backend<Bits2>, self_type>::value>::type* = 0) noexcept {
                        *this = static_cast<cpp_int_modular_backend<Bits2>&&>(o);
                    }
                    //
                    // Direct construction from arithmetic type:
                    //
#ifdef __EVM__
                    // For EVM backend we need to distingwish signed and unsigned integral types, otherwise frontend
                    // cannot decide which version(__int128_t or __uint128_t) of cpp_int_modular_base's constructor to use.
                    // Separating constructors via of `std::is_signed`, we help frontend to handle that.
                    template<class Arg>
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_backend(
                        Arg i,
                        typename std::enable_if<!std::is_integral<Arg>::value &&
                                                is_allowed_cpp_int_modular_base_conversion<Arg, base_type>::value>::
                            type const* = 0) : base_type(i) {
                    }

                    template<class Arg, typename std::enable_if_t<std::is_integral<Arg>::value &&
                                                                  std::is_convertible<Arg, signed_limb_type>::value &&
                                                                  std::is_signed<Arg>::value> const * = nullptr>
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_backend(Arg i) : base_type((signed_limb_type)i) {
                    }

                    template<class Arg, typename std::enable_if_t<std::is_integral<Arg>::value &&
                                                                  std::is_convertible<Arg, limb_type>::value &&
                                                                  !std::is_signed<Arg>::value> const * = nullptr>
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_backend(Arg i) : base_type((limb_type)i) {
                    }
#else
                    template<class Arg>
                    BOOST_MP_FORCEINLINE constexpr cpp_int_modular_backend(
                        Arg i,
                        typename std::enable_if<is_allowed_cpp_int_modular_base_conversion<Arg, base_type>::value>::
                            type const* = 0) noexcept(noexcept(base_type(std::declval<Arg>()))) :
                        base_type(i) {
                    }
#endif  // __EVM__
                    //
                    // Aliasing constructor: the result will alias the memory referenced, unless
                    // we have fixed precision and storage, in which case we copy the memory:
                    //
                    explicit constexpr cpp_int_modular_backend(limb_type* data, unsigned offset, unsigned len) noexcept :
                        base_type(data, offset, len) {
                    }
                    explicit cpp_int_modular_backend(const limb_type* data, unsigned offset, unsigned len) noexcept :
                        base_type(data, offset, len) {
                        this->normalize();
                    }
                    explicit constexpr cpp_int_modular_backend(typename base_type::scoped_shared_storage& data,
                                                       unsigned len) noexcept :
                        base_type(data, len) {
                    }

                private:
                    template<unsigned Bits2>
                    BOOST_MP_CXX14_CONSTEXPR void
                        do_assign(const cpp_int_modular_backend<Bits2>& other,
                                  std::integral_constant<bool, true> const&,
                                  std::integral_constant<bool, true> const&) {
                        // Assigning trivial type to trivial type:
                        this->check_in_range(*other.limbs());
                        *this->limbs() = static_cast<typename self_type::local_limb_type>(*other.limbs());
                        this->sign(other.sign());
                        this->normalize();
                    }
                    template<unsigned Bits2>
                    BOOST_MP_CXX14_CONSTEXPR void
                        do_assign(const cpp_int_modular_backend<Bits2>& other,
                                  std::integral_constant<bool, true> const&,
                                  std::integral_constant<bool, false> const&) {
                        // non-trivial to trivial narrowing conversion:
                        double_limb_type v = *other.limbs();
                        if (other.size() > 1) {
                            v |= static_cast<double_limb_type>(other.limbs()[1]) << bits_per_limb;
                            BOOST_IF_CONSTEXPR(Checked == checked) {
                                if (other.size() > 2) {
                                    BOOST_THROW_EXCEPTION(std::range_error(
                                        "Assignment of a cpp_int that is out of range for the target type."));
                                }
                            }
                        }
                        *this = v;
                        this->normalize();
                    }
                    template<unsigned Bits2>
                    BOOST_MP_CXX14_CONSTEXPR void
                        do_assign(const cpp_int_modular_backend<Bits2>& other,
                                  std::integral_constant<bool, false> const&,
                                  std::integral_constant<bool, true> const&) {
                        // trivial to non-trivial, treat the trivial argument as if it were an unsigned arithmetic type,
                        // then set the sign afterwards:
                        *this = static_cast<typename boost::multiprecision::detail::canonical<
                            typename cpp_int_modular_backend<Bits2>::
                                local_limb_type,
                            cpp_int_modular_backend<Bits>>::type>(*other.limbs());
                        this->sign(other.sign());
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    BOOST_MP_CXX14_CONSTEXPR void
                        do_assign(const cpp_int_modular_backend<Bits2>& other,
                                  std::integral_constant<bool, false> const&,
                                  std::integral_constant<bool, false> const&) {
                        // regular non-trivial to non-trivial assign:
                        this->resize(other.size(), other.size());

#if !defined(BOOST_MP_HAS_IS_CONSTANT_EVALUATED) && !defined(BOOST_MP_HAS_BUILTIN_IS_CONSTANT_EVALUATED) && \
    !defined(BOOST_NO_CXX14_CONSTEXPR)
                        unsigned count = (std::min)(other.size(), this->size());
                        for (unsigned i = 0; i < count; ++i)
                            this->limbs()[i] = other.limbs()[i];
#else
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
                        if (BOOST_MP_IS_CONST_EVALUATED(other.size())) {
                            unsigned count = (std::min)(other.size(), this->size());
                            for (unsigned i = 0; i < count; ++i)
                                this->limbs()[i] = other.limbs()[i];
                        } else
#endif
                            std::memcpy(this->limbs(),
                                        other.limbs(),
                                        (std::min)(other.size(), this->size()) * limb_size);
#endif
                        this->sign(other.sign());
                        this->normalize();
                    }

                public:
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(
                        const cpp_int_modular_backend<Bits2>& other,
                        typename std::enable_if<is_implicit_cpp_int_conversion<
                            cpp_int_modular_backend<Bits2>,
                            self_type>::value>::type* = 0) :
                        base_type() {
                        do_assign(
                            other,
                            std::integral_constant<bool, is_trivial_cpp_int<self_type>::value>(),
                            std::integral_constant<
                                bool,
                                is_trivial_cpp_int<
                                    cpp_int_modular_backend<Bits2>>::value>());
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    explicit BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(
                        const cpp_int_modular_backend<Bits2>& other,
                        typename std::enable_if<!(is_implicit_cpp_int_conversion<
                                                  cpp_int_modular_backend<Bits2>,
                                                  self_type>::value)>::type* = 0) :
                        base_type() {
                        do_assign(
                            other,
                            std::integral_constant<bool, is_trivial_cpp_int<self_type>::value>(),
                            std::integral_constant<
                                bool,
                                is_trivial_cpp_int<
                                    cpp_int_modular_backend<Bits2>>::value>());
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend&
                        operator=(const cpp_int_modular_backend<Bits2>& other) {
                        do_assign(
                            other,
                            std::integral_constant<bool, is_trivial_cpp_int<self_type>::value>(),
                            std::integral_constant<
                                bool,
                                is_trivial_cpp_int<
                                    cpp_int_modular_backend<Bits2>>::value>());
                        return *this;
                    }
                    constexpr cpp_int_modular_backend(const cpp_int_modular_backend& a, const literals::detail::negate_tag& tag) :
                        base_type(static_cast<const base_type&>(a), tag) {
                    }

                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend&
                        operator=(const cpp_int_modular_backend& o) noexcept(
                            noexcept(std::declval<cpp_int_modular_backend>().assign(std::declval<const cpp_int_modular_backend&>()))) {
                        this->assign(o);
                        return *this;
                    }
                    // rvalue copy:
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend&
                        operator=(cpp_int_modular_backend&& o) noexcept(
                            noexcept(std::declval<base_type&>() = std::declval<base_type>())) {
                        *static_cast<base_type*>(this) = static_cast<base_type&&>(o);
                        return *this;
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR
                        typename std::enable_if<((MaxBits2 <= MaxBits) || (MaxBits == 0)) &&
                                                    !std::is_void<Allocator>::value,
                                                cpp_int_modular_backend&>::type
                        operator=(cpp_int_modular_backend<Bits2, MaxBits2, SignType2, Checked2, Allocator>&& o) noexcept {
                        *static_cast<base_type*>(this) =
                            static_cast<typename cpp_int_modular_backend<Bits2, MaxBits2, SignType2, Checked2>::base_type&&>(
                                o);
                        return *this;
                    }

                private:
                    template<class A>
                    BOOST_MP_CXX14_CONSTEXPR
                        typename std::enable_if<boost::multiprecision::detail::is_unsigned<A>::value>::type
                        do_assign_arithmetic(A val, const std::integral_constant<bool, true>&) noexcept(
                            noexcept(std::declval<cpp_int_modular_backend>().check_in_range(std::declval<A>()))) {
                        this->check_in_range(val);
                        *this->limbs() = static_cast<typename self_type::local_limb_type>(val);
                        this->sign(false);
                        this->normalize();
                    }
                    template<class A>
                    BOOST_MP_CXX14_CONSTEXPR
                        typename std::enable_if<!(boost::multiprecision::detail::is_unsigned<A>::value ||
                                                  !boost::multiprecision::detail::is_integral<A>::value)>::type
                        do_assign_arithmetic(A val, const std::integral_constant<bool, true>&) noexcept(
                            noexcept(std::declval<cpp_int_modular_backend>().check_in_range(std::declval<A>())) && noexcept(
                                std::declval<cpp_int_modular_backend>().sign(true))) {
                        this->check_in_range(val);
                        *this->limbs() = (val < 0) ? static_cast<typename self_type::local_limb_type>(
                                                         boost::multiprecision::detail::unsigned_abs(val)) :
                                                     static_cast<typename self_type::local_limb_type>(val);
                        this->sign(val < 0);
                        this->normalize();
                    }
                    template<class A>
                    BOOST_MP_CXX14_CONSTEXPR
                        typename std::enable_if<!boost::multiprecision::detail::is_integral<A>::value>::type
                        do_assign_arithmetic(A val, const std::integral_constant<bool, true>&) {
                        this->check_in_range(val);
                        *this->limbs() = (val < 0) ? static_cast<typename self_type::local_limb_type>(
                                                         boost::multiprecision::detail::abs(val)) :
                                                     static_cast<typename self_type::local_limb_type>(val);
                        this->sign(val < 0);
                        this->normalize();
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void
                        do_assign_arithmetic(limb_type i, const std::integral_constant<bool, false>&) noexcept {
                        this->resize(1, 1);
                        *this->limbs() = i;
                        this->sign(false);
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void
                        do_assign_arithmetic(signed_limb_type i, const std::integral_constant<bool, false>&) noexcept(
                            noexcept(std::declval<cpp_int_modular_backend>().sign(true))) {
                        this->resize(1, 1);
                        *this->limbs() = static_cast<limb_type>(boost::multiprecision::detail::unsigned_abs(i));
                        this->sign(i < 0);
                    }
                    BOOST_MP_CXX14_CONSTEXPR void
                        do_assign_arithmetic(double_limb_type i, const std::integral_constant<bool, false>&) noexcept {
#ifndef TVM
                        static_assert(sizeof(i) == 2 * sizeof(limb_type), "Failed integer size check");
#endif // TVM
                        static_assert(base_type::internal_limb_count >= 2, "Failed internal limb count");
                        typename base_type::limb_pointer p = this->limbs();
#ifdef __MSVC_RUNTIME_CHECKS
                        *p = static_cast<limb_type>(i & ~static_cast<limb_type>(0));
#else
                        *p = static_cast<limb_type>(i);
#endif
                        p[1] = static_cast<limb_type>(i >> base_type::limb_bits);
                        this->resize(p[1] ? 2 : 1, p[1] ? 2 : 1);
                        this->sign(false);
                    }
                    BOOST_MP_CXX14_CONSTEXPR void do_assign_arithmetic(
                        signed_double_limb_type i,
                        const std::integral_constant<bool, false>&) noexcept(noexcept(std::declval<cpp_int_modular_backend>()
                                                                                          .sign(true))) {
#ifndef TVM
                        static_assert(sizeof(i) == 2 * sizeof(limb_type), "double limb type size check failed");
#endif
                        static_assert(base_type::internal_limb_count >= 2, "Failed internal limb count check");
                        bool s = false;
                        if (i < 0)
                            s = true;
                        double_limb_type ui =
                            static_cast<double_limb_type>(boost::multiprecision::detail::unsigned_abs(i));
                        typename base_type::limb_pointer p = this->limbs();
#ifdef __MSVC_RUNTIME_CHECKS
                        *p = static_cast<limb_type>(ui & ~static_cast<limb_type>(0));
#else
                        *p = static_cast<limb_type>(ui);
#endif
                        p[1] = static_cast<limb_type>(ui >> base_type::limb_bits);
                        this->resize(p[1] ? 2 : 1, p[1] ? 2 : 1);
                        this->sign(s);
                    }

#ifdef TVM
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void
                        do_assign_arithmetic(unsigned i, const std::integral_constant<bool, false>& tag) noexcept {
                        do_assign_arithmetic(double_limb_type(i), tag);
                    }
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void
                        do_assign_arithmetic(int i, const std::integral_constant<bool, false>& tag) noexcept {
                        do_assign_arithmetic(signed_double_limb_type(i), tag);
                    }
#endif

                    BOOST_MP_CXX14_CONSTEXPR void do_assign_arithmetic(long double a,
                                                                       const std::integral_constant<bool, false>&) {
                        using default_ops::eval_add;
                        using default_ops::eval_subtract;
                        using std::floor;
                        using std::frexp;
                        using std::ldexp;

                        if (a < 0) {
                            do_assign_arithmetic(-a, std::integral_constant<bool, false>());
                            this->sign(true);
                            return;
                        }

                        if (a == 0) {
                            *this = static_cast<limb_type>(0u);
                        }

                        if (a == 1) {
                            *this = static_cast<limb_type>(1u);
                        }

                        if ((boost::math::isinf)(a) || (boost::math::isnan)(a)) {
                            BOOST_THROW_EXCEPTION(
                                std::runtime_error("Cannot convert a non-finite number to an integer."));
                        }

                        int e = 0;
                        long double f(0), term(0);
                        *this = static_cast<limb_type>(0u);

                        f = frexp(a, &e);

#if !(defined(__clang__) && (__clang_major__ <= 7))
                        constexpr limb_type shift = std::numeric_limits<limb_type>::digits;
#else
                        // clang 7 has an issue converting long double to unsigned long long in
                        // release mode (bits get dropped, conversion appears to go via float)
                        // Never extract more than double bits at a time:
                        constexpr limb_type shift =
                            std::numeric_limits<limb_type>::digits > std::numeric_limits<double>::digits ?
                                std::numeric_limits<double>::digits :
                                std::numeric_limits<limb_type>::digits;
#endif

                        while (f) {
                            // extract int sized bits from f:
                            f = ldexp(f, shift);
                            term = floor(f);
                            e -= shift;
                            eval_left_shift(*this, shift);
#if !(defined(__clang__) && (__clang_major__ <= 7))
                            if (term > 0)
                                eval_add(*this, static_cast<limb_type>(term));
                            else
                                eval_subtract(*this, static_cast<limb_type>(-term));
#else
                            // clang 7 requires extra cast to double to avoid buggy code generation:
                            if (term > 0)
                                eval_add(*this, static_cast<limb_type>(static_cast<double>(term)));
                            else
                                eval_subtract(*this, static_cast<limb_type>(static_cast<double>(-term)));
#endif
                            f -= term;
                        }
                        if (e > 0)
                            eval_left_shift(*this, e);
                        else if (e < 0)
                            eval_right_shift(*this, -e);
                    }

                public:
                    template<class Arithmetic>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
                        !boost::multiprecision::detail::is_byte_container<Arithmetic>::value,
                        cpp_int_modular_backend&>::type
                        operator=(Arithmetic val) noexcept(
                            noexcept(std::declval<cpp_int_modular_backend>().do_assign_arithmetic(std::declval<Arithmetic>(),
                                                                                          trivial_tag()))) {
                        do_assign_arithmetic(val, trivial_tag());
                        return *this;
                    }
#ifndef TVM
                private:
                    void do_assign_string(const char* s, const std::integral_constant<bool, true>&) {
                        std::size_t n = s ? std::strlen(s) : 0;
                        *this = 0;
                        unsigned radix = 10;
                        bool isneg = false;
                        if (n && (*s == '-')) {
                            --n;
                            ++s;
                            isneg = true;
                        }
                        if (n && (*s == '0')) {
                            if ((n > 1) && ((s[1] == 'x') || (s[1] == 'X'))) {
                                radix = 16;
                                s += 2;
                                n -= 2;
                            } else {
                                radix = 8;
                                n -= 1;
                            }
                        }
                        if (n) {
                            unsigned val;
                            while (*s) {
                                if (*s >= '0' && *s <= '9')
                                    val = *s - '0';
                                else if (*s >= 'a' && *s <= 'f')
                                    val = 10 + *s - 'a';
                                else if (*s >= 'A' && *s <= 'F')
                                    val = 10 + *s - 'A';
                                else
                                    val = radix + 1;
                                if (val >= radix) {
                                    BOOST_THROW_EXCEPTION(
                                        std::runtime_error("Unexpected content found while parsing character string."));
                                }
                                *this->limbs() =
                                    detail::checked_multiply(*this->limbs(),
                                                             static_cast<typename base_type::local_limb_type>(radix),
                                                             checked_type());
                                *this->limbs() =
                                    detail::checked_add(*this->limbs(),
                                                        static_cast<typename base_type::local_limb_type>(val),
                                                        checked_type());
                                ++s;
                            }
                        }
                        if (isneg)
                            this->negate();
                    }
                    void do_assign_string(const char* s, const std::integral_constant<bool, false>&) {
                        using default_ops::eval_add;
                        using default_ops::eval_multiply;
                        std::size_t n = s ? std::strlen(s) : 0;
                        *this = static_cast<limb_type>(0u);
                        unsigned radix = 10;
                        bool isneg = false;
                        if (n && (*s == '-')) {
                            --n;
                            ++s;
                            isneg = true;
                        }
                        if (n && (*s == '0')) {
                            if ((n > 1) && ((s[1] == 'x') || (s[1] == 'X'))) {
                                radix = 16;
                                s += 2;
                                n -= 2;
                            } else {
                                radix = 8;
                                n -= 1;
                            }
                        }
                        //
                        // Exception guarantee: create the result in stack variable "result"
                        // then do a swap at the end.  In the event of a throw, *this will
                        // be left unchanged.
                        //
                        cpp_int_modular_backend result;
                        if (n) {
                            if (radix == 16) {
                                while (*s == '0')
                                    ++s;
                                std::size_t bitcount = 4 * std::strlen(s);
                                limb_type val;
                                std::size_t limb, shift;
                                if (bitcount > 4)
                                    bitcount -= 4;
                                else
                                    bitcount = 0;
                                std::size_t newsize = bitcount / (sizeof(limb_type) * CHAR_BIT) + 1;
                                result.resize(
                                    static_cast<unsigned>(newsize),
                                    static_cast<unsigned>(
                                        newsize));    // will throw if this is a checked integer that cannot be resized
                                std::memset(result.limbs(), 0, result.size() * sizeof(limb_type));
                                while (*s) {
                                    if (*s >= '0' && *s <= '9')
                                        val = *s - '0';
                                    else if (*s >= 'a' && *s <= 'f')
                                        val = 10 + *s - 'a';
                                    else if (*s >= 'A' && *s <= 'F')
                                        val = 10 + *s - 'A';
                                    else {
                                        BOOST_THROW_EXCEPTION(std::runtime_error(
                                            "Unexpected content found while parsing character string."));
                                    }
                                    limb = bitcount / (sizeof(limb_type) * CHAR_BIT);
                                    shift = bitcount % (sizeof(limb_type) * CHAR_BIT);
                                    val <<= shift;
                                    if (result.size() > limb) {
                                        result.limbs()[limb] |= val;
                                    }
                                    ++s;
                                    bitcount -= 4;
                                }
                                result.normalize();
                            } else if (radix == 8) {
                                while (*s == '0')
                                    ++s;
                                std::size_t bitcount = 3 * std::strlen(s);
                                limb_type val;
                                std::size_t limb, shift;
                                if (bitcount > 3)
                                    bitcount -= 3;
                                else
                                    bitcount = 0;
                                std::size_t newsize = bitcount / (sizeof(limb_type) * CHAR_BIT) + 1;
                                result.resize(
                                    static_cast<unsigned>(newsize),
                                    static_cast<unsigned>(
                                        newsize));    // will throw if this is a checked integer that cannot be resized
                                std::memset(result.limbs(), 0, result.size() * sizeof(limb_type));
                                while (*s) {
                                    if (*s >= '0' && *s <= '7')
                                        val = *s - '0';
                                    else {
                                        BOOST_THROW_EXCEPTION(std::runtime_error(
                                            "Unexpected content found while parsing character string."));
                                    }
                                    limb = bitcount / (sizeof(limb_type) * CHAR_BIT);
                                    shift = bitcount % (sizeof(limb_type) * CHAR_BIT);
                                    if (result.size() > limb) {
                                        result.limbs()[limb] |= (val << shift);
                                        if (shift > sizeof(limb_type) * CHAR_BIT - 3) {
                                            // Deal with the bits in val that overflow into the next limb:
                                            val >>= (sizeof(limb_type) * CHAR_BIT - shift);
                                            if (val) {
                                                // If this is the most-significant-limb, we may need to allocate an
                                                // extra one for the overflow:
                                                if (limb + 1 == newsize)
                                                    result.resize(static_cast<unsigned>(newsize + 1),
                                                                  static_cast<unsigned>(newsize + 1));
                                                if (result.size() > limb + 1) {
                                                    result.limbs()[limb + 1] |= val;
                                                }
                                            }
                                        }
                                    }
                                    ++s;
                                    bitcount -= 3;
                                }
                                result.normalize();
                            } else {
                                // Base 10, we extract blocks of size 10^9 at a time, that way
                                // the number of multiplications is kept to a minimum:
                                limb_type block_mult = max_block_10;
                                while (*s) {
                                    limb_type block = 0;
                                    for (unsigned i = 0; i < digits_per_block_10; ++i) {
                                        limb_type val;
                                        if (*s >= '0' && *s <= '9')
                                            val = *s - '0';
                                        else
                                            BOOST_THROW_EXCEPTION(
                                                std::runtime_error("Unexpected character encountered in input."));
                                        block *= 10;
                                        block += val;
                                        if (!*++s) {
                                            block_mult = block_multiplier(i);
                                            break;
                                        }
                                    }
                                    eval_multiply(result, block_mult);
                                    eval_add(result, block);
                                }
                            }
                        }
                        if (isneg)
                            result.negate();
                        result.swap(*this);
                    }

                public:
                    cpp_int_modular_backend& operator=(const char* s) {
                        do_assign_string(s, trivial_tag());
                        return *this;
                    }
#endif
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR void swap(cpp_int_modular_backend& o) noexcept {
                        this->do_swap(o);
                    }
#ifndef TVM
                private:
                    std::string do_get_trivial_string(std::ios_base::fmtflags f,
                                                      const std::integral_constant<bool, false>&) const {
                        using io_type = typename std::conditional<sizeof(typename base_type::local_limb_type) == 1,
                                                                  unsigned,
                                                                  typename base_type::local_limb_type>::type;
                        if (this->sign() && (((f & std::ios_base::hex) == std::ios_base::hex) ||
                                             ((f & std::ios_base::oct) == std::ios_base::oct)))
                            BOOST_THROW_EXCEPTION(
                                std::runtime_error("Base 8 or 16 printing of negative numbers is not supported."));
                        std::stringstream ss;
                        ss.flags(f & ~std::ios_base::showpos);
                        ss << static_cast<io_type>(*this->limbs());
                        std::string result;
                        if (this->sign())
                            result += '-';
                        else if (f & std::ios_base::showpos)
                            result += '+';
                        result += ss.str();
                        return result;
                    }
                    std::string do_get_trivial_string(std::ios_base::fmtflags f,
                                                      const std::integral_constant<bool, true>&) const {
                        // Even though we have only one limb, we can't do IO on it :-(
                        int base = 10;
                        if ((f & std::ios_base::oct) == std::ios_base::oct)
                            base = 8;
                        else if ((f & std::ios_base::hex) == std::ios_base::hex)
                            base = 16;
                        std::string result;

                        unsigned Bits = sizeof(typename base_type::local_limb_type) * CHAR_BIT;

                        if (base == 8 || base == 16) {
                            if (this->sign())
                                BOOST_THROW_EXCEPTION(
                                    std::runtime_error("Base 8 or 16 printing of negative numbers is not supported."));
                            limb_type shift = base == 8 ? 3 : 4;
                            limb_type mask = static_cast<limb_type>((1u << shift) - 1);
                            typename base_type::local_limb_type v = *this->limbs();
                            result.assign(Bits / shift + (Bits % shift ? 1 : 0), '0');
                            std::string::difference_type pos = result.size() - 1;
                            char letter_a = f & std::ios_base::uppercase ? 'A' : 'a';
                            for (unsigned i = 0; i < Bits / shift; ++i) {
                                char c = '0' + static_cast<char>(v & mask);
                                if (c > '9')
                                    c += letter_a - '9' - 1;
                                result[pos--] = c;
                                v >>= shift;
                            }
                            if (Bits % shift) {
                                mask = static_cast<limb_type>((1u << (Bits % shift)) - 1);
                                char c = '0' + static_cast<char>(v & mask);
                                if (c > '9')
                                    c += letter_a - '9';
                                result[pos] = c;
                            }
                            //
                            // Get rid of leading zeros:
                            //
                            std::string::size_type n = result.find_first_not_of('0');
                            if (!result.empty() && (n == std::string::npos))
                                n = result.size() - 1;
                            result.erase(0, n);
                            if (f & std::ios_base::showbase) {
                                const char* pp = base == 8 ? "0" : (f & std::ios_base::uppercase) ? "0X" : "0x";
                                result.insert(static_cast<std::string::size_type>(0), pp);
                            }
                        } else {
                            result.assign(Bits / 3 + 1, '0');
                            std::string::difference_type pos = result.size() - 1;
                            typename base_type::local_limb_type v(*this->limbs());
                            bool neg = false;
                            if (this->sign()) {
                                neg = true;
                            }
                            while (v) {
                                result[pos] = (v % 10) + '0';
                                --pos;
                                v /= 10;
                            }
                            std::string::size_type n = result.find_first_not_of('0');
                            result.erase(0, n);
                            if (result.empty())
                                result = "0";
                            if (neg)
                                result.insert(static_cast<std::string::size_type>(0), 1, '-');
                            else if (f & std::ios_base::showpos)
                                result.insert(static_cast<std::string::size_type>(0), 1, '+');
                        }
                        return result;
                    }
                    std::string do_get_string(std::ios_base::fmtflags f,
                                              const std::integral_constant<bool, true>&) const {
#ifdef BOOST_MP_NO_DOUBLE_LIMB_TYPE_IO
                        return do_get_trivial_string(
                            f,
                            std::integral_constant<
                                bool,
                                std::is_same<typename base_type::local_limb_type, double_limb_type>::value>());
#else
                        return do_get_trivial_string(f, std::integral_constant<bool, false>());
#endif
                    }
                    std::string do_get_string(std::ios_base::fmtflags f,
                                              const std::integral_constant<bool, false>&) const {
                        using default_ops::eval_get_sign;
                        int base = 10;
                        if ((f & std::ios_base::oct) == std::ios_base::oct)
                            base = 8;
                        else if ((f & std::ios_base::hex) == std::ios_base::hex)
                            base = 16;
                        std::string result;

                        unsigned Bits = this->size() * base_type::limb_bits;

                        if (base == 8 || base == 16) {
                            if (this->sign())
                                BOOST_THROW_EXCEPTION(
                                    std::runtime_error("Base 8 or 16 printing of negative numbers is not supported."));
                            limb_type shift = base == 8 ? 3 : 4;
                            limb_type mask = static_cast<limb_type>((1u << shift) - 1);
                            cpp_int_modular_backend t(*this);
                            result.assign(Bits / shift + ((Bits % shift) ? 1 : 0), '0');
                            std::string::difference_type pos = result.size() - 1;
                            char letter_a = f & std::ios_base::uppercase ? 'A' : 'a';
                            for (unsigned i = 0; i < Bits / shift; ++i) {
                                char c = '0' + static_cast<char>(t.limbs()[0] & mask);
                                if (c > '9')
                                    c += letter_a - '9' - 1;
                                result[pos--] = c;
                                eval_right_shift(t, shift);
                            }
                            if (Bits % shift) {
                                mask = static_cast<limb_type>((1u << (Bits % shift)) - 1);
                                char c = '0' + static_cast<char>(t.limbs()[0] & mask);
                                if (c > '9')
                                    c += letter_a - '9';
                                result[pos] = c;
                            }
                            //
                            // Get rid of leading zeros:
                            //
                            std::string::size_type n = result.find_first_not_of('0');
                            if (!result.empty() && (n == std::string::npos))
                                n = result.size() - 1;
                            result.erase(0, n);
                            if (f & std::ios_base::showbase) {
                                const char* pp = base == 8 ? "0" : (f & std::ios_base::uppercase) ? "0X" : "0x";
                                result.insert(static_cast<std::string::size_type>(0), pp);
                            }
                        } else {
                            result.assign(Bits / 3 + 1, '0');
                            std::string::difference_type pos = result.size() - 1;
                            cpp_int_modular_backend t(*this);
                            cpp_int_modular_backend r;
                            bool neg = false;
                            if (t.sign()) {
                                t.negate();
                                neg = true;
                            }
                            if (this->size() == 1) {
                                result = boost::lexical_cast<std::string>(t.limbs()[0]);
                            } else {
                                cpp_int_modular_backend block10;
                                block10 = max_block_10;
                                while (eval_get_sign(t) != 0) {
                                    cpp_int_modular_backend t2;
                                    divide_unsigned_helper(&t2, t, block10, r);
                                    t = t2;
                                    limb_type v = r.limbs()[0];
                                    for (unsigned i = 0; i < digits_per_block_10; ++i) {
                                        char c = '0' + v % 10;
                                        v /= 10;
                                        result[pos] = c;
                                        if (pos-- == 0)
                                            break;
                                    }
                                }
                            }
                            std::string::size_type n = result.find_first_not_of('0');
                            result.erase(0, n);
                            if (result.empty())
                                result = "0";
                            if (neg)
                                result.insert(static_cast<std::string::size_type>(0), 1, '-');
                            else if (f & std::ios_base::showpos)
                                result.insert(static_cast<std::string::size_type>(0), 1, '+');
                        }
                        return result;
                    }

                public:
                    std::string str(std::streamsize /*digits*/, std::ios_base::fmtflags f) const {
                        return do_get_string(f, trivial_tag());
                    }
#endif // TVM
#ifndef TVM
                private:
                    template<class Container>
                    void construct_from_container(const Container& c, const std::integral_constant<bool, false>&) {
                        //
                        // We assume that c is a sequence of (unsigned) bytes with the most significant byte first:
                        //
                        unsigned newsize = static_cast<unsigned>(c.size() / sizeof(limb_type));
                        if (c.size() % sizeof(limb_type)) {
                            ++newsize;
                        }
                        if (newsize) {
                            this->resize(newsize, newsize);    // May throw
                            std::memset(this->limbs(), 0, this->size());
                            typename Container::const_iterator i(c.begin()), j(c.end());
                            unsigned byte_location = static_cast<unsigned>(c.size() - 1);
                            while (i != j) {
                                unsigned limb = byte_location / sizeof(limb_type);
                                unsigned shift = (byte_location % sizeof(limb_type)) * CHAR_BIT;
                                if (this->size() > limb)
                                    this->limbs()[limb] |= static_cast<limb_type>(static_cast<unsigned char>(*i))
                                                           << shift;
                                ++i;
                                --byte_location;
                            }
                        }
                    }
#endif

                    template<class Container>
                    BOOST_MP_CXX14_CONSTEXPR void construct_from_container(const Container& c,
                                                                           const std::integral_constant<bool, true>&) {
                        //
                        // We assume that c is a sequence of (unsigned) bytes with the most significant byte first:
                        //
                        using local_limb_type = typename base_type::local_limb_type;
                        *this->limbs() = 0;
                        if (c.size()) {
                            typename Container::const_iterator i(c.begin()), j(c.end());
                            unsigned byte_location = static_cast<unsigned>(c.size() - 1);
                            while (i != j) {
                                unsigned limb = byte_location / sizeof(local_limb_type);
                                unsigned shift = (byte_location % sizeof(local_limb_type)) * CHAR_BIT;
                                if (limb == 0)
                                    this->limbs()[0] |= static_cast<limb_type>(static_cast<unsigned char>(*i)) << shift;
                                ++i;
                                --byte_location;
                            }
                        }
                    }

                public:
                    template<class Container>
                    BOOST_MP_CXX14_CONSTEXPR cpp_int_modular_backend(
                        const Container& c,
                        typename std::enable_if<
                            boost::multiprecision::detail::is_byte_container<Container>::value>::type const* =
                            0) {
                        //
                        // We assume that c is a sequence of (unsigned) bytes with the most significant byte first:
                        //
                        construct_from_container(c, trivial_tag());
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    BOOST_MP_CXX14_CONSTEXPR int
                        compare_imp(const cpp_int_modular_backend<Bits2>& o,
                                    const std::integral_constant<bool, false>&,
                                    const std::integral_constant<bool, false>&) const noexcept {
                        if (this->sign() != o.sign())
                            return this->sign() ? -1 : 1;

                        // Only do the compare if the same sign:
                        int result = compare_unsigned(o);

                        if (this->sign())
                            result = -result;
                        return result;
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    BOOST_MP_CXX14_CONSTEXPR int
                        compare_imp(const cpp_int_modular_backend<Bits2>& o,
                                    const std::integral_constant<bool, true>&,
                                    const std::integral_constant<bool, false>&) const {
                        cpp_int_modular_backend<Bits2> t(*this);
                        return t.compare(o);
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    BOOST_MP_CXX14_CONSTEXPR int
                        compare_imp(const cpp_int_modular_backend<Bits2>& o,
                                    const std::integral_constant<bool, false>&,
                                    const std::integral_constant<bool, true>&) const {
                        cpp_int_modular_backend<Bits> t(o);
                        return compare(t);
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    BOOST_MP_CXX14_CONSTEXPR int
                        compare_imp(const cpp_int_modular_backend<Bits2>& o,
                                    const std::integral_constant<bool, true>&,
                                    const std::integral_constant<bool, true>&) const noexcept {
                        if (this->sign()) {
                            if (o.sign()) {
                                return *this->limbs() < *o.limbs() ? 1 : (*this->limbs() > *o.limbs() ? -1 : 0);
                            } else
                                return -1;
                        } else {
                            if (o.sign())
                                return 1;
                            return *this->limbs() < *o.limbs() ? -1 : (*this->limbs() > *o.limbs() ? 1 : 0);
                        }
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    BOOST_MP_CXX14_CONSTEXPR int compare(
                        const cpp_int_modular_backend<Bits2>& o) const noexcept {
                        using t1 = std::integral_constant<
                            bool,
                            is_trivial_cpp_int<cpp_int_modular_backend<Bits>>::value>;
                        using t2 = std::integral_constant<
                            bool,
                            is_trivial_cpp_int<
                                cpp_int_modular_backend<Bits2>>::value>;
                        return compare_imp(o, t1(), t2());
                    }
                    template<unsigned Bits2,
                             unsigned MaxBits2,
                             cpp_integer_type SignType2,
                             cpp_int_check_type Checked2,
                             class Allocator2>
                    BOOST_MP_CXX14_CONSTEXPR int compare_unsigned(
                        const cpp_int_modular_backend<Bits2>& o) const noexcept {
                        if (this->size() != o.size()) {
                            return this->size() > o.size() ? 1 : -1;
                        }
                        typename base_type::const_limb_pointer pa = this->limbs();
                        typename base_type::const_limb_pointer pb = o.limbs();
                        for (int i = this->size() - 1; i >= 0; --i) {
                            if (pa[i] != pb[i])
                                return pa[i] > pb[i] ? 1 : -1;
                        }
                        return 0;
                    }
                    template<class Arithmetic>
                    BOOST_MP_FORCEINLINE BOOST_MP_CXX14_CONSTEXPR
                        typename std::enable_if<boost::multiprecision::detail::is_arithmetic<Arithmetic>::value,
                                                int>::type
                        compare(Arithmetic i) const {
                        // braindead version:
                        cpp_int_modular_backend t;
                        t = i;
                        return compare(t);
                    }
                };

            }    // namespace backends

            namespace default_ops {

                template<class Backend>
                struct double_precision_type;

                template<unsigned Bits,
                         unsigned MaxBits,
                         cpp_integer_type SignType,
                         cpp_int_check_type Checked,
                         class Allocator>
                struct double_precision_type<
                    cpp_int_modular_backend<Bits>> {
                    using type = typename std::conditional<
                        backends::is_fixed_precision<
                            cpp_int_modular_backend<Bits>>::value,
                        cpp_int_modular_backend<
                            (std::is_void<Allocator>::value ?
                                 2 * backends::max_precision<
                                         cpp_int_modular_backend<Bits>>::
                                         value :
                                 Bits),
                            2 * backends::max_precision<
                                    cpp_int_modular_backend<Bits>>::value,
                            SignType,
                            Checked,
                            Allocator>,
                        cpp_int_modular_backend<Bits>>::type;
                };

            }    // namespace default_ops

            template<unsigned Bits,
                     unsigned MaxBits,
                     cpp_integer_type SignType,
                     cpp_int_check_type Checked,
                     class Allocator,
                     unsigned Bits2,
                     unsigned MaxBits2,
                     cpp_integer_type SignType2,
                     cpp_int_check_type Checked2,
                     class Allocator2>
            struct is_equivalent_number_type<
                cpp_int_modular_backend<Bits>,
                cpp_int_modular_backend<Bits2>>
                : public std::integral_constant<
                      bool,
                      std::numeric_limits<
                          number<cpp_int_modular_backend<Bits>,
                                 et_on>>::digits ==
                          std::numeric_limits<
                              number<cpp_int_modular_backend<Bits2>,
                                     et_on>>::digits> { };

            template<unsigned Bits, unsigned MaxBits, cpp_integer_type SignType, cpp_int_check_type Checked>
            struct expression_template_default<cpp_int_modular_backend<Bits, MaxBits, SignType, Checked, void>> {
                static constexpr const expression_template_option value = et_off;
            };

            using cpp_int_modular_backend;

            template<unsigned Bits>
            struct number_category<cpp_int_modular_backend<Bits>>
                : public std::integral_constant<int, number_kind_integer> { };

            using cpp_int = number<cpp_int_modular_backend<>>;

            // Fixed precision unsigned types:
            using uint128_t  = number<cpp_int_modular_backend<128>>;
            using uint256_t  = number<cpp_int_modular_backend<256>>;
            using uint512_t  = number<cpp_int_modular_backend<512>>;
            using uint1024_t = number<cpp_int_modular_backend<1024>>;

#ifdef _MSC_VER
#pragma warning(pop)
#endif

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

//
// Last of all we include the implementations of all the eval_* non member functions:
//
#include <nil/crypto3/multiprecision/cpp_int_modular/limits.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/comparison.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/add.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/multiply.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/divide.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/bitwise.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/misc.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/literals.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/serialize.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/import_export.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/eval_jacobi.hpp>

#endif
