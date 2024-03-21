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

#include <boost/multiprecision/cpp_int/checked.hpp>
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/detail/integer_ops.hpp>
#include <boost/multiprecision/detail/rebind.hpp>
#include <boost/multiprecision/traits/is_byte_container.hpp>
#include <boost/multiprecision/detail/constexpr.hpp>

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
        } // namespace detail

        namespace backends {
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
                static constexpr const unsigned value = boost::static_unsigned_max<Bits, Bits>::value;
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
            struct is_implicit_cpp_int_modular_conversion;

            template<unsigned Bits1, unsigned Bits2>
            struct is_implicit_cpp_int_modular_conversion<
                nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits1>,
                nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits2>> {
                static constexpr const bool value = (Bits1 <= Bits2);
            };

           //
            // Traits class, determines whether the cpp_int is fixed precision or not:
            //
            template<class T>
            struct is_fixed_precision;

            template<unsigned Bits>
            struct is_fixed_precision<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>>
                : public std::integral_constant<
                      bool,
                      max_precision<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>>::value != UINT_MAX> { };
        }    // namespace backends
    } // namespace multiprecision
} // namespace boost

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {

            //
            // Traits class determines whether the number of bits precision requested could fit in a native type,
            // we call this a "trivial" cpp_int:
            //
            template<class T>
            struct is_trivial_cpp_int_modular {
                static constexpr const bool value = false;
            };

            template<unsigned Bits>
            struct is_trivial_cpp_int_modular<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>> {
                static constexpr const bool value = (Bits <= (sizeof(double_limb_type) * CHAR_BIT));
            };

            template<unsigned Bits>
            struct is_trivial_cpp_int_modular<nil::crypto3::multiprecision::backends::cpp_int_modular_base<Bits, true>> {
                static constexpr const bool value = true;
            };

                //
                // Now define the various data layouts that are possible.
                // For modular we only use fixed precision (i.e. no allocator), unsigned type with limb-usage count:
                //
                template<unsigned Bits>
                struct cpp_int_modular_base<Bits, false> {
                    using limb_pointer = limb_type*;
                    using const_limb_pointer = const limb_type*;

                    struct scoped_shared_storage {
                        constexpr scoped_shared_storage(const cpp_int_modular_base&, unsigned) {
                        }
                        constexpr void deallocate(unsigned) {
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

                        constexpr data_type() = default;

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
                    bool m_carry = false;

                public:
                    //
                    // Direct construction:
                    //
                    inline constexpr cpp_int_modular_base(limb_type i) noexcept : m_wrapper(i), m_limbs(1) {
                    }

#if BOOST_ENDIAN_LITTLE_BYTE && !defined(BOOST_MP_TEST_NO_LE)
                    inline constexpr cpp_int_modular_base(double_limb_type i) noexcept :
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
                    inline constexpr unsigned size() const noexcept {
                        return m_limbs;
                    }
                    inline constexpr limb_pointer limbs() noexcept {
                        return m_wrapper.m_data;
                    }
                    inline constexpr const_limb_pointer limbs() const noexcept {
                        return m_wrapper.m_data;
                    }
                    inline constexpr bool sign() const noexcept {
                        return false;
                    }
                    inline constexpr bool has_carry() const noexcept {
                        return m_carry;
                    }
                    inline constexpr void set_carry(bool carry) noexcept {
                        m_carry = carry;
                    }
                    inline constexpr void normalize() noexcept {
                        limb_pointer p = limbs();
                        p[internal_limb_count - 1] &= upper_limb_mask;
                        while ((m_limbs - 1) && !p[m_limbs - 1])
                            --m_limbs;
                    }

                    inline constexpr cpp_int_modular_base() noexcept
                        : m_wrapper(), m_limbs(1) {
                    }

                    inline constexpr cpp_int_modular_base(const cpp_int_modular_base& o) noexcept :
                        m_wrapper(o.m_wrapper), m_limbs(o.m_limbs) {
                    }

                    // Defaulted functions:
                    //~cpp_int_modular_base() noexcept {}
                    //
                    // These are deprecated in C++20 unless we make them explicit:
                    //
                    constexpr cpp_int_modular_base& operator=(const cpp_int_modular_base&) = default;

                    inline constexpr void assign(const cpp_int_modular_base& o) noexcept {
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
                    inline constexpr void do_swap(cpp_int_modular_base& o) noexcept {
                        for (unsigned i = 0; i < (std::max)(size(), o.size()); ++i)
                            boost::multiprecision::std_constexpr::swap(m_wrapper.m_data[i], o.m_wrapper.m_data[i]);
                        boost::multiprecision::std_constexpr::swap(m_limbs, o.m_limbs);
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
                        constexpr scoped_shared_storage(const cpp_int_modular_base&, unsigned) {
                        }
                        constexpr void deallocate(unsigned) {
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

                    //
                    // Interface invariants:
                    //
                    static_assert(Bits <= sizeof(double_limb_type) * CHAR_BIT,
                                  "Template parameter Bits is inconsistent with the parameter trivial - did you "
                                  "mistakingly try to override the trivial parameter?");

                public:
                    //
                    // Direct construction:
                    //
                    template<class UI>
                    inline constexpr cpp_int_modular_base(
                        UI i,
                        typename std::enable_if<boost::multiprecision::detail::is_unsigned<UI>::value
                                                >::type const* = 0) noexcept :
                        m_data(static_cast<local_limb_type>(i) & limb_mask) {
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
                    constexpr cpp_int_modular_base& operator=(const cpp_int_modular_base&) = default;

                    explicit constexpr cpp_int_modular_base(scoped_shared_storage&, unsigned) noexcept : m_data(0) {
                    }
                    //
                    // Helper functions for getting at our internal data, and manipulating storage:
                    //
                    inline constexpr unsigned size() const noexcept {
// TODO(martun): why does this return 1?
                        return 1;
                    }
                    inline constexpr limb_pointer limbs() noexcept {
                        return &m_data;
                    }
                    inline constexpr const_limb_pointer limbs() const noexcept {
                        return &m_data;
                    }
                    inline constexpr void normalize() noexcept {
                        m_data &= limb_mask;
                    }

                    inline constexpr cpp_int_modular_base() noexcept : m_data(0) {
                    }
                    inline constexpr cpp_int_modular_base(const cpp_int_modular_base& o) noexcept
                        : m_data(o.m_data) {
                    }
                    //~cpp_int_modular_base() noexcept {}
                    inline constexpr void assign(const cpp_int_modular_base& o) noexcept {
                        m_data = o.m_data;
                    }
                    inline constexpr void do_swap(cpp_int_modular_base& o) noexcept {
                        boost::multiprecision::std_constexpr::swap(m_data, o.m_data);
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
                                                  (is_trivial_cpp_int_modular<Base>::value &&
                                                   boost::multiprecision::detail::is_arithmetic<Arg>::value),
                                              std::integral_constant<bool, true>,
                                              std::integral_constant<bool, false>>::type {
                };

                //
                // Now the actual backend, normalising parameters passed to the base class:
                //
                template<unsigned Bits>
                struct cpp_int_modular_backend
                    : public cpp_int_modular_base<Bits, is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value> {
                    using self_type = cpp_int_modular_backend<Bits>;
                    using base_type = cpp_int_modular_base<Bits, is_trivial_cpp_int_modular<self_type>::value>;
                    using trivial_tag = std::integral_constant<bool, is_trivial_cpp_int_modular<self_type>::value>;
                public:
#ifdef TVM
                    using unsigned_types = std::tuple<unsigned, limb_type, double_limb_type>;
#else

                    using unsigned_types = typename std::conditional<is_trivial_cpp_int_modular<self_type>::value,
                                                                     std::tuple<unsigned char,
                                                                                unsigned short,
                                                                                unsigned,
                                                                                unsigned long,
                                                                                boost::ulong_long_type,
                                                                                double_limb_type>,
                                                                     std::tuple<limb_type, double_limb_type>>::type;
#endif
                    inline constexpr cpp_int_modular_backend() noexcept
                    { }
                    inline constexpr cpp_int_modular_backend(const cpp_int_modular_backend& o) noexcept
                        : base_type(o)
                    { }

                    // rvalue copy:
                    inline constexpr cpp_int_modular_backend(cpp_int_modular_backend&& o) noexcept
                        : base_type(static_cast<base_type&&>(o)) {
                    }

                    // Sometimes we need to convert from one bit length to another. For example from 'Backend_doubled_limbs' to 'Backend'.
                    template<unsigned Bits2>
                    inline constexpr cpp_int_modular_backend(
                            cpp_int_modular_backend<Bits2>&& o,
                            typename std::enable_if<boost::multiprecision::backends::is_implicit_cpp_int_modular_conversion<cpp_int_modular_backend<Bits2>, self_type>::value>::type* = 0) noexcept {
                        *this = static_cast<cpp_int_modular_backend<Bits2>&&>(o);
                    }

                    //
                    // Direct construction from arithmetic type:
                    //
                    template<class Arg>
                    inline constexpr cpp_int_modular_backend(
                        Arg i,
                        typename std::enable_if<is_allowed_cpp_int_modular_base_conversion<Arg, base_type>::value>::
                            type const* = 0) noexcept(noexcept(base_type(std::declval<Arg>()))) :
                        base_type(i) {
                    }
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
                    explicit constexpr cpp_int_modular_backend(
                            typename base_type::scoped_shared_storage& data,
                            unsigned len) noexcept
                        : base_type(data, len) {
                    }

                private:
                    template<unsigned Bits2>
                    constexpr void
                        do_assign(const cpp_int_modular_backend<Bits2>& other,
                                  std::integral_constant<bool, true> const&,
                                  std::integral_constant<bool, true> const&) {
                        // Assigning trivial type to trivial type:
                        *this->limbs() = static_cast<typename self_type::local_limb_type>(*other.limbs());
                        this->normalize();
                    }

                    template<unsigned Bits2>
                    constexpr void
                        do_assign(const cpp_int_modular_backend<Bits2>& other,
                                  std::integral_constant<bool, true> const&,
                                  std::integral_constant<bool, false> const&) {
                        // non-trivial to trivial narrowing conversion:
                        double_limb_type v = *other.limbs();
                        if (other.size() > 1) {
                            v |= static_cast<double_limb_type>(other.limbs()[1]) << bits_per_limb;
                        }
                        *this = v;
                        this->normalize();
                    }
                    template<unsigned Bits2>
                    constexpr void
                        do_assign(const cpp_int_modular_backend<Bits2>& other,
                                  std::integral_constant<bool, false> const&,
                                  std::integral_constant<bool, true> const&) {
                        // trivial to non-trivial.
                        *this = static_cast<typename boost::multiprecision::detail::canonical<
                            typename cpp_int_modular_backend<Bits2>::local_limb_type,
                            cpp_int_modular_backend<Bits>>::type>(*other.limbs());
                    }
                    template<unsigned Bits2>
                    constexpr void
                        do_assign(const cpp_int_modular_backend<Bits2>& other,
                                  std::integral_constant<bool, false> const&,
                                  std::integral_constant<bool, false> const&) {
// TODO(martun): we cannot resize here, check that size fits, add zeros at the end.

                        // regular non-trivial to non-trivial assign:
                        //this->resize(other.size(), other.size());

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
                        this->normalize();
                    }

                public:
                    template<unsigned Bits2>
                    constexpr cpp_int_modular_backend(
                        const cpp_int_modular_backend<Bits2>& other,
                        typename std::enable_if<boost::multiprecision::backends::is_implicit_cpp_int_modular_conversion<
                            cpp_int_modular_backend<Bits2>, self_type>::value>::type* = 0)
                            : base_type() {
                        do_assign(
                            other,
                            std::integral_constant<bool, is_trivial_cpp_int_modular<self_type>::value>(),
                            std::integral_constant<
                                bool,
                                is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>());
                    }

                    template<unsigned Bits2>
                    explicit constexpr cpp_int_modular_backend(
                        const cpp_int_modular_backend<Bits2>& other,
                        typename std::enable_if<!(boost::multiprecision::backends::is_implicit_cpp_int_modular_conversion<
                                                  cpp_int_modular_backend<Bits2>, self_type>::value)>::type* = 0)
                            : base_type() {
                        do_assign(
                            other,
                            std::integral_constant<bool, is_trivial_cpp_int_modular<self_type>::value>(),
                            std::integral_constant<
                                bool,
                                is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>());
                    }

                    template<unsigned Bits2>
                    constexpr cpp_int_modular_backend&
                        operator=(const cpp_int_modular_backend<Bits2>& other) {
                        do_assign(
                            other,
                            std::integral_constant<bool, is_trivial_cpp_int_modular<self_type>::value>(),
                            std::integral_constant<
                                bool,
                                is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits2>>::value>());
                        return *this;
                    }

                    inline constexpr cpp_int_modular_backend&
                        operator=(const cpp_int_modular_backend& o) noexcept(
                            noexcept(std::declval<cpp_int_modular_backend>().assign(std::declval<const cpp_int_modular_backend&>()))) {
                        this->assign(o);
                        return *this;
                    }
                    // rvalue copy:
                    inline constexpr cpp_int_modular_backend&
                        operator=(cpp_int_modular_backend&& o) noexcept(
                            noexcept(std::declval<base_type&>() = std::declval<base_type>())) {
                        *static_cast<base_type*>(this) = static_cast<base_type&&>(o);
                        return *this;
                    }
                    template<unsigned Bits2>
                    inline constexpr
                        typename std::enable_if<(Bits2 <= Bits), cpp_int_modular_backend&>::type
                        operator=(cpp_int_modular_backend<Bits2>&& o) noexcept {
                        *static_cast<base_type*>(this) =
                            static_cast<typename cpp_int_modular_backend<Bits2>::base_type&&>(o);
                        return *this;
                    }
                    
                private:
                    // Second argument "std::integral_constant<bool, true>" is set to true to indicate A being a "trivial cpp_int type".
                    template<class A>
                    constexpr
                        typename std::enable_if<boost::multiprecision::detail::is_unsigned<A>::value>::type
                        do_assign_arithmetic(A val, const std::integral_constant<bool, true>&) noexcept {
                        *this->limbs() = static_cast<typename self_type::local_limb_type>(val);
                        this->normalize();
                    }

                    inline constexpr void
                        do_assign_arithmetic(limb_type i, const std::integral_constant<bool, false>&) noexcept {
// TODO(martun): we cannot resize here.
                        // this->resize(1, 1);
                        *this->limbs() = i;
                    }
                    constexpr void
                        do_assign_arithmetic(double_limb_type i) noexcept {
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
                        // TODO(martun): check this, we don't have resize any more.
                        p[1] = static_cast<limb_type>(i >> base_type::limb_bits);
                        // this->resize(p[1] ? 2 : 1, p[1] ? 2 : 1);
                    }
#ifdef TVM
                    inline constexpr void
                        do_assign_arithmetic(unsigned i, const std::integral_constant<bool, false>& tag) noexcept {
                        do_assign_arithmetic(double_limb_type(i), tag);
                    }
#endif

                public:
                    template<class Arithmetic>
                    inline constexpr typename std::enable_if<
                        !boost::multiprecision::detail::is_byte_container<Arithmetic>::value,
                        cpp_int_modular_backend&>::type
                        operator=(Arithmetic val) noexcept {
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
                                *this->limbs() *= static_cast<typename base_type::local_limb_type>(radix);
                                *this->limbs() += static_cast<typename base_type::local_limb_type>(val);
                                ++s;
                            }
                        }
                    }

                    void do_assign_string(const char* s, const std::integral_constant<bool, false>&) {
// TODO(martun): consider removing this from here, and just convert to boost::cpp_int then to our structure.
                        using boost::multiprecision::default_ops::eval_add;
                        using boost::multiprecision::default_ops::eval_multiply;

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
                        result.swap(*this);
                    }

                public:
                    cpp_int_modular_backend& operator=(const char* s) {
                        do_assign_string(s, trivial_tag());
                        return *this;
                    }
#endif
                    inline constexpr void swap(cpp_int_modular_backend& o) noexcept {
                        this->do_swap(o);
                    }
#ifndef TVM
                private:
                    std::string do_get_trivial_string(std::ios_base::fmtflags f,
                                                      const std::integral_constant<bool, false>&) const {
                        using io_type = typename std::conditional<sizeof(typename base_type::local_limb_type) == 1,
                                                                  unsigned,
                                                                  typename base_type::local_limb_type>::type;
                        std::stringstream ss;
                        ss.flags(f & ~std::ios_base::showpos);
                        ss << static_cast<io_type>(*this->limbs());
                        std::string result;
                        if (f & std::ios_base::showpos)
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

                        if (base == 8 || base == 16) {
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
                            while (v) {
                                result[pos] = (v % 10) + '0';
                                --pos;
                                v /= 10;
                            }
                            std::string::size_type n = result.find_first_not_of('0');
                            result.erase(0, n);
                            if (result.empty())
                                result = "0";
                            if (f & std::ios_base::showpos)
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
                        int base = 10;
                        if ((f & std::ios_base::oct) == std::ios_base::oct)
                            base = 8;
                        else if ((f & std::ios_base::hex) == std::ios_base::hex)
                            base = 16;
                        std::string result;

                        if (base == 8 || base == 16) {
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
                            if (f & std::ios_base::showpos)
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
                            // TODO(martun): We can not resize, the size must match.
                            // this->resize(newsize, newsize);    // May throw
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
                    constexpr void construct_from_container(const Container& c,
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
                    constexpr cpp_int_modular_backend(
                        const Container& c,
                        typename std::enable_if<
                            boost::multiprecision::detail::is_byte_container<Container>::value>::type const* =
                            0) {
                        //
                        // We assume that c is a sequence of (unsigned) bytes with the most significant byte first:
                        //
                        construct_from_container(c, trivial_tag());
                    }
                   constexpr int
                        compare_imp(const cpp_int_modular_backend<Bits>& o,
                                    const std::integral_constant<bool, false>&,
                                    const std::integral_constant<bool, false>&) const noexcept {
                        return compare_unsigned(o);
                    }
                    constexpr int
                        compare_imp(const cpp_int_modular_backend<Bits>& o,
                                    const std::integral_constant<bool, true>&,
                                    const std::integral_constant<bool, false>&) const {
                        cpp_int_modular_backend<Bits> t(*this);
                        return t.compare(o);
                    }
                    constexpr int
                        compare_imp(const cpp_int_modular_backend<Bits>& o,
                                    const std::integral_constant<bool, false>&,
                                    const std::integral_constant<bool, true>&) const {
                        cpp_int_modular_backend<Bits> t(o);
                        return compare(t);
                    }
                    constexpr int
                        compare_imp(const cpp_int_modular_backend<Bits>& o,
                                    const std::integral_constant<bool, true>&,
                                    const std::integral_constant<bool, true>&) const noexcept {
                        return *this->limbs() < *o.limbs() ? 1 : (*this->limbs() > *o.limbs() ? -1 : 0);
                    }
                    constexpr int compare(
                        const cpp_int_modular_backend<Bits>& o) const noexcept {
                        using t = std::integral_constant<
                            bool,
                            is_trivial_cpp_int_modular<cpp_int_modular_backend<Bits>>::value>;
                        return compare_imp(o, t(), t());
                    }
                    constexpr int compare_unsigned(
                        const cpp_int_modular_backend<Bits>& o) const noexcept {
                        typename base_type::const_limb_pointer pa = this->limbs();
                        typename base_type::const_limb_pointer pb = o.limbs();
                        for (int i = this->size() - 1; i >= 0; --i) {
                            if (pa[i] != pb[i])
                                return pa[i] > pb[i] ? 1 : -1;
                        }
                        return 0;
                    }
                    template<class Arithmetic>
                    inline constexpr
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
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil


namespace boost {
    namespace multiprecision {
        using nil::crypto3::multiprecision::backends::cpp_int_modular_backend;

        template<unsigned Bits>
        struct number_category<cpp_int_modular_backend<Bits>>
            : public std::integral_constant<int, number_kind_integer> { };

        template<unsigned Bits>
        struct expression_template_default<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>> {
            static constexpr const expression_template_option value = boost::multiprecision::et_off;
        };

    } // namespace multiprecision
} // namespace boost


#ifdef _MSC_VER
#pragma warning(pop)
#endif


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
#include <nil/crypto3/multiprecision/traits/is_backend.hpp>

#endif
