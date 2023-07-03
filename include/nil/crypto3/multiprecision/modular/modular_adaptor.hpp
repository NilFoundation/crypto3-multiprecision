//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019-2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_ADAPTOR_HPP
#define BOOST_MULTIPRECISION_MODULAR_ADAPTOR_HPP

#include <boost/cstdint.hpp>
#include <boost/functional/hash_fwd.hpp>
#include <boost/predef.h>

#include <nil/crypto3/multiprecision/detail/digits.hpp>
#include <nil/crypto3/multiprecision/detail/number_base.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/multiprecision/modular/modular_params.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor_fixed.hpp>

#include <boost/container/small_vector.hpp>

#include <algorithm>
#include <cmath>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
                template<typename Backend, const nil::crypto3::multiprecision::modular_params<Backend> &Modulus>
                class modular_params_ct {
                public:
                    typedef modular_params<Backend> modular_type;

                    constexpr modular_params_ct() {
                    }

                    constexpr modular_params_ct(modular_type &input) {
                    }

                    constexpr void set_modular_params(const modular_type &input) {
                    }

                    template<typename T>
                    constexpr void set_modular_params(const T &input) {
                    }

                    constexpr const modular_type &mod_data() const {
                        return m_mod;
                    }

                protected:
                    constexpr static const modular_type m_mod = Modulus;
                };

                template<typename Backend>
                class modular_params_rt {
                public:
                    typedef modular_params<Backend> modular_type;

                    constexpr modular_params_rt() {
                    }

                    constexpr modular_params_rt(modular_type input) {
                        m_mod = input;
                    }

                    constexpr void set_modular_params(const modular_type &input) {
                        m_mod = input;
                    }

                    constexpr void set_modular_params(const number<Backend> &input) {
                        m_mod = input;
                    }

                    constexpr modular_type &mod_data() {
                        return m_mod;
                    }
                    constexpr const modular_type &mod_data() const {
                        return m_mod;
                    }

                public:
                    modular_type m_mod;
                };

                template<typename Backend, const nil::crypto3::multiprecision::modular_params<Backend> &Modulus>
                constexpr modular_params<Backend> const modular_params_ct<Backend, Modulus>::m_mod;

                template<typename Backend, typename StorageType>
                struct modular_adaptor {
                    typedef modular_params<Backend> modular_type;
                    typedef Backend backend_type;

                protected:
                    Backend m_base;
                    modular_type m_mod;

                public:
                    inline Backend &base_data() {
                        return m_base;
                    }
                    inline const Backend &base_data() const {
                        return m_base;
                    }
                    inline modular_type &mod_data() {
                        return m_mod;
                    }
                    inline const modular_type &mod_data() const {
                        return m_mod;
                    }

                    typedef typename Backend::signed_types signed_types;
                    typedef typename Backend::unsigned_types unsigned_types;

                    modular_adaptor() {
                    }

                    modular_adaptor(const modular_adaptor &o) : m_base(o.base_data()), m_mod(o.mod_data()) {
                    }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES

                    modular_adaptor(modular_adaptor &&o) :
                        m_base(std::move(o.base_data())), m_mod(std::move(o.mod_data())) {
                    }

#endif
                    // TODO: implement create_internal_representation
                    // modular_adaptor(const Backend& val, const modular_params<Backend>& mod) : m_mod(mod),
                    // m_base(mod.create_internal_representation(val))
                    // {
                    //
                    // }

                    modular_adaptor(const Backend &val, const Backend &mod) : m_base(val), m_mod(mod) {
                    }

                    modular_adaptor(Backend &val, Backend &mod) : m_base(val), m_mod(mod) {
                    }

                    // TODO: maybe initialize modulus rather than base
                    modular_adaptor(const Backend &val) :
                        m_base(val), m_mod(typename std::tuple_element<0, unsigned_types>::type(0u)) {
                    }

                    modular_adaptor(const modular_params<Backend> &mod) :
                        m_base(typename std::tuple_element<0, unsigned_types>::type(0u)), m_mod(mod) {
                    }

                    modular_adaptor &operator=(const modular_adaptor &o) {
                        m_base = o.base_data();
                        m_mod = o.mod_data();
                        return *this;
                    }

#ifndef BOOST_NO_CXX11_RVALUE_REFERENCES

                    modular_adaptor &operator=(modular_adaptor &&o)

                        BOOST_NOEXCEPT {
                        m_base = std::move(o.base_data());
                        m_mod = std::move(o.mod_data());
                        return *this;
                    }
#endif

                    modular_adaptor &operator=(const char *s) {
                        using ui_type = typename std::tuple_element<0, unsigned_types>::type;
                        ui_type zero = 0u;

                        using default_ops::eval_fpclassify;

                        if (s && (*s == '(')) {
                            std::string part;
                            const char *p = ++s;
                            while (*p && (*p != ',') && (*p != ')'))
                                ++p;
                            part.assign(s, p);
                            if (!part.empty())
                                m_base() = part.c_str();
                            else
                                m_base() = zero;
                            s = p;
                            if (*p && (*p != ')')) {
                                ++p;
                                while (*p && (*p != ')'))
                                    ++p;
                                part.assign(s + 1, p);
                            } else
                                part.erase();
                            if (!part.empty())
                                m_mod() = part.c_str();
                            else
                                m_mod() = zero;
                        } else {
                            base_data() = s;
                            m_mod() = zero;
                        }
                        return *this;
                    }

                    bool compare_eq(const modular_adaptor &o) const {
                        return !m_mod.compare(o.mod_data()) && !base_data().compare(o.base_data());
                    }

                    template<class T>
                    int compare_eq(const T &val) const {
                        return !base_data().compare(val);
                    }

                    int compare(const modular_adaptor &o) const {
                        // They are either equal or not:<
                        if (m_mod.compare(o.mod_data()) != 0) {
                            BOOST_THROW_EXCEPTION(
                                std::runtime_error("Could not compare modular number with different mod."));
                        }
                        Backend tmp1, tmp2;
                        mod_data().adjust_regular(tmp1, base_data());
                        mod_data().adjust_regular(tmp2, o.base_data());
                        return tmp1.compare(tmp2);
                    }

                    template<class T>
                    int compare(const T &val) const {
                        using default_ops::eval_lt;
                        if (!eval_lt(m_mod, val)) {
                            BOOST_THROW_EXCEPTION(std::runtime_error(
                                "Could not compare modular number with mod bigger than compared number."));
                        }
                        Backend tmp;
                        mod_data().adjust_regular(tmp, base_data());
                        return tmp.compare(val);
                    }

                    inline void swap(modular_adaptor &o) {
                        base_data().swap(o.base_data());
                        std::swap(mod_data(), o.mod_data());
                    }

                    inline std::string str(std::streamsize dig, std::ios_base::fmtflags f) const {
                        Backend tmp;
                        mod_data().adjust_regular(tmp, base_data());
                        return tmp.str(dig, f);
                    }

                    inline void negate() {
                        base_data().negate();
                        eval_add(base_data(), mod_data().get_mod().backend());
                    }
                };

                template<class Result, class Backend, typename StorageType>
                constexpr void eval_convert_to(Result *result, const modular_adaptor<Backend, StorageType> &val) {
                    using default_ops::eval_convert_to;
                    eval_convert_to(result, val.base_data());
                }

                template<class Backend, typename StorageType, class T>
                constexpr typename boost::enable_if<boost::is_arithmetic<T>, bool>::type
                    eval_eq(const modular_adaptor<Backend, StorageType> &a, const T &b) {
                    return a.compare(b) == 0;
                }

                template<class Backend1, class Backend2>
                constexpr void eval_redc(Backend1 &result, const modular_params<Backend2> &mod) {
                    mod.reduce(result);
                    eval_modulus(result, mod.get_mod().backend());
                }

                template<class Backend, typename StorageType>
                constexpr void eval_add(modular_adaptor<Backend, StorageType> &result,
                                        const modular_adaptor<Backend, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    using default_ops::eval_lt;

                    eval_add(result.base_data(), o.base_data());
                    if (!eval_lt(result.base_data(), result.mod_data().get_mod())) {
                        eval_subtract(result.base_data(), result.mod_data().get_mod().backend());
                    }
                }

                template<class Backend, typename StorageType>
                constexpr void eval_subtract(modular_adaptor<Backend, StorageType> &result,
                                             const modular_adaptor<Backend, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    using ui_type = typename std::tuple_element<0, typename Backend::unsigned_types>::type;
                    using default_ops::eval_lt;
                    eval_subtract(result.base_data(), o.base_data());
                    if (eval_lt(result.base_data(), ui_type(0u))) {
                        eval_add(result.base_data(), result.mod_data().get_mod().backend());
                    }
                }

                template<unsigned MinBits, unsigned MaxBits, cpp_integer_type SignType, cpp_int_check_type Checked,
                         typename StorageType>
                constexpr void eval_subtract(
                    modular_adaptor<cpp_int_backend<MinBits, MaxBits, SignType, Checked>, StorageType> &result,
                    const modular_adaptor<cpp_int_backend<MinBits, MaxBits, SignType, Checked>, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    using ui_type = typename std::tuple_element<
                        0, typename cpp_int_backend<MinBits, MaxBits, SignType, Checked>::unsigned_types>::type;
                    using default_ops::eval_lt;
#ifndef BOOST_MP_NO_CONSTEXPR_DETECTION
#if BOOST_ARCH_X86_64
                    auto limbs_count = result.base_data().size();
                    if (!BOOST_MP_IS_CONST_EVALUATED(result.base_data().limbs()) &&
                        !is_trivial_cpp_int<cpp_int_backend<MinBits, MaxBits, SignType, Checked>>::value &&
                        result.base_data().size() == o.base_data().size() &&
                        result.base_data().size() == result.mod_data().get_mod().backend().size()) {

                        sub_mod_asm(limbs_count, result.base_data().limbs(), o.base_data().limbs(),
                                    result.mod_data().get_mod().backend().limbs());
                        result.base_data().resize(limbs_count, limbs_count);
                        result.base_data().normalize();
                    } else
#endif
#endif
                    {
                        eval_subtract(result.base_data(), o.base_data());
                        if (eval_lt(result.base_data(), ui_type(0u))) {
                            eval_add(result.base_data(), result.mod_data().get_mod().backend());
                        }
                    }
                }

                template<class Backend, typename StorageType>
                constexpr void eval_multiply(modular_adaptor<Backend, StorageType> &result,
                                             const modular_adaptor<Backend, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    eval_multiply(result.base_data(), o.base_data());
                    eval_redc(result.base_data(), result.mod_data());
                }

                template<class Backend, typename StorageType>
                constexpr void eval_divide(modular_adaptor<Backend, StorageType> &result,
                                           const modular_adaptor<Backend, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    Backend tmp1, tmp2;
                    result.mod_data().adjust_regular(tmp1, result.base_data());
                    result.mod_data().adjust_regular(tmp2, o.base_data());
                    eval_divide(tmp1, tmp2);
                    result.base_data() = tmp1;
                    result.mod_data().adjust_modular(result.base_data());
                    result.mod_data().adjust_regular(tmp2, result.base_data());
                }

                template<class Backend, typename StorageType>
                constexpr void eval_modulus(modular_adaptor<Backend, StorageType> &result,
                                            const modular_adaptor<Backend, StorageType> &o) {
                    BOOST_ASSERT(result.mod_data().get_mod() == o.mod_data().get_mod());
                    Backend tmp1, tmp2;
                    result.mod_data().adjust_regular(tmp1, result.base_data());
                    result.mod_data().adjust_regular(tmp2, o.base_data());
                    eval_modulus(tmp1, tmp2);
                    result.base_data() = tmp1;
                    result.mod_data().adjust_modular(result.base_data());
                    result.mod_data().adjust_regular(tmp2, result.base_data());
                }

                template<class Backend, typename StorageType>
                constexpr bool eval_is_zero(const modular_adaptor<Backend, StorageType> &val)

                    BOOST_NOEXCEPT {
                    using default_ops::eval_is_zero;
                    return eval_is_zero(val.base_data());
                }

                // TODO: check returned value
                template<class Backend, typename StorageType>
                constexpr int eval_get_sign(const modular_adaptor<Backend, StorageType> &) {
                    return 1;
                }

                // TODO: is the function required
                // template <class Result, class Backend>
                // constexpr typename boost::disable_if_c<boost::is_complex<Result>::value>::type
                // eval_convert_to(Result* result, const modular_adaptor<Backend, StateType>& val)
                // {
                //    using default_ops::eval_convert_to;
                //    eval_convert_to(result, val.base_data());
                // }

                template<class Backend, typename StorageType, class T, class V>
                constexpr void assign_components(modular_adaptor<Backend, StorageType> &result, const T &a,
                                                 const V &b) {
                    result.base_data() = a;
                    result.mod_data() = b;
                    result.mod_data().adjust_modular(result.base_data());
                }

                template<class Backend, typename StorageType>
                constexpr void eval_sqrt(modular_adaptor<Backend, StorageType> &result,
                                         const modular_adaptor<Backend, StorageType> &val) {
                    eval_sqrt(result.base_data(), val.base_data());
                }

                template<class Backend, typename StorageType>
                constexpr void eval_abs(modular_adaptor<Backend, StorageType> &result,
                                        const modular_adaptor<Backend, StorageType> &val) {
                    result = val;
                }

                size_t window_bits(size_t exp_bits) {
                    BOOST_STATIC_CONSTEXPR size_t wsize_count = 6;
                    BOOST_STATIC_CONSTEXPR size_t wsize[wsize_count][2] = {{1434, 7}, {539, 6}, {197, 4},
                                                                           {70, 3},   {17, 2},  {0, 0}};

                    size_t window_bits = 1;

                    size_t j = wsize_count - 1;
                    while (wsize[j][0] > exp_bits) {
                        --j;
                    }
                    window_bits += wsize[j][1];

                    return window_bits;
                };

                template<class Backend, typename StorageType>
                inline void find_modular_pow(modular_adaptor<Backend, StorageType> &result,
                                             const modular_adaptor<Backend, StorageType> &b,
                                             const Backend &exp) {
                    using default_ops::eval_bit_set;
                    using default_ops::eval_convert_to;
                    using default_ops::eval_decrement;
                    using default_ops::eval_multiply;

                    typedef number<modular_adaptor<Backend, StorageType>> modular_type;
                    modular_params<Backend> mod = b.mod_data();
                    size_t m_window_bits;
                    unsigned long cur_exp_index;
                    size_t exp_bits = eval_msb(exp);
                    m_window_bits = window_bits(exp_bits + 1);

                    std::vector<modular_type> m_g(1U << m_window_bits);
                    modular_type *p_g = m_g.data();
                    modular_type x(1, mod);
                    Backend nibble = exp;
                    Backend mask;
                    eval_bit_set(mask, m_window_bits);
                    eval_decrement(mask);
                    *p_g = x;
                    ++p_g;
                    *p_g = b;
                    ++p_g;
                    for (size_t i = 2; i < (1U << m_window_bits); i++) {
                        eval_multiply((*p_g).backend(), m_g[i - 1].backend(), b);
                        ++p_g;
                    }
                    size_t exp_nibbles = (exp_bits + 1 + m_window_bits - 1) / m_window_bits;
                    std::vector<size_t> exp_index;

                    for (size_t i = 0; i < exp_nibbles; ++i) {
                        Backend tmp = nibble;
                        eval_bitwise_and(tmp, mask);
                        eval_convert_to(&cur_exp_index, tmp);
                        eval_right_shift(nibble, m_window_bits);
                        exp_index.push_back(cur_exp_index);
                    }

                    x = x * m_g[exp_index[exp_nibbles - 1]];
                    for (size_t i = exp_nibbles - 1; i > 0; --i) {

                        for (size_t j = 0; j != m_window_bits; ++j) {
                            x = x * x;
                        }

                        x = x * m_g[exp_index[i - 1]];
                    }
                    result = x.backend();
                }

                template<class Backend, typename StorageType, typename T>
                constexpr void eval_pow(modular_adaptor<Backend, StorageType> &result,
                                        const modular_adaptor<Backend, StorageType> &b, const T &e) {
                    find_modular_pow(result, b, e);
                }

                template<class Backend, typename StorageType>
                constexpr void eval_pow(modular_adaptor<Backend, StorageType> &result,
                                        const modular_adaptor<Backend, StorageType> &b,
                                        const modular_adaptor<Backend, StorageType> &e) {
                    Backend exp;
                    e.mod_data().adjust_regular(exp, e.base_data());
                    find_modular_pow(result, b, exp);
                }

                template<typename Backend1, typename Backend2, typename T, typename StorageType>
                constexpr void eval_powm(modular_adaptor<Backend1, StorageType> &result,
                                         const modular_adaptor<Backend2, StorageType> &b, const T &e) {
                    eval_pow(result, b, e);
                }

                template<typename Backend1, typename Backend2, typename Backend3, typename StorageType>
                constexpr void eval_powm(modular_adaptor<Backend1, StorageType> &result,
                                         const modular_adaptor<Backend2, StorageType> &b,
                                         const modular_adaptor<Backend3, StorageType> &e) {
                    eval_pow(result, b, e);
                }

                template<class Backend, typename StorageType, class UI>
                constexpr void eval_left_shift(modular_adaptor<Backend, StorageType> &t, UI i) {
                    using default_ops::eval_left_shift;
                    Backend tmp;
                    t.mod_data().adjust_regular(tmp, t.base_data());
                    eval_left_shift(tmp, i);
                    t.base_data() = tmp;
                    t.mod_data().adjust_modular(t.base_data());
                }

                template<class Backend, typename StorageType, class UI>
                constexpr void eval_right_shift(modular_adaptor<Backend, StorageType> &t, UI i) {
                    using default_ops::eval_right_shift;
                    Backend tmp;
                    t.mod_data().adjust_regular(tmp, t.base_data());
                    eval_right_shift(tmp, i);
                    t.base_data() = tmp;
                    t.mod_data().adjust_modular(t.base_data());
                }

                template<class Backend, typename StorageType, class UI>
                constexpr void eval_left_shift(modular_adaptor<Backend, StorageType> &t,
                                               const modular_adaptor<Backend, StorageType> &v, UI i) {
                    using default_ops::eval_left_shift;
                    Backend tmp1, tmp2;
                    t.mod_data().adjust_regular(tmp1, t.base_data());
                    t.mod_data().adjust_regular(tmp2, v.base_data());
                    eval_left_shift(tmp1, tmp2, static_cast<unsigned long>(i));
                    t.base_data() = tmp1;
                    t.mod_data().adjust_modular(t.base_data());
                }

                template<class Backend, typename StorageType, class UI>
                constexpr void eval_right_shift(modular_adaptor<Backend, StorageType> &t,
                                                const modular_adaptor<Backend, StorageType> &v, UI i) {
                    using default_ops::eval_right_shift;
                    Backend tmp1, tmp2;
                    t.mod_data().adjust_regular(tmp1, t.base_data());
                    t.mod_data().adjust_regular(tmp2, v.base_data());
                    eval_right_shift(tmp1, tmp2, static_cast<unsigned long>(i));
                    t.base_data() = tmp1;
                    t.mod_data().adjust_modular(t.base_data());
                }

                template<class Backend, typename StorageType>
                constexpr void eval_bitwise_and(modular_adaptor<Backend, StorageType> &result,
                                                const modular_adaptor<Backend, StorageType> &v) {
                    using default_ops::eval_bitwise_and;
                    BOOST_ASSERT(result.mod_data().get_mod() == v.mod_data().get_mod());

                    Backend tmp1, tmp2;
                    result.mod_data().adjust_regular(tmp1, result.base_data());
                    v.mod_data().adjust_regular(tmp2, v.base_data());
                    eval_bitwise_and(tmp1, tmp1, tmp2);
                    result.base_data() = tmp1;
                    result.mod_data().adjust_modular(result.base_data());
                }

                template<class Backend, typename StorageType>
                constexpr void eval_bitwise_or(modular_adaptor<Backend, StorageType> &result,
                                               const modular_adaptor<Backend, StorageType> &v) {
                    using default_ops::eval_bitwise_or;
                    BOOST_ASSERT(result.mod_data().get_mod() == v.mod_data().get_mod());

                    Backend tmp1, tmp2;
                    result.mod_data().adjust_regular(tmp1, result.base_data());
                    v.mod_data().adjust_regular(tmp2, v.base_data());
                    eval_bitwise_or(tmp1, tmp1, tmp2);
                    result.base_data() = tmp1;
                    result.mod_data().adjust_modular(result.base_data());
                }

                template<class Backend, typename StorageType>
                constexpr void eval_bitwise_xor(modular_adaptor<Backend, StorageType> &result,
                                                const modular_adaptor<Backend, StorageType> &v) {
                    using default_ops::eval_bitwise_xor;
                    BOOST_ASSERT(result.mod_data().get_mod() == v.mod_data().get_mod());

                    Backend tmp1, tmp2;
                    result.mod_data().adjust_regular(tmp1, result.base_data());
                    v.mod_data().adjust_regular(tmp2, v.base_data());
                    eval_bitwise_xor(tmp1, tmp1, tmp2);
                    result.base_data() = tmp1;
                    result.mod_data().adjust_modular(result.base_data());
                }

                template<typename Backend, typename StorageType>
                constexpr int eval_msb(const modular_adaptor<Backend, StorageType> &m) {
                    using default_ops::eval_msb;
                    Backend tmp;
                    m.mod_data().adjust_regular(tmp, m.base_data());
                    return eval_msb(tmp);
                }

                template<typename Backend, typename StorageType>
                constexpr unsigned eval_lsb(const modular_adaptor<Backend, StorageType> &m) {
                    using default_ops::eval_lsb;
                    Backend tmp;
                    m.mod_data().adjust_regular(tmp, m.base_data());
                    return eval_lsb(tmp);
                }

                template<typename Backend, typename StorageType>
                constexpr bool eval_bit_test(const modular_adaptor<Backend, StorageType> &m, unsigned index) {
                    using default_ops::eval_bit_test;
                    Backend tmp;
                    m.mod_data().adjust_regular(tmp, m.base_data());
                    return eval_bit_test(tmp, index);
                }

                template<typename Backend, typename StorageType>
                constexpr void eval_bit_set(modular_adaptor<Backend, StorageType> &result, unsigned index) {
                    using default_ops::eval_bit_set;
                    Backend tmp;
                    result.mod_data().adjust_regular(tmp, result.base_data());
                    eval_bit_set(tmp, index);
                    result.mod_data().adjust_modular(result.base_data(), tmp);
                }

                template<typename Backend, typename StorageType>
                constexpr void eval_bit_unset(modular_adaptor<Backend, StorageType> &result, unsigned index) {
                    using default_ops::eval_bit_unset;
                    Backend tmp;
                    result.mod_data().adjust_regular(tmp, result.base_data());
                    eval_bit_unset(tmp, index);
                    result.mod_data().adjust_modular(result.base_data(), tmp);
                }

                template<typename Backend, typename StorageType>
                constexpr void eval_bit_flip(modular_adaptor<Backend, StorageType> &result, unsigned index) {
                    using default_ops::eval_bit_flip;
                    Backend tmp;
                    result.mod_data().adjust_regular(tmp, result.base_data());
                    eval_bit_flip(tmp, index);
                    result.mod_data().adjust_modular(result.base_data(), tmp);
                }

                template<typename Backend, typename StorageType>
                constexpr modular_adaptor<Backend, StorageType>
                    eval_ressol(const modular_adaptor<Backend, StorageType> &input) {

                    number<Backend> new_base, res;
                    number<modular_adaptor<Backend, StorageType>> res_mod;

                    input.mod_data().adjust_regular(new_base.backend(), input.base_data());
                    res = eval_ressol(new_base.backend(), input.mod_data().get_mod().backend());
                    assign_components(res_mod.backend(), res.backend(), input.mod_data().get_mod().backend());

                    return res_mod.backend();
                }

                template<typename Backend, typename StorageType>
                constexpr void eval_inverse_mod(modular_adaptor<Backend, StorageType> &result,
                                                const modular_adaptor<Backend, StorageType> &input) {
                    Backend new_base, res;

                    input.mod_data().adjust_regular(new_base, input.base_data());
                    eval_inverse_mod(res, new_base, input.mod_data().get_mod().backend());
                    assign_components(result, res, input.mod_data().get_mod().backend());
                }

                template<typename Backend, typename StorageType>
                inline std::size_t hash_value(const modular_adaptor<Backend, StorageType>& val) {
                    return hash_value(val.base_data());
                }

            }    // namespace backends

            using nil::crypto3::multiprecision::backends::modular_adaptor;

            template<class Backend, typename StorageType>
            struct number_category<modular_adaptor<Backend, StorageType>>
                : public std::integral_constant<int, nil::crypto3::multiprecision::number_kind_modular> { };

            template<class Backend, typename StorageType, expression_template_option ExpressionTemplates>
            struct component_type<number<modular_adaptor<Backend, StorageType>, ExpressionTemplates>> {
                typedef number<Backend, ExpressionTemplates> type;
            };

            template<class T>
            struct is_modular_number : public std::integral_constant<bool, false> { };

            template<class Backend, typename StorageType, expression_template_option ExpressionTemplates>
            struct is_modular_number<number<backends::modular_adaptor<Backend, StorageType>, ExpressionTemplates>>
                : public std::integral_constant<bool, true> { };
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif
