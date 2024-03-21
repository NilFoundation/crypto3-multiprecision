
#ifndef CRYPTO3_MP_DETAIL_INTEGER_OPS_HPP
#define CRYPTO3_MP_DETAIL_INTEGER_OPS_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/detail/no_exceptions_support.hpp>

namespace boost { namespace multiprecision {

// Only for our modular numbers function powm takes 2 arguments,
// so we need to add this specialization.
template<class Backend, class modular_params_type, class U>
inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
    detail::is_backend<Backend>::value && is_integral<U>::value,
    number<nil::crypto3::multiprecision::backends::modular_adaptor<Backend, modular_params_type>>>::type powm(
        const number<nil::crypto3::multiprecision::backends::modular_adaptor<Backend, modular_params_type>>& b, const U& p) {

    // We will directly call eval_powm here, that's what a call through a default_ops::powm_func would do if expression tempaltes are off. We don't want to change that structure.
    nil::crypto3::multiprecision::backends::modular_adaptor<Backend, modular_params_type> result;
    nil::crypto3::multiprecision::backends::eval_powm(result, b.backend(), p); 
    return result;
}

template<class Backend, class modular_params_type, class U>
inline BOOST_MP_CXX14_CONSTEXPR typename std::enable_if<
    (detail::is_backend<Backend>::value && (is_number<U>::value || is_number_expression<U>::value)),
    number<nil::crypto3::multiprecision::backends::modular_adaptor<Backend, modular_params_type>>>::type powm(
        const number<nil::crypto3::multiprecision::backends::modular_adaptor<Backend, modular_params_type>>& b, const U& p) {

    // We will directly call eval_powm here, that's what a call through a default_ops::powm_func would do if expression tempaltes are off. We don't want to change that structure.
    nil::crypto3::multiprecision::backends::modular_adaptor<Backend, modular_params_type> result;
    nil::crypto3::multiprecision::backends::eval_powm(result, b.backend(), p.backend()); 
    return result;
}
}} // namespace boost::multiprecision

#endif // CRYPTO3_MP_DETAIL_INTEGER_OPS_HPP
