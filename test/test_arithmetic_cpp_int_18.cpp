///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include "test_arithmetic.hpp"

template<unsigned MinBits, unsigned MaxBits, nil::crypto3::multiprecision::cpp_integer_type SignType, class Allocator,
         nil::crypto3::multiprecision::expression_template_option ET>
struct is_checked_cpp_int<nil::crypto3::multiprecision::number<
    nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType, nil::crypto3::multiprecision::checked,
                                                  Allocator>,
    ET>> : public std::integral_constant<bool, true> { };

template<unsigned MinBits, unsigned MaxBits, nil::crypto3::multiprecision::cpp_integer_type SignType, class Allocator,
         nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
struct is_twos_complement_integer<nil::crypto3::multiprecision::number<
    nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType, nil::crypto3::multiprecision::checked,
                                                  Allocator>,
    ExpressionTemplates>> : public std::integral_constant<bool, false> { };

template<>
struct related_type<nil::crypto3::multiprecision::cpp_int> {
    typedef nil::crypto3::multiprecision::int256_t type;
};
template<unsigned MinBits, unsigned MaxBits, nil::crypto3::multiprecision::cpp_integer_type SignType,
         nil::crypto3::multiprecision::cpp_int_check_type Checked, class Allocator,
         nil::crypto3::multiprecision::expression_template_option ET>
struct related_type<nil::crypto3::multiprecision::number<
    nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType, Checked, Allocator>, ET>> {
    typedef nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_int_backend<MinBits / 2, MaxBits / 2, SignType, Checked, Allocator>, ET>
        type;
};

int main() {
    test<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_int_backend<
        31, 31, nil::crypto3::multiprecision::signed_magnitude, nil::crypto3::multiprecision::checked, void>>>();
    return boost::report_errors();
}
