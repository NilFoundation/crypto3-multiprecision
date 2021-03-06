///////////////////////////////////////////////////////////////
//  Copyright 2015 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <boost/detail/lightweight_test.hpp>
#include <boost/array.hpp>
#include "test.hpp"

#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>
#include <boost/math/constants/constants.hpp>

int main() {
    using namespace nil::crypto3::multiprecision;

    BOOST_STATIC_ASSERT((boost::is_convertible<float, cpp_bin_float_single>::value));
    BOOST_STATIC_ASSERT(!(boost::is_convertible<double, cpp_bin_float_single>::value));
    BOOST_STATIC_ASSERT(!(boost::is_convertible<long double, cpp_bin_float_single>::value));

    cpp_bin_float_single s = boost::math::constants::pi<cpp_bin_float_single>();
    std::cout << s << std::endl;

    typedef number<backends::cpp_bin_float<11, backends::digit_base_2, void, boost::int8_t, -14, 15>, et_off>
        cpp_bin_float_half;

    BOOST_STATIC_ASSERT(!(boost::is_convertible<float, cpp_bin_float_half>::value));
    BOOST_STATIC_ASSERT(!(boost::is_convertible<double, cpp_bin_float_half>::value));
    BOOST_STATIC_ASSERT(!(boost::is_convertible<long double, cpp_bin_float_half>::value));
#ifdef BOOST_HAS_FLOAT128
    BOOST_STATIC_ASSERT(!(boost::is_convertible<__float128, cpp_bin_float_half>::value));
#endif

    cpp_bin_float_half hs = boost::math::constants::pi<cpp_bin_float_half>();
    std::cout << hs << std::endl;

    return boost::report_errors();
}
