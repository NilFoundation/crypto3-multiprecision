///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>

#include "test_arithmetic.hpp"

template<unsigned D>
struct related_type<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_dec_float<D>>> {
    typedef nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_dec_float<D / 2>> type;
};

int main() {
    test<nil::crypto3::multiprecision::cpp_dec_float_50>();
    return boost::report_errors();
}
