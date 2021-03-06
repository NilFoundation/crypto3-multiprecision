///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <nil/crypto3/multiprecision/debug_adaptor.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include "test_arithmetic.hpp"

int main() {
    test<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::debug_adaptor<nil::crypto3::multiprecision::cpp_int_backend<>>>>();
    return boost::report_errors();
}
