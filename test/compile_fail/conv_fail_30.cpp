///////////////////////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#include <nil/crypto3/multiprecision/cpp_int.hpp>

using namespace nil::crypto3::multiprecision;

int main() {
    cpp_int i(3), j;
    j = 3.3 + i;
}
