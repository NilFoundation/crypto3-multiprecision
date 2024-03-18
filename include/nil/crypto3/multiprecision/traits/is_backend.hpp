///////////////////////////////////////////////////////////////////////////////
//  Copyright 2015 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef CRYPTO3_MP_IS_BACKEND_HPP
#define CRYPTO3_MP_IS_BACKEND_HPP

#include <type_traits>
#include <boost/multiprecision/detail/number_base.hpp>

namespace boost { namespace multiprecision { namespace detail {

// Even though cpp_int_modular_backend doesn't have signed and floating point types, still make boost consider
// it a backend.
template<unsigned Bits>
struct is_backend<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>> {
   static constexpr bool value = true;
};

}
}
} // namespace boost::multiprecision::detail

#endif // CRYPTO3_MP_IS_BACKEND_HPP
