//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MP_CPP_MODULAR_HPP
#define BOOST_MP_CPP_MODULAR_HPP

#include <nil/crypto3/multiprecision/modular/modular_params.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            // mnt params
            // TODO(martun): verify that 0 was actually the right parameter here.
            typedef modular_params<cpp_int_modular_backend<0>> cpp_mod_params;

            // Fixed precision unsigned types:
            typedef modular_params<cpp_int_modular_backend<64>> umod_params_params64_t;
            typedef modular_params<cpp_int_modular_backend<128>> umod_params_params128_t;
            typedef modular_params<cpp_int_modular_backend<256>> umod_params256_t;
            typedef modular_params<cpp_int_modular_backend<512>> umod_params512_t;
            typedef modular_params<cpp_int_modular_backend<1024>> umod_params1024_t;

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif
