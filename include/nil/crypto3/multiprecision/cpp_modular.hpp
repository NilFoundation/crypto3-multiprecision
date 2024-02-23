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
#include <nil/crypto3/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            // mnt params
            typedef modular_params<cpp_int_backend<>> cpp_mod_params;

            // Fixed precision unsigned types:
            typedef modular_params<cpp_int_backend<64, 64, unsigned_magnitude, unchecked, void>>
                umod_params_params64_t;
            typedef modular_params<cpp_int_backend<128, 128, unsigned_magnitude, unchecked, void>>
                umod_params_params128_t;
            typedef modular_params<cpp_int_backend<256, 256, unsigned_magnitude, unchecked, void>> umod_params256_t;
            typedef modular_params<cpp_int_backend<512, 512, unsigned_magnitude, unchecked, void>> umod_params512_t;
            typedef modular_params<cpp_int_backend<1024, 1024, unsigned_magnitude, unchecked, void>> umod_params1024_t;

            // Fixed precision signed types:
            typedef modular_params<cpp_int_backend<128, 128, signed_magnitude, unchecked, void>> mod_params128_t;
            typedef modular_params<cpp_int_backend<256, 256, signed_magnitude, unchecked, void>> mod_params256_t;
            typedef modular_params<cpp_int_backend<512, 512, signed_magnitude, unchecked, void>> mod_params512_t;
            typedef modular_params<cpp_int_backend<1024, 1024, signed_magnitude, unchecked, void>> mod_params1024_t;

            // Over again, but with checking enabled this time:
            typedef modular_params<cpp_int_backend<0, 0, signed_magnitude, checked>> checked_cpp_mod_params;

            // Fixed precision unsigned types:
            typedef modular_params<cpp_int_backend<128, 128, unsigned_magnitude, checked, void>>
                checked_umod_params128_t;
            typedef modular_params<cpp_int_backend<256, 256, unsigned_magnitude, checked, void>>
                checked_umod_params256_t;
            typedef modular_params<cpp_int_backend<512, 512, unsigned_magnitude, checked, void>>
                checked_umod_params512_t;
            typedef modular_params<cpp_int_backend<1024, 1024, unsigned_magnitude, checked, void>>
                checked_umod_params1024_t;

            // Fixed precision signed types:
            typedef modular_params<cpp_int_backend<128, 128, signed_magnitude, checked, void>> checked_mod_params128_t;
            typedef modular_params<cpp_int_backend<256, 256, signed_magnitude, checked, void>> checked_mod_params256_t;
            typedef modular_params<cpp_int_backend<512, 512, signed_magnitude, checked, void>> checked_mod_params512_t;
            typedef modular_params<cpp_int_backend<1024, 1024, signed_magnitude, checked, void>>
                checked_mod_params1024_t;

            // mod_paramsular_adapter
            typedef number<modular_adaptor<cpp_int_backend<>, backends::modular_params_rt<cpp_int_backend<>>>> cpp_mod;

            // Fixed precision unsigned types:
            typedef number<modular_adaptor<cpp_int_backend<128, 128, unsigned_magnitude, unchecked, void>, backends::modular_params_rt<cpp_int_backend<>>>> umod128_t;
            typedef number<modular_adaptor<cpp_int_backend<256, 256, unsigned_magnitude, unchecked, void>, backends::modular_params_rt<cpp_int_backend<>>>> umod256_t;
            typedef number<modular_adaptor<cpp_int_backend<512, 512, unsigned_magnitude, unchecked, void>, backends::modular_params_rt<cpp_int_backend<>>>> umod512_t;
            typedef number<modular_adaptor<cpp_int_backend<1024, 1024, unsigned_magnitude, unchecked, void>, backends::modular_params_rt<cpp_int_backend<>>>>
                umod1024_t;

            // Fixed precision signed types:
            typedef number<modular_adaptor<cpp_int_backend<128, 128, signed_magnitude, unchecked, void>, backends::modular_params_rt<cpp_int_backend<>>>> mod128_t;
            typedef number<modular_adaptor<cpp_int_backend<256, 256, signed_magnitude, unchecked, void>, backends::modular_params_rt<cpp_int_backend<>>>> mod256_t;
            typedef number<modular_adaptor<cpp_int_backend<512, 512, signed_magnitude, unchecked, void>, backends::modular_params_rt<cpp_int_backend<>>>> mod512_t;
            typedef number<modular_adaptor<cpp_int_backend<1024, 1024, signed_magnitude, unchecked, void>, backends::modular_params_rt<cpp_int_backend<>>>> mod1024_t;

            // Over again, but with checking enabled this time:
            typedef number<modular_adaptor<cpp_int_backend<0, 0, signed_magnitude, checked>, backends::modular_params_rt<cpp_int_backend<>>>> checked_cpp_mod;

            // Fixed precision unsigned types:
            typedef number<modular_adaptor<cpp_int_backend<128, 128, unsigned_magnitude, checked, void>, backends::modular_params_rt<cpp_int_backend<>>>>
                checked_umod128_t;
            typedef number<modular_adaptor<cpp_int_backend<256, 256, unsigned_magnitude, checked, void>, backends::modular_params_rt<cpp_int_backend<>>>>
                checked_umod256_t;
            typedef number<modular_adaptor<cpp_int_backend<512, 512, unsigned_magnitude, checked, void>, backends::modular_params_rt<cpp_int_backend<>>>>
                checked_umod512_t;
            typedef number<modular_adaptor<cpp_int_backend<1024, 1024, unsigned_magnitude, checked, void>, backends::modular_params_rt<cpp_int_backend<>>>>
                checked_umod1024_t;

            // Fixed precision signed types:
            typedef number<modular_adaptor<cpp_int_backend<128, 128, signed_magnitude, checked, void>, backends::modular_params_rt<cpp_int_backend<>>>>
                checked_mod128_t;
            typedef number<modular_adaptor<cpp_int_backend<256, 256, signed_magnitude, checked, void>, backends::modular_params_rt<cpp_int_backend<>>>>
                checked_mod256_t;
            typedef number<modular_adaptor<cpp_int_backend<512, 512, signed_magnitude, checked, void>, backends::modular_params_rt<cpp_int_backend<>>>>
                checked_mod512_t;
            typedef number<modular_adaptor<cpp_int_backend<1024, 1024, signed_magnitude, checked, void>, backends::modular_params_rt<cpp_int_backend<>>>>
                checked_mod1024_t;

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif
