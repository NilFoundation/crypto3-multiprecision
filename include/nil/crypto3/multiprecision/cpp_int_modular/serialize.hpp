///////////////////////////////////////////////////////////////
//  Copyright 2013 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifndef CRYPTO3_MP_CPP_INT_SERIALIZE_HPP
#define CRYPTO3_MP_CPP_INT_SERIALIZE_HPP

namespace boost {

    namespace archive {

        class binary_oarchive;
        class binary_iarchive;

    }    // namespace archive

    namespace serialization {

        template<class Archive, unsigned Bits>
        void serialize(Archive& ar, nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>& val,
                       const unsigned int /*version*/) {
            using archive_save_tag = typename Archive::is_saving;
            using save_tag = std::integral_constant<bool, archive_save_tag::value>;
            using trivial_tag = std::integral_constant<bool, 
                nil::crypto3::multiprecision::backends::is_trivial_cpp_int_modular<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>>::value>;
            using binary_tag = typename cpp_int_detail::is_binary_archive<Archive>::type;

            // Just dispatch to the correct method:
            cpp_int_detail::do_serialize(ar, val, save_tag(), trivial_tag(), binary_tag());
        }
    }    // namespace serialization
}    // namespace boost

#endif    // CRYPTO3_MP_CPP_INT_SERIALIZE_HPP
