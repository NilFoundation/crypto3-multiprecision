///////////////////////////////////////////////////////////////
//  Copyright 2015 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifndef CRYPTO3_MP_CPP_INT_IMPORT_EXPORT_HPP
#define CRYPTO3_MP_CPP_INT_IMPORT_EXPORT_HPP

#include <climits>
#include <cstring>

#include <boost/multiprecision/traits/std_integer_traits.hpp>
#include <boost/multiprecision/detail/endian.hpp>

// TODO(martun): consider removing this code, just use cpp_int and convert to cpp_int_modular.
namespace boost {
    namespace multiprecision {
        namespace detail {

            template<std::size_t Bits, expression_template_option ExpressionTemplates, class Iterator>
            number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&
            import_bits_generic(
                number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, 
                ExpressionTemplates>& val, Iterator i, Iterator j, std::size_t chunk_size = 0, bool msv_first = true)
            {
               typename number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>::backend_type newval;
            
               using value_type = typename std::iterator_traits<Iterator>::value_type;
               using unsigned_value_type = typename ::boost::multiprecision::detail::make_unsigned<value_type>::type;
               using difference_type = typename std::iterator_traits<Iterator>::difference_type;
               using size_type = typename ::boost::multiprecision::detail::make_unsigned<difference_type>::type;
               using tag_type = typename nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>::trivial_tag;
            
               if (!chunk_size)
                  chunk_size = std::numeric_limits<value_type>::digits;
            
               size_type limbs = std::distance(i, j);
               size_type bits  = limbs * chunk_size;
               BOOST_ASSERT(bits <= Bits);
            
               difference_type bit_location        = msv_first ? bits - chunk_size : 0;
               difference_type bit_location_change = msv_first ? -static_cast<difference_type>(chunk_size) : chunk_size;
            
               while (i != j)
               {
                  assign_bits(
                    newval, *i,
                    static_cast<std::size_t>(bit_location), chunk_size, tag_type());
                  ++i;
                  bit_location += bit_location_change;
               }
            
               newval.normalize();
            
               val.backend().swap(newval);
               return val;
            }
            
            template <std::size_t Bits, expression_template_option ExpressionTemplates, class T>
            inline typename std::enable_if<!nil::crypto3::multiprecision::backends::is_trivial_cpp_int_modular<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits> >::value, number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&>::type
            import_bits_fast(
                number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>& val, T* i, T* j, std::size_t chunk_size = 0)
            {
               std::size_t byte_len = (j - i) * (chunk_size ? chunk_size / CHAR_BIT : sizeof(*i));
               std::size_t limb_len = byte_len / sizeof(limb_type);
               if (byte_len % sizeof(limb_type))
                  ++limb_len;
               nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>& result = val.backend();
               result.resize(static_cast<unsigned>(limb_len), static_cast<unsigned>(limb_len)); // checked types may throw here if they're not large enough to hold the data!
               result.limbs()[result.size() - 1] = 0u;
               std::memcpy(result.limbs(), i, (std::min)(byte_len, result.size() * sizeof(limb_type)));
               result.normalize(); // In case data has leading zeros.
               return val;
            }

            template <std::size_t Bits, expression_template_option ExpressionTemplates, class T>
            inline typename std::enable_if<nil::crypto3::multiprecision::backends::is_trivial_cpp_int_modular<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits> >::value, number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&>::type
            import_bits_fast(
                number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>& val, T* i, T* j, std::size_t chunk_size = 0)
            {
               nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>& result   = val.backend();
               std::size_t byte_len = (j - i) * (chunk_size ? chunk_size / CHAR_BIT : sizeof(*i));
               std::size_t limb_len = byte_len / sizeof(result.limbs()[0]);
               if (byte_len % sizeof(result.limbs()[0]))
                  ++limb_len;
               result.limbs()[0] = 0u;
               result.resize(static_cast<unsigned>(limb_len), static_cast<unsigned>(limb_len)); // checked types may throw here if they're not large enough to hold the data!
               std::memcpy(result.limbs(), i, (std::min)(byte_len, result.size() * sizeof(result.limbs()[0])));
               result.normalize(); // In case data has leading zeros.
               return val;
            }
        } // namespace detail
            
        template <std::size_t Bits, expression_template_option ExpressionTemplates, class Iterator>
        inline number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&
        import_bits(
            number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>& val, Iterator i, Iterator j, std::size_t chunk_size = 0, bool msv_first = true)
        {
           return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
        }
        
        template <std::size_t Bits, expression_template_option ExpressionTemplates, class T>
        inline number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>&
        import_bits(
            number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, 
            ExpressionTemplates>& val,
            T* i, T* j, std::size_t chunk_size = 0, bool msv_first = true)
        {
        #if CRYPTO3_MP_ENDIAN_LITTLE_BYTE
           if (((chunk_size % CHAR_BIT) == 0) && !msv_first && (sizeof(*i) * CHAR_BIT == chunk_size))
              return detail::import_bits_fast(val, i, j, chunk_size);
        #endif
           return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
        }
            
        template <std::size_t Bits, expression_template_option ExpressionTemplates,
            class OutputIterator>
        OutputIterator export_bits(
            const number<nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>, ExpressionTemplates>& val,
                OutputIterator out, std::size_t chunk_size, bool msv_first = true)
        {
        #ifdef BOOST_MSVC
        #pragma warning(push)
        #pragma warning(disable : 4244)
        #endif
           using tag_type = typename nil::crypto3::multiprecision::backends::cpp_int_modular_backend<Bits>::trivial_tag;
           if (!val)
           {
              *out = 0;
              ++out;
              return out;
           }
           std::size_t bitcount = eval_msb_imp(val.backend()) + 1;
        
           std::ptrdiff_t bit_location = msv_first ? static_cast<std::ptrdiff_t>(bitcount - chunk_size) : 0;
           const std::ptrdiff_t bit_step     = msv_first ? static_cast<std::ptrdiff_t>(-static_cast<std::ptrdiff_t>(chunk_size)) : static_cast<std::ptrdiff_t>(chunk_size);
           while (bit_location % bit_step)
              ++bit_location;
           do
           {
              *out = extract_bits(val.backend(), bit_location, chunk_size, tag_type());
              ++out;
              bit_location += bit_step;
           } while ((bit_location >= 0) && (bit_location < static_cast<int>(bitcount)));
        
           return out;
        #ifdef BOOST_MSVC
        #pragma warning(pop)
        #endif
        }
    }    // namespace multiprecision
}    // namespace boost

#endif // CRYPTO3_MP_CPP_INT_IMPORT_EXPORT_HPP
