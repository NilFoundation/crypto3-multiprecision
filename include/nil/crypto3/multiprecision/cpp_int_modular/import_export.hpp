///////////////////////////////////////////////////////////////
//  Copyright 2015 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifndef CRYPTO3_MP_CPP_INT_IMPORT_EXPORT_HPP
#define CRYPTO3_MP_CPP_INT_IMPORT_EXPORT_HPP

#include <climits>
#include <cstring>

#include <boost/multiprecision/detail/endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace bmp = boost::multiprecision;
            using namespace backends;

            namespace detail {
                
                template <class Backend, class Unsigned>
                void assign_bits(Backend& val, Unsigned bits, std::size_t bit_location,
                                 std::size_t chunk_bits, const std::integral_constant<bool, false>& tag)
                {
                   std::size_t limb  = bit_location / (sizeof(limb_type) * CHAR_BIT);
                   std::size_t shift = bit_location % (sizeof(limb_type) * CHAR_BIT);
                
                   limb_type mask = chunk_bits >= sizeof(limb_type) * CHAR_BIT ? ~static_cast<limb_type>(0u) : (static_cast<limb_type>(1u) << chunk_bits) - 1;
                
                   limb_type value = static_cast<limb_type>(bits & mask) << shift;
                   if (value)
                   {
                      if (val.size() == limb)
                      {
                         val.resize(limb + 1, limb + 1);
                         if (val.size() > limb)
                            val.limbs()[limb] = value;
                      }
                      else if (val.size() > limb)
                         val.limbs()[limb] |= value;
                   }
                   if (chunk_bits > sizeof(limb_type) * CHAR_BIT - shift)
                   {
                      shift = sizeof(limb_type) * CHAR_BIT - shift;
                      chunk_bits -= shift;
                      bit_location += shift;
                      bits >>= shift;
                      if (bits)
                         assign_bits(val, bits, bit_location, chunk_bits, tag);
                   }
                }

                template <class Backend, class Unsigned>
                void assign_bits(Backend& val, Unsigned bits, std::size_t bit_location,
                                 std::size_t chunk_bits, const std::integral_constant<bool, true>&)
                {
                   using local_limb_type = typename Backend::local_limb_type;
                   //
                   // Check for possible overflow, this may trigger an exception, or have no effect
                   // depending on whether this is a checked integer or not:
                   //
                   if ((bit_location >= sizeof(local_limb_type) * CHAR_BIT) && bits)
                      val.resize(2, 2);
                   else
                   {
                      local_limb_type mask  = chunk_bits >= sizeof(local_limb_type) * CHAR_BIT ? 
                        ~static_cast<local_limb_type>(0u) : 
                        (static_cast<local_limb_type>(1u) << chunk_bits) - 1;
                      local_limb_type value = (static_cast<local_limb_type>(bits) & mask) << bit_location;
                      *val.limbs() |= value;
                      //
                      // Check for overflow bits:
                      //
                      bit_location = sizeof(local_limb_type) * CHAR_BIT - bit_location;
                      if ((bit_location < sizeof(bits) * CHAR_BIT) && (bits >>= bit_location))
                         val.resize(2, 2); // May throw!
                   }
                }
                template<std::size_t Bits, boost::multiprecision::expression_template_option ExpressionTemplates, class Iterator>
                bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>&
                import_bits_generic(
                    bmp::number<cpp_int_modular_backend<Bits>, 
                    ExpressionTemplates>& val, Iterator i, Iterator j, std::size_t chunk_size = 0, bool msv_first = true)
                {
                   typename bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>::backend_type newval;
                
                   using value_type = typename std::iterator_traits<Iterator>::value_type;
                   using unsigned_value_type = typename boost::multiprecision::detail::make_unsigned<value_type>::type;
                   using difference_type = typename std::iterator_traits<Iterator>::difference_type;
                   using size_type = typename boost::multiprecision::detail::make_unsigned<difference_type>::type;
                   using tag_type = typename cpp_int_modular_backend<Bits>::trivial_tag;
                
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
                        newval, static_cast<unsigned_value_type>(*i),
                        static_cast<std::size_t>(bit_location), chunk_size, tag_type());
                      ++i;
                      bit_location += bit_location_change;
                   }
                
                   newval.normalize();
                
                   val.backend().swap(newval);
                   return val;
                }
                
                template <std::size_t Bits, boost::multiprecision::expression_template_option ExpressionTemplates, class T>
                inline typename std::enable_if<!is_trivial_cpp_int<cpp_int_modular_backend<Bits> >::value, bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>&>::type
                import_bits_fast(
                    bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>& val, T* i, T* j, std::size_t chunk_size = 0)
                {
                   std::size_t byte_len = (j - i) * (chunk_size ? chunk_size / CHAR_BIT : sizeof(*i));
                   std::size_t limb_len = byte_len / sizeof(limb_type);
                   if (byte_len % sizeof(limb_type))
                      ++limb_len;
                   cpp_int_modular_backend<Bits>& result = val.backend();
                   result.resize(static_cast<unsigned>(limb_len), static_cast<unsigned>(limb_len)); // checked types may throw here if they're not large enough to hold the data!
                   result.limbs()[result.size() - 1] = 0u;
                   std::memcpy(result.limbs(), i, (std::min)(byte_len, result.size() * sizeof(limb_type)));
                   result.normalize(); // In case data has leading zeros.
                   return val;
                }

                template <std::size_t Bits, boost::multiprecision::expression_template_option ExpressionTemplates, class T>
                inline typename std::enable_if<is_trivial_cpp_int<cpp_int_modular_backend<Bits> >::value, bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>&>::type
                import_bits_fast(
                    bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>& val, T* i, T* j, std::size_t chunk_size = 0)
                {
                   cpp_int_modular_backend<Bits>& result   = val.backend();
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
                
            template <std::size_t Bits, boost::multiprecision::expression_template_option ExpressionTemplates, class Iterator>
            inline bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>&
            import_bits(
                bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>& val, Iterator i, Iterator j, std::size_t chunk_size = 0, bool msv_first = true)
            {
               return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
            }
            
            template <std::size_t Bits, boost::multiprecision::expression_template_option ExpressionTemplates, class T>
            inline bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>&
            import_bits(
                bmp::number<cpp_int_modular_backend<Bits>, 
                ExpressionTemplates>& val,
                T* i, T* j, std::size_t chunk_size = 0, bool msv_first = true)
            {
            #if CRYPTO3_MP_ENDIAN_LITTLE_BYTE
               if (((chunk_size % CHAR_BIT) == 0) && !msv_first && (sizeof(*i) * CHAR_BIT == chunk_size))
                  return detail::import_bits_fast(val, i, j, chunk_size);
            #endif
               return detail::import_bits_generic(val, i, j, chunk_size, msv_first);
            }
                
            template <std::size_t Bits, boost::multiprecision::expression_template_option ExpressionTemplates,
                class OutputIterator>
            OutputIterator export_bits(
                const bmp::number<cpp_int_modular_backend<Bits>, ExpressionTemplates>& val,
                    OutputIterator out, std::size_t chunk_size, bool msv_first = true)
            {
            #ifdef BOOST_MSVC
            #pragma warning(push)
            #pragma warning(disable : 4244)
            #endif
               using tag_type = typename cpp_int_modular_backend<Bits>::trivial_tag;
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
    }        // namespace crypto3
}    // namespace nil

#endif // CRYPTO3_MP_CPP_INT_IMPORT_EXPORT_HPP
