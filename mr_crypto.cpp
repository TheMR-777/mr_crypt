#include <range/v3/view.hpp>
#include <openssl/evp.h>
#include <random>
#include <ranges>
#include <print>

namespace mr_crypt
{
	namespace rg = ranges;
	namespace vs = rg::views;
	using byte_t = std::uint8_t;
	using view_t = std::string_view;

	namespace details
	{
		namespace convert
		{
			static constexpr auto base64_table = std::string_view{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
			static constexpr auto my_hex_table = std::string_view{ "0123456789abcdef" };
			static constexpr auto m_padding = '=';

			auto to_base64(view_t input) noexcept
			{
				auto const o_size = ((4 * input.size() / 3) + 3) & ~3;
				auto output = std::string(o_size, '=');
				auto it_out = output.begin();

				for (size_t i = 0; i < input.size(); i += 3)
				{
					// Get the three bytes as an unsigned integer
					auto group = static_cast<byte_t>(input[i]) << 16;
					if (i + 1 < input.size())
					{
						group |= static_cast<byte_t>(input[i + 1]) << 8;
					}
					if (i + 2 < input.size())
					{
						group |= static_cast<byte_t>(input[i + 2]);
					}

					// Encode the four base64 characters from the group
					*it_out++ = base64_table[(group >> 18) & 0x3F];
					*it_out++ = base64_table[(group >> 12) & 0x3F];
					if (i + 1 < input.size())
					{
						*it_out++ = base64_table[(group >> 6) & 0x3F];
					}
					if (i + 2 < input.size())
					{
						*it_out++ = base64_table[group & 0x3F];
					}
				}

				return output;
			}

			auto to_hex(view_t data) noexcept
			{
				auto result = std::string(data.size() * 2, '\0');
				auto it_res = result.begin();

				for (byte_t const b : data)
				{
					*it_res++ = my_hex_table[b >> 4];
					*it_res++ = my_hex_table[b & 0x0F];
				}

				return result;
			}
		}

		template <std::string(*just_fun)(view_t)>
		struct adapter_base_f : std::ranges::range_adaptor_closure<adapter_base_f<just_fun>>
		{
			auto operator()(view_t input) const noexcept
			{
				return just_fun(input);
			}
		};

		constexpr auto cipher_final_size(const size_t in_size, const int block_size) noexcept
		{
			return ((in_size + block_size - 1) / block_size) * block_size;
		}

		template <const EVP_MD* (*evp_x)()>
		auto hash(view_t input) noexcept
		{
			auto digest = evp_x();
			auto output = std::string(EVP_MD_get_size(digest), '\0');
			EVP_Digest(input.data(), input.size(), reinterpret_cast<byte_t*>(output.data()), nullptr, digest, nullptr);
			return output;
		}

		template <const EVP_CIPHER* (*evp_cipher_x)(), bool to_encrypt>
		auto cipher(view_t input, view_t key, view_t iv) noexcept
		{
			auto mode_c = evp_cipher_x();
			auto output = std::string(cipher_final_size(input.size(), EVP_CIPHER_block_size(mode_c)), '\0');
			auto it_out = reinterpret_cast<byte_t*>(output.data());
			auto size_i = int{};
			auto size_f = int{};
			{
				constexpr auto init = to_encrypt ? EVP_EncryptInit : EVP_DecryptInit;
				constexpr auto ping = to_encrypt ? EVP_EncryptUpdate : EVP_DecryptUpdate;
				constexpr auto ends = to_encrypt ? EVP_EncryptFinal : EVP_DecryptFinal;

				auto state = EVP_CIPHER_CTX_new();
				init(state, mode_c, reinterpret_cast<const byte_t*>(key.data()), reinterpret_cast<const byte_t*>(iv.data()));
				ping(state, it_out, &size_i, reinterpret_cast<const byte_t*>(input.data()), input.size());
				ends(state, it_out + size_i, &size_f);
				EVP_CIPHER_CTX_free(state);
			}
			return output;
		}

		template <const EVP_MD* (*evp_x)()>
		static constexpr auto hash_adapter = adapter_base_f<hash<evp_x>>{};
	}

	namespace convert
	{
		constexpr auto to_base64 = details::adapter_base_f<details::convert::to_base64>{};
		constexpr auto to_hex = details::adapter_base_f<details::convert::to_hex>{};
	}

	namespace generate
	{
		auto random_byte() noexcept -> byte_t
		{
			static auto my_engine = std::mt19937{ std::random_device{}() };
			return std::uniform_int_distribution<int>{ 0, 255 }(my_engine);
		}

		auto random_bytes(const size_t n) noexcept
		{
			return vs::generate_n(random_byte, n) | rg::to<std::string>;
		}

		auto guid() noexcept
		{
			return random_bytes(16);
		}

		constexpr auto key = random_bytes;
	}

	namespace hash
	{
		constexpr auto md_5 = details::hash_adapter<EVP_md5>;
		constexpr auto md_5_sha_160 = details::hash_adapter<EVP_sha1>;
		constexpr auto ripe_md_160 = details::hash_adapter<EVP_ripemd160>;
		constexpr auto blake_2s_256 = details::hash_adapter<EVP_blake2s256>;
		constexpr auto blake_2b_512 = details::hash_adapter<EVP_blake2b512>;
		constexpr auto shake_128 = details::hash_adapter<EVP_shake128>;
		constexpr auto shake_256 = details::hash_adapter<EVP_shake256>;

		constexpr auto sha_160 = details::hash_adapter<EVP_sha1>;
		constexpr auto sha_224 = details::hash_adapter<EVP_sha224>;
		constexpr auto sha_256 = details::hash_adapter<EVP_sha256>;
		constexpr auto sha_384 = details::hash_adapter<EVP_sha384>;
		constexpr auto sha_512 = details::hash_adapter<EVP_sha512>;
		constexpr auto sha_512_224 = details::hash_adapter<EVP_sha512_224>;
		constexpr auto sha_512_256 = details::hash_adapter<EVP_sha512_256>;

		constexpr auto sha3_224 = details::hash_adapter<EVP_sha3_224>;
		constexpr auto sha3_256 = details::hash_adapter<EVP_sha3_256>;
		constexpr auto sha3_384 = details::hash_adapter<EVP_sha3_384>;
		constexpr auto sha3_512 = details::hash_adapter<EVP_sha3_512>;
	}
}

int main()
{
	constexpr auto my_data = std::string_view{ "TheMR" };
}
