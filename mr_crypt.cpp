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

	namespace produce
	{
		auto random_byte() noexcept -> byte_t
		{
			static auto my_engine = std::mt19937{ std::random_device{}() };
			return std::uniform_int_distribution<int>{ 0, 255 }(my_engine);
		}

		auto random_bytes(const size_t n = 32) noexcept
		{
			return vs::generate_n(random_byte, n) | rg::to<std::string>;
		}

		auto guid() noexcept
		{
			return random_bytes(16);
		}

		constexpr auto key = random_bytes;
	}

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

		template <const EVP_CIPHER* (*evp_cipher_x)()>
		struct info_provider
		{
			static auto key_size() noexcept
			{
				return EVP_CIPHER_key_length(evp_cipher_x());
			}

			static auto iv_size() noexcept
			{
				return EVP_CIPHER_iv_length(evp_cipher_x());
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

		template <const EVP_CIPHER* (*evp_cipher_x)(), bool to_encrypt = true, bool requires_tag = false>
		auto cipher(view_t input, view_t key, view_t iv = {}) noexcept
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

		template <const EVP_CIPHER* (*evp_cipher_x)(), bool to_encrypt = true>
		struct cipher_adapter_wrap : std::ranges::range_adaptor_closure<cipher_adapter_wrap<evp_cipher_x, to_encrypt>>, info_provider<evp_cipher_x>
		{
			view_t my_key, my_iv;
			constexpr cipher_adapter_wrap(view_t key, view_t iv) noexcept : my_key{ key }, my_iv{ iv } {}
			auto operator()(view_t input) const noexcept
			{
				return cipher<evp_cipher_x, to_encrypt>(input, my_key, my_iv);
			}
		};

		template <const EVP_CIPHER* (*evp_cipher_x)()>
		using enc_adapter = cipher_adapter_wrap<evp_cipher_x>;

		template <const EVP_CIPHER* (*evp_cipher_x)()>
		using dec_adapter = cipher_adapter_wrap<evp_cipher_x, false>;

		template <const EVP_CIPHER* (*evp_cipher_x)()>
		struct cipher_stateful_t : std::ranges::range_adaptor_closure<cipher_stateful_t<evp_cipher_x>>, info_provider<evp_cipher_x>
		{
			const std::string my_key = produce::key(info_provider<evp_cipher_x>::key_size());
			const std::string the_iv = produce::key(info_provider<evp_cipher_x>::iv_size());

			enc_adapter<evp_cipher_x> encrypt = { my_key, the_iv };
			dec_adapter<evp_cipher_x> decrypt = { my_key, the_iv };

			constexpr cipher_stateful_t() noexcept = default;
			constexpr cipher_stateful_t(view_t key) noexcept : my_key{ key }, the_iv{} {}
			constexpr cipher_stateful_t(view_t key, view_t iv) noexcept : my_key{ key }, the_iv{ iv } {}

			auto encrypt_fn(view_t input) const noexcept
			{
				return input | encrypt;
			}

			auto decrypt_fn(view_t input) const noexcept
			{
				return input | decrypt;
			}

			auto operator()(view_t input) const noexcept
			{
				return encrypt_fn(input);
			}
		};

		template <const EVP_MD* (*evp_x)()>
		static constexpr auto hash_adapter = adapter_base_f<hash<evp_x>>{};
	}

	namespace convert
	{
		constexpr auto to_base64 = details::adapter_base_f<details::convert::to_base64>{};
		constexpr auto to_hex = details::adapter_base_f<details::convert::to_hex>{};
	}

	namespace encrypt
	{
		using des_ede = details::enc_adapter<EVP_des_ede>;
		using des_ede_ecb = details::enc_adapter<EVP_des_ede_ecb>;
		using des_ede_cbc = details::enc_adapter<EVP_des_ede_cbc>;
		using des_ede_ofb = details::enc_adapter<EVP_des_ede_ofb>;
		using des_ede_cfb64 = details::enc_adapter<EVP_des_ede_cfb64>;
		using des_ede_cfb = des_ede_cfb64;

		using des_ede3 = details::enc_adapter<EVP_des_ede3>;
		using des_ede3_ecb = details::enc_adapter<EVP_des_ede3_ecb>;
		using des_ede3_cbc = details::enc_adapter<EVP_des_ede3_cbc>;
		using des_ede3_ofb = details::enc_adapter<EVP_des_ede3_ofb>;
		using des_ede3_cfb1 = details::enc_adapter<EVP_des_ede3_cfb1>;
		using des_ede3_cfb8 = details::enc_adapter<EVP_des_ede3_cfb8>;
		using des_ede3_cfb64 = details::enc_adapter<EVP_des_ede3_cfb64>;
		using des_ede3_cfb = des_ede3_cfb64;

		using aes_128_ecb = details::enc_adapter<EVP_aes_128_ecb>;
		using aes_128_cbc = details::enc_adapter<EVP_aes_128_cbc>;
		using aes_128_ofb = details::enc_adapter<EVP_aes_128_ofb>;
		using aes_128_ctr = details::enc_adapter<EVP_aes_128_ctr>;
		using aes_128_cfb1 = details::enc_adapter<EVP_aes_128_cfb1>;
		using aes_128_cfb8 = details::enc_adapter<EVP_aes_128_cfb8>;
		using aes_128_cfb128 = details::enc_adapter<EVP_aes_128_cfb128>;
		using aes_128_cfb = aes_128_cfb128;

		using aes_192_ecb = details::enc_adapter<EVP_aes_192_ecb>;
		using aes_192_cbc = details::enc_adapter<EVP_aes_192_cbc>;
		using aes_192_ofb = details::enc_adapter<EVP_aes_192_ofb>;
		using aes_192_ctr = details::enc_adapter<EVP_aes_192_ctr>;
		using aes_192_cfb1 = details::enc_adapter<EVP_aes_192_cfb1>;
		using aes_192_cfb8 = details::enc_adapter<EVP_aes_192_cfb8>;
		using aes_192_cfb128 = details::enc_adapter<EVP_aes_192_cfb128>;
		using aes_192_cfb = aes_192_cfb128;

		using aes_256_ecb = details::enc_adapter<EVP_aes_256_ecb>;
		using aes_256_cbc = details::enc_adapter<EVP_aes_256_cbc>;
		using aes_256_ofb = details::enc_adapter<EVP_aes_256_ofb>;
		using aes_256_ctr = details::enc_adapter<EVP_aes_256_ctr>;
		using aes_256_cfb1 = details::enc_adapter<EVP_aes_256_cfb1>;
		using aes_256_cfb8 = details::enc_adapter<EVP_aes_256_cfb8>;
		using aes_256_cfb128 = details::enc_adapter<EVP_aes_256_cfb128>;
		using aes_256_cfb = aes_256_cfb128;

		using aria_128_ecb = details::enc_adapter<EVP_aria_128_ecb>;
		using aria_128_cbc = details::enc_adapter<EVP_aria_128_cbc>;
		using aria_128_ofb = details::enc_adapter<EVP_aria_128_ofb>;
		using aria_128_ctr = details::enc_adapter<EVP_aria_128_ctr>;
		using aria_128_cfb1 = details::enc_adapter<EVP_aria_128_cfb1>;
		using aria_128_cfb8 = details::enc_adapter<EVP_aria_128_cfb8>;
		using aria_128_cfb128 = details::enc_adapter<EVP_aria_128_cfb128>;
		using aria_128_cfb = aria_128_cfb128;

		using aria_192_ecb = details::enc_adapter<EVP_aria_192_ecb>;
		using aria_192_cbc = details::enc_adapter<EVP_aria_192_cbc>;
		using aria_192_ofb = details::enc_adapter<EVP_aria_192_ofb>;
		using aria_192_ctr = details::enc_adapter<EVP_aria_192_ctr>;
		using aria_192_cfb1 = details::enc_adapter<EVP_aria_192_cfb1>;
		using aria_192_cfb8 = details::enc_adapter<EVP_aria_192_cfb8>;
		using aria_192_cfb128 = details::enc_adapter<EVP_aria_192_cfb128>;
		using aria_192_cfb = aria_192_cfb128;

		using aria_256_ecb = details::enc_adapter<EVP_aria_256_ecb>;
		using aria_256_cbc = details::enc_adapter<EVP_aria_256_cbc>;
		using aria_256_ofb = details::enc_adapter<EVP_aria_256_ofb>;
		using aria_256_ctr = details::enc_adapter<EVP_aria_256_ctr>;
		using aria_256_cfb1 = details::enc_adapter<EVP_aria_256_cfb1>;
		using aria_256_cfb8 = details::enc_adapter<EVP_aria_256_cfb8>;
		using aria_256_cfb128 = details::enc_adapter<EVP_aria_256_cfb128>;
		using aria_256_cfb = aria_256_cfb128;

		using camellia_128_ecb = details::enc_adapter<EVP_camellia_128_ecb>;
		using camellia_128_cbc = details::enc_adapter<EVP_camellia_128_cbc>;
		using camellia_128_ofb = details::enc_adapter<EVP_camellia_128_ofb>;
		using camellia_128_ctr = details::enc_adapter<EVP_camellia_128_ctr>;
		using camellia_128_cfb1 = details::enc_adapter<EVP_camellia_128_cfb1>;
		using camellia_128_cfb8 = details::enc_adapter<EVP_camellia_128_cfb8>;
		using camellia_128_cfb128 = details::enc_adapter<EVP_camellia_128_cfb128>;
		using camellia_128_cfb = camellia_128_cfb128;

		using camellia_192_ecb = details::enc_adapter<EVP_camellia_192_ecb>;
		using camellia_192_cbc = details::enc_adapter<EVP_camellia_192_cbc>;
		using camellia_192_ofb = details::enc_adapter<EVP_camellia_192_ofb>;
		using camellia_192_ctr = details::enc_adapter<EVP_camellia_192_ctr>;
		using camellia_192_cfb1 = details::enc_adapter<EVP_camellia_192_cfb1>;
		using camellia_192_cfb8 = details::enc_adapter<EVP_camellia_192_cfb8>;
		using camellia_192_cfb128 = details::enc_adapter<EVP_camellia_192_cfb128>;
		using camellia_192_cfb = camellia_192_cfb128;

		using camellia_256_ecb = details::enc_adapter<EVP_camellia_256_ecb>;
		using camellia_256_cbc = details::enc_adapter<EVP_camellia_256_cbc>;
		using camellia_256_ofb = details::enc_adapter<EVP_camellia_256_ofb>;
		using camellia_256_ctr = details::enc_adapter<EVP_camellia_256_ctr>;
		using camellia_256_cfb1 = details::enc_adapter<EVP_camellia_256_cfb1>;
		using camellia_256_cfb8 = details::enc_adapter<EVP_camellia_256_cfb8>;
		using camellia_256_cfb128 = details::enc_adapter<EVP_camellia_256_cfb128>;
		using camellia_256_cfb = camellia_256_cfb128;

		using sm4_ecb = details::enc_adapter<EVP_sm4_ecb>;
		using sm4_cbc = details::enc_adapter<EVP_sm4_cbc>;
		using sm4_ofb = details::enc_adapter<EVP_sm4_ofb>;
		using sm4_ctr = details::enc_adapter<EVP_sm4_ctr>;
		using sm4_cfb = details::enc_adapter<EVP_sm4_cfb>;
		using sm4_cfb128 = details::enc_adapter<EVP_sm4_cfb128>;

		using chacha_20 = details::enc_adapter<EVP_chacha20>;
		using chacha_20_poly_1305 = details::enc_adapter<EVP_chacha20_poly1305>;
	}

	namespace decrypt
	{
		using des_ede = details::dec_adapter<EVP_des_ede>;
		using des_ede_ecb = details::dec_adapter<EVP_des_ede_ecb>;
		using des_ede_cbc = details::dec_adapter<EVP_des_ede_cbc>;
		using des_ede_ofb = details::dec_adapter<EVP_des_ede_ofb>;
		using des_ede_cfb64 = details::dec_adapter<EVP_des_ede_cfb64>;
		using des_ede_cfb = des_ede_cfb64;

		using des_ede3 = details::dec_adapter<EVP_des_ede3>;
		using des_ede3_ecb = details::dec_adapter<EVP_des_ede3_ecb>;
		using des_ede3_cbc = details::dec_adapter<EVP_des_ede3_cbc>;
		using des_ede3_ofb = details::dec_adapter<EVP_des_ede3_ofb>;
		using des_ede3_cfb1 = details::dec_adapter<EVP_des_ede3_cfb1>;
		using des_ede3_cfb8 = details::dec_adapter<EVP_des_ede3_cfb8>;
		using des_ede3_cfb64 = details::dec_adapter<EVP_des_ede3_cfb64>;
		using des_ede3_cfb = des_ede3_cfb64;

		using aes_128_ecb = details::dec_adapter<EVP_aes_128_ecb>;
		using aes_128_cbc = details::dec_adapter<EVP_aes_128_cbc>;
		using aes_128_ofb = details::dec_adapter<EVP_aes_128_ofb>;
		using aes_128_ctr = details::dec_adapter<EVP_aes_128_ctr>;
		using aes_128_cfb1 = details::dec_adapter<EVP_aes_128_cfb1>;
		using aes_128_cfb8 = details::dec_adapter<EVP_aes_128_cfb8>;
		using aes_128_cfb128 = details::dec_adapter<EVP_aes_128_cfb128>;
		using aes_128_cfb = aes_128_cfb128;

		using aes_192_ecb = details::dec_adapter<EVP_aes_192_ecb>;
		using aes_192_cbc = details::dec_adapter<EVP_aes_192_cbc>;
		using aes_192_ofb = details::dec_adapter<EVP_aes_192_ofb>;
		using aes_192_ctr = details::dec_adapter<EVP_aes_192_ctr>;
		using aes_192_cfb1 = details::dec_adapter<EVP_aes_192_cfb1>;
		using aes_192_cfb8 = details::dec_adapter<EVP_aes_192_cfb8>;
		using aes_192_cfb128 = details::dec_adapter<EVP_aes_192_cfb128>;
		using aes_192_cfb = aes_192_cfb128;

		using aes_256_ecb = details::dec_adapter<EVP_aes_256_ecb>;
		using aes_256_cbc = details::dec_adapter<EVP_aes_256_cbc>;
		using aes_256_ofb = details::dec_adapter<EVP_aes_256_ofb>;
		using aes_256_ctr = details::dec_adapter<EVP_aes_256_ctr>;
		using aes_256_cfb1 = details::dec_adapter<EVP_aes_256_cfb1>;
		using aes_256_cfb8 = details::dec_adapter<EVP_aes_256_cfb8>;
		using aes_256_cfb128 = details::dec_adapter<EVP_aes_256_cfb128>;
		using aes_256_cfb = aes_256_cfb128;

		using aria_128_ecb = details::dec_adapter<EVP_aria_128_ecb>;
		using aria_128_cbc = details::dec_adapter<EVP_aria_128_cbc>;
		using aria_128_ofb = details::dec_adapter<EVP_aria_128_ofb>;
		using aria_128_ctr = details::dec_adapter<EVP_aria_128_ctr>;
		using aria_128_cfb1 = details::dec_adapter<EVP_aria_128_cfb1>;
		using aria_128_cfb8 = details::dec_adapter<EVP_aria_128_cfb8>;
		using aria_128_cfb128 = details::dec_adapter<EVP_aria_128_cfb128>;
		using aria_128_cfb = aria_128_cfb128;

		using aria_192_ecb = details::dec_adapter<EVP_aria_192_ecb>;
		using aria_192_cbc = details::dec_adapter<EVP_aria_192_cbc>;
		using aria_192_ofb = details::dec_adapter<EVP_aria_192_ofb>;
		using aria_192_ctr = details::dec_adapter<EVP_aria_192_ctr>;
		using aria_192_cfb1 = details::dec_adapter<EVP_aria_192_cfb1>;
		using aria_192_cfb8 = details::dec_adapter<EVP_aria_192_cfb8>;
		using aria_192_cfb128 = details::dec_adapter<EVP_aria_192_cfb128>;
		using aria_192_cfb = aria_192_cfb128;

		using aria_256_ecb = details::dec_adapter<EVP_aria_256_ecb>;
		using aria_256_cbc = details::dec_adapter<EVP_aria_256_cbc>;
		using aria_256_ofb = details::dec_adapter<EVP_aria_256_ofb>;
		using aria_256_ctr = details::dec_adapter<EVP_aria_256_ctr>;
		using aria_256_cfb1 = details::dec_adapter<EVP_aria_256_cfb1>;
		using aria_256_cfb8 = details::dec_adapter<EVP_aria_256_cfb8>;
		using aria_256_cfb128 = details::dec_adapter<EVP_aria_256_cfb128>;
		using aria_256_cfb = aria_256_cfb128;

		using camellia_128_ecb = details::dec_adapter<EVP_camellia_128_ecb>;
		using camellia_128_cbc = details::dec_adapter<EVP_camellia_128_cbc>;
		using camellia_128_ofb = details::dec_adapter<EVP_camellia_128_ofb>;
		using camellia_128_ctr = details::dec_adapter<EVP_camellia_128_ctr>;
		using camellia_128_cfb1 = details::dec_adapter<EVP_camellia_128_cfb1>;
		using camellia_128_cfb8 = details::dec_adapter<EVP_camellia_128_cfb8>;
		using camellia_128_cfb128 = details::dec_adapter<EVP_camellia_128_cfb128>;
		using camellia_128_cfb = camellia_128_cfb128;

		using camellia_192_ecb = details::dec_adapter<EVP_camellia_192_ecb>;
		using camellia_192_cbc = details::dec_adapter<EVP_camellia_192_cbc>;
		using camellia_192_ofb = details::dec_adapter<EVP_camellia_192_ofb>;
		using camellia_192_ctr = details::dec_adapter<EVP_camellia_192_ctr>;
		using camellia_192_cfb1 = details::dec_adapter<EVP_camellia_192_cfb1>;
		using camellia_192_cfb8 = details::dec_adapter<EVP_camellia_192_cfb8>;
		using camellia_192_cfb128 = details::dec_adapter<EVP_camellia_192_cfb128>;
		using camellia_192_cfb = camellia_192_cfb128;

		using camellia_256_ecb = details::dec_adapter<EVP_camellia_256_ecb>;
		using camellia_256_cbc = details::dec_adapter<EVP_camellia_256_cbc>;
		using camellia_256_ofb = details::dec_adapter<EVP_camellia_256_ofb>;
		using camellia_256_ctr = details::dec_adapter<EVP_camellia_256_ctr>;
		using camellia_256_cfb1 = details::dec_adapter<EVP_camellia_256_cfb1>;
		using camellia_256_cfb8 = details::dec_adapter<EVP_camellia_256_cfb8>;
		using camellia_256_cfb128 = details::dec_adapter<EVP_camellia_256_cfb128>;
		using camellia_256_cfb = camellia_256_cfb128;

		using sm4_ecb = details::dec_adapter<EVP_sm4_ecb>;
		using sm4_cbc = details::dec_adapter<EVP_sm4_cbc>;
		using sm4_ofb = details::dec_adapter<EVP_sm4_ofb>;
		using sm4_ctr = details::dec_adapter<EVP_sm4_ctr>;
		using sm4_cfb = details::dec_adapter<EVP_sm4_cfb>;
		using sm4_cfb128 = details::dec_adapter<EVP_sm4_cfb128>;

		using chacha_20 = details::dec_adapter<EVP_chacha20>;
		using chacha_20_poly_1305 = details::dec_adapter<EVP_chacha20_poly1305>;
	}

	namespace majesty
	{
		using des_ede = details::cipher_stateful_t<EVP_des_ede>;
		using des_ede_ecb = details::cipher_stateful_t<EVP_des_ede_ecb>;
		using des_ede_cbc = details::cipher_stateful_t<EVP_des_ede_cbc>;
		using des_ede_ofb = details::cipher_stateful_t<EVP_des_ede_ofb>;
		using des_ede_cfb64 = details::cipher_stateful_t<EVP_des_ede_cfb64>;
		using des_ede_cfb = des_ede_cfb64;

		using des_ede3 = details::cipher_stateful_t<EVP_des_ede3>;
		using des_ede3_ecb = details::cipher_stateful_t<EVP_des_ede3_ecb>;
		using des_ede3_cbc = details::cipher_stateful_t<EVP_des_ede3_cbc>;
		using des_ede3_ofb = details::cipher_stateful_t<EVP_des_ede3_ofb>;
		using des_ede3_cfb1 = details::cipher_stateful_t<EVP_des_ede3_cfb1>;
		using des_ede3_cfb8 = details::cipher_stateful_t<EVP_des_ede3_cfb8>;
		using des_ede3_cfb64 = details::cipher_stateful_t<EVP_des_ede3_cfb64>;
		using des_ede3_cfb = des_ede3_cfb64;

		using aes_128_ecb = details::cipher_stateful_t<EVP_aes_128_ecb>;
		using aes_128_cbc = details::cipher_stateful_t<EVP_aes_128_cbc>;
		using aes_128_ofb = details::cipher_stateful_t<EVP_aes_128_ofb>;
		using aes_128_ctr = details::cipher_stateful_t<EVP_aes_128_ctr>;
		using aes_128_cfb1 = details::cipher_stateful_t<EVP_aes_128_cfb1>;
		using aes_128_cfb8 = details::cipher_stateful_t<EVP_aes_128_cfb8>;
		using aes_128_cfb128 = details::cipher_stateful_t<EVP_aes_128_cfb128>;
		using aes_128_cfb = aes_128_cfb128;

		using aes_192_ecb = details::cipher_stateful_t<EVP_aes_192_ecb>;
		using aes_192_cbc = details::cipher_stateful_t<EVP_aes_192_cbc>;
		using aes_192_ofb = details::cipher_stateful_t<EVP_aes_192_ofb>;
		using aes_192_ctr = details::cipher_stateful_t<EVP_aes_192_ctr>;
		using aes_192_cfb1 = details::cipher_stateful_t<EVP_aes_192_cfb1>;
		using aes_192_cfb8 = details::cipher_stateful_t<EVP_aes_192_cfb8>;
		using aes_192_cfb128 = details::cipher_stateful_t<EVP_aes_192_cfb128>;
		using aes_192_cfb = aes_192_cfb128;

		using aes_256_ecb = details::cipher_stateful_t<EVP_aes_256_ecb>;
		using aes_256_cbc = details::cipher_stateful_t<EVP_aes_256_cbc>;
		using aes_256_ofb = details::cipher_stateful_t<EVP_aes_256_ofb>;
		using aes_256_ctr = details::cipher_stateful_t<EVP_aes_256_ctr>;
		using aes_256_cfb1 = details::cipher_stateful_t<EVP_aes_256_cfb1>;
		using aes_256_cfb8 = details::cipher_stateful_t<EVP_aes_256_cfb8>;
		using aes_256_cfb128 = details::cipher_stateful_t<EVP_aes_256_cfb128>;
		using aes_256_cfb = aes_256_cfb128;

		using aria_128_ecb = details::cipher_stateful_t<EVP_aria_128_ecb>;
		using aria_128_cbc = details::cipher_stateful_t<EVP_aria_128_cbc>;
		using aria_128_ofb = details::cipher_stateful_t<EVP_aria_128_ofb>;
		using aria_128_ctr = details::cipher_stateful_t<EVP_aria_128_ctr>;
		using aria_128_cfb1 = details::cipher_stateful_t<EVP_aria_128_cfb1>;
		using aria_128_cfb8 = details::cipher_stateful_t<EVP_aria_128_cfb8>;
		using aria_128_cfb128 = details::cipher_stateful_t<EVP_aria_128_cfb128>;
		using aria_128_cfb = aria_128_cfb128;

		using aria_192_ecb = details::cipher_stateful_t<EVP_aria_192_ecb>;
		using aria_192_cbc = details::cipher_stateful_t<EVP_aria_192_cbc>;
		using aria_192_ofb = details::cipher_stateful_t<EVP_aria_192_ofb>;
		using aria_192_ctr = details::cipher_stateful_t<EVP_aria_192_ctr>;
		using aria_192_cfb1 = details::cipher_stateful_t<EVP_aria_192_cfb1>;
		using aria_192_cfb8 = details::cipher_stateful_t<EVP_aria_192_cfb8>;
		using aria_192_cfb128 = details::cipher_stateful_t<EVP_aria_192_cfb128>;
		using aria_192_cfb = aria_192_cfb128;

		using aria_256_ecb = details::cipher_stateful_t<EVP_aria_256_ecb>;
		using aria_256_cbc = details::cipher_stateful_t<EVP_aria_256_cbc>;
		using aria_256_ofb = details::cipher_stateful_t<EVP_aria_256_ofb>;
		using aria_256_ctr = details::cipher_stateful_t<EVP_aria_256_ctr>;
		using aria_256_cfb1 = details::cipher_stateful_t<EVP_aria_256_cfb1>;
		using aria_256_cfb8 = details::cipher_stateful_t<EVP_aria_256_cfb8>;
		using aria_256_cfb128 = details::cipher_stateful_t<EVP_aria_256_cfb128>;
		using aria_256_cfb = aria_256_cfb128;

		using camellia_128_ecb = details::cipher_stateful_t<EVP_camellia_128_ecb>;
		using camellia_128_cbc = details::cipher_stateful_t<EVP_camellia_128_cbc>;
		using camellia_128_ofb = details::cipher_stateful_t<EVP_camellia_128_ofb>;
		using camellia_128_ctr = details::cipher_stateful_t<EVP_camellia_128_ctr>;
		using camellia_128_cfb1 = details::cipher_stateful_t<EVP_camellia_128_cfb1>;
		using camellia_128_cfb8 = details::cipher_stateful_t<EVP_camellia_128_cfb8>;
		using camellia_128_cfb128 = details::cipher_stateful_t<EVP_camellia_128_cfb128>;
		using camellia_128_cfb = camellia_128_cfb128;

		using camellia_192_ecb = details::cipher_stateful_t<EVP_camellia_192_ecb>;
		using camellia_192_cbc = details::cipher_stateful_t<EVP_camellia_192_cbc>;
		using camellia_192_ofb = details::cipher_stateful_t<EVP_camellia_192_ofb>;
		using camellia_192_ctr = details::cipher_stateful_t<EVP_camellia_192_ctr>;
		using camellia_192_cfb1 = details::cipher_stateful_t<EVP_camellia_192_cfb1>;
		using camellia_192_cfb8 = details::cipher_stateful_t<EVP_camellia_192_cfb8>;
		using camellia_192_cfb128 = details::cipher_stateful_t<EVP_camellia_192_cfb128>;
		using camellia_192_cfb = camellia_192_cfb128;

		using camellia_256_ecb = details::cipher_stateful_t<EVP_camellia_256_ecb>;
		using camellia_256_cbc = details::cipher_stateful_t<EVP_camellia_256_cbc>;
		using camellia_256_ofb = details::cipher_stateful_t<EVP_camellia_256_ofb>;
		using camellia_256_ctr = details::cipher_stateful_t<EVP_camellia_256_ctr>;
		using camellia_256_cfb1 = details::cipher_stateful_t<EVP_camellia_256_cfb1>;
		using camellia_256_cfb8 = details::cipher_stateful_t<EVP_camellia_256_cfb8>;
		using camellia_256_cfb128 = details::cipher_stateful_t<EVP_camellia_256_cfb128>;
		using camellia_256_cfb = camellia_256_cfb128;

		using sm4_ecb = details::cipher_stateful_t<EVP_sm4_ecb>;
		using sm4_cbc = details::cipher_stateful_t<EVP_sm4_cbc>;
		using sm4_ofb = details::cipher_stateful_t<EVP_sm4_ofb>;
		using sm4_ctr = details::cipher_stateful_t<EVP_sm4_ctr>;
		using sm4_cfb = details::cipher_stateful_t<EVP_sm4_cfb>;
		using sm4_cfb128 = details::cipher_stateful_t<EVP_sm4_cfb128>;

		using chacha_20 = details::cipher_stateful_t<EVP_chacha20>;
		using chacha_20_poly_1305 = details::cipher_stateful_t<EVP_chacha20_poly1305>;
	}

	namespace hashing
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
