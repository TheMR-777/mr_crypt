#include <range/v3/view.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <random>
#include <ranges>

namespace mr_crypt
{
	namespace rg = ranges;
	namespace vs = rg::views;
	using byte_t = std::uint8_t;
	using view_t = std::string_view;

	namespace eternal
	{
		static constexpr auto std_iterations = 10'000;
		static constexpr auto std_key_length = 32;
	}

	namespace
	{
#define DECLARE_HASH_EX(NAME, FUNC, ...) \
	constexpr auto NAME = details::hash_adapter<FUNC, ##__VA_ARGS__>;

#define DECLARE_CIPHER_EX(NAME, FUNC, ...) \
    template <bool ownership = true> \
    using NAME = details::cipher_stateful_t<FUNC, ownership, ##__VA_ARGS__>;

#define DECLARE_CIPHER(NAME, ...) \
    DECLARE_CIPHER_EX(NAME, EVP_##NAME, ##__VA_ARGS__)
	}

	namespace produce
	{
		auto random_byte() noexcept -> byte_t
		{
			static auto my_engine = std::mt19937{ std::random_device{}() };
			return std::uniform_int_distribution<int>{ 0, 255 }(my_engine);
		}

		auto random_bytes(const size_t n = eternal::std_key_length) noexcept
		{
			return vs::generate_n(random_byte, n) | rg::to<std::string>;
		}

		auto random_prime_rsa_pair(const size_t bits_n) noexcept
		{
			auto key_loc = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(nullptr, EVP_PKEY_free);
			{
				const auto key_ctx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), &EVP_PKEY_CTX_free);
				EVP_PKEY_keygen_init(key_ctx.get());
				EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx.get(), bits_n);
				EVP_PKEY_generate(key_ctx.get(), std::out_ptr(key_loc));
			}

			auto keys = std::pair
			{
				std::string(i2d_PrivateKey(key_loc.get(), nullptr), '\0'),
				std::string(i2d_PUBKEY(key_loc.get(), nullptr), '\0'),
			};

			auto pvt_buf = reinterpret_cast<mr_crypt::byte_t*>(keys.first.data());
			auto pub_buf = reinterpret_cast<mr_crypt::byte_t*>(keys.second.data());

			i2d_PrivateKey(key_loc.get(), &pvt_buf);
			i2d_PUBKEY(key_loc.get(), &pub_buf);

			return keys;
		}

		auto guid() noexcept
		{
			return random_bytes(16);
		}

		constexpr auto key = random_bytes;
	}

	namespace pk_cs_5
	{
		template <const EVP_MD* (*underlying_hash)() = mr_crypt::hashing::sha_256.underlying_f>
		auto pb_kdf2_hmac(const mr_crypt::view_t password, const size_t key_length, const mr_crypt::view_t salt = {}, const size_t iterations = eternal::std_iterations)
		{
			auto out = std::string(key_length, '\0');
			PKCS5_PBKDF2_HMAC(password.data(), password.size(), reinterpret_cast<const mr_crypt::byte_t*>(salt.data()), salt.size(), iterations, underlying_hash(), key_length, reinterpret_cast<mr_crypt::byte_t*>(out.data()));
			return out;
		}
	}

	namespace details
	{
		using hash_t = EVP_MD;
		using ciph_t = EVP_CIPHER;
		using hash_f_t = const hash_t* (*)();
		using ciph_f_t = const ciph_t* (*)();

		namespace convert
		{
			static constexpr auto base64_table = std::string_view{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" };
			static constexpr auto my_hex_table = std::string_view{ "0123456789abcdef" };
			static constexpr auto m_padding = '=';

			auto to_base64(const view_t input) noexcept
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

			auto to_hex(const view_t data) noexcept
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

		template <std::string(*just_fun)(view_t), class Derived = void>
		struct adapter_base_f : std::ranges::range_adaptor_closure<std::conditional_t<std::is_void_v<Derived>, adapter_base_f<just_fun>, Derived>>
		{
			auto operator()(const view_t input) const noexcept
			{
				return just_fun(input);
			}
		};

		template <const auto* (*evp_x)()>
		struct expose_evp
		{
			static constexpr auto underlying_f = evp_x;
		};

		template <ciph_f_t evp_cipher_x>
		struct info_provider : expose_evp<evp_cipher_x>
		{
			static auto key_size() noexcept
			{
				return EVP_CIPHER_key_length(evp_cipher_x());
			}

			static auto iv_size() noexcept
			{
				return EVP_CIPHER_iv_length(evp_cipher_x());
			}

			static auto make_key() noexcept
			{
				return produce::random_bytes(key_size());
			}

			static auto make_iv() noexcept
			{
				return produce::random_bytes(iv_size());
			}

			template <hash_f_t evp_x = mr_crypt::hashing::sha_256.underlying_f>
			static auto make_key_with_password(view_t password, view_t salt = {}, size_t iterations = eternal::std_iterations) noexcept
			{
				return pk_cs_5::pb_kdf2_hmac<evp_x>(password, key_size(), salt, iterations);
			}

			template <hash_f_t evp_x = mr_crypt::hashing::sha_256.underlying_f>
			static auto make_iv_with_password(view_t password, view_t salt = {}, size_t iterations = eternal::std_iterations) noexcept
			{
				return pk_cs_5::pb_kdf2_hmac<evp_x>(password, iv_size(), salt, iterations);
			}
		};

		template <hash_f_t evp_x>
		auto hash(const view_t input) noexcept
		{
			const auto digest = evp_x();
			auto output = std::string(EVP_MD_get_size(digest), '\0');
			EVP_Digest(input.data(), input.size(), reinterpret_cast<byte_t*>(output.data()), nullptr, digest, nullptr);
			return output;
		}

		template <hash_f_t evp_x>
		struct hash_adapter_wrap : adapter_base_f<hash<evp_x>, hash_adapter_wrap<evp_x>>, expose_evp<evp_x> { };

		template <hash_f_t evp_x>
		static constexpr auto hash_adapter = hash_adapter_wrap<evp_x>{};

		constexpr auto cipher_final_size(const size_t in_size, const int block_size) noexcept
		{
			return (in_size + block_size - 1) / block_size * block_size;
		}

		template <ciph_f_t evp_cipher_x, bool to_encrypt = true, bool requires_tag = false>
		auto cipher(view_t input, const view_t key, const view_t iv) noexcept
		{
			constexpr auto tag_length = requires_tag
				? to_encrypt ? 16 : -16
				: 0;
			const auto mode_c = evp_cipher_x();
			auto output = std::string(input.size() + EVP_MAX_BLOCK_LENGTH + tag_length, '\0');
			const auto it_out = reinterpret_cast<byte_t*>(output.data());
			auto size_i = int{}, size_f = int{};
			{
				constexpr auto init = to_encrypt ? EVP_EncryptInit : EVP_DecryptInit;
				constexpr auto ping = to_encrypt ? EVP_EncryptUpdate : EVP_DecryptUpdate;
				constexpr auto ends = to_encrypt ? EVP_EncryptFinal : EVP_DecryptFinal;

				const auto state = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>{ EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };
				init(state.get(), mode_c, reinterpret_cast<const byte_t*>(key.data()), reinterpret_cast<const byte_t*>(iv.data()));
				ping(state.get(), it_out, &size_i, reinterpret_cast<const byte_t*>(input.data()), input.size() + (requires_tag && !to_encrypt) * tag_length);
				if constexpr (requires_tag && !to_encrypt) EVP_CIPHER_CTX_ctrl(state.get(), EVP_CTRL_AEAD_SET_TAG, -tag_length, (view_t::value_type*)input.data() + input.size() + tag_length);
				ends(state.get(), it_out + size_i, &size_f);
				if constexpr (requires_tag && to_encrypt)  EVP_CIPHER_CTX_ctrl(state.get(), EVP_CTRL_AEAD_GET_TAG, tag_length, it_out + size_i + size_f);
			}
			output.resize(size_i + size_f);
			return output;
		}

		template <ciph_f_t evp_cipher_x, bool to_encrypt = true, bool requires_tag = false>
		struct cipher_adapter_wrap : std::ranges::range_adaptor_closure<cipher_adapter_wrap<evp_cipher_x, to_encrypt, requires_tag>>, info_provider<evp_cipher_x>
		{
			view_t my_key, my_iv;
			constexpr cipher_adapter_wrap(const view_t key, const view_t iv = {}) noexcept : my_key{ key }, my_iv{ iv } {}
			auto operator()(const view_t input) const noexcept
			{
				return cipher<evp_cipher_x, to_encrypt, requires_tag>(input, my_key, my_iv);
			}
		};

		template <ciph_f_t evp_cipher_x, bool requires_tag = false>
		using enc_adapter = cipher_adapter_wrap<evp_cipher_x, true, requires_tag>;

		template <ciph_f_t evp_cipher_x, bool requires_tag = false>
		using dec_adapter = cipher_adapter_wrap<evp_cipher_x, false, requires_tag>;

		template <ciph_f_t evp_cipher_x, bool ownership = true, bool requires_tag = false>
		struct cipher_stateful_t : std::ranges::range_adaptor_closure<cipher_stateful_t<evp_cipher_x, ownership, requires_tag>>, info_provider<evp_cipher_x>
		{
			using container_t = std::conditional_t<ownership, std::string, view_t>;
			using encrypt_t = enc_adapter<evp_cipher_x, requires_tag>;
			using decrypt_t = dec_adapter<evp_cipher_x, requires_tag>;

			const container_t my_key = make_key(), the_iv = make_iv();

			const encrypt_t encrypt = { my_key, the_iv };
			const decrypt_t decrypt = { my_key, the_iv };

			constexpr cipher_stateful_t() noexcept requires ownership = default;
			constexpr cipher_stateful_t(container_t key, container_t iv = {}) noexcept : my_key{ std::move(key) }, the_iv{ std::move(iv) } {}

			template <bool include_iv = true, hash_f_t evp_x = EVP_sha256> requires ownership
				static auto with_password(view_t password, view_t salt = {}, size_t iterations = eternal::std_iterations) noexcept
			{
				return cipher_stateful_t
				{
					pk_cs_5::pb_kdf2_hmac<evp_x>(password, info_provider<evp_cipher_x>::key_size(), salt, iterations),
					include_iv ? pk_cs_5::pb_kdf2_hmac<evp_x>(password, info_provider<evp_cipher_x>::iv_size(), salt, iterations) : container_t{}
				};
			}

			auto operator()(view_t input) const noexcept
			{
				return encrypt(input);
			}
		};
	}

	namespace hashing
	{
		DECLARE_HASH_EX(md_5, EVP_md5);
		DECLARE_HASH_EX(md_5_sha_160, EVP_sha1);
		DECLARE_HASH_EX(ripe_md_160, EVP_ripemd160);
		DECLARE_HASH_EX(blake_2s_256, EVP_blake2s256);
		DECLARE_HASH_EX(blake_2b_512, EVP_blake2b512);
		DECLARE_HASH_EX(shake_128, EVP_shake128);
		DECLARE_HASH_EX(shake_256, EVP_shake256);

		DECLARE_HASH_EX(sha_160, EVP_sha1);
		DECLARE_HASH_EX(sha_224, EVP_sha224);
		DECLARE_HASH_EX(sha_256, EVP_sha256);
		DECLARE_HASH_EX(sha_384, EVP_sha384);
		DECLARE_HASH_EX(sha_512, EVP_sha512);
		DECLARE_HASH_EX(sha_512_224, EVP_sha512_224);
		DECLARE_HASH_EX(sha_512_256, EVP_sha512_256);

		DECLARE_HASH_EX(sha3_224, EVP_sha3_224);
		DECLARE_HASH_EX(sha3_256, EVP_sha3_256);
		DECLARE_HASH_EX(sha3_384, EVP_sha3_384);
		DECLARE_HASH_EX(sha3_512, EVP_sha3_512);
	}

	namespace pk_cs_5
	{
		template <const details::hash_t* (*underlying_hash)() = mr_crypt::hashing::sha_256.underlying_f>
		struct as_key : std::ranges::range_adaptor_closure<as_key<underlying_hash>>, details::expose_evp<underlying_hash>
		{
			const size_t key_length;
			const view_t salt;
			const size_t iterations;

			constexpr as_key(const size_t key_length = eternal::std_key_length, const view_t salt = {}, const size_t iterations = eternal::std_iterations) noexcept
				: key_length{ key_length }, salt{ salt }, iterations{ iterations } {}

			auto operator()(const view_t password) const noexcept
			{
				return pb_kdf2_hmac<underlying_hash>(password, key_length, salt, iterations);
			}
		};
	}

	namespace convert
	{
		template <const details::hash_t* (*underlying_hash)() = mr_crypt::hashing::sha_256.underlying_f>
		using to_key = pk_cs_5::as_key<underlying_hash>;

		constexpr auto to_base64 = details::adapter_base_f<details::convert::to_base64>{};
		constexpr auto to_hex = details::adapter_base_f<details::convert::to_hex>{};
	}

	namespace supreme
	{
		DECLARE_CIPHER(des_ede);
		DECLARE_CIPHER(des_ede_ecb);
		DECLARE_CIPHER(des_ede_cbc);
		DECLARE_CIPHER(des_ede_ofb);
		DECLARE_CIPHER(des_ede_cfb);
		DECLARE_CIPHER(des_ede_cfb64);

		DECLARE_CIPHER(des_ede3);
		DECLARE_CIPHER(des_ede3_ecb);
		DECLARE_CIPHER(des_ede3_cbc);
		DECLARE_CIPHER(des_ede3_ofb);
		DECLARE_CIPHER(des_ede3_cfb);
		DECLARE_CIPHER(des_ede3_cfb1);
		DECLARE_CIPHER(des_ede3_cfb8);
		DECLARE_CIPHER(des_ede3_cfb64);

		DECLARE_CIPHER(aes_128_ecb);
		DECLARE_CIPHER(aes_128_cbc);
		DECLARE_CIPHER(aes_128_ofb);
		DECLARE_CIPHER(aes_128_ctr);
		DECLARE_CIPHER(aes_128_cfb);
		DECLARE_CIPHER(aes_128_cfb1);
		DECLARE_CIPHER(aes_128_cfb8);
		DECLARE_CIPHER(aes_128_cfb128);
		DECLARE_CIPHER(aes_128_gcm, true);

		DECLARE_CIPHER(aes_192_ecb);
		DECLARE_CIPHER(aes_192_cbc);
		DECLARE_CIPHER(aes_192_ofb);
		DECLARE_CIPHER(aes_192_ctr);
		DECLARE_CIPHER(aes_192_cfb);
		DECLARE_CIPHER(aes_192_cfb1);
		DECLARE_CIPHER(aes_192_cfb8);
		DECLARE_CIPHER(aes_192_cfb128);
		DECLARE_CIPHER(aes_192_gcm, true);

		DECLARE_CIPHER(aes_256_ecb);
		DECLARE_CIPHER(aes_256_cbc);
		DECLARE_CIPHER(aes_256_ofb);
		DECLARE_CIPHER(aes_256_ctr);
		DECLARE_CIPHER(aes_256_cfb);
		DECLARE_CIPHER(aes_256_cfb1);
		DECLARE_CIPHER(aes_256_cfb8);
		DECLARE_CIPHER(aes_256_cfb128);
		DECLARE_CIPHER(aes_256_gcm, true);

		DECLARE_CIPHER(aria_128_ecb);
		DECLARE_CIPHER(aria_128_cbc);
		DECLARE_CIPHER(aria_128_ofb);
		DECLARE_CIPHER(aria_128_ctr);
		DECLARE_CIPHER(aria_128_cfb);
		DECLARE_CIPHER(aria_128_cfb1);
		DECLARE_CIPHER(aria_128_cfb8);
		DECLARE_CIPHER(aria_128_cfb128);
		DECLARE_CIPHER(aria_128_gcm, true);

		DECLARE_CIPHER(aria_192_ecb);
		DECLARE_CIPHER(aria_192_cbc);
		DECLARE_CIPHER(aria_192_ofb);
		DECLARE_CIPHER(aria_192_ctr);
		DECLARE_CIPHER(aria_192_cfb);
		DECLARE_CIPHER(aria_192_cfb1);
		DECLARE_CIPHER(aria_192_cfb8);
		DECLARE_CIPHER(aria_192_cfb128);
		DECLARE_CIPHER(aria_192_gcm, true);

		DECLARE_CIPHER(aria_256_ecb);
		DECLARE_CIPHER(aria_256_cbc);
		DECLARE_CIPHER(aria_256_ofb);
		DECLARE_CIPHER(aria_256_ctr);
		DECLARE_CIPHER(aria_256_cfb);
		DECLARE_CIPHER(aria_256_cfb1);
		DECLARE_CIPHER(aria_256_cfb8);
		DECLARE_CIPHER(aria_256_cfb128);
		DECLARE_CIPHER(aria_256_gcm, true);

		DECLARE_CIPHER(camellia_128_ecb);
		DECLARE_CIPHER(camellia_128_cbc);
		DECLARE_CIPHER(camellia_128_ofb);
		DECLARE_CIPHER(camellia_128_ctr);
		DECLARE_CIPHER(camellia_128_cfb);
		DECLARE_CIPHER(camellia_128_cfb1);
		DECLARE_CIPHER(camellia_128_cfb8);
		DECLARE_CIPHER(camellia_128_cfb128);

		DECLARE_CIPHER(camellia_192_ecb);
		DECLARE_CIPHER(camellia_192_cbc);
		DECLARE_CIPHER(camellia_192_ofb);
		DECLARE_CIPHER(camellia_192_ctr);
		DECLARE_CIPHER(camellia_192_cfb);
		DECLARE_CIPHER(camellia_192_cfb1);
		DECLARE_CIPHER(camellia_192_cfb8);
		DECLARE_CIPHER(camellia_192_cfb128);

		DECLARE_CIPHER(camellia_256_ecb);
		DECLARE_CIPHER(camellia_256_cbc);
		DECLARE_CIPHER(camellia_256_ofb);
		DECLARE_CIPHER(camellia_256_ctr);
		DECLARE_CIPHER(camellia_256_cfb);
		DECLARE_CIPHER(camellia_256_cfb1);
		DECLARE_CIPHER(camellia_256_cfb8);
		DECLARE_CIPHER(camellia_256_cfb128);

		DECLARE_CIPHER(sm4_ecb);
		DECLARE_CIPHER(sm4_cbc);
		DECLARE_CIPHER(sm4_ofb);
		DECLARE_CIPHER(sm4_ctr);
		DECLARE_CIPHER(sm4_cfb);
		DECLARE_CIPHER(sm4_cfb128);

		DECLARE_CIPHER_EX(chacha_20, EVP_chacha20);
		DECLARE_CIPHER_EX(chacha_20_poly_1305, EVP_chacha20_poly1305);
	}
}

int main()
{
	constexpr auto my_data = std::string_view{ "TheMR" };
}
