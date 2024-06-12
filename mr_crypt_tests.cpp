#include "mr_crypt.cpp"

int main()
{
	using namespace std::literals;
	constexpr auto my_data = "Created with LOVE, PASSION, HONOR, and PERSEVERENCE by TheMR"sv;
	constexpr auto my_pass = "TheMR"sv;

	// Hashing
	{
		namespace hash = mr_crypt::hashing;
		constexpr auto hashed = "N0elXFdCqgivnwDe5RkBew==";
		const auto my_hash = my_data
			| hash::sha3_512
			| hash::sha3_384
			| hash::sha3_256
			| hash::sha3_224
			| hash::sha_512_256
			| hash::sha_512_224
			| hash::sha_512
			| hash::sha_384
			| hash::sha_256
			| hash::sha_224
			| hash::sha_160
			| hash::shake_256
			| hash::shake_128
			| hash::blake_2b_512
			| hash::blake_2s_256
			| hash::ripe_md_160
			| hash::md_5_sha_160
			| hash::md_5
			| mr_crypt::convert::to_base64;
		std::println("Hash : {}", my_hash == hashed);
	}

	// Symmetric Encryption
	{
		namespace cipher = mr_crypt::supreme;

		using my_algo_00 = cipher::des_ede<>;
		using my_algo_01 = cipher::des_ede_ecb<>;
		using my_algo_02 = cipher::des_ede_cbc<>;
		using my_algo_03 = cipher::des_ede_ofb<>;
		using my_algo_04 = cipher::des_ede_cfb<>;
		using my_algo_05 = cipher::des_ede_cfb64<>;

		using my_algo_06 = cipher::des_ede3<>;
		using my_algo_07 = cipher::des_ede3_ecb<>;
		using my_algo_08 = cipher::des_ede3_cbc<>;
		using my_algo_09 = cipher::des_ede3_ofb<>;
		using my_algo_10 = cipher::des_ede3_cfb<>;
		using my_algo_11 = cipher::des_ede3_cfb1<>;
		using my_algo_12 = cipher::des_ede3_cfb8<>;
		using my_algo_13 = cipher::des_ede3_cfb64<>;

		using my_algo_14 = cipher::aes_128_ecb<>;
		using my_algo_15 = cipher::aes_128_cbc<>;
		using my_algo_16 = cipher::aes_128_ofb<>;
		using my_algo_17 = cipher::aes_128_ctr<>;
		using my_algo_18 = cipher::aes_128_cfb<>;
		using my_algo_19 = cipher::aes_128_cfb1<>;
		using my_algo_20 = cipher::aes_128_cfb8<>;
		using my_algo_21 = cipher::aes_128_cfb128<>;
		using my_algo_22 = cipher::aes_128_gcm<>;

		using my_algo_23 = cipher::aes_192_ecb<>;
		using my_algo_24 = cipher::aes_192_cbc<>;
		using my_algo_25 = cipher::aes_192_ofb<>;
		using my_algo_26 = cipher::aes_192_ctr<>;
		using my_algo_27 = cipher::aes_192_cfb<>;
		using my_algo_28 = cipher::aes_192_cfb1<>;
		using my_algo_29 = cipher::aes_192_cfb8<>;
		using my_algo_30 = cipher::aes_192_cfb128<>;
		using my_algo_31 = cipher::aes_192_gcm<>;

		using my_algo_32 = cipher::aes_256_ecb<>;
		using my_algo_33 = cipher::aes_256_cbc<>;
		using my_algo_34 = cipher::aes_256_ofb<>;
		using my_algo_35 = cipher::aes_256_ctr<>;
		using my_algo_36 = cipher::aes_256_cfb<>;
		using my_algo_37 = cipher::aes_256_cfb1<>;
		using my_algo_38 = cipher::aes_256_cfb8<>;
		using my_algo_39 = cipher::aes_256_cfb128<>;
		using my_algo_40 = cipher::aes_256_gcm<>;

		using my_algo_41 = cipher::aria_128_ecb<>;
		using my_algo_42 = cipher::aria_128_cbc<>;
		using my_algo_43 = cipher::aria_128_ofb<>;
		using my_algo_44 = cipher::aria_128_ctr<>;
		using my_algo_45 = cipher::aria_128_cfb<>;
		using my_algo_46 = cipher::aria_128_cfb1<>;
		using my_algo_47 = cipher::aria_128_cfb8<>;
		using my_algo_48 = cipher::aria_128_cfb128<>;
		using my_algo_49 = cipher::aria_128_gcm<>;

		using my_algo_50 = cipher::aria_192_ecb<>;
		using my_algo_51 = cipher::aria_192_cbc<>;
		using my_algo_52 = cipher::aria_192_ofb<>;
		using my_algo_53 = cipher::aria_192_ctr<>;
		using my_algo_54 = cipher::aria_192_cfb<>;
		using my_algo_55 = cipher::aria_192_cfb1<>;
		using my_algo_56 = cipher::aria_192_cfb8<>;
		using my_algo_57 = cipher::aria_192_cfb128<>;
		using my_algo_58 = cipher::aria_192_gcm<>;

		using my_algo_59 = cipher::aria_256_ecb<>;
		using my_algo_60 = cipher::aria_256_cbc<>;
		using my_algo_61 = cipher::aria_256_ofb<>;
		using my_algo_62 = cipher::aria_256_ctr<>;
		using my_algo_63 = cipher::aria_256_cfb<>;
		using my_algo_64 = cipher::aria_256_cfb1<>;
		using my_algo_65 = cipher::aria_256_cfb8<>;
		using my_algo_66 = cipher::aria_256_cfb128<>;
		using my_algo_67 = cipher::aria_256_gcm<>;

		using my_algo_68 = cipher::camellia_128_ecb<>;
		using my_algo_69 = cipher::camellia_128_cbc<>;
		using my_algo_70 = cipher::camellia_128_ofb<>;
		using my_algo_71 = cipher::camellia_128_ctr<>;
		using my_algo_72 = cipher::camellia_128_cfb<>;
		using my_algo_73 = cipher::camellia_128_cfb1<>;
		using my_algo_74 = cipher::camellia_128_cfb8<>;
		using my_algo_75 = cipher::camellia_128_cfb128<>;

		using my_algo_76 = cipher::camellia_192_ecb<>;
		using my_algo_77 = cipher::camellia_192_cbc<>;
		using my_algo_78 = cipher::camellia_192_ofb<>;
		using my_algo_79 = cipher::camellia_192_ctr<>;
		using my_algo_80 = cipher::camellia_192_cfb<>;
		using my_algo_81 = cipher::camellia_192_cfb1<>;
		using my_algo_82 = cipher::camellia_192_cfb8<>;
		using my_algo_83 = cipher::camellia_192_cfb128<>;

		using my_algo_84 = cipher::camellia_256_ecb<>;
		using my_algo_85 = cipher::camellia_256_cbc<>;
		using my_algo_86 = cipher::camellia_256_ofb<>;
		using my_algo_87 = cipher::camellia_256_ctr<>;
		using my_algo_88 = cipher::camellia_256_cfb<>;
		using my_algo_89 = cipher::camellia_256_cfb1<>;
		using my_algo_90 = cipher::camellia_256_cfb8<>;
		using my_algo_91 = cipher::camellia_256_cfb128<>;

		using my_algo_92 = cipher::sm4_ecb<>;
		using my_algo_93 = cipher::sm4_cbc<>;
		using my_algo_94 = cipher::sm4_ofb<>;
		using my_algo_95 = cipher::sm4_ctr<>;
		using my_algo_96 = cipher::sm4_cfb<>;
		using my_algo_97 = cipher::sm4_cfb128<>;

		using my_algo_98 = cipher::chacha_20<>;
		using my_algo_99 = cipher::chacha_20_poly_1305<>;

		const auto encrypt = my_data
			| my_algo_00::using_password(my_pass).encrypt
			| my_algo_01::using_password(my_pass).encrypt
			| my_algo_02::using_password(my_pass).encrypt
			| my_algo_03::using_password(my_pass).encrypt
			| my_algo_04::using_password(my_pass).encrypt
			| my_algo_05::using_password(my_pass).encrypt
			| my_algo_06::using_password(my_pass).encrypt
			| my_algo_07::using_password(my_pass).encrypt
			| my_algo_08::using_password(my_pass).encrypt
			| my_algo_09::using_password(my_pass).encrypt
			| my_algo_10::using_password(my_pass).encrypt
			| my_algo_11::using_password(my_pass).encrypt
			| my_algo_12::using_password(my_pass).encrypt
			| my_algo_13::using_password(my_pass).encrypt
			| my_algo_14::using_password(my_pass).encrypt
			| my_algo_15::using_password(my_pass).encrypt
			| my_algo_16::using_password(my_pass).encrypt
			| my_algo_17::using_password(my_pass).encrypt
			| my_algo_18::using_password(my_pass).encrypt
			| my_algo_19::using_password(my_pass).encrypt
			| my_algo_20::using_password(my_pass).encrypt
			| my_algo_21::using_password(my_pass).encrypt
			| my_algo_22::using_password(my_pass).encrypt
			| my_algo_23::using_password(my_pass).encrypt
			| my_algo_24::using_password(my_pass).encrypt
			| my_algo_25::using_password(my_pass).encrypt
			| my_algo_26::using_password(my_pass).encrypt
			| my_algo_27::using_password(my_pass).encrypt
			| my_algo_28::using_password(my_pass).encrypt
			| my_algo_29::using_password(my_pass).encrypt
			| my_algo_30::using_password(my_pass).encrypt
			| my_algo_31::using_password(my_pass).encrypt
			| my_algo_32::using_password(my_pass).encrypt
			| my_algo_33::using_password(my_pass).encrypt
			| my_algo_34::using_password(my_pass).encrypt
			| my_algo_35::using_password(my_pass).encrypt
			| my_algo_36::using_password(my_pass).encrypt
			| my_algo_37::using_password(my_pass).encrypt
			| my_algo_38::using_password(my_pass).encrypt
			| my_algo_39::using_password(my_pass).encrypt
			| my_algo_40::using_password(my_pass).encrypt
			| my_algo_41::using_password(my_pass).encrypt
			| my_algo_42::using_password(my_pass).encrypt
			| my_algo_43::using_password(my_pass).encrypt
			| my_algo_44::using_password(my_pass).encrypt
			| my_algo_45::using_password(my_pass).encrypt
			| my_algo_46::using_password(my_pass).encrypt
			| my_algo_47::using_password(my_pass).encrypt
			| my_algo_48::using_password(my_pass).encrypt
			| my_algo_49::using_password(my_pass).encrypt
			| my_algo_50::using_password(my_pass).encrypt
			| my_algo_51::using_password(my_pass).encrypt
			| my_algo_52::using_password(my_pass).encrypt
			| my_algo_53::using_password(my_pass).encrypt
			| my_algo_54::using_password(my_pass).encrypt
			| my_algo_55::using_password(my_pass).encrypt
			| my_algo_56::using_password(my_pass).encrypt
			| my_algo_57::using_password(my_pass).encrypt
			| my_algo_58::using_password(my_pass).encrypt
			| my_algo_59::using_password(my_pass).encrypt
			| my_algo_60::using_password(my_pass).encrypt
			| my_algo_61::using_password(my_pass).encrypt
			| my_algo_62::using_password(my_pass).encrypt
			| my_algo_63::using_password(my_pass).encrypt
			| my_algo_64::using_password(my_pass).encrypt
			| my_algo_65::using_password(my_pass).encrypt
			| my_algo_66::using_password(my_pass).encrypt
			| my_algo_67::using_password(my_pass).encrypt
			| my_algo_68::using_password(my_pass).encrypt
			| my_algo_69::using_password(my_pass).encrypt
			| my_algo_70::using_password(my_pass).encrypt
			| my_algo_71::using_password(my_pass).encrypt
			| my_algo_72::using_password(my_pass).encrypt
			| my_algo_73::using_password(my_pass).encrypt
			| my_algo_74::using_password(my_pass).encrypt
			| my_algo_75::using_password(my_pass).encrypt
			| my_algo_76::using_password(my_pass).encrypt
			| my_algo_77::using_password(my_pass).encrypt
			| my_algo_78::using_password(my_pass).encrypt
			| my_algo_79::using_password(my_pass).encrypt
			| my_algo_80::using_password(my_pass).encrypt
			| my_algo_81::using_password(my_pass).encrypt
			| my_algo_82::using_password(my_pass).encrypt
			| my_algo_83::using_password(my_pass).encrypt
			| my_algo_84::using_password(my_pass).encrypt
			| my_algo_85::using_password(my_pass).encrypt
			| my_algo_86::using_password(my_pass).encrypt
			| my_algo_87::using_password(my_pass).encrypt
			| my_algo_88::using_password(my_pass).encrypt
			| my_algo_89::using_password(my_pass).encrypt
			| my_algo_90::using_password(my_pass).encrypt
			| my_algo_91::using_password(my_pass).encrypt
			| my_algo_92::using_password(my_pass).encrypt
			| my_algo_93::using_password(my_pass).encrypt
			| my_algo_94::using_password(my_pass).encrypt
			| my_algo_95::using_password(my_pass).encrypt
			| my_algo_96::using_password(my_pass).encrypt
			| my_algo_97::using_password(my_pass).encrypt
			| my_algo_98::using_password(my_pass).encrypt
			| my_algo_99::using_password(my_pass).encrypt;

		const auto decrypt = encrypt 
			| my_algo_99::using_password(my_pass).decrypt
			| my_algo_98::using_password(my_pass).decrypt
			| my_algo_97::using_password(my_pass).decrypt
			| my_algo_96::using_password(my_pass).decrypt
			| my_algo_95::using_password(my_pass).decrypt
			| my_algo_94::using_password(my_pass).decrypt
			| my_algo_93::using_password(my_pass).decrypt
			| my_algo_92::using_password(my_pass).decrypt
			| my_algo_91::using_password(my_pass).decrypt
			| my_algo_90::using_password(my_pass).decrypt
			| my_algo_89::using_password(my_pass).decrypt
			| my_algo_88::using_password(my_pass).decrypt
			| my_algo_87::using_password(my_pass).decrypt
			| my_algo_86::using_password(my_pass).decrypt
			| my_algo_85::using_password(my_pass).decrypt
			| my_algo_84::using_password(my_pass).decrypt
			| my_algo_83::using_password(my_pass).decrypt
			| my_algo_82::using_password(my_pass).decrypt
			| my_algo_81::using_password(my_pass).decrypt
			| my_algo_80::using_password(my_pass).decrypt
			| my_algo_79::using_password(my_pass).decrypt
			| my_algo_78::using_password(my_pass).decrypt
			| my_algo_77::using_password(my_pass).decrypt
			| my_algo_76::using_password(my_pass).decrypt
			| my_algo_75::using_password(my_pass).decrypt
			| my_algo_74::using_password(my_pass).decrypt
			| my_algo_73::using_password(my_pass).decrypt
			| my_algo_72::using_password(my_pass).decrypt
			| my_algo_71::using_password(my_pass).decrypt
			| my_algo_70::using_password(my_pass).decrypt
			| my_algo_69::using_password(my_pass).decrypt
			| my_algo_68::using_password(my_pass).decrypt
			| my_algo_67::using_password(my_pass).decrypt
			| my_algo_66::using_password(my_pass).decrypt
			| my_algo_65::using_password(my_pass).decrypt
			| my_algo_64::using_password(my_pass).decrypt
			| my_algo_63::using_password(my_pass).decrypt
			| my_algo_62::using_password(my_pass).decrypt
			| my_algo_61::using_password(my_pass).decrypt
			| my_algo_60::using_password(my_pass).decrypt
			| my_algo_59::using_password(my_pass).decrypt
			| my_algo_58::using_password(my_pass).decrypt
			| my_algo_57::using_password(my_pass).decrypt
			| my_algo_56::using_password(my_pass).decrypt
			| my_algo_55::using_password(my_pass).decrypt
			| my_algo_54::using_password(my_pass).decrypt
			| my_algo_53::using_password(my_pass).decrypt
			| my_algo_52::using_password(my_pass).decrypt
			| my_algo_51::using_password(my_pass).decrypt
			| my_algo_50::using_password(my_pass).decrypt
			| my_algo_49::using_password(my_pass).decrypt
			| my_algo_48::using_password(my_pass).decrypt
			| my_algo_47::using_password(my_pass).decrypt
			| my_algo_46::using_password(my_pass).decrypt
			| my_algo_45::using_password(my_pass).decrypt
			| my_algo_44::using_password(my_pass).decrypt
			| my_algo_43::using_password(my_pass).decrypt
			| my_algo_42::using_password(my_pass).decrypt
			| my_algo_41::using_password(my_pass).decrypt
			| my_algo_40::using_password(my_pass).decrypt
			| my_algo_39::using_password(my_pass).decrypt
			| my_algo_38::using_password(my_pass).decrypt
			| my_algo_37::using_password(my_pass).decrypt
			| my_algo_36::using_password(my_pass).decrypt
			| my_algo_35::using_password(my_pass).decrypt
			| my_algo_34::using_password(my_pass).decrypt
			| my_algo_33::using_password(my_pass).decrypt
			| my_algo_32::using_password(my_pass).decrypt
			| my_algo_31::using_password(my_pass).decrypt
			| my_algo_30::using_password(my_pass).decrypt
			| my_algo_29::using_password(my_pass).decrypt
			| my_algo_28::using_password(my_pass).decrypt
			| my_algo_27::using_password(my_pass).decrypt
			| my_algo_26::using_password(my_pass).decrypt
			| my_algo_25::using_password(my_pass).decrypt
			| my_algo_24::using_password(my_pass).decrypt
			| my_algo_23::using_password(my_pass).decrypt
			| my_algo_22::using_password(my_pass).decrypt
			| my_algo_21::using_password(my_pass).decrypt
			| my_algo_20::using_password(my_pass).decrypt
			| my_algo_19::using_password(my_pass).decrypt
			| my_algo_18::using_password(my_pass).decrypt
			| my_algo_17::using_password(my_pass).decrypt
			| my_algo_16::using_password(my_pass).decrypt
			| my_algo_15::using_password(my_pass).decrypt
			| my_algo_14::using_password(my_pass).decrypt
			| my_algo_13::using_password(my_pass).decrypt
			| my_algo_12::using_password(my_pass).decrypt
			| my_algo_11::using_password(my_pass).decrypt
			| my_algo_10::using_password(my_pass).decrypt
			| my_algo_09::using_password(my_pass).decrypt
			| my_algo_08::using_password(my_pass).decrypt
			| my_algo_07::using_password(my_pass).decrypt
			| my_algo_06::using_password(my_pass).decrypt
			| my_algo_05::using_password(my_pass).decrypt
			| my_algo_04::using_password(my_pass).decrypt
			| my_algo_03::using_password(my_pass).decrypt
			| my_algo_02::using_password(my_pass).decrypt
			| my_algo_01::using_password(my_pass).decrypt
			| my_algo_00::using_password(my_pass).decrypt;

		std::println("Symmetric Encryption : {}", decrypt == my_data);
	}
}
