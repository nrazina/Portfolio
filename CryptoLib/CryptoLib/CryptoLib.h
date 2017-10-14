#pragma once
#pragma comment(lib, "NTL.lib") 

typedef unsigned char BYTE;

#include <iostream>
#include <vector>
#include <NTL/ZZ_p.h>

using namespace std;
using namespace NTL;

#ifdef CRYPTOLIB_EXPORTS
#define CRYPTOLIB_API __declspec(dllexport) 
#else
#define CRYPTOLIB_API __declspec(dllimport) 
#endif

class RC5
{
	static const int b = 16; //длина ключа
	static const int w = 32; //половина длины блока
	static const int R = 12; //количество раундов шифрования

public:

	vector<unsigned int> new_key_for_coding;
	vector<BYTE> rest; //для шифрования, остаток от блока

	int padding; // 1 = PKCS#5, 2 = ISO 10126, 3 = ANSI X.923 
	int crypt; // 1 - ECB, 2 - CBC, 3 - CNT(CTR), 4 - CFB
	unsigned int rest_size;
	unsigned long long int Lctr; //counter for CTR
	unsigned int IV_A;
	unsigned int IV_B;

	CRYPTOLIB_API vector<BYTE> RC5_gen_key();
	CRYPTOLIB_API void RC5_init(int padding_mode, int crypt_mode, vector<BYTE> key, unsigned int IV_high = 0, unsigned int IV_low = 0);
	CRYPTOLIB_API vector<BYTE> RC5_update(vector<BYTE> data, bool mode); // mode: 1 -шифрование, 0 - расшифрование
	CRYPTOLIB_API vector<BYTE> RC5_doFinal(vector<BYTE> data, bool mode); // mode: 1 -шифрование, 0 - расшифрование
};

class HMAC
{
	static const int block_size = 64; 

public:
	static const int L = 32; //размер строки, возвращаемой хэш-функцией
	int b_hash; //длина ключа
	vector<BYTE> hash_message;

	vector<BYTE> ipad, opad;
	vector<BYTE> Si, So;
	vector<unsigned int> A, B, C;

	CRYPTOLIB_API vector<BYTE> HMAC_gen_key();
	CRYPTOLIB_API void HMAC_init(vector<BYTE> key);
	CRYPTOLIB_API vector<BYTE> HMAC_update(vector<BYTE> data);
	CRYPTOLIB_API vector<BYTE> HMAC_doFinal(vector<BYTE> data);

	CRYPTOLIB_API void hash_init();
	CRYPTOLIB_API void hash_update(vector<BYTE> K);
	CRYPTOLIB_API vector<BYTE> hash_doFinal();
};


class dot
{
public:
	ZZ_p x;
	ZZ_p y;
	bool is_inf;
	dot()
	{
		ZZ z;
		z = to_ZZ("115792089210356248762697446949407573530086143415290314195533631308867097853951");
		ZZ_p::init(z);
		x = 0;
		y = 0;
		is_inf = false;
	}
	dot(ZZ_p a, ZZ_p b)
	{
		ZZ z;
		z = to_ZZ("115792089210356248762697446949407573530086143415290314195533631308867097853951");
		ZZ_p::init(z);
		x = a;
		y = b;
		if (b == 0)
			is_inf = true;
		else
			is_inf = false;
	}
	dot operator +(dot A)
	{
		if ((*this).is_inf == true)
			return dot(A);
		if (A.is_inf == true)
			return *this;
		ZZ z;
		z = to_ZZ("115792089210356248762697446949407573530086143415290314195533631308867097853951");
		ZZ_p::init(z);
		ZZ_p a;
		a = to_ZZ_p(-3);
		dot R;
		ZZ_p s;
		if (x != A.x)
		{
			s = (A.y - y) / (A.x - x);
			R.x = s * s - A.x - x;
			R.y = -A.y + s * (A.x - R.x);
			R.is_inf = false;
		}
		else if (y == A.y && y != 0)
		{
			s = (3 * A.x * A.x + a) / (2 * A.y);
			R.x = s * s - 2 * A.x;
			R.y = -A.y + s * (A.x - R.x);
			R.is_inf = false;
		}
		else
		{
			R.x = x;
			R.y = 0;
			R.is_inf = true;
		}
		return R;
	}
	static dot multiply(ZZ_p k, dot A) //считаем k положительным, так как по программе другим оно быть не может
	{
		ZZ z;
		z = to_ZZ("115792089210356248762697446949407573530086143415290314195533631308867097853951");
		ZZ_p::init(z);
		if (A.is_inf == true)
			return dot(to_ZZ_p(0), to_ZZ_p(0));
		ZZ t;
		conv(t, k);
		dot tmp = A;
		t--;
		while (t > 0)
		{
			if (t % 2 != 0)
			{
				if (tmp.x == A.x || tmp.y == A.y)
					tmp = tmp + tmp;
				else
					tmp = tmp + A;
				t--;
			}
			t = t / 2;
			A = A + A;
		}
		return tmp;
	}
};

class ECDSA
{
	ZZ p;
	ZZ_p a;
	ZZ_p b; 
	ZZ_p n_p;
public:
	ZZ n;
	dot G;
	ZZ_p secret_key;

	ECDSA()
	{
		ZZ z;
		p = to_ZZ("115792089210356248762697446949407573530086143415290314195533631308867097853951");
		ZZ_p::init(p);
		ZZ_p xG, yG;
		z = 6;		
		z *= 16;		z += 11;	z *= 16;		z += 1;
		z *= 16;		z += 7;		z *= 16;		z += 13;
		z *= 16;		z += 1;		z *= 16;		z += 15;
		z *= 16;		z += 2;		z *= 16;		z += 14;
		z *= 16;		z += 1;		z *= 16;		z += 2;
		z *= 16;     	z += 12;	z *= 16;		z += 4;
		z *= 16;		z += 2;		z *= 16;		z += 4;
		z *= 16;		z += 7;		z *= 16;		z += 15;
		z *= 16;		z += 8;		z *= 16;		z += 11;
		z *= 16;		z += 12;	z *= 16;		z += 14;
		z *= 16;		z += 6;		z *= 16;		z += 14;
		z *= 16;		z += 5;		z *= 16;		z += 6;
		z *= 16;		z += 3;		z *= 16;		z += 10;
		z *= 16;		z += 4;		z *= 16;		z += 4;
		z *= 16;		z += 0;		z *= 16;		z += 15;
		z *= 16;		z += 2;		z *= 16;		z += 7;
		z *= 16;		z += 7;		z *= 16;		z += 0;
		z *= 16;		z += 3;		z *= 16;		z += 7;
		z *= 16;		z += 13;	z *= 16;		z += 8;
		z *= 16;		z += 1; 	z *= 16;		z += 2;
		z *= 16;		z += 13;	z *= 16;		z += 14;
		z *= 16;		z += 11;	z *= 16;		z += 3;
		z *= 16;		z += 3;		z *= 16;		z += 10;
		z *= 16;		z += 0;		z *= 16;		z += 15;
		z *= 16;		z += 4;		z *= 16;		z += 10;
		z *= 16;		z += 1;		z *= 16;		z += 3;
		z *= 16;		z += 9;		z *= 16;		z += 4;
		z *= 16;		z += 5;		z *= 16;		z += 13;
		z *= 16;		z += 8;		z *= 16;		z += 9;
		z *= 16;		z += 8;		z *= 16;		z += 12;
		z *= 16;		z += 2;		z *= 16;		z += 9;
		z *= 16;        z += 6;
		// 0x 6 B1 7D 1F 2E 12 C4 24 7F 8B CE 6E 56 3A 44 0F 27 70 37 D8 12 DE B3 3A 0F 4A 13 94 5D 89 8C 29 6
		xG = to_ZZ_p(z);
		z = 4;
		z *= 16;		z += 15;	z *= 16;		z += 14;
		z *= 16;		z += 3;		z *= 16;		z += 4;
		z *= 16;		z += 2;		z *= 16;		z += 14;
		z *= 16;		z += 2;		z *= 16;		z += 15;
		z *= 16;		z += 14;	z *= 16;		z += 1;
		z *= 16;     	z += 10;	z *= 16;		z += 7;
		z *= 16;		z += 15;	z *= 16;		z += 9;
		z *= 16;		z += 11;	z *= 16;		z += 8;
		z *= 16;		z += 14;	z *= 16;		z += 14;
		z *= 16;		z += 7;	    z *= 16;		z += 14;
		z *= 16;		z += 11;	z *= 16;		z += 4;
		z *= 16;		z += 10;	z *= 16;		z += 7;
		z *= 16;		z += 12;	z *= 16;		z += 0;
		z *= 16;		z += 15;	z *= 16;		z += 9;
		z *= 16;		z += 14;	z *= 16;		z += 1;
		z *= 16;		z += 6;		z *= 16;		z += 2;
		z *= 16;		z += 11;	z *= 16;		z += 12;
		z *= 16;		z += 14;	z *= 16;		z += 3;
		z *= 16;		z += 3;	    z *= 16;		z += 5;
		z *= 16;		z += 7; 	z *= 16;		z += 6;
		z *= 16;		z += 11;	z *= 16;		z += 3;
		z *= 16;		z += 1;	    z *= 16;		z += 5;
		z *= 16;		z += 14;	z *= 16;		z += 12;
		z *= 16;		z += 14;	z *= 16;		z += 12;
		z *= 16;		z += 11;	z *= 16;		z += 11;
		z *= 16;		z += 6;		z *= 16;		z += 4;
		z *= 16;		z += 0;		z *= 16;		z += 6;
		z *= 16;		z += 8;		z *= 16;		z += 3;
		z *= 16;		z += 7;		z *= 16;		z += 11;
		z *= 16;		z += 15;	z *= 16;		z += 5;
		z *= 16;		z += 1;		z *= 16;		z += 15;
		z *= 16;        z += 5;
		//0x4 FE 34 2E 2F E1 A7 F9 B8 EE 7E B4 A7 C0 F9 E1 62 BC E3 35 76 B3 15 EC EC BB 64 06 83 7B F5 1F 5
		yG = to_ZZ_p(z);
		G = dot(xG, yG);
		G.is_inf = false;
		a = to_ZZ_p(-3);
		z = 5;
		z *= 16;		z += 10;	z *= 16;		z += 12;
		z *= 16;		z += 6;		z *= 16;		z += 3;
		z *= 16;		z += 5;		z *= 16;		z += 13;
		z *= 16;		z += 8;		z *= 16;		z += 10;
		z *= 16;		z += 10;	z *= 16;		z += 3;
		z *= 16;     	z += 10;	z *= 16;		z += 9;
		z *= 16;		z += 3;		z *= 16;		z += 14;
		z *= 16;		z += 7;		z *= 16;		z += 11;
		z *= 16;		z += 3;		z *= 16;		z += 14;
		z *= 16;		z += 11;	z *= 16;		z += 11;
		z *= 16;		z += 13;	z *= 16;		z += 5;
		z *= 16;		z += 5;		z *= 16;		z += 7;
		z *= 16;		z += 6;		z *= 16;		z += 9;
		z *= 16;		z += 8;		z *= 16;		z += 8;
		z *= 16;		z += 6;		z *= 16;		z += 11;
		z *= 16;		z += 12;	z *= 16;		z += 6;
		z *= 16;		z += 5;		z *= 16;		z += 1;
		z *= 16;		z += 13;	z *= 16;		z += 0;
		z *= 16;		z += 6;  	z *= 16;		z += 11;
		z *= 16;		z += 0; 	z *= 16;		z += 12;
		z *= 16;		z += 12;	z *= 16;		z += 5;
		z *= 16;		z += 3;	    z *= 16;		z += 11;
		z *= 16;		z += 0;		z *= 16;		z += 15;
		z *= 16;		z += 6;		z *= 16;		z += 3;
		z *= 16;		z += 11;	z *= 16;		z += 12;
		z *= 16;		z += 14;	z *= 16;		z += 3;
		z *= 16;		z += 12;	z *= 16;		z += 3;
		z *= 16;		z += 14;	z *= 16;		z += 2;
		z *= 16;		z += 7;		z *= 16;		z += 13;
		z *= 16;		z += 2;		z *= 16;		z += 6;
		z *= 16;		z += 0;		z *= 16;		z += 4;
		z *= 16;        z += 11;
		//0x5 AC 63 5D 8A A3 A9 3E 7B 3E BB D5 57 69 88 6B C6 51 D0 6B 0C C5 3B 0F 63 BC E3 C3 E2 7D 26 04 B
		b = to_ZZ_p(z);
		n = to_ZZ("115792089210356248762697446949407573529996955224135760342422259061068512044369");
		n_p = to_ZZ_p(n);
	}

	CRYPTOLIB_API pair<ZZ_p, dot> ECDSA_gen_keys();
	CRYPTOLIB_API void ECDSA_save(ZZ_p private_key, vector<BYTE> password);
	CRYPTOLIB_API ZZ_p ECDSA_load(const char *s, vector<BYTE> password);
	CRYPTOLIB_API void ECDSA_init_sign(const char *s, vector<BYTE> password);
	CRYPTOLIB_API bool ECDSA_init_check(dot public_key);
	CRYPTOLIB_API ZZ_p ECDSA_update(vector<BYTE> data);
	CRYPTOLIB_API pair<ZZ_p, ZZ_p> ECDSA_sign(vector<BYTE> data);
	CRYPTOLIB_API bool ECDSA_verify(vector<BYTE> data, dot public_key, ZZ r, ZZ s);
};

class DH
{
	ZZ p;
	ZZ_p a;
	ZZ_p b;
	ZZ n;
	ZZ_p n_p;
	ZZ_p secret_key;
public:
	dot G;
	dot B_public_key;
	DH()
	{
		ZZ z;
		p = to_ZZ("115792089210356248762697446949407573530086143415290314195533631308867097853951");
		ZZ_p::init(p);
		ZZ_p xG, yG;
		z = 6;
		z *= 16;		z += 11;	z *= 16;		z += 1;
		z *= 16;		z += 7;		z *= 16;		z += 13;
		z *= 16;		z += 1;		z *= 16;		z += 15;
		z *= 16;		z += 2;		z *= 16;		z += 14;
		z *= 16;		z += 1;		z *= 16;		z += 2;
		z *= 16;     	z += 12;	z *= 16;		z += 4;
		z *= 16;		z += 2;		z *= 16;		z += 4;
		z *= 16;		z += 7;		z *= 16;		z += 15;
		z *= 16;		z += 8;		z *= 16;		z += 11;
		z *= 16;		z += 12;	z *= 16;		z += 14;
		z *= 16;		z += 6;		z *= 16;		z += 14;
		z *= 16;		z += 5;		z *= 16;		z += 6;
		z *= 16;		z += 3;		z *= 16;		z += 10;
		z *= 16;		z += 4;		z *= 16;		z += 4;
		z *= 16;		z += 0;		z *= 16;		z += 15;
		z *= 16;		z += 2;		z *= 16;		z += 7;
		z *= 16;		z += 7;		z *= 16;		z += 0;
		z *= 16;		z += 3;		z *= 16;		z += 7;
		z *= 16;		z += 13;	z *= 16;		z += 8;
		z *= 16;		z += 1; 	z *= 16;		z += 2;
		z *= 16;		z += 13;	z *= 16;		z += 14;
		z *= 16;		z += 11;	z *= 16;		z += 3;
		z *= 16;		z += 3;		z *= 16;		z += 10;
		z *= 16;		z += 0;		z *= 16;		z += 15;
		z *= 16;		z += 4;		z *= 16;		z += 10;
		z *= 16;		z += 1;		z *= 16;		z += 3;
		z *= 16;		z += 9;		z *= 16;		z += 4;
		z *= 16;		z += 5;		z *= 16;		z += 13;
		z *= 16;		z += 8;		z *= 16;		z += 9;
		z *= 16;		z += 8;		z *= 16;		z += 12;
		z *= 16;		z += 2;		z *= 16;		z += 9;
		z *= 16;        z += 6;
		// 0x 6 B1 7D 1F 2E 12 C4 24 7F 8B CE 6E 56 3A 44 0F 27 70 37 D8 12 DE B3 3A 0F 4A 13 94 5D 89 8C 29 6
		xG = to_ZZ_p(z);
		z = 4;
		z *= 16;		z += 15;	z *= 16;		z += 14;
		z *= 16;		z += 3;		z *= 16;		z += 4;
		z *= 16;		z += 2;		z *= 16;		z += 14;
		z *= 16;		z += 2;		z *= 16;		z += 15;
		z *= 16;		z += 14;	z *= 16;		z += 1;
		z *= 16;     	z += 10;	z *= 16;		z += 7;
		z *= 16;		z += 15;	z *= 16;		z += 9;
		z *= 16;		z += 11;	z *= 16;		z += 8;
		z *= 16;		z += 14;	z *= 16;		z += 14;
		z *= 16;		z += 7;	    z *= 16;		z += 14;
		z *= 16;		z += 11;	z *= 16;		z += 4;
		z *= 16;		z += 10;	z *= 16;		z += 7;
		z *= 16;		z += 12;	z *= 16;		z += 0;
		z *= 16;		z += 15;	z *= 16;		z += 9;
		z *= 16;		z += 14;	z *= 16;		z += 1;
		z *= 16;		z += 6;		z *= 16;		z += 2;
		z *= 16;		z += 11;	z *= 16;		z += 12;
		z *= 16;		z += 14;	z *= 16;		z += 3;
		z *= 16;		z += 3;	    z *= 16;		z += 5;
		z *= 16;		z += 7; 	z *= 16;		z += 6;
		z *= 16;		z += 11;	z *= 16;		z += 3;
		z *= 16;		z += 1;	    z *= 16;		z += 5;
		z *= 16;		z += 14;	z *= 16;		z += 12;
		z *= 16;		z += 14;	z *= 16;		z += 12;
		z *= 16;		z += 11;	z *= 16;		z += 11;
		z *= 16;		z += 6;		z *= 16;		z += 4;
		z *= 16;		z += 0;		z *= 16;		z += 6;
		z *= 16;		z += 8;		z *= 16;		z += 3;
		z *= 16;		z += 7;		z *= 16;		z += 11;
		z *= 16;		z += 15;	z *= 16;		z += 5;
		z *= 16;		z += 1;		z *= 16;		z += 15;
		z *= 16;        z += 5;
		//0x4 FE 34 2E 2F E1 A7 F9 B8 EE 7E B4 A7 C0 F9 E1 62 BC E3 35 76 B3 15 EC EC BB 64 06 83 7B F5 1F 5
		yG = to_ZZ_p(z);
		G = dot(xG, yG);
		G.is_inf = false;
		a = to_ZZ_p(-3);
		z = 5;
		z *= 16;		z += 10;	z *= 16;		z += 12;
		z *= 16;		z += 6;		z *= 16;		z += 3;
		z *= 16;		z += 5;		z *= 16;		z += 13;
		z *= 16;		z += 8;		z *= 16;		z += 10;
		z *= 16;		z += 10;	z *= 16;		z += 3;
		z *= 16;     	z += 10;	z *= 16;		z += 9;
		z *= 16;		z += 3;		z *= 16;		z += 14;
		z *= 16;		z += 7;		z *= 16;		z += 11;
		z *= 16;		z += 3;		z *= 16;		z += 14;
		z *= 16;		z += 11;	z *= 16;		z += 11;
		z *= 16;		z += 13;	z *= 16;		z += 5;
		z *= 16;		z += 5;		z *= 16;		z += 7;
		z *= 16;		z += 6;		z *= 16;		z += 9;
		z *= 16;		z += 8;		z *= 16;		z += 8;
		z *= 16;		z += 6;		z *= 16;		z += 11;
		z *= 16;		z += 12;	z *= 16;		z += 6;
		z *= 16;		z += 5;		z *= 16;		z += 1;
		z *= 16;		z += 13;	z *= 16;		z += 0;
		z *= 16;		z += 6;  	z *= 16;		z += 11;
		z *= 16;		z += 0; 	z *= 16;		z += 12;
		z *= 16;		z += 12;	z *= 16;		z += 5;
		z *= 16;		z += 3;	    z *= 16;		z += 11;
		z *= 16;		z += 0;		z *= 16;		z += 15;
		z *= 16;		z += 6;		z *= 16;		z += 3;
		z *= 16;		z += 11;	z *= 16;		z += 12;
		z *= 16;		z += 14;	z *= 16;		z += 3;
		z *= 16;		z += 12;	z *= 16;		z += 3;
		z *= 16;		z += 14;	z *= 16;		z += 2;
		z *= 16;		z += 7;		z *= 16;		z += 13;
		z *= 16;		z += 2;		z *= 16;		z += 6;
		z *= 16;		z += 0;		z *= 16;		z += 4;
		z *= 16;        z += 11;
		//0x5 AC 63 5D 8A A3 A9 3E 7B 3E BB D5 57 69 88 6B C6 51 D0 6B 0C C5 3B 0F 63 BC E3 C3 E2 7D 26 04 B
		b = to_ZZ_p(z);
		n = to_ZZ("115792089210356248762697446949407573529996955224135760342422259061068512044369");
		n_p = to_ZZ_p(n);
	}
	CRYPTOLIB_API pair<ZZ_p, dot> DH_gen_keys();
	CRYPTOLIB_API void DH_save(ZZ_p private_key, vector<BYTE> password);
	CRYPTOLIB_API ZZ_p DH_load(const char *s, vector<BYTE> password);
	CRYPTOLIB_API void DH_init(const char *s, vector<BYTE> password);
	CRYPTOLIB_API void DH_doPhase(dot public_key);
	CRYPTOLIB_API pair<ZZ_p, dot> DH_genSecret();
};