// CryptoLib.cpp: определяет экспортированные функции для приложения DLL.
//
#include "stdafx.h"

#include "CryptoLib.h"
#include <cmath>
#include "Wincrypt.h"
#include <fstream>

using namespace std;

unsigned long ROL(unsigned long a, int offset)
{
	return a << (offset & 31) | a >> (32 - (offset & 31));
}

unsigned long ROR(unsigned long a, int offset)
{
	return a >> (offset & 31) | a << (32 - (offset & 31));
}


vector<BYTE> RC5::RC5_gen_key()
{
	HCRYPTPROV   hCryptProv = 0;
	if (!CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0))
		cout << "Error in CryptAcquireContext" << endl;
	BYTE key_for_coding[b];
	if (!CryptGenRandom(hCryptProv, b, key_for_coding))
		cout << "Error in CryptGenRandom" << endl;
	int i;
	vector<BYTE> key(b);
	for (i = 0; i < b; i++)
	{
		key[i] = key_for_coding[i];
	}
	if (!CryptReleaseContext(hCryptProv, 0))
		cout << "Error in CryptReleaseContext" << endl;
	return key;
}

void RC5::RC5_init(int padding_mode, int crypt_mode, vector<BYTE> key, unsigned int IV_high, unsigned int IV_low)
{
	padding = padding_mode;
	crypt = crypt_mode;
	unsigned int P = 0xB7E15163;
	unsigned int Q = 0x9E3779B9;
	int c = ceil(b / (w / 8)); // = 4
	int i, j;
	IV_A = IV_high;
	IV_B = IV_low;
	Lctr = 0;

	if (b == 0 && c == 0) 
	{
		c = 1;
	}
	vector<BYTE> L(c * (w / 8));

	int res = b % (w / 8);
	for (i = 0; i < c - 1; i++)
	{
		for (j = 0; j < (w / 8); j++)
			L[i * (w / 8) + j] = key[i * (w / 8) + j];
	}

	if (b == 0)
	{
		for (j = 0; j < w / 8; j++)
			L[j] = 0x0;
	}
	else if (res != 0)
	{
		for (j = 0; j < res; j++)
			L[(c - 1) * (w / 8) + j] = key[(c - 1) * (w / 8) + j];
		for (j = res; j < (w / 8); j++)
			L[(c - 1) * (w / 8) + j] = 0x0;
	}
	else
	{
		for (j = 0; j < w / 8; j++)
			L[(c - 1) * (w / 8) + j] = key[(c - 1) * (w / 8) + j];
	}
	BYTE z;
	for (i = 0; i < c; i++)
	{
		for (j = 0; j < (w / 8) / 2; j++)
		{
			z = L[i * (w / 8) + j];
			L[i * (w / 8) + j] = L[(i + 1) * (w / 8) - j - 1];
			L[(i + 1) * (w / 8) - j - 1] = z;
		}
	}

	vector<unsigned int> S(2 * R + 2);
	S[0] = P;
	for (i = 1; i < 2 * R + 2; i++)
	{
		S[i] = (S[i - 1] + Q);
	}

	int N = max(3 * c, 3 * 2 * (R + 1));
	int k, t;
	unsigned int G, H, tmp;
	i = j = 0;
	G = H = 0;
	for (k = 0; k < N; k++)
	{
		G = S[i] = ROL((S[i] + G + H), 3);
		tmp = 0;
		for (t = 0; t < w / 8; t++)
		{
			tmp *= 256;
			tmp += L[j * (w / 8) + t];
		}
		tmp = ROL((tmp + G + H), (G + H));
		H = tmp;
		for (t = w / 8 - 1; t >= 0; t--)
		{
			L[j * (w / 8) + t] = tmp & 255;
			tmp /= 256;
		}
		i = (i + 1) % (2 * R + 2);
		j = (j + 1) % c;
	}
	new_key_for_coding.resize(S.size());
	new_key_for_coding = S;
}

vector<BYTE> RC5::RC5_update(vector<BYTE> data, bool mode)
{
	unsigned int i, j;
	unsigned int A, B;
	unsigned int tmp_A, tmp_B;
	vector<BYTE> result;
	rest_size = rest.size();
	unsigned int num_of_blocks = (data.size() + rest_size) / 8;
	unsigned int res = (data.size() + rest_size) % 8;
	int counter = 8 - rest_size;
	A = 0;
	B = 0;
	if (data.size() + rest_size >= 8)
	{
		if (rest_size <= 4) //остаток полностью поместится в А
		{
			for (j = 0; j < rest_size; j++)
			{
				A <<= 8;
				A += rest[j];
			}
			for (j = rest_size; j < 4; j++)
			{
				A <<= 8;
				A += data[j - rest_size];
			}
			for (j = 4; j < 8; j++)
			{
				B <<= 8;
				B += data[j - rest_size];
			}
		}
		else
		{
			for (j = 0; j < 4; j++)
			{
				A <<= 8;
				A += rest[j];
			}
			for (j = 4; j < rest_size; j++)
			{
				B <<= 8;
				B += rest[j];
			}
			for (j = rest_size; j < 8; j++)
			{
				B <<= 8;
				B += data[j - rest_size];
			}
		}

		for (j = 0; j < num_of_blocks; j++)
		{
			if (mode)
			{
				if (crypt == 1) //ECB
				{
					A = (A + new_key_for_coding[0]);
					B = (B + new_key_for_coding[1]);
					for (i = 1; i <= R; i++)
					{
						A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
						B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
					}
				}
				else if (crypt == 2) //CBC
				{
					A ^= IV_A;
					B ^= IV_B;
					A = (A + new_key_for_coding[0]);
					B = (B + new_key_for_coding[1]);
					for (i = 1; i <= R; i++)
					{
						A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
						B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
					}
					IV_A = A;
					IV_B = B;
				}
				else if (crypt == 3) //CNT
				{
					tmp_A = A;
					tmp_B = B;
					A = ((IV_A >> 16) << 16) | (((Lctr << 16) >> 48) & 4294967295); //max unsigned int
					B = ((IV_B >> 16) << 16) | (((Lctr << 48) >> 48) & 4294967295);
					A = (A + new_key_for_coding[0]);
					B = (B + new_key_for_coding[1]);
					for (i = 1; i <= R; i++)
					{
						A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
						B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
					}
					A ^= tmp_A;
					B ^= tmp_B;
					Lctr++;
				}
				else // CFB
				{
					tmp_A = A;
					tmp_B = B;
					A = IV_A;
					B = IV_B;
					A = (A + new_key_for_coding[0]);
					B = (B + new_key_for_coding[1]);
					for (i = 1; i <= R; i++)
					{
						A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
						B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
					}
					IV_A = tmp_A ^ A;
					IV_B = tmp_B ^ B;
					A = IV_A;
					B = IV_B;
				}
			}
			else
			{
				if (crypt == 1)
				{
					for (i = R; i >= 1; i--)
					{
						B = ROR((B - new_key_for_coding[2 * i + 1]), A) ^ A;
						A = ROR((A - new_key_for_coding[2 * i]), B) ^ B;
					}
					B = (B - new_key_for_coding[1]);
					A = (A - new_key_for_coding[0]);
				}
				else if (crypt == 2)
				{
					tmp_A = A;
					tmp_B = B;
					for (i = R; i >= 1; i--)
					{
						B = ROR((B - new_key_for_coding[2 * i + 1]), A) ^ A;
						A = ROR((A - new_key_for_coding[2 * i]), B) ^ B;
					}
					B = (B - new_key_for_coding[1]);
					A = (A - new_key_for_coding[0]);
					A ^= IV_A;
					B ^= IV_B;
					IV_A = tmp_A;
					IV_B = tmp_B;
				}
				else if (crypt == 3)
				{
					tmp_A = A;
					tmp_B = B;
					A = ((IV_A >> 16) << 16) | (((Lctr << 16) >> 48) & 4294967295); //max unsigned int
					B = ((IV_B >> 16) << 16) | (((Lctr << 48) >> 48) & 4294967295);
					A = (A + new_key_for_coding[0]);
					B = (B + new_key_for_coding[1]);
					for (i = 1; i <= R; i++)
					{
						A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
						B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
					}
					A ^= tmp_A;
					B ^= tmp_B;
					Lctr++;
				}
				else
				{
					tmp_A = A;
					tmp_B = B;
					A = IV_A;
					B = IV_B;
					A = (A + new_key_for_coding[0]);
					B = (B + new_key_for_coding[1]);
					for (i = 1; i <= R; i++)
					{
						A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
						B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
					}
					A ^= tmp_A;
					B ^= tmp_B;
					IV_A = tmp_A;
					IV_B = tmp_B;
				}
			}
			result.push_back(A >> 24 & 255);
			A <<= 8;
			A >>= 8;
			result.push_back(A >> 16 & 255);
			A <<= 16;
			A >>= 16;
			result.push_back(A >> 8 & 255);
			A <<= 24;
			A >>= 24;
			result.push_back(A & 255);

			result.push_back(B >> 24 & 255);
			B <<= 8;
			B >>= 8;
			result.push_back(B >> 16 & 255);
			B <<= 16;
			B >>= 16;
			result.push_back(B >> 8 & 255);
			B <<= 24;
			B >>= 24;
			result.push_back(B & 255);

			if (j != num_of_blocks - 1)
			{
				A = 0;
				B = 0;
				for (i = 0; i < 4; i++)
				{
					A <<= 8;
					A += data[i + counter];
				}
				for (i = 4; i < 8; i++)
				{
					B <<= 8;
					B += data[i + counter];
				}
			}
			counter += 8;
		}
		rest.resize(res);
		for (j = 0; j < res; j++)
		{
			rest[j] = data[num_of_blocks * 8 + j - rest_size];
		}
		rest_size = res;
	}
	else
	{
		for (j = 0; j < data.size(); j++)
		{
			rest.push_back(data[j]);
		}
		rest_size = data.size() + rest_size;
	}
	return result;
}

vector<BYTE> RC5::RC5_doFinal(vector<BYTE> data, bool mode)
{
	int i, j;
	unsigned int A, B, tmp_A, tmp_B;
	vector<BYTE> result(RC5_update(data, mode));
	A = 0;
	B = 0;
	if (rest_size != 0)
	{
		if (padding == 1)
		{
			for (j = rest_size; j < 8; j++)
			{
				rest.push_back(8 - rest_size);
			}
		}
		else if (padding == 2)
		{
			for (j = rest_size; j < 7; j++)
			{
				HCRYPTPROV   hCryptProv = 0;
				if (!CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0))
					cout << "Error in CryptAcquireContext" << endl;
				BYTE tmp[1];
				if (!CryptGenRandom(hCryptProv, 1, tmp))
					cout << "Error in CryptGenRandom" << endl;
				if (!CryptReleaseContext(hCryptProv, 0))
					cout << "Error in CryptReleaseContext" << endl;
				rest.push_back(tmp[0]);
			}
			rest.push_back(8 - rest_size);
		}
		else
		{
			for (j = rest_size; j < 7; j++)
			{
				rest.push_back(0x0);
			}
			rest.push_back(8 - rest_size);
		}
		rest_size = 8;

		for (j = 0; j < 4; j++)
		{
			A <<= 8;
			A += rest[j];
		}
		for (j = 4; j < 8; j++)
		{
			B <<= 8;
			B += rest[j];
		}
		if (mode)
		{
			if (crypt == 1) //ECB
			{
				A = (A + new_key_for_coding[0]);
				B = (B + new_key_for_coding[1]);
				for (i = 1; i <= R; i++)
				{
					A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
					B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
				}
			}
			else if (crypt == 2) //CBC
			{
				A ^= IV_A;
				B ^= IV_B;
				A = (A + new_key_for_coding[0]);
				B = (B + new_key_for_coding[1]);
				for (i = 1; i <= R; i++)
				{
					A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
					B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
				}
				IV_A = A;
				IV_B = B;
			}
			else if (crypt == 3) //CNT
			{
				tmp_A = A;
				tmp_B = B;
				A = ((IV_A >> 16) << 16) | (((Lctr << 16) >> 48) & 4294967295); //max unsigned int
				B = ((IV_B >> 16) << 16) | (((Lctr << 48) >> 48) & 4294967295);
				A = (A + new_key_for_coding[0]);
				B = (B + new_key_for_coding[1]);
				for (i = 1; i <= R; i++)
				{
					A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
					B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
				}
				A ^= tmp_A;
				B ^= tmp_B;
				Lctr++;
			}
			else // CFB
			{
				tmp_A = A;
				tmp_B = B;
				A = IV_A;
				B = IV_B;
				A = (A + new_key_for_coding[0]);
				B = (B + new_key_for_coding[1]);
				for (i = 1; i <= R; i++)
				{
					A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
					B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
				}
				IV_A = tmp_A ^ A;
				IV_B = tmp_B ^ B;
				A = IV_A;
				B = IV_B;
			}
		}
		else
		{
			if (crypt == 1)
			{
				for (i = R; i >= 1; i--)
				{
					B = ROR((B - new_key_for_coding[2 * i + 1]), A) ^ A;
					A = ROR((A - new_key_for_coding[2 * i]), B) ^ B;
				}
				B = (B - new_key_for_coding[1]);
				A = (A - new_key_for_coding[0]);
			}
			else if (crypt == 2)
			{
				tmp_A = A;
				tmp_B = B;
				for (i = R; i >= 1; i--)
				{
					B = ROR((B - new_key_for_coding[2 * i + 1]), A) ^ A;
					A = ROR((A - new_key_for_coding[2 * i]), B) ^ B;
				}
				B = (B - new_key_for_coding[1]);
				A = (A - new_key_for_coding[0]);
				A ^= IV_A;
				B ^= IV_B;
				IV_A = tmp_A;
				IV_B = tmp_B;
			}
			else if (crypt == 3)
			{
				tmp_A = A;
				tmp_B = B;
				A = ((IV_A >> 16) << 16) | (((Lctr << 16) >> 48) & 4294967295); //max unsigned int
				B = ((IV_B >> 16) << 16) | (((Lctr << 48) >> 48) & 4294967295);
				A = (A + new_key_for_coding[0]);
				B = (B + new_key_for_coding[1]);
				for (i = 1; i <= R; i++)
				{
					A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
					B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
				}
				A ^= tmp_A;
				B ^= tmp_B;
				Lctr++;
			}
			else
			{
				tmp_A = A;
				tmp_B = B;
				A = IV_A;
				B = IV_B;
				A = (A + new_key_for_coding[0]);
				B = (B + new_key_for_coding[1]);
				for (i = 1; i <= R; i++)
				{
					A = (ROL((A ^ B), B) + new_key_for_coding[2 * i]);
					B = (ROL((B ^ A), A) + new_key_for_coding[2 * i + 1]);
				}
				A ^= tmp_A;
				B ^= tmp_B;
				IV_A = tmp_A;
				IV_B = tmp_B;
			}
		}

		result.push_back(A >> 24 & 255);
		A <<= 8;
		A >>= 8;
		result.push_back(A >> 16 & 255);
		A <<= 16;
		A >>= 16;
		result.push_back(A >> 8 & 255);
		A <<= 24;
		A >>= 24;
		result.push_back(A & 255);

		result.push_back(B >> 24 & 255);
		B <<= 8;
		B >>= 8;
		result.push_back(B >> 16 & 255);
		B <<= 16;
		B >>= 16;
		result.push_back(B >> 8 & 255);
		B <<= 24;
		B >>= 24;
		result.push_back(B & 255);
	}
	rest_size = 0;
	rest.clear();
	new_key_for_coding.clear();

	return result;
}




vector<BYTE> HMAC::HMAC_gen_key()
{
	HCRYPTPROV   hCryptProv = 0;
	if (!CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0))
		cout << "Error in CryptAcquireContext" << endl;
	BYTE key[L];
	if (!CryptGenRandom(hCryptProv, L, key))
		cout << "Error in CryptGenRandom" << endl;
	int i;
	vector<BYTE> key_for_hmac;
	for (i = 0; i < L; i++)
	{
		key_for_hmac.push_back(key[i]);
	}
	if (!CryptReleaseContext(hCryptProv, 0))
		cout << "Error in CryptReleaseContext" << endl;
	return key_for_hmac;
}

void HMAC::HMAC_init(vector<BYTE> key)
{
	b_hash = key.size();
	vector<BYTE> new_key_for_hash;
	int i;
	if (b_hash == block_size)
	{
		for (i = 0; i < b_hash; i++)
		{
			new_key_for_hash.push_back(key[i]);
		}
	}
	else if (b_hash > block_size)
	{
		new_key_for_hash.resize(L);
		hash_init();
		hash_update(key);
		new_key_for_hash = hash_doFinal();
		for (i = L; i < block_size; i++)
		{
			new_key_for_hash.push_back(0x00);
		}
	}
	else
	{
		new_key_for_hash.resize(block_size);	
		for (i = 0; i < b_hash; i++)
		{
			new_key_for_hash[i] = key[i];
		}
		for (i = b_hash; i < block_size; i++)
		{
			new_key_for_hash[i] = 0x00;
		}
	}
	for (i = 0; i < block_size; i++)
	{
		ipad.push_back(0x36);
		opad.push_back(0x5c);
	}
	Si.resize(block_size);
	So.resize(block_size);
	for (i = 0; i < block_size; i++)
	{
		Si[i] = new_key_for_hash[i] ^ ipad[i];
		So[i] = new_key_for_hash[i] ^ opad[i];
	}
}

vector<BYTE> HMAC::HMAC_update(vector<BYTE> data)
{
	unsigned int i, j;
	vector<BYTE> tmp(L);
	vector<BYTE> message;
	for (i = 0; i < data.size() / block_size; i++)
	{
		for (j = 0; j < block_size; j++)
		{
			message.push_back(Si[j]);
		}
		for (j = 0; j < block_size; j++)
		{
			message.push_back(data[i * block_size + j]);
		}
	}
	if (i * block_size != data.size())
	{
		for (j = 0; j < block_size; j++)
		{
			message.push_back(Si[j]);
		}
		for (j = (i - 1) * block_size; j < data.size(); j++)
		{
			message.push_back(data[i]);
		}
	}
	hash_init();
	hash_update(message);
	tmp = hash_doFinal();
	return tmp;
}

vector<BYTE>  HMAC::HMAC_doFinal(vector<BYTE> data)
{
	unsigned int j;
	vector<BYTE> HMAC_result;
	vector<BYTE> message(block_size + L);
	vector<BYTE> tmp(HMAC_update(data));
	for (j = 0; j < block_size; j++)
	{
		message[j] = So[j];
	}
	for (j = 0; j < L; j++)
	{
		message[j + block_size] = tmp[j];
	}
	hash_init();
	hash_update(message);
	tmp.resize(L);
	tmp = hash_doFinal();

	for (j = 0; j < L; j++)
	{
		HMAC_result.push_back(tmp[j]);
	}

	ipad.clear();
	opad.clear();
	Si.clear();
	So.clear();
	return HMAC_result;
}


void HMAC::hash_init()
{
	int r = 12;
	int la = (32 * r / 8) / 4; // деление на 4 т.к массив из int
	int lh = 256; //длина хэша в битах
	int lm = 64 / 4;
	int lb = lm, lc = lm;
	int p = 3;
	long long int W = -1;
	A.resize(la);
	B.resize(lb);
	C.resize(lc);
	int i, j;
	for (i = 0; i < la; i++)
		A[i] = 0;
	for (i = 0; i < lb; i++)
	{
		B[i] = 0;
		C[i] = 0;
	}
	unsigned int tmp;
	for (i = 0; i < 32; i++)
	{
		tmp = lh + i;
		hash_message.push_back(tmp >> 24 & 255);
		tmp <<= 8;
		tmp >>= 8;
		hash_message.push_back(tmp >> 16 & 255);
		tmp <<= 16;
		tmp >>= 16;
		hash_message.push_back(tmp >> 8 & 255);
		tmp <<= 24;
		tmp >>= 24;
		hash_message.push_back(tmp & 255);
	}
	for (W = -1; W <= 0; W++)
	{
		for (i = 0; i < lb; i++)
		{
			tmp = hash_message[(W + 1) * lb * 4 + i * 4];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 1];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 2];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 3];
			B[i] += tmp;
		}

		tmp = (W >> 32);
		A[1] ^= tmp;
		tmp = (W << 32) >> 32;
		A[0] ^= tmp;

		for (i = 0; i < 16; i++)
		{
			B[i] = ROL(B[i], 17);
		}

		unsigned int u, v, t;
		for (j = 0; j < p; j++)
		{
			for (i = 0; i < 16; i++)
			{
				t = ROL(A[(i - 1 + 16 * j + r) % r], 15);
				v = 5 * t;
				v ^= C[(8 - i + 16) % 16];
				v ^= A[(i + 16 * j) % r];
				u = 3 * v;
				u ^= B[(i + 13) % 16];
				u ^= B[(i + 9) % 16] & (~B[(i + 6) % 16]);
				tmp = hash_message[(W + 1) * lb * 4 + i * 4];
				tmp <<= 8;
				tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 1];
				tmp <<= 8;
				tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 2];
				tmp <<= 8;
				tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 3];
				A[(i + 16 * j) % r] = u ^ tmp;
				B[i] = ROL(B[i], 1) ^ (~A[(i + 16 * j) % r]);
			}
		}
		for (j = 0; j < 36; j++)
		{
			A[j % r] += C[(j + 3) % 16];
		}

		for (i = 0; i < lc; i++)
		{
			tmp = hash_message[(W + 1) * lb * 4 + i * 4];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 1];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 2];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 3];
			C[i] -= tmp;
		}
		for (i = 0; i < lc; i++)
		{
			tmp = B[i];
			B[i] = C[i];
			C[i] = tmp;
		}
	}
}

void HMAC::hash_update(vector<BYTE> K)
{
	int parts = K.size() / 64;
	int res = K.size() % 64;
	if (res != 0)
		parts++;
	unsigned int i, j;
	for (i = 0; i < K.size(); i++)
	{
		hash_message.push_back(K[i]);
	}
	if (res != 0)
	{
		hash_message.push_back(128);
		for (i = res + 1; i < 64; i++)
			hash_message.push_back(0);
	}

	unsigned int r = 12;
	unsigned int la = (32 * r / 8) / 4; // деление на 4 т.к массив из int
	unsigned int lh = 256; //длина хэша в битах
	unsigned int lm = 64 / 4;
	unsigned int lb = lm, lc = lm;
	unsigned int p = 3;

	long long int W;

	unsigned int tmp;
	for (W = 1; W <= parts; W++)
	{
		for (i = 0; i < lb; i++)
		{
			tmp = hash_message[(W + 1) * lb * 4 + i * 4];
			tmp <<= 8;
			tmp |= hash_message[(W + 1) * lb * 4 + i * 4 + 1];
			tmp <<= 8;
			tmp |= hash_message[(W + 1) * lb * 4 + i * 4 + 2];
			tmp <<= 8;
			tmp |= hash_message[(W + 1) * lb * 4 + i * 4 + 3];
			B[i] += tmp;
		}

		tmp = (W >> 32);
		A[1] ^= tmp;
		tmp = (W << 32) >> 32;
		A[0] ^= tmp;

		for (i = 0; i < 16; i++)
		{
			B[i] = ROL(B[i], 17);
		}
		unsigned int u, v, t;
		for (j = 0; j < p; j++)
		{
			for (i = 0; i < 16; i++)
			{
				t = ROL(A[(i - 1 + 16 * j + r) % r], 15);
				v = 5 * t;
				v ^= C[(8 - i + 16) % 16];
				v ^= A[(i + 16 * j) % r];
				u = 3 * v;
				u ^= B[(i + 13) % 16];
				u ^= B[(i + 9) % 16] & (~B[(i + 6) % 16]);
				tmp = hash_message[(W + 1) * lb * 4 + i * 4];
				tmp <<= 8;
				tmp |= hash_message[(W + 1) * lb * 4 + i * 4 + 1];
				tmp <<= 8;
				tmp |= hash_message[(W + 1) * lb * 4 + i * 4 + 2];
				tmp <<= 8;
				tmp |= hash_message[(W + 1) * lb * 4 + i * 4 + 3];
				A[(i + 16 * j) % r] = u ^ tmp;
				B[i] = ROL(B[i], 1) ^ (~A[(i + 16 * j) % r]);
			}
		}

		for (j = 0; j < 36; j++)
		{
			A[j % r] += C[(j + 3) % 16];
		}

		for (i = 0; i < lc; i++)
		{
			tmp = hash_message[(W + 1) * lb * 4 + i * 4];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 1];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 2];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 3];
			C[i] -= tmp;
		}
		for (i = 0; i < lc; i++)
		{
			tmp = B[i];
			B[i] = C[i];
			C[i] = tmp;
		}
	}
	W = parts;
	for (int s = 0; s < 3; s++)
	{
		for (i = 0; i < lb; i++)
		{
			tmp = hash_message[(W + 1) * lb * 4 + i * 4];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 1];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 2];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 3];
			B[i] += tmp;
		}
		tmp = (W >> 32);
		A[1] ^= tmp;
		tmp = (W << 32) >> 32;
		A[0] ^= tmp;

		for (i = 0; i < 16; i++)
		{
			B[i] = ROL(B[i], 17);
		}
		unsigned int u, v, t;
		for (j = 0; j < p; j++)
		{
			for (i = 0; i < 16; i++)
			{
				t = ROL(A[(i - 1 + 16 * j + r) % r], 15);
				v = 5 * t;
				v ^= C[(8 - i + 16) % 16];
				v ^= A[(i + 16 * j) % r];
				u = 3 * v;
				u ^= B[(i + 13) % 16];
				u ^= B[(i + 9) % 16] & (~B[(i + 6) % 16]);
				tmp = hash_message[(W + 1) * lb * 4 + i * 4];
				tmp <<= 8;
				tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 1];
				tmp <<= 8;
				tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 2];
				tmp <<= 8;
				tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 3];
				A[(i + 16 * j) % r] = u ^ tmp;
				B[i] = ROL(B[i], 1) ^ (~A[(i + 16 * j) % r]);
			}
		}
		for (j = 0; j < 36; j++)
		{
			A[j % r] += C[(j + 3) % 16];
		}

		for (i = 0; i < lc; i++)
		{
			tmp = hash_message[(W + 1) * lb * 4 + i * 4];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 1];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 2];
			tmp <<= 8;
			tmp += hash_message[(W + 1) * lb * 4 + i * 4 + 3];
			C[i] -= tmp;
		}
		for (i = 0; i < lc; i++)
		{
			tmp = B[i];
			B[i] = C[i];
			C[i] = tmp;
		}
	}
}

vector<BYTE> HMAC::hash_doFinal()
{
	vector<BYTE> x;
	int lh = 256; //длина хэша в битах
	int lm = 64 / 4;
	int lb = lm, lc = lm;
	int i;
	unsigned int tmp;
	hash_message.clear();

	for (i = 16 - lh / 32; i < 16; i++)
	{
		tmp = C[i];
		x.push_back(tmp);
		x.push_back(tmp >> 8 & 255);
		x.push_back(tmp >> 16 & 255);
		x.push_back(tmp >> 24 & 255);
	}

	A.clear();
	B.clear();
	C.clear();
	return x;
}


vector<BYTE> F(vector<BYTE> password, vector<BYTE> salt, unsigned int c, unsigned int num_of_block)
{
	HMAC PRF;
	vector<BYTE> result(HMAC::L);
	vector<BYTE> U;
	unsigned int i;
	for (i = 0; i < salt.size(); i++)
		U.push_back(salt[i]);
	vector<BYTE> tmp;
	i = 0;
	while (num_of_block > 0)
	{
		tmp.push_back(num_of_block % 255);
		num_of_block /= 256;
		i++;
	}
	int j;
	for (j = i - 1; j >= 0; j--)
	{
		U.push_back(tmp[j]);
	}
	PRF.HMAC_init(password);
	result = PRF.HMAC_doFinal(U);
	for (i = 1; i < c; i++)
	{
		PRF.HMAC_init(password);
		U = PRF.HMAC_doFinal(U);
		for (j = 0; j < HMAC::L; j++)
			result[j] ^= U[j];
	}
	return result;
}

vector<BYTE> PBKDF2(vector<BYTE> password, vector<BYTE> salt, unsigned int c, unsigned int key_length)
{
	unsigned int l = key_length / HMAC::L;
	if (key_length % HMAC::L != 0)
		l++;
	unsigned int r = key_length - (l - 1) * HMAC::L;
	unsigned int i, j;
	vector<BYTE> result;

	for (i = 0; i < l - 1; i++)
	{
		vector<BYTE> tmp(F(password, salt, c, i));
		for (j = 0; j < tmp.size(); j++)
			result.push_back(tmp[j]);
	}
	vector<BYTE> tmp(F(password, salt, c, l));
	for (j = 0; j < r; j++)
		result.push_back(tmp[j]);
	return result;
}


pair<ZZ_p, dot> ECDSA::ECDSA_gen_keys()
{
	ZZ_p::init(n);
	ZZ_p pr_key = to_ZZ_p(0);
	while (pr_key == 0)
	{
		HCRYPTPROV   hCryptProv = 0;
		if (!CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0))
			cout << "Error in CryptAcquireContext" << endl;
		BYTE private_key[32];
		if (!CryptGenRandom(hCryptProv, 32, private_key))
			cout << "Error in CryptGenRandom" << endl;
		if (!CryptReleaseContext(hCryptProv, 0))
			cout << "Error in CryptReleaseContext" << endl;
		int i;
		for (i = 0; i < 32; i++)
		{
			pr_key *= 256;
			pr_key += private_key[i];
		}
	}
	dot public_key;
	public_key = dot::multiply(pr_key, G);
	return make_pair(pr_key, public_key);
}


void ECDSA::ECDSA_save(ZZ_p private_key, vector<BYTE> password)
{
	ZZ_p::init(n);
	ZZ pr_key;
	conv(pr_key, private_key);
	ofstream fout;
	fout.open("key.txt");
	RC5 T;
	vector<BYTE> key(16);
	int i;
	
	HCRYPTPROV   hCryptProv = 0;
	if (!CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0))
		cout << "Error in CryptAcquireContext" << endl;
	BYTE salt_byte[8];
	if (!CryptGenRandom(hCryptProv, 8, salt_byte))
		cout << "Error in CryptGenRandom" << endl;
	if (!CryptReleaseContext(hCryptProv, 0))
		cout << "Error in CryptReleaseContext" << endl;

	vector<BYTE> salt;
	for (i = 0; i < 8; i++)
		salt.push_back(salt_byte[i]);
	key = PBKDF2(password, salt, 2048, 16);
	T.RC5_init(1, 1, key);
	vector<BYTE> data, tmp;
	while (pr_key != 0)
	{
		tmp.push_back(pr_key % 256);
		pr_key /= 256;
	}
	if (tmp.size() != 32)
	{
		for (i = tmp.size(); i < 32; i++)
			tmp.push_back(0);
	}
	for (i = 31; i >= 0; i--)
	{
		data.push_back(tmp[i]);
	}
	ZZ_p res;
	vector<BYTE> crypted_key(T.RC5_doFinal(data, 1));
	for (i = 0; i < crypted_key.size(); i++)
	{
		res *= to_ZZ_p(256);
		res += to_ZZ_p(crypted_key[i]);
	}
	fout << res << endl;

	fout << "1.2.840.10045" << endl; //OID ECDSA?
	fout << "1.2.840.10045.3.1.7" << endl; //OID кривой P-256?
	for (i = 0; i < 8; i++)
		fout << salt[i];
	fout << endl;
	fout.close();
}

ZZ_p ECDSA::ECDSA_load(const char *s, vector<BYTE> password)
{
	ZZ_p::init(n);
	RC5 T;
	int i;
	ifstream fin;
	fin.open(s);
	ZZ key;
	fin >> key;
	vector<BYTE> crypted_key, tmp;
	while (key != 0)
	{
		tmp.push_back(key % 256);
		key /= 256;
	}
	if (tmp.size() != 32)
	{
		for (i = tmp.size(); i < 32; i++)
			tmp.push_back(0);
	}
	for (i = 31; i >= 0; i--)
	{
		crypted_key.push_back(tmp[i]);
	}
	string OID;
	fin >> OID;
	fin >> OID;
	vector<BYTE> salt(8);
	for (i = 0; i < 8; i++)
		fin >> salt[i];
	vector<BYTE> en_key(16);
	en_key = PBKDF2(password, salt, 2048, 16);
	T.RC5_init(1, 1, en_key);
	vector<BYTE> encrypted_key(T.RC5_doFinal(crypted_key, 0));
	fin.close();
	ZZ_p::init(n);
	ZZ_p res = to_ZZ_p(0);
	for (i = 0; i < encrypted_key.size(); i++)
	{
		res *= to_ZZ_p(256);
		res += to_ZZ_p(encrypted_key[i]);
	}
	return res;
}

void ECDSA::ECDSA_init_sign(const char *s, vector<BYTE> password)
{
	ZZ_p::init(n);
	ZZ_p key(ECDSA_load(s, password));
	secret_key = key;
}

bool ECDSA::ECDSA_init_check(dot public_key) //true, если Q подтвержден
{
	ZZ_p::init(p);
	if (public_key.is_inf == true)
		return false;
	if (public_key.y * public_key.y !=
		public_key.x * public_key.x * public_key.x + a * public_key.x + b)
		return false;
	dot m = dot::multiply(n_p, public_key);
	if (m.is_inf == true)
		return false;
	return true;
}

ZZ_p ECDSA::ECDSA_update(vector<BYTE> data)
{
	ZZ_p::init(n);
	ZZ_p h = to_ZZ_p(0);
	HMAC H;
	H.hash_init();
	H.hash_update(data);
	vector<BYTE> hash = H.hash_doFinal();
	int i;
	for (i = 0; i < 32; i++)
	{
		h *= 256;
		h += hash[i];
	}
	return h;
}

pair<ZZ_p, ZZ_p> ECDSA::ECDSA_sign(vector<BYTE> data)
{
	ZZ_p::init(n);
	ZZ_p r = to_ZZ_p(0);
	ZZ_p s = to_ZZ_p(0);
	dot A;
	ZZ_p k = to_ZZ_p(0), h;
	h = ECDSA_update(data);
	ZZ_p k_rev;
	int i;
	while (r == 0 || s == 0)
	{
		k = to_ZZ_p(0);
		HCRYPTPROV   hCryptProv = 0;
		if (!CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0))
			cout << "Error in CryptAcquireContext" << endl;
		BYTE byte_key[32];
		if (!CryptGenRandom(hCryptProv, 32, byte_key))
			cout << "Error in CryptGenRandom" << endl;
		if (!CryptReleaseContext(hCryptProv, 0))
			cout << "Error in CryptReleaseContext" << endl;
		for (i = 0; i < 32; i++)
		{
			k *= 256;
			k += byte_key[i];
		}
		A = dot::multiply(k, G);
		r = A.x;
		if (r != 0)
		{
			k_rev = 1 / k;
			s = k_rev * (h + secret_key * r);
		}
	}
	secret_key = 0;
	return make_pair(r, s);
}

bool ECDSA::ECDSA_verify(vector<BYTE> data, dot public_key, ZZ r, ZZ s)
{
	ZZ_p::init(n);
	if (!(r >= 1 && r < n && s >= 1 && s < n)) //r,s из публичного ключа
		return false;
	ZZ_p h = ECDSA_update(data);
	ZZ_p s_rev = to_ZZ_p(s);
	s_rev = 1 / s_rev;
	ZZ_p r_p;
	conv(r_p, r);
	ZZ_p u1 = h * s_rev;
	ZZ_p u2 = r_p * s_rev;
	dot t1, t2;
	t1 = dot::multiply(u1, G);
	t2 = dot::multiply(u2, public_key);
	dot X = t1 + t2;
	ZZ_p v = X.x;
	if (v != r_p)
		return false;
	return true;
}



pair<ZZ_p, dot> DH::DH_gen_keys()
{
	ZZ_p::init(n);
	ZZ_p pr_key = to_ZZ_p(0);
	while (pr_key == 0)
	{
		HCRYPTPROV   hCryptProv = 0;
		if (!CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0))
			cout << "Error in CryptAcquireContext" << endl;
		BYTE private_key[32];
		if (!CryptGenRandom(hCryptProv, 32, private_key))
			cout << "Error in CryptGenRandom" << endl;
		if (!CryptReleaseContext(hCryptProv, 0))
			cout << "Error in CryptReleaseContext" << endl;
		int i;
		for (i = 0; i < 32; i++)
		{
			pr_key *= 256;
			pr_key += private_key[i];
		}
	}
	dot public_key;
	public_key = dot::multiply(pr_key, G);
	return make_pair(pr_key, public_key);
}


void DH::DH_save(ZZ_p private_key, vector<BYTE> password)
{
	ZZ_p::init(n);
	ZZ pr_key;
	conv(pr_key, private_key);
	ofstream fout;
	fout.open("key.txt");
	RC5 T;
	vector<BYTE> key(16);
	int i;

	HCRYPTPROV   hCryptProv = 0;
	if (!CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0))
		cout << "Error in CryptAcquireContext" << endl;
	BYTE salt_byte[8];
	if (!CryptGenRandom(hCryptProv, 8, salt_byte))
		cout << "Error in CryptGenRandom" << endl;
	if (!CryptReleaseContext(hCryptProv, 0))
		cout << "Error in CryptReleaseContext" << endl;

	vector<BYTE> salt;
	for (i = 0; i < 8; i++)
		salt.push_back(salt_byte[i]);
	key = PBKDF2(password, salt, 2048, 16);
	T.RC5_init(1, 1, key);
	vector<BYTE> data, tmp;
	while (pr_key != 0)
	{
		tmp.push_back(pr_key % 256);
		pr_key /= 256;
	}
	if (tmp.size() != 32)
	{
		for (i = tmp.size(); i < 32; i++)
			tmp.push_back(0);
	}
	for (i = 31; i >= 0; i--)
	{
		data.push_back(tmp[i]);
	}
	ZZ_p res;
	vector<BYTE> crypted_key(T.RC5_doFinal(data, 1));
	for (i = 0; i < crypted_key.size(); i++)
	{
		res *= to_ZZ_p(256);
		res += to_ZZ_p(crypted_key[i]);
	}
	fout << res << endl;

	fout << "1.2.643.2.2.98" << endl; //OID DH?
	fout << "1.2.840.10045.3.1.7" << endl; //OID кривой P-256?
	for (i = 0; i < 8; i++)
		fout << salt[i];
	fout << endl;
	fout.close();
}

ZZ_p DH::DH_load(const char *s, vector<BYTE> password)
{
	ZZ_p::init(n);
	RC5 T;
	int i;
	ifstream fin;
	fin.open(s);
	ZZ key;
	fin >> key;
	vector<BYTE> crypted_key, tmp;
	while (key != 0)
	{
		tmp.push_back(key % 256);
		key /= 256;
	}
	if (tmp.size() != 32)
	{
		for (i = tmp.size(); i < 32; i++)
			tmp.push_back(0);
	}
	for (i = 31; i >= 0; i--)
	{
		crypted_key.push_back(tmp[i]);
	}
	string OID;
	fin >> OID;
	fin >> OID;
	vector<BYTE> salt(8);
	for (i = 0; i < 8; i++)
		fin >> salt[i];
	vector<BYTE> en_key(16);
	en_key = PBKDF2(password, salt, 2048, 16);
	T.RC5_init(1, 1, en_key);
	vector<BYTE> encrypted_key(T.RC5_doFinal(crypted_key, 0));
	fin.close();
	ZZ_p::init(n);
	ZZ_p res = to_ZZ_p(0);
	for (i = 0; i < encrypted_key.size(); i++)
	{
		res *= to_ZZ_p(256);
		res += to_ZZ_p(encrypted_key[i]);
	}
	return res;
}

void DH::DH_init(const char *s, vector<BYTE> password)
{
	ZZ_p::init(n);
	ZZ_p key(DH_load(s, password));
	secret_key = key;
}

void DH::DH_doPhase(dot public_key)
{
	ZZ_p::init(n);
	if (public_key.is_inf == true)
		B_public_key.is_inf = false;
	else if (public_key.y * public_key.y !=
		public_key.x * public_key.x * public_key.x + a * public_key.x + b)
		B_public_key.is_inf = false;
	else
	{
		dot m = dot::multiply(n_p, public_key);
		if (m.is_inf == true)
			B_public_key.is_inf = false;
		else
			B_public_key = public_key;
	}
	if (B_public_key.is_inf = false)
	{
		cout << "Incorrect public key" << endl;
		B_public_key = dot(to_ZZ_p(0), to_ZZ_p(0));
	}
	else
	{
		B_public_key = dot::multiply(secret_key, B_public_key);
	}
}

pair<ZZ_p, dot> DH::DH_genSecret()
{
	ZZ_p::init(n);
	return make_pair(secret_key, B_public_key);
}
