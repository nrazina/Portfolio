#include <iostream>
#include <windows.h>
#include "CryptoLib.h"

using namespace std;


#define w 32
#define r 12
#define b 16
#define c 4
#define t 26
typedef unsigned long int DWORD;
DWORD S[t];
DWORD P = 0xb7e15163, Q = 0x9e3779b9;

#define ROTL(x, y) (((x) << (y & (w - 1))) | ((x) >> (w - (y & (w - 1)))))
#define ROTR(x, y) (((x) >> (y & (w - 1))) | ((x) << (w - (y & (w - 1)))))

void RC5_ENCRYPT(DWORD *pt, DWORD *ct)
{
	DWORD i, A = pt[0] + S[0], B = pt[1] + S[1];
	for (i = 1; i <= r; i++)
	{
		A = ROTL(A ^ B, B) + S[2 * i];
		B = ROTL(B ^ A, A) + S[2 * i + 1];
	}
	ct[0] = A;
	ct[1] = B;
}

void RC5_DECRYPT(DWORD *ct, DWORD *pt)
{
	DWORD i, A = ct[0], B = ct[1];
	for (i = r; i > 0; i--)
	{
		B = ROTR(B - S[2 * i + 1], A) ^ A;
		A = ROTR(A - S[2 * i], B) ^ B;
	}
	pt[1] = B - S[1];
	pt[0] = A - S[0];
}

void RC5_SETUP(unsigned char *K)
{
	DWORD i, j, k, u = w / 8, A, B, L[c];
	for (i = b - 1, L[c - 1] = 0; i != -1; i--)
		L[i / u] = (L[i / u] << 8) + K[i];
	for (S[0] = P, i = 1; i < t; i++)
		S[i] = S[i - 1] + Q;
	for (A = B = i = j = k = 0; k < 3 * t; k++, i = (i + 1) % t, j = (j + 1) % c)
	{
		A = S[i] = ROTL(S[i] + (A + B), 3);
		B = L[j] = ROTL(L[j] + (A + B), (A + B));
	}
}

int main()
{
	unsigned int i;
	cout << "1 - check RC5, 2 - check hash" << endl;
	int ch;
	cin >> ch;
	BYTE tmp;
	string s;
	vector<BYTE> data;
	vector<BYTE> key;
	if (ch == 1)
	{
		cout << "Enter padding mode:" << endl;
		cout << "1 = PKCS#5, 2 = ISO 10126, 3 = ANSI X.923" << endl;
		int padding;
		cin >> padding;
		cout << "Enter crypt mode:" << endl;
		cout << "1 - ECB, 2 - CBC, 3 - CNT(CTR), 4 - CFB" << endl;
		int crypt;
		cin >> crypt;
		cout << "If you want to crypt data, enter 1. If you want to decrypt data, enter 0" << endl;
		bool mode;
		cin >> mode;
		RC5 C;
		cout << "Enter data" << endl;
		cin >> s;
		for (i = 0; i < s.length(); i += 2)
		{
			if (s[i] >= 'A')
			    tmp = s[i] - 'A' + 10;
			else
				tmp = s[i] - '0';
			tmp *= 16;
			if (s[i + 1] >= 'A')
				tmp += s[i + 1] - 'A' + 10;
			else
				tmp += s[i + 1] - '0';
			data.push_back(tmp);
		}
		if (mode == 1)
		{
			vector<BYTE> tmp_RC5(C.RC5_gen_key());
			key.resize(tmp_RC5.size());
			key = tmp_RC5;
		}
		else
		{
			cout << "Enter key" << endl;
			cin >> s;
			for (i = 0; i < s.length(); i += 2)
			{
				if (s[i] >= 'A')
					tmp = s[i] - 'A' + 10;
				else
					tmp = s[i] - '0';
				tmp *= 16;
				if (s[i + 1] >= 'A')
					tmp += s[i + 1] - 'A' + 10;
				else
					tmp += s[i + 1] - '0';
				key.push_back(tmp);
			}
		}
		BYTE IV[8];
		if (crypt == 1)
		    C.RC5_init(padding, crypt, key);
		else
		{
			HCRYPTPROV   hCryptProv = 0;
			if (!CryptAcquireContext(&hCryptProv, 0, 0, PROV_RSA_FULL, 0))
				cout << "Error in CryptAcquireContext" << endl;
			if (!CryptGenRandom(hCryptProv, 8, IV))
				cout << "Error in CryptGenRandom" << endl;
			if (!CryptReleaseContext(hCryptProv, 0))
				cout << "Error in CryptReleaseContext" << endl;
			unsigned int IV_A = 0, IV_B = 0;
			for (i = 0; i < 4; i++)
			{
				IV_A *= 256;
				IV_A += IV[i];
			}
			for (i = 4; i < 8; i++)
			{
				IV_B *= 256;
				IV_B += IV[i];
			}
			C.RC5_init(padding, crypt, key, IV_A, IV_B);
		}
		vector<BYTE> res_RC5(C.RC5_doFinal(data, mode));
		for (i = 0; i < res_RC5.size(); i++)
			printf("%X", res_RC5[i]);
		cout << endl;

		cout << "Correct result:" << endl;
		BYTE key_b[b];
		for (i = 0; i < b; i++)
			key_b[i] = key[i];
		RC5_SETUP(key_b);
		DWORD pt[2], ct[2];
		if (mode == 1)
		{
			pt[0] = ((data[0] << 8 | data[1]) << 8 | data[2]) << 8 | data[3];
			pt[1] = ((data[4] << 8 | data[5]) << 8 | data[6]) << 8 | data[7];
			RC5_ENCRYPT(pt, ct);
			printf("%X%X\n", ct[0], ct[1]);
		}
		else
		{
			ct[0] = ((data[0] << 8 | data[1]) << 8 | data[2]) << 8 | data[3];
			ct[1] = ((data[4] << 8 | data[5]) << 8 | data[6]) << 8 | data[7];
			RC5_DECRYPT(ct, pt);
			printf("%X%X\n", pt[0], pt[1]);
		}
		
	}
	else if (ch == 2) //проверка хэша. провер€ла, использу€ пример из https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
	{
		HMAC h;
		h.hash_init();
		vector<BYTE> H(128);
		H[0] = 0x64;
		H[1] = 0x63;
		H[2] = 0x62;
		H[3] = 0x61;
		H[4] = 0x68;
		H[5] = 0x67;
		H[6] = 0x66;
		H[7] = 0x65;
		H[8] = 0x6C;
		H[9] = 0x6B;
		H[10] = 0x6A;
		H[11] = 0x69;
		H[12] = 0x70;
		H[13] = 0x6F;
		H[14] = 0x6E;
		H[15] = 0x6D;
		H[16] = 0x74;
		H[17] = 0x73;
		H[18] = 0x72;
		H[19] = 0x71;
		H[20] = 0x78;
		H[21] = 0x77;
		H[22] = 0x76;
		H[23] = 0x75;
		H[24] = 0x30;
		H[25] = 0x2D;
		H[26] = 0x7A;
		H[27] = 0x79;
		H[28] = 0x34;
		H[29] = 0x33;
		H[30] = 0x32;
		H[31] = 0x31;
		H[32] = 0x38;
		H[33] = 0x37;
		H[34] = 0x36;
		H[35] = 0x35;
		H[36] = 0x42;
		H[37] = 0x41;
		H[38] = 0x2D;
		H[39] = 0x39;
		H[40] = 0x46;
		H[41] = 0x45;
		H[42] = 0x44;
		H[43] = 0x43;
		H[44] = 0x4A;
		H[45] = 0x49;
		H[46] = 0x48;
		H[47] = 0x47;
		H[48] = 0x4E;
		H[49] = 0x4D;
		H[50] = 0x4C;
		H[51] = 0x4B;
		H[52] = 0x52;
		H[53] = 0x51;
		H[54] = 0x50;
		H[55] = 0x4F;
		H[56] = 0x56;
		H[57] = 0x55;
		H[58] = 0x54;
		H[59] = 0x53;
		H[60] = 0x5A;
		H[61] = 0x59;
		H[62] = 0x58;
		H[63] = 0x57;
		H[64] = 0x32;
		H[65] = 0x31;
		H[66] = 0x30;
		H[67] = 0x2D;
		H[68] = 0x36;
		H[69] = 0x35;
		H[70] = 0x34;
		H[71] = 0x33;
		H[72] = 0x2D;
		H[73] = 0x39;
		H[74] = 0x38;
		H[75] = 0x37;
		H[76] = 0x64;
		H[77] = 0x63;
		H[78] = 0x62;
		H[79] = 0x61;
		H[80] = 0x68;
		H[81] = 0x67;
		H[82] = 0x66;
		H[83] = 0x65;
		H[84] = 0x6C;
		H[85] = 0x6B;
		H[86] = 0x6A;
		H[87] = 0x69;
		H[88] = 0x70;
		H[89] = 0x6F;
		H[90] = 0x6E;
		H[91] = 0x6D;
		H[92] = 0x74;
		H[93] = 0x73;
		H[94] = 0x72;
		H[95] = 0x71;
		H[96] = 0x78;
		H[97] = 0x77;
		H[98] = 0x76;
		H[99] = 0x75;
		H[100] = 0x00;
		H[101] = 0x80;
		H[102] = 0x7A;
		H[103] = 0x79;
		H[104] = 0x00;
		H[105] = 0x00;
		H[106] = 0x00;
		H[107] = 0x00;
		H[108] = 0x00;
		H[109] = 0x00;
		H[110] = 0x00;
		H[111] = 0x00;
		H[112] = 0x00;
		H[113] = 0x00;
		H[114] = 0x00;
		H[115] = 0x00;
		H[116] = 0x00;
		H[117] = 0x00;
		H[118] = 0x00;
		H[119] = 0x00;
		H[120] = 0x00;
		H[121] = 0x00;
		H[122] = 0x00;
		H[123] = 0x00;
		H[124] = 0x00;
		H[125] = 0x00;
		H[126] = 0x00;
		H[127] = 0x00;
		cout << "Example 1:" << endl;
		for (i = 0; i < 128; i++)
			printf("%X ", H[i]);
		cout << endl;
		h.hash_update(H);
		vector<BYTE> res_hash(32);
		res_hash = h.hash_doFinal();
		cout << "Result" << endl;
		for (i = 0; i < 32; i++)
			printf("%X ", res_hash[i]);
		cout << endl;
		cout << "Correct result:" << endl;
		cout << "B4 9F 34 BF 51 86 4C 30 53 3C C4 6C C2 54 2B DE C2 F9 6F D0 6F 5C 53 9A FF 6E AD 58 83 F7 32 7A" << endl;

		cout << "Example 2" << endl;
		H.resize(128);
		for (i = 0; i < 128; i++)
		{
			if (i != 67)
				H[i] = 0x0;
			else
				H[i] = 0x80;
			printf("%X ", H[i]);
		}
		cout << endl;
		h.hash_init();
		h.hash_update(H);
		res_hash = h.hash_doFinal();
		cout << "Result" << endl;
		for (i = 0; i < 32; i++)
			printf("%X ", res_hash[i]);
		cout << endl;
		cout << "Correct result:" << endl;
		cout << "DA 8F 08 C0 2A 67 BA 9A 56 BD D0 79 8E 48 AE 07 14 21 5E 09 3B 5B 85 06 49 A3 77 18 99 3F 54 A2" << endl;

	}

	/*int n; //чтобы не сразу закрывалс€
	cin >> n;*/
    return 0;
}

