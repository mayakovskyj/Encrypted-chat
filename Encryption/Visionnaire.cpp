#include "Visionnaire.h"

int Mod(int a, int b)
{
	return (a % b + b) % b;
}

string Cipher(string input, string key, bool encipher)
{
	int keyLen = key.size();

	for (int i = 0; i < keyLen; ++i)
		if (!isalpha(key[i]))
			return ""; // Error

	string output = "";
	int nonAlphaCharCount = 0;
	int inputLen = input.size();

	for (int i = 0; i < inputLen; ++i)
	{
		if (isalpha(input[i]))
		{
			bool cIsUpper = isupper(input[i]);
			char offset = cIsUpper ? 'A' : 'a';
			int keyIndex = (i - nonAlphaCharCount) % keyLen;
			int k = (cIsUpper ? toupper(key[keyIndex]) : tolower(key[keyIndex])) - offset;
			k = encipher ? k : -k;
			char ch = (char)((Mod(((input[i] + k) - offset), 26)) + offset);
			output += ch;
		}
		else
		{
			output += input[i];
			++nonAlphaCharCount;
		}
	}

	return output;
}

string Encipher(string input, string key)
{
	return Cipher(input, key, true);
}

string Decipher(string input, string key)
{
	return Cipher(input, key, false);
}

	