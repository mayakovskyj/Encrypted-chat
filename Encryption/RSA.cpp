#include "RSA.h"
#include <iostream>

using namespace std;

long int e[100], d[100];

// Generate RSA key pair 
long int* rsaGenKeyPair(long int prime1, long int prime2)
{
	long int r = (prime1 - 1) * (prime2 - 1);
	calcE(r, prime1, prime2);
	long int keyPair[2] = { e[0],d[0] };
	return keyPair;
}

// Check is number a prime number 
int prime(long int pr) {
	int i;
	long int j = sqrt((double)pr);
	for (i = 2; i <= j; i++) {
		if (pr % i == 0)
			return 0;
	}
	return 1;
}

// Calculate value of e. 
void calcE(long int r, long int prime1, long int prime2)
{
	int k = 0;
	int isPrime = 0;
	long int possibleD = 0;
	for (int i = 2; i < r; i++)
	{
		if (r % i == 0)
			continue;
		isPrime = prime(i);
		if (isPrime == 1 && i != prime1 && i != prime2)
		{
			// all possible values of e
			e[k] = i;
			possibleD = calcD(e[k], r);
			if (possibleD > 0)
			{
				//all possible values of d
				d[k] = possibleD;
				k++;
			}
			if (k == 99)
				break;
		}
	}
}

// Calculate value of d.
long int calcD(long int x, long int r)
{
	long int k = 1;
	while (1)
	{
		k = k + r;
		if (k % x == 0)
			return (k / x);
	}
}


// Do RSA encryption with the public key(e).
char* doEncrypt(char* msg, long int n, long int key)
{
	int len = strlen(msg);
	int i = 0;
	long int plaintext;
	long int ciphertext;
	long int k;
	char *encryptedText = (char*)malloc(1024 * sizeof(char));

	while (i != len)
	{
		plaintext = msg[i];
		plaintext = plaintext - 96;
		k = 1;
		for (int j = 0; j < key; j++)
		{
			k = k * plaintext;
			k = k % n;
		}
		ciphertext = k + 96;
		encryptedText[i] = (char)ciphertext;
		i++;
	}
	encryptedText[i] = '\0';
	return encryptedText;
}


// RSA decryption with private key d. 
char* doDecrypt(char *encryptedMsg, long int n, long int key)
{
	long int plainText;
	long int cipherText;
	long int k;
	int i = 0;
	char *decryptedMsg = (char*)malloc(1024 * sizeof(char));
	while (encryptedMsg[i] != '\0')
	{
		cipherText = encryptedMsg[i];
		cipherText = cipherText - 96;
		if (cipherText < 0)
			cipherText += 256;
		if ((cipherText <= 90 && cipherText >= 65) || (cipherText < 121 && cipherText >= 97) || (cipherText >= 10 && cipherText <= 15))
			cipherText += 256;
		
		k = 1;
		for (int j = 0; j < key; j++)
		{
			k = k * cipherText;
			k = k % n;
		}
		plainText = k + 96;
		decryptedMsg[i] = char(plainText);
		i++;
	}
	decryptedMsg[i] = '\0';
	return decryptedMsg;
}
