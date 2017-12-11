#ifndef RSA_h
#define RSA_h

#include<stdio.h>
#include<conio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>

int prime(long int);
void calcE(long int r, long int prime1, long int prime2);
long int calcD(long int x, long int r);
char* doEncrypt(char* msg, long int n, long int key);
char* doDecrypt(char *encrytedMsg, long int n, long int key);
long int* rsaGenKeyPair(long int prime1, long int prime2);

#endif