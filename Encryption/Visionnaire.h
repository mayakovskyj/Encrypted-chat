#ifndef Visionnaire_h
#define Visionnaire_h

#include <string>
#include <ctype.h>
#include <iostream>

using namespace std;
using std::string;
using namespace std;

int Mod(int a, int b);
string Cipher(string input, string key, bool encipher);
string Encipher(string input, string key);
string Decipher(string input, string key);

#endif