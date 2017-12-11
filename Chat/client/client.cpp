#define _CRT_SECURE_NO_WARNINGS

#include<iostream>
#include<queue>
#include<string>
#include<cstdlib>

#include<boost/thread.hpp>
#include<boost/bind.hpp>
#include<boost/asio.hpp>
#include<boost/asio/ip/tcp.hpp>
#include<boost/algorithm/string.hpp>

#include "RSA.h"
#include "Visionnaire.h"

using namespace std;
using namespace boost;
using namespace boost::asio;
using namespace boost::asio::ip;

typedef boost::shared_ptr<tcp::socket> socket_ptr;
typedef boost::shared_ptr<string> string_ptr;
typedef boost::shared_ptr< queue<string_ptr> > messageQueue_ptr;

io_service service;
messageQueue_ptr messageQueue(new queue<string_ptr>);
tcp::endpoint ep(ip::address::from_string("127.0.0.1"), 8001);
const int inputSize = 256;
string_ptr promptCpy;
const int bufSize = 1024;

//only small latin letters
char *password = "password";

// Function Prototypes
bool isOwnMessage(string_ptr);
void displayLoop(socket_ptr); //Removes items from messageQueue to display on the client terminal; consumer
void inboundLoop(socket_ptr, string_ptr); //Pushing items from the socket to messageQueue; producer
void writeLoop(socket_ptr, string_ptr);
char* string_to_char(const string& str);

/*
// Handles the display of the terminal input for clients.
// Its fairly simple in that it takes a string of the clients name, 
// and assigns it to the value of the prompt pointer we declared earlier.
*/
string* buildPrompt(); 
// End of Function Prototypes

int main(int argc, char** argv)
{
	try
	{
		boost::thread_group threads;
		socket_ptr sock(new tcp::socket(service));

		string_ptr prompt(buildPrompt());
		promptCpy = prompt;

		sock->connect(ep);
		
		cout << "Welcome to the ChatServer\nType \"exit\" to quit" << endl;

		threads.create_thread(boost::bind(displayLoop, sock));
		threads.create_thread(boost::bind(inboundLoop, sock, prompt));
		threads.create_thread(boost::bind(writeLoop, sock, prompt));

		threads.join_all();
	}
	catch (std::exception& e)
	{
		setlocale(LC_CTYPE, "Ukrainian");
		cerr << e.what() << endl;
	}

	puts("Press any key to continue...");
	//system("pause");
	getc(stdin);
	return 0;
}

char* string_to_char(const string& str) {
	int size = str.size();
	char *ch = new char[size + 1];
	for (int i = 0; i < size; i++)
		ch[i] = str[i];
	ch[size] = 0;
	return ch;
}

string* buildPrompt()
{
	const int inputSize = 256;
	char inputBuf[inputSize] = { 0 };
	char nameBuf[inputSize] = { 0 };
	string* prompt = new string(": ");

	cout << "Please input a new username and password, separeted with coma: ";
	cin.getline(nameBuf, inputSize);
	string log = string(nameBuf);
	(*prompt) = log.substr(0,log.find(',')) + *prompt;
//	cout << *prompt << endl;
	string pass = log.substr(log.find(',') + 1, log.length());
	password = string_to_char(pass);
//	cout << password << endl;
	boost::algorithm::to_lower(*prompt);

	return prompt;
}

// "входящий" цикл
/*
// creates a loop which only inserts into the thread when a message is available on the socket connected to the server
// Reading from the socket object is an operation which may potentially interfere with writing to the socket so we put 
// a one second delay on checks for reading.
*/
void inboundLoop(socket_ptr sock, string_ptr prompt)
{
	int bytesRead = 0;
	char readBuf[1024] = { 0 };
	string publicKeys;

	//receiving public key from server for encrypting
	sock->receive(buffer(readBuf, bufSize));
	publicKeys = readBuf;

	//encrypting password
	string e_ = publicKeys.substr(0, publicKeys.find(' '));
	string n_ = publicKeys.substr(publicKeys.find(' ') + 1, publicKeys .length());
	int e = stoi(e_);
	int n = stoi(n_);

	cout << "This is your decrypted password: " << password << endl;
	char *encryptedPassword = doEncrypt(password, n, e);
	cout << "This is your encrypted password: " << encryptedPassword << endl;
	
	//sending encrypted password to server
	sock->send(buffer(encryptedPassword, bufSize));

	cout << "You can start chatting!" << endl << endl;
	for (;;)
	{
		if (sock->available())
		{
			bytesRead = sock->read_some(buffer(readBuf, inputSize));
			string_ptr msg(new string(readBuf, bytesRead));

			messageQueue->push(msg);
		}

		boost::this_thread::sleep(boost::posix_time::millisec(1000));
	}
}


/* 
// Writting messages to the socket
// to send off to other members of the Chat session we need a loop that will constantly poll for user input. 
*/
void writeLoop(socket_ptr sock, string_ptr prompt)
{
	char inputBuf[inputSize] = { 0 };
	string inputMsg;
	string encryptedMsg;
	for (;;)
	{
		cin.getline(inputBuf, inputSize);
		inputMsg = *prompt + (string)inputBuf + '\n';	
		encryptedMsg = Encipher(inputMsg, password);

		if (!inputMsg.empty())
		{
			sock->write_some(buffer(encryptedMsg, inputSize));
		}

		// The string for quitting the application
		// On the server-side there is also a check for "quit" to terminate the TCP socket
		if (inputMsg.find("exit") != string::npos) 
			exit(1);

		inputMsg.clear();
		memset(inputBuf, 0, inputSize);
	}
}

/*
// We rely on the fact that every message begins with a user prompt 
// in order to determine if the message belonged to the client or not. 
*/
void displayLoop(socket_ptr sock)
{
	for (;;)
	{
		if (!messageQueue->empty())
		{
			if (!isOwnMessage(messageQueue->front()))
			{
				cout << *(messageQueue->front());
			}

			messageQueue->pop();
		}

		boost::this_thread::sleep(boost::posix_time::millisec(500));
	}
}

bool isOwnMessage(string_ptr message)
{
	if (message->find(*promptCpy) != string::npos)
		return true;
	else
		return false;
}