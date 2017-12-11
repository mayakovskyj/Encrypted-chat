#include<iostream>
#include<list>
#include<map>
#include<queue>
#include<cstdlib>

#include<boost/asio.hpp>
#include<boost/thread.hpp>
#include<boost/asio/ip/tcp.hpp>

#include "RSA.h"
#include "Visionnaire.h"

using namespace std;
using namespace boost::asio;
using namespace boost::asio::ip;

typedef boost::shared_ptr<tcp::socket> socket_ptr;
typedef boost::shared_ptr<string> string_ptr;
typedef map<socket_ptr, string_ptr> clientMap; //Maps client socket connections to client messages and passwords
typedef boost::shared_ptr<clientMap> clientMap_ptr;
typedef boost::shared_ptr< list<socket_ptr> > clientList_ptr; //clients connected to the server
typedef boost::shared_ptr< queue<clientMap_ptr> > messageQueue_ptr; // Collects messages sent to the server and routes them to connected clients

io_service service;
tcp::acceptor acceptor(service, tcp::endpoint(tcp::v4(), 8001));
boost::mutex mtx;
clientList_ptr clientList(new list<socket_ptr>);
messageQueue_ptr messageQueue(new queue<clientMap_ptr>);
clientMap passwords;

const int bufSize = 1024;
enum sleepLen // Time is in milliseconds
{
	sml = 100,
	lon = 200
};

// Function Prototypes
bool clientSentExit(string_ptr);
void disconnectClient(socket_ptr);
void acceptorLoop();
void requestLoop();
void responseLoop();
// End of Function Prototypes

int main(int argc, char** argv)
{
	boost::thread_group threads;

	threads.create_thread(boost::bind(acceptorLoop));
	boost::this_thread::sleep(boost::posix_time::millisec(sleepLen::sml));

	threads.create_thread(boost::bind(requestLoop));
	boost::this_thread::sleep(boost::posix_time::millisec(sleepLen::sml));

	threads.create_thread(boost::bind(responseLoop));
	boost::this_thread::sleep(boost::posix_time::millisec(sleepLen::sml));

	threads.join_all();

	puts("Press any key to continue...");
	getc(stdin);
	return 1;
}

void acceptorLoop()
{
	cout << "Waiting for clients..." << endl;

	for (;;)
	{
		socket_ptr clientSock(new tcp::socket(service));

		acceptor.accept(*clientSock);

		cout << "-----------------------------------------------------------" << endl;
		cout << "New client joined! " << endl;

		//generating (e,d)
		long int a = 17;
		long int b = 23;
		long int* keyPair = rsaGenKeyPair(a, b);
		long int eRSA = keyPair[0];
		long int dRSA = keyPair[1];

		//sending (e,n)
		string keys_ = to_string(eRSA) + " " + to_string(a*b);
		string_ptr keys(new string(keys_));
		clientSock->send(buffer((*keys),bufSize));	

		// receiving enrypted password
		char password_[1024] = { 0 };
		clientSock->receive(buffer(password_, bufSize));
		cout << "This is user's encrypted password: " << password_ << endl;

		//decrypting password using RSA 
		char *password = doDecrypt(password_, a*b, dRSA);
		string pass_ = password;
		cout << "This is user's decrypted password: " << pass_ << endl;

		//adding password and client to containers
		string_ptr pass(new string(pass_));
		passwords.insert(pair<socket_ptr, string_ptr>(clientSock, pass));
		clientList->emplace_back(clientSock);

		cout << clientList->size() << " total clients" << endl;
		cout << "-----------------------------------------------------------" << endl;
	}
}

void requestLoop()
{
	for (;;)
	{
		if (!clientList->empty())
		{
			mtx.lock();
			for (auto& clientSock : *clientList)
			{
				if (clientSock->available())
				{
					char readBuf[bufSize] = { 0 };

					//receiving encrypting message from client
					int bytesRead = clientSock->read_some(buffer(readBuf, bufSize));
					string_ptr msg(new string(readBuf, bytesRead));

					//decrypting message
					auto key = passwords.find(clientSock);
					string_ptr pass = (*key).second;
					string plainText = Decipher((*msg), (*pass));

					// creating char mess for pushing to the messageQueue
					char mess[bufSize] = { 0 };
					for (int i = 0; i < plainText.length(); i++)
						mess[i] += plainText[i];
					string_ptr message(new string(mess, bytesRead));
	
					// if message is "exit"
					if (clientSentExit(message))
					{
						disconnectClient(clientSock);
						break;
					}

					//pushing to messageQueue
					clientMap_ptr cm(new clientMap);
					cm->insert(pair<socket_ptr, string_ptr>(clientSock, message));
					messageQueue->push(cm);

					cout << *message;
				}
			}
			mtx.unlock();
		}

		boost::this_thread::sleep(boost::posix_time::millisec(sleepLen::lon));
	}
}

bool clientSentExit(string_ptr message)
{
	if (message->find("exit") != string::npos)
		return true;
	else
		return false;
}

void disconnectClient(socket_ptr clientSock)
{
	auto position = find(clientList->begin(), clientList->end(), clientSock);

	clientSock->shutdown(tcp::socket::shutdown_both);
	clientSock->close();

	clientList->erase(position);

	cout << "Client Disconnected! " << clientList->size() << " total clients" << endl;
}

void responseLoop()
{
	for (;;)
	{
		if (!messageQueue->empty())
		{
			auto message = messageQueue->front();

			mtx.lock();
			for (auto& clientSock : *clientList)
			{
				clientSock->write_some(buffer(*(message->begin()->second), bufSize));
			}
			mtx.unlock();

			mtx.lock();
			messageQueue->pop();
			mtx.unlock();
		}

		boost::this_thread::sleep(boost::posix_time::millisec(sleepLen::lon));
	}
}