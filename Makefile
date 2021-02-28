all: client server

client: client.cpp
	g++ client.cpp -o client -lpthread -lssl -lcrypto
server: server.cpp
	g++ server.cpp -o server -lpthread -lssl -lcrypto