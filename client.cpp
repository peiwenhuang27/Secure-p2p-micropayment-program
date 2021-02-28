#include <iostream>
#include <cstdio>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
const int BUFSIZE = 1024;
const int ECRTSIZE = 256;
const int ECRTSIZE2 = 128;
char CLIENT_CERT[BUFSIZE] = "client.crt";
char CLIENT_PRI[BUFSIZE] = "client.key";
pthread_mutex_t mtx_lock = PTHREAD_MUTEX_INITIALIZER;
SSL* ssl;
SSL_CTX *ctx;
RSA* cliPri;

SSL_CTX* initCTX(void) // certificate initializer
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method()); // generate a client certificate
    if(ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

SSL_CTX* initCTXServer(void) // server certificate (for listening)
{   
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_server_method()); // generate a server certificate 
    if(ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void showCerts(SSL *ssl)
{
    X509* certification;
    char* certResult;
    
    certification = SSL_get_certificate(ssl);
    if(certification != NULL)
    {
        cout << "Digital Certificate Information:\n";
        certResult = X509_NAME_oneline(X509_get_subject_name(certification), 0, 0);
        cout << "Certification: " << certResult << "\n";
        free(certResult);
        certResult = X509_NAME_oneline(X509_get_issuer_name(certification), 0, 0);
        cout << "Issuer: " << certResult << "\n";
        free(certResult);
        X509_free(certification);
    }
    else
    {
        cout << "--> No certification!" << endl;
    }
}

void certify_client(SSL_CTX* ctx, char * cert, char * pri)
{
    if(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
    //see the client certificate
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, pri, SSL_FILETYPE_PEM) <= 0)
    // see the client private key
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    if (!SSL_CTX_check_private_key(ctx)) 
    //check if private key match certification
    {
        ERR_print_errors_fp(stderr);
        cout << "--> Private key does not match the public certification." << endl;
        abort();
    }
    else
    {
        cout << "ctx cert and private key match!\n";
    }
}

void certify_server(SSL_CTX* ctx, char * cert, char * pri)
{
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, pri, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    if (!SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stderr);
        cout << "--> Private key does not match the public certification." << endl;
        abort();
    }
}

// function headers
void transactionProc(int mysockfd, int portcli, SSL* ssl_toServ);

struct List
{
    int accBal;
    int onlineCnt;
    string myName;
    string onlineList[BUFSIZE]; 
    string IPList[BUFSIZE];
    string portList[BUFSIZE];
    
    List();
    List(int accBal, int cnt, string name, string online[], string IP[], string port[]);
    struct List operator=(List const &rhs);
    void print();
};
List::List()
{
    onlineCnt = 0;
    myName = "";
    bzero((string *) &onlineList, sizeof(onlineList));
    bzero((string *) &IPList, sizeof(IPList));
    bzero((string *) &portList, sizeof(portList));
}
List::List(int bal, int cnt, string name, string online[], string IP[], string port[])
{
    accBal = bal;
    onlineCnt = cnt;
    myName = name;
    for(int i = 0; i < onlineCnt; i++)
    {
        onlineList[i] = online[i];
        IPList[i] = IP[i];
        portList[i] = port[i];
    }
}
void List::print()
{
    // print
    std::cout << "\n----------------------------------------\n";
    std::cout << "Hello " << myName << "!\n";
    std::cout << "Here comes your status check! :)\n";
    std::cout << "\nYour current account balance: " << accBal << "\n";
    std::cout << "# of users online: " << onlineCnt << "\n\n";
    for(int i = 0; i < onlineCnt; i++)
    {
        std::cout << "Name: " << onlineList[i] << "\n";
        std::cout << "IP address: " << IPList[i] << "\n";
        std::cout << "Port number: " << portList[i] << "\n";
    }
    std::cout << "----------------------------------------\n";
}
struct List List::operator=(List const &rhs)
{
    this->accBal = rhs.accBal;
    this->onlineCnt = rhs.onlineCnt;
    this->myName = rhs.myName;
    for(int i = 0; i < this->onlineCnt; i++)
    {
        this->onlineList[i] = rhs.onlineList[i];
        this->IPList[i] = rhs.IPList[i];
        this->portList[i] = rhs.portList[i];
    }
    
    return *this;
}

struct thrdArgs
{
    int clientfd;
    int portcli;
    SSL* ssl;

    thrdArgs();
    thrdArgs(int fd, int port, SSL* newSSL);
    ~thrdArgs();
};
thrdArgs::thrdArgs()
{
    clientfd = 0;
    portcli = 0;
    
}
thrdArgs::thrdArgs(int fd, int port, SSL* newSSL)
{
    clientfd = fd;
    portcli = port;
    ssl = newSSL;
}
thrdArgs::~thrdArgs() { }

// server thread
void* lstnMsg(void* threadarg)
{
    struct thrdArgs* arg;
    arg = (struct thrdArgs *) threadarg;
    int client = arg->clientfd;
    int portcli = arg->portcli;
    SSL* ssl_toserv = arg->ssl;
    transactionProc(client, portcli, ssl_toserv);

    pthread_exit(NULL);
}

void printService();
char* regis();
char* login(string &myName, int portcli);
char* check();
List processList(string myName, char* buffer);
string askPayeeName();
string askPayAmnt(string payeeName);
struct sockaddr_in getPayeeAddr(string payeeName, List myList, string myName, int &code);
char* transactionMsg(string myName, string payeeName, string payAmnt);
char* exitmsg();


int main (int argc, char *argv[])
{
// initialization
    int client, portcli, portserv;
    struct sockaddr_in serv_addr;
    char buffer[BUFSIZE];
    bzero((char *) &buffer, sizeof(buffer));
    if(argc < 3)
    {
       fprintf(stderr,"usage %s hostname\n", argv[0]);
       exit(0);
    }
    std::cout << "Please enter your desired port number:\n";
    string portcli_str;
    getline(cin, portcli_str);
    portcli = stoi(portcli_str);

// client socket creation   
    client = socket(AF_INET, SOCK_STREAM, 0);
    if(client < 0)
    {
        std::cout << "Client socket creation failed\n";
        exit(1);
    }

// server initialization
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portserv = atoi(argv[2]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portserv);
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);

// connect to server
    int rc = connect(client, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if(rc != 0) // failure
    {
        std::cout << "Connection failed\n";
        exit(1);
    }
    else
    {
        std::cout << "Accepted successfully!\n";
        std::cout << "Certifying server...\n";
    }

// initialize SSL certificate
    SSL_library_init();
    ctx = initCTX(); // generate a client certificate
    certify_client(ctx, CLIENT_CERT, CLIENT_PRI); // check if private key and certificate match
    FILE* priFile = fopen(CLIENT_PRI,"r"); // private key
    cliPri = PEM_read_RSAPrivateKey(priFile, NULL, NULL, NULL);

// based on CTX and generate new SSL and connect it
    ssl = SSL_new(ctx); // new SSL structure to hold data for TLS/SSL connection
    SSL_set_fd(ssl, client); // set interface BIO between ssl and fd
    if(SSL_connect(ssl) <= 0)
        ERR_print_errors_fp(stderr);
    showCerts(ssl); // show certificate

// wait to be assigned a handler
    int n = SSL_read(ssl, buffer, BUFSIZE);
    if(n <= 0)
    {
        cout << "ERROR in first SSL read";
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    std::cout << "-> Waiting for a handler to be assigned...\n";
    bzero((char *) &buffer, sizeof(buffer));
    n = SSL_read(ssl, buffer, BUFSIZE);
    std::cout << "-> Connection confirmed!\nHello World~~~\n\n\n";
    bzero((char *) &buffer, sizeof(buffer));

// connection initialization
    bool isExit = false;
    struct List myList;
    int onlineCnt = 0;
    string myName;
    bool loggedIn = false;

// open server thread
    pthread_t thrd;
    struct thrdArgs arg (client, portcli, ssl);
    rc = pthread_create(&thrd, NULL, lstnMsg, (void *)&arg);
    if(rc)
    {
        std::cout << "Error:unable to create thread, " << rc << "\n";
        exit(-1);
    }
    std::cout << "Listening thread created!\n\n";    

    do
    {
    // client side
        bzero((char *) &buffer, sizeof(buffer));
        printService(); // ask user to enter command code
        string query;
        getline(cin, query, '\n');

    // REGISTER
        if(query == "0")
        {
            bzero((char *) &buffer, sizeof(buffer));
            strcpy(buffer, regis());
            SSL_write(ssl, buffer, strlen(buffer));
        }
    // LOGIN
        else if(query == "1")
        {
            bzero((char *) &buffer, sizeof(buffer));
            strcpy(buffer, login(myName, portcli));
            SSL_write(ssl, buffer, strlen(buffer));
        }
    // CHECK
        else if(query == "2")
        {
            bzero((char *) &buffer, sizeof(buffer));
            strcpy(buffer, check());
            SSL_write(ssl, buffer, strlen(buffer));
        }
    // COMMIT
        else if(query == "3")
        {
            if(!loggedIn)
            {
                std::cout << "Please login first to commit transactions!\n\n";
                continue;
            }
            string payeeName = askPayeeName();
            string payAmnt = askPayAmnt(payeeName);
            struct sockaddr_in payee_addr;
            bzero((char *) &payee_addr, sizeof(payee_addr));
            int returnCode = 0;
            payee_addr = getPayeeAddr(payeeName, myList, myName, returnCode);
            if(returnCode == -1)
            {
                cout << "The user does not exist!\n";
                continue;
            }
            else if(returnCode == -2)
            {
                cout << "You cannot transfer to yourself!\n";
                continue;
            }
        
        // initialize SSL
            SSL_CTX* ctx_cli; // my certificate as client
            ctx_cli = initCTX();
            certify_client(ctx_cli, CLIENT_CERT, CLIENT_PRI); // certify
            SSL* ssl_cli;
            ssl_cli = SSL_new(ctx_cli);
            showCerts(ssl_cli);
        // create socket to connect to payee
            int out = 0;
            out = socket(AF_INET, SOCK_STREAM, 0);
            if (out < 0)
            {
                std::cout << "\n\n-> Socket creation failed\n";
                exit(1);
            }
            int retc_toC = connect(out, (struct sockaddr*)&payee_addr, sizeof(payee_addr));
            if(retc_toC != 0)
            {
                std::cout << "-> Connecting to client failed\n";
                exit(1);
            }
            
        // set ssl to fd
            SSL_set_fd(ssl_cli, out);
            if(SSL_connect(ssl_cli) <= 0)
                ERR_print_errors_fp(stderr);

        // receive message
            bzero((char *) &buffer, sizeof(buffer));
            n = SSL_read(ssl_cli, buffer, BUFSIZE); // ""Connection accepted!""
            if(n <= 0)
                ERR_print_errors_fp(stderr);
            bzero((char *) &buffer, sizeof(buffer));
            strcpy(buffer, transactionMsg(myName, payeeName, payAmnt));

        // generate encryted message
            char ecrt [BUFSIZE];
            int statcode = RSA_private_encrypt((strlen(buffer)+1) * sizeof(char), (unsigned char *) buffer, (unsigned char *) ecrt, cliPri, RSA_PKCS1_PADDING);
            if(statcode < 0) // check error
                ERR_print_errors_fp(stderr);
            SSL_write(ssl_cli, ecrt, ECRTSIZE); // Transaction msg
            std::cout << "-> Transaction message sent to the payee!\n";
            bzero((char *) &buffer, sizeof(buffer));
            SSL_read(ssl_cli, buffer, sizeof(buffer));
            cout << "-> Response: " << buffer << "\n";
            bzero((char *) &buffer, sizeof(buffer));
            SSL_read(ssl_cli, buffer, sizeof(buffer));
            cout << "-> " << buffer << "\n";

            close(out);
            SSL_shutdown(ssl_cli);
            SSL_free(ssl_cli);
            SSL_CTX_free(ctx_cli);
            continue;
        }
    // EXIT
        else if (query == "4")
        {
            bzero((char *) &buffer, sizeof(buffer));
            strcpy(buffer, exitmsg());
            SSL_write(ssl, buffer, strlen(buffer));
            std::cout << "Sad to see you leave :(\n";
            isExit = true; // break WHILE loop
        }
        else
        {
            std::cout << "We don't have this option, let's try again!\n";
            continue; // don't receive from server
        }
        

        
    // server side
        bzero((char *) &buffer, sizeof(buffer));
        SSL_read(ssl, buffer, BUFSIZE);
  
        if(strstr(buffer, "100 OK") != NULL) // REGISTER SUCCESS
        {
            std::cout << "Registration completed!\nYou're one of us now :D\n\n";
        }
        else if(strstr(buffer, "210 FAIL") != NULL) // REGISTER FAIL
        {
            std::cout << "This account name is already taken :(\nPlease try with a different name later!\n\n";
        }
        else if(strstr(buffer, "User already logged in!") != NULL)
        {
            std::cout << "The account has already been logged in!\n\n";
        }
        else if(strstr(buffer, "Only one account can log in once!") != NULL)
        {
            std::cout << buffer << "\n\n";
        }
        else if(strstr(buffer, "Please login to access the list!") != NULL)
        {
            std::cout << buffer << "\n\n";
        }
        else if(strstr(buffer, "220 AUTH_FAIL") != NULL) // LOGIN FAIL
        {
            std::cout << "You have not registered, no? :3\nMaybe consider registering one!\n\n";
        }
        else if(strstr(buffer, "Bye") != NULL) // EXIT
        {
            std::cout << "Server confirmed your departure.\n\n";
        }
        else if(strstr(buffer, "not valid") != NULL) // invalid
        {
            std::cout << "Invalid input, let's try again!\n\n";
        }
        else
        {
            // LOGIN SUCCESS or CHECK
            myList = processList(myName, buffer);
            loggedIn = true;
        }
    } while(!isExit);

    std::cout << "\nConnection terminatd.\n";
    std::cout << "Thank you! :) See you again soon\n";

    close(client);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

void transactionProc(int mysockfd, int portcli, SSL* ssl_toServ)
{
// create socket
    int server, client;
    socklen_t cli;
    char buffer[BUFSIZE];
    SSL* ssl = ssl_toServ; // to server
    struct sockaddr_in serv_addr, cli_addr;
    int n;
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) 
        std::cout << "ERROR opening socket\n";
    bzero((char *) &serv_addr, sizeof(serv_addr));

// initialize server information
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portcli);

// bind the server socket
    int rc = ::bind(server, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (rc < 0) 
        std::cout << "ERROR on binding\n";
    std::cout << "Binding port #" << portcli << " successfully!\n";
    std::cout << "Listening...\n";
    cli = sizeof(cli_addr);
    listen(server, 3);

    while(true)
    {
        client = accept(server, (struct sockaddr *) &cli_addr, &cli);
        if(client < 0) 
            std::cout << "ERROR on accept\n";
        bzero(&buffer, BUFSIZE);

    // create SSL session
        SSL_CTX* ctx_serv; // server certificate
        ctx_serv = initCTXServer();
        certify_server(ctx_serv, CLIENT_CERT, CLIENT_PRI);
        SSL_library_init();
        SSL_CTX_set_verify(ctx_serv, SSL_VERIFY_PEER, NULL);
        SSL_CTX_load_verify_locations(ctx_serv, CLIENT_CERT, NULL);


    // initialize SSL
        SSL* ssl_serv; // client-server SSL
        ssl_serv = SSL_new(ctx_serv);
        SSL_set_fd(ssl_serv, client); // set interface between fd and SSL
        showCerts(ssl_serv);
        n = SSL_accept(ssl_serv); // SSL handshake
        if(n < 0)
        {
            std::cout << "ERROR on SSL accpect\n";
            exit(0);
        }
        strcpy(buffer, "Connection accepted!");
        n = SSL_write(ssl_serv, buffer, strlen(buffer));
        if(n < 0)
        {
            std::cout << "ERROR on SSL sending\n";
            exit(0);
        }
    // get public key
        X509* pub0 = SSL_get_peer_certificate(ssl_serv);
        EVP_PKEY* pub1 = X509_get_pubkey(pub0);
        RSA* pub_cli = EVP_PKEY_get1_RSA(pub1);

        bzero(&buffer, BUFSIZE);
        n = SSL_read(ssl_serv, buffer, sizeof(buffer));
        if(n < 0)
            std::cout << "ERROR reading from socket\n";
        char dcrt [BUFSIZE];
        int code = RSA_public_decrypt(ECRTSIZE, (unsigned char*) buffer, (unsigned char *) dcrt, pub_cli, RSA_PKCS1_PADDING);
        if(code < 0)
        {
            cout << "ERROR decrypting\n";
            exit(1);
        }
        std::cout << "Transaction message:\n" << dcrt << "\n";

        char* msg = (char *) "Got it! Encrypting and sending message to server..\n";
        n = SSL_write(ssl_serv, msg, strlen(msg));
        if(n < 0)
            std::cout << "ERROR writing to socket\n";
        
        // parse 
        char cipher1 [ECRTSIZE2] = {0};
        char cipher2 [ECRTSIZE2] = {0};
        int cnt = 0;
        for(int i = 0; i < ECRTSIZE2; i++)
        {
            cipher1[i] = buffer[cnt];
            cnt++;
        }
        for(int i = 0; i < ECRTSIZE2; i++)
        {
            cipher2[i] = buffer[cnt];
            cnt++;
        }
        // encrypt
        char ecrt1 [BUFSIZE] = {0};
        char ecrt2 [BUFSIZE] = {0};
        int statcode = RSA_private_encrypt(ECRTSIZE2 * sizeof(char), (unsigned char *) cipher1, (unsigned char *) ecrt1, cliPri, RSA_PKCS1_PADDING);
        if(statcode < 0) // check error
            ERR_print_errors_fp(stderr);
        statcode = RSA_private_encrypt(ECRTSIZE2 * sizeof(char), (unsigned char *) cipher2, (unsigned char *) ecrt2, cliPri, RSA_PKCS1_PADDING);
        if(statcode < 0) // check error
            ERR_print_errors_fp(stderr);
        char ecrt [BUFSIZE] = {0};
        strcpy(ecrt, "TRANS#");
        cnt = 0;
        for(int i = 6; i - 6 < strlen(dcrt); i++)
        {
            ecrt[i] = dcrt[cnt];
            cnt++;
        }
        cnt = strlen(dcrt) + 6;
        ecrt[cnt] = '&';
        cnt++;
        for(int i = 0; i < ECRTSIZE; i++)
        {
            ecrt[cnt] = ecrt1[i];
            cnt++;
        }
        for(int i = 0; i < ECRTSIZE; i++)
        {
            ecrt[cnt] = ecrt2[i];
            cnt++;
        }
        ecrt[cnt] = '\0';
        SSL_write(ssl, ecrt, cnt);
        std::cout << "Message sent to server..\n";

        bzero(&buffer, BUFSIZE);
        n = SSL_read(ssl, buffer, BUFSIZE);
        std::cout << "Server response:\n" << buffer << "\n";
        if(strstr(buffer, "OK") != NULL) // transaction successful
        {
            char* msg = (char *) "OK! Server updated our payment.";
            n = SSL_write(ssl_serv, msg, strlen(msg));
        }
        else
        {
            char* msg = (char *) "Oops! Looks like you do not have enough money to make the payment..\n";
            n = SSL_write(ssl_serv, msg, strlen(msg));
        }
        close(client);
        SSL_shutdown(ssl_serv);
        SSL_free(ssl_serv);
        SSL_CTX_free(ctx_serv);
    }
    close(server);
}

void printService()
{
    std::cout << "What can we do for you today? :)\n\n";
    // REGISTER-- press 0
    std::cout << "Register for an account now!             -> ENTER 0\n";
    // LOGIN-- press 1
    std::cout << "Got an account? Login!                   -> ENTER 1\n";
    // CHECK ACCT BAL & ONLINE LIST-- press 2
    std::cout << "Check account balance and online list    -> ENTER 2\n";
    // COMMIT TRANSACTION WITH FRIENDS-- press 3
    std::cout << "Owe your friends money? Pay here!        -> ENTER 3\n";
    // EXIT PROGRAM-- press 4
    std::cout << "Tired... Exiting :0                      -> ENTER 4\n\n";
}

char* regis() // return message to send to server
{
    std::cout << "*** Register for new account:\n";
    std::cout << "-> Enter your user account name:\n";
    string accName;
    getline(cin, accName, '\n');
    std::cout << "-> Hello " << accName << ", please enter your deposit amount:\n";
    string accBal;
    getline(cin, accBal, '\n');
    string temp;
    temp = "REGISTER#" + accName + "#" + accBal + "\n";
    char* msg = new char [BUFSIZE];
    strcpy(msg, temp.c_str());
    return msg; 
}

char* login(string &myName, int portcli)
{
    std::cout << "*** Login to existing account:\n";
    std::cout << "-> Enter your user account name:\n";
    getline(cin, myName);
    string temp = "";
    temp = myName + "#" + to_string(portcli) + "\n";
    char* msg = new char [BUFSIZE];
    strcpy(msg, temp.c_str());   
    return msg;
}

char* check()
{
    string temp;
    temp = "LIST";
    char* msg = new char [BUFSIZE];
    strcpy(msg, temp.c_str());   
    return msg;
}

List processList(string myName, char* buffer) // returns the number of online users
{
    string onlineList[BUFSIZE];
    string IPList[BUFSIZE];
    string portList[BUFSIZE];
    bzero((string *) &onlineList, sizeof(onlineList));
    bzero((string *) &IPList, sizeof(IPList));
    bzero((string *) &portList, sizeof(portList));
    char* stat = strtok(buffer, " \n"); // account balance
    int accBal = strtol(stat, NULL, 10);
    stat = strtok(NULL, " \n"); // num of online users
    int onlineCnt = strtol(stat, NULL, 10);

    // process
    for(int i = 0; i < onlineCnt; i++) // online users info
    {
        stat = strtok(NULL, "#"); // user name
        string temp = string(stat);
        onlineList[i] = temp;
        stat = strtok(NULL, "#"); // IP address
        temp = string(stat);
        IPList[i] = temp;
        stat = strtok(NULL, " \n"); // port number
        temp = string(stat);
        portList[i] = temp;
    }

    List myList (accBal, onlineCnt, myName, onlineList, IPList, portList);
    myList.print();
    
    return myList;
}

string askPayeeName()
{
    std::cout << "Which of the online users do you want to pay to?\n";
    std::cout << "Enter his/her user account name:\n";
    string payeeName;
    getline(cin, payeeName);
    return payeeName;
}

string askPayAmnt(string payeeName)
{
    int num = 0;
    std::cout << "How much are you paying to " << payeeName << "?\n";
    string amnt;
    getline(cin, amnt);
    std::cout << "\nYou are paying " << payeeName << " $" << amnt << "\n\n";
    return amnt;
}

struct sockaddr_in getPayeeAddr(string payeeName, List myList, string myName, int &code)
{
    int index = -1;
    for(int i = 0; i < myList.onlineCnt; i++) // find index of the payee
    {
        if(myList.onlineList[i] == payeeName)
        {
            index = i;
            break;
        }
    }

    struct sockaddr_in payeeInfo;
    if(index == -1)
    {
        code = -1; // not existent
        return payeeInfo;
    }
    else if(myList.onlineList[index] == myName)
    {
        code = -2; // to myself
        return payeeInfo;
    }

    payeeInfo.sin_family = AF_INET;
    payeeInfo.sin_port = htons(stoi(myList.portList[index]));
    payeeInfo.sin_addr.s_addr = inet_addr(myList.IPList[index].c_str());
    return payeeInfo;
}

char* transactionMsg(string myName, string payeeName, string payAmnt)
{
    string temp;
    temp = myName + "#" + payAmnt + "#" + payeeName + "\0";
    char* msg = new char [BUFSIZE];
    strcpy(msg, temp.c_str());   
    return msg;
}

char* exitmsg()
{
    string temp;
    temp = "EXIT";
    char* msg = new char [BUFSIZE];
    strcpy(msg, temp.c_str());   
    return msg;
}