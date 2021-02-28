#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <pthread.h> 
#include <vector>
#include <queue>
#include <algorithm>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
const int BUFSIZE = 1024;
const int ECRTSIZE = 256;
const int ECRTSIZE2 = 128;
const int CLINUM = 2;
SSL_CTX *ctx;
char SERVER_CERT[BUFSIZE] = "server.crt";
char SERVER_PRI[BUFSIZE] = "server.key";
char CLIENTS_CERT[BUFSIZE] = "client.crt";
char CLIENTS_PRI[BUFSIZE] = "client.key";

SSL_CTX* initCTX(void) // certificate initializer
{
    const SSL_METHOD *ssl_method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    ssl_method = SSLv23_client_method(); // client SSL method
    ctx = SSL_CTX_new(ssl_method); // generate a client certificate
    if(ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

SSL_CTX* initCTXServer(void) //initializer
{   
    const SSL_METHOD *ssl_method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms(); // load & register cryptos
    SSL_load_error_strings(); // load all error messages
    ssl_method = TLS_server_method(); // create
    ctx = SSL_CTX_new(ssl_method);
    if(ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void certify_server(SSL_CTX* ctx, char* cert, char* key)
{   
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
    //set the local certificate from SERVER_CERT
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
    // set the praivate key from SERVER_PRI
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    
    if (!SSL_CTX_check_private_key(ctx))
    // verify: check if private key and certificate match
    {
        ERR_print_errors_fp(stderr);
        cout << "--> Private key does not match the public certification." << endl;
        abort();
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if(SSL_CTX_load_verify_locations(ctx, CLIENTS_CERT, NULL) < 1)
    {
        cout << "Error setting the verify locations.\n";
        exit(0);
    }
}

void showCerts(SSL *ssl)
{
    X509* certification;
    char* certResult;
    
    certification = SSL_get_peer_certificate(ssl);
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

struct User
{
    string name;
    int accBal;
    string IP;
    int servPort; // port connects to server
    int cliPort; // port listens to client
    bool status;
    RSA* key; // public key of client

    User();
    User(string n, int a, string ip, int sp, int cp, bool stat);
    ~User();
    bool setRSA(RSA* k);
    struct User operator=(User const &rhs);
    bool operator==(User const &rhs);
    void print();
    bool isEmpty();
    bool isOnline(string userName);
    bool login(string userName, int portN, struct sockaddr_in cli_addr);
    bool logout();
    bool sufBal(int amt);
    bool payment(int amt);
};

class List
{
private:
    int regCnt; // # of users registered
    int onlineCnt; // # of users online
    const int USER_MAX = 20;
    User** users;
public:
    List();
    ~List();
    struct List operator=(List const &rhs);
    void print();
    int getIndex(string userName);
    bool regis(User newUser);
    bool setRSAkey(User u, RSA* k);
    bool redundantRegis(string userName);
    struct User login(string userName, int portN, struct sockaddr_in cli_addr);
    bool redAcctLogin(string userName);
    bool redDeviceLogin(User const &myUser);
    bool logout(User const &aUser);
    bool userNotExist(string userName);
    bool notLoginLogout(User const &aUser);
    char* getList(User const &reqUser);
    bool transact(string const &payer, string const &payee, int const &amt);
    bool transInsuf(string const &payer, string const &payee, int const &amt);
    bool verifyTrans(char* buffer);
};

class Client
{
private:
    int clientfd;
    struct sockaddr_in cli_addr;
    SSL* ssl;
public:
    Client();
    Client(int fd, struct sockaddr_in addr, SSL* newssl);
    ~Client();
    int getFD() const;
    struct sockaddr_in getAddr() const;
    SSL* getSSL() const;
};

class WorkerPool
{
private:
    int THRD_MAX;
    std::vector<pthread_t> workers; // a vector of pthread
    std::queue<Client> waitList; // a queue of clients
    pthread_mutex_t lock; // shared mutex
    static void* feed_work_t(void* thrd);
    void* feed_work();
public:
    WorkerPool(int max);
    ~WorkerPool();
    void new_ssl(SSL* aSSL);
    void start_working();
    void add_client(Client aCli);
};

void handler(Client cli);
// global
pthread_mutex_t op_lock = PTHREAD_MUTEX_INITIALIZER;
struct List database;

int main()
{
    std::cout << "Enter the port number to listen to:\n";
    string tempPort;
    getline(std::cin, tempPort);
    int port = 0;
    port = stoi(tempPort);

// initialize SSL
    std::cout << "Initializing SSL...\n";
    SSL_library_init();
    ctx = initCTXServer();
    certify_server(ctx, SERVER_CERT, SERVER_PRI);
    std::cout << "SSL initialization complete!\n";

    
// create socket and bind
    int server, client;
    socklen_t cli_size;
    struct sockaddr_in serv_addr, cli_addr;
    int n;
    server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) 
        std::cout << "ERROR opening socket\n";
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (::bind(server, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cout << "ERROR on binding\n";
        exit(1);
    }
    std::cout << "Binding port #" << port << " successfully!\n";
    std::cout << "Listening...\n";
    cli_size = sizeof(cli_addr);

// activate worker pool
    WorkerPool pool (CLINUM);
    pool.start_working();   
    std::cout << "Waiting for connection...\n";
    listen(server, CLINUM);

    while(true)
    {
        client = accept(server, (struct sockaddr *) &cli_addr, &cli_size);
        if(client < 0)
            std::cout << "Failed to accept new client...\n";

// create SSL object
        SSL* ssl = SSL_new(ctx);
        if(!ssl)
        {
            std::cout << "ERROR creating SSL structure.\n";
            continue;
        }
        SSL_set_fd(ssl, client); // bind SSL object with socket

        int err = SSL_accept(ssl); // SSL handshake
        if(err < 0)
        {
            cout << "ERROR on acception from server\n";
            err = SSL_get_error(ssl, err);
            if((err = ERR_get_error()))
                cout << ERR_reason_error_string(err) << "\n";
            SSL_free(ssl);
            close(client);
            SSL_CTX_free(ctx);
            continue;
        }
        showCerts(ssl);

        char* msg = (char *) "Connection accepted!\n";
        err = SSL_write(ssl, msg, strlen(msg));
        if(err < 1)
        {
            std::cout << "SSL sending message failed...\n";
            SSL_free(ssl);
            close(client);
            SSL_CTX_free(ctx);
            exit(0);
        }

        // push client to waitlist queue
        Client cli (client, cli_addr, ssl);
        pool.add_client(cli);
    }
    
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}

int getCode(char buffer[])
{
    if(strstr(buffer, "REGISTER") != NULL)  // 1: REGISTER
        return 1;
    else if(strstr(buffer, "LIST") != NULL) // 3: LIST
        return 3;
    else if(strstr(buffer, "TRANS") != NULL) // 4: COMMIT
        return 4;
    else if(strstr(buffer, "EXIT") != NULL) // 5: EXIT
        return 5;
    string temp = buffer;
    int cnt = std::count(temp.begin(), temp.end(), '#');
    if(cnt == 1) // 2: LOGIN (1 #)
        return 2;

    // invalid messages
    return -1;
}
User parseUser(char buffer[], struct sockaddr_in cli_addr)
{
    char* stat = strtok(buffer, "#"); // REGISTER
    stat = strtok(NULL, "#"); // name
    string name = stat;
    stat = strtok(NULL, "\n"); // accBal
    int accBal = stoi(stat);
    char IP [BUFSIZE];
    inet_ntop(AF_INET, &(cli_addr.sin_addr), IP, INET_ADDRSTRLEN);
    int port = 0;
    port = ntohs(cli_addr.sin_port); // servPort

    struct User newUser (name, accBal, IP, port, 0, false); // no cliPort
    return newUser;
}

void* servThrd(void* threadarg)
{
    struct Client cli;
    cli = *((struct Client *) threadarg);
    handler(cli);

}
void handler(Client cli)
{
    int client = 0;
    client = cli.getFD();
    struct sockaddr_in cli_addr;
    cli_addr = cli.getAddr();
    SSL* ssl;
    ssl = cli.getSSL();
    X509* pub0 = SSL_get_peer_certificate(ssl);
    EVP_PKEY* pub1 = X509_get_pubkey(pub0);
    RSA* pub_cli = EVP_PKEY_get1_RSA(pub1);

    char* msg = (char *) "Handler assigned!\n";
    SSL_write(ssl, msg, strlen(msg));
    std::cout << msg << "\n\n";
    char buffer[BUFSIZE];
    bzero(&buffer, BUFSIZE);
    int n = 0;
    bool isExit = false;
    struct User myUser; // only one account can log in

    do
    {
        bzero(&buffer, BUFSIZE);
        n = SSL_read(ssl, buffer, BUFSIZE);
        if (n == 0)
        {
            std::cout << "Offline!\n";
            break;
        }
        std::cout << "Client message: " << buffer << "\n\n";
        
        int servCode = getCode(buffer);
        std::cout << "Service code: " << servCode << "\n";

    // REGISTER
        if(servCode == 1) 
        {
            struct User newUser;
            newUser = parseUser(buffer, cli_addr);
            pthread_mutex_lock(&op_lock);
            if(!database.redundantRegis(newUser.name))
            {
                database.regis(newUser);
                database.setRSAkey(newUser, pub_cli);
                char* msg = (char *) "100 OK";
                SSL_write(ssl, msg, strlen(msg));
                std::cout << msg << "\n\n";
            }
            else
            {
                char* msg = (char *) "210 FAIL";
                SSL_write(ssl, msg, strlen(msg));
                std::cout << msg << " User already registered!\n";
            }
            pthread_mutex_unlock(&op_lock);
        }
    // LOGIN
        else if(servCode == 2) 
        {
            char* stat = strtok(buffer, "#");
            string name = stat;
            stat = strtok(NULL, "\n");
            int port = stoi(stat);
            
            pthread_mutex_lock(&op_lock);
            if(!database.userNotExist(name))
            {
                if(database.redAcctLogin(name))
                {
                    char* msg = (char *) "User already logged in!";
                    SSL_write(ssl, msg, strlen(msg));
                    std::cout << msg << "\n\n";
                }
                else if(database.redDeviceLogin(myUser))
                {
                    char* msg = (char *) "Only one account can log in once!";
                    SSL_write(ssl, msg, strlen(msg));
                    std::cout << msg << "\n\n";
                }
                else
                {
                    myUser = database.login(name, port, cli_addr);
                    char* list;
                    list = database.getList(myUser);
                    SSL_write(ssl, list, strlen(list));
                }
            }
            else
            {
                char* msg = (char *) "220 AUTH_FAIL";
                SSL_write(ssl, msg, strlen(msg));
                std::cout << msg << "\n\n";
            }
            pthread_mutex_unlock(&op_lock);
        }
    // LIST
        else if(servCode == 3) 
        {
            pthread_mutex_lock(&op_lock);
            if(!myUser.isEmpty())
            {
                char* list;
                list = database.getList(myUser);
                SSL_write(ssl, list, strlen(list));
                std::cout << list << "\n\n";
            }
            else
            {
                char* msg = (char *) "Please login to access the list!";
                SSL_write(ssl, msg, strlen(msg));
                std::cout << msg << "\n\n";
            }
            pthread_mutex_unlock(&op_lock);
        }
    // COMMIT
        else if(servCode == 4) 
        {
            if(database.verifyTrans(buffer))
            {
                char* msg = (char *) "TRANS OK";
                SSL_write(ssl, msg, strlen(msg));
                std::cout << msg << "\n\n";
            }
            else
            {
                char* msg = (char *) "TRANS FAIL";
                SSL_write(ssl, msg, strlen(msg));
                std::cout << msg << "\n\n";
            }
        }
    // EXIT
        else if(servCode == 5) 
        {
            isExit = true;
            pthread_mutex_lock(&op_lock);
            char* msg = (char *) "Bye";
            SSL_write(ssl, msg, strlen(msg));
            std::cout << msg << "\n\n";
            if(!database.notLoginLogout(myUser))
            {
                database.logout(myUser);
                std::cout << "Client " << myUser.name << " is leaving!\n";
            }
            pthread_mutex_unlock(&op_lock);
        }
        else
        {
            char* msg = (char *) "The message is invalid, try again!";
            std::cout << msg;
            SSL_write(ssl, msg, strlen(msg));
        }
    } while (!isExit);
       
    close(client);
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

WorkerPool::WorkerPool(int max)
{
    this->THRD_MAX = max;
    for(int i = 0; i < THRD_MAX; i++)
    {
        pthread_t t;
        this->workers.push_back(t);
    }
    pthread_mutex_init(&this->lock, NULL);
}
WorkerPool::~WorkerPool()
{
    for(int i = 0; i < THRD_MAX; i++)
        pthread_join(this->workers[i], NULL);
    pthread_mutex_destroy(&this->lock);
    this->workers.clear();
    while(!this->waitList.empty())
        this->waitList.pop();
}
void* WorkerPool::feed_work_t(void* pool)
{
    WorkerPool* thrd = (WorkerPool *) pool;
    thrd->feed_work();
}
void* WorkerPool::feed_work()
{
    while(true)
    {
        pthread_mutex_lock(&(this->lock));
        Client aCli;
        bool e = this->waitList.empty();
        if (!e)
        {
            aCli = this->waitList.front();
            this->waitList.pop();
        }
        pthread_mutex_unlock(&(this->lock));
        if(!e)
        {
            handler(aCli);
        }
    }
}
void WorkerPool::start_working()
{
    std::cout << "Starting worker pool...\n";
    for(int i = 0; i < THRD_MAX; i++)
        pthread_create(&(this->workers[i]), NULL, this->feed_work_t, this);
    std::cout << "Worker pool activated\n";
    std::cout << "-----------------------------\n\n";
}
void WorkerPool::add_client(Client aCli)
{
    pthread_mutex_lock(&(this->lock));
    this->waitList.push(aCli);
    pthread_mutex_unlock(&(this->lock));
    std::cout << "Please wait until a thread is finished\n";
}
//////////////////////////////////////////////////////////////////////////////
User::User()
{
    name = "";
    accBal = 0;
    IP = "";
    servPort = 0;
    cliPort = 0;
    status = false;
}
User::User(string n, int a, string ip, int sp, int cp, bool stat)
{
    name = n;
    accBal = a;
    IP = ip;
    servPort = sp;
    cliPort = cp;
    status = stat;
}
User::~User() { }
bool User::setRSA(RSA* k)
{
    this->key = k;
    if(this->key != NULL)
    {
        cout << "RSA set to user!\n";
        return true;
    }
    cout << "RSA set to nullptr\n";
    return false;
}
struct User User::operator=(User const &rhs)
{
    this->name = rhs.name;
    this->accBal = rhs.accBal;
    this->IP = rhs.IP;
    this->servPort = rhs.servPort;
    this->cliPort = rhs.cliPort;
    this->status = rhs.status;
    
    return *this;
}
bool User::operator==(User const &rhs)
{
    if(this->name == rhs.name && this->IP == rhs.IP && this->servPort == rhs.servPort) // same name + IP + port
        return true;
    return false;
}
void User::print()
{
    std::cout << "Name: " << name << "\n";
    std::cout << "Balance: " << accBal << "\n";
    std::cout << "IP address: " << IP << "\n";
    std::cout << "Server Port number: " << servPort << "\n";
    std::cout << "Client Port number: " << cliPort << "\n";
    std::cout << "Status: " << (status == 1 ? "Online":"Offline") << "\n";
}
bool User::isEmpty()
{
    if(this->name.empty()) // no name -> empty!
    {
        return true;
    }
    return false;
}
bool User::isOnline(string userName)
{
    if(this->name == userName && this->status == true)
        return true;
    return false;
}
bool User::login(string userName, int portN, struct sockaddr_in cli_addr)
{
    if(!this->isOnline(userName)) // not online
    {
        this->status = true;
        this->cliPort = portN;
        char newIP [BUFSIZE];
        inet_ntop(AF_INET, &(cli_addr.sin_addr), newIP, INET_ADDRSTRLEN);
        this->IP = newIP;
        return true;
    }
    return false;
}
bool User::logout()
{
    if(!this->status) // not logged in
        return false;
    this->status = false;
    return true;
}
bool User::payment(int amt)
{
    this->accBal += amt;
    return true;
}
bool User::sufBal(int amt)
{
    if(this->accBal >= amt)
        return true;
    return false;
}
//////////////////////////////////////////////////////////////////////////////
List::List()
{
    regCnt = 0;
    onlineCnt = 0; 
    users = new User* [USER_MAX];
}
List::~List()
{
    // testing!
    for(int i = 0; i < USER_MAX; i++)
    {
        delete [] this->users[i];
    }
    delete this->users;
}
class List List::operator=(List const &rhs)
{
    this->regCnt = rhs.regCnt;
    this->onlineCnt = rhs.onlineCnt;
    this->users = rhs.users;
    return *this;
}
void List::print()
{
    // print
    std::cout << "\n----------------------------------------\n";
    std::cout << "Current database check\n";
    std::cout << "# of users registered: " << regCnt << "\n";
    std::cout << "# of users online: " << onlineCnt << "\n\n";
    for(int i = 0; i < regCnt; i++)
    {
        users[i]->print();
    }
    std::cout << "----------------------------------------\n\n\n";
}
int List::getIndex(string userName)
{
    // find the user
    int ind = -1;
    for(int i = 0; i < regCnt; i++)
    {
        if(users[i]->name == userName)
        {
            ind = i;
            break;
        }
    }
    return ind;
}
bool List::regis(User newUser)
{
    this->users[regCnt] = new User (); //////////////////
    this->users[regCnt]->name = newUser.name; //////////////
    this->users[regCnt]->status = newUser.status;
    this->users[regCnt]->accBal = newUser.accBal;
    this->users[regCnt]->IP = newUser.IP;
    this->users[regCnt]->servPort = newUser.servPort;
    this->users[regCnt]->cliPort = newUser.cliPort;
    regCnt++;
    std::cout << "Regisration successful\n";
    std::cout << "New user: \n";
    users[regCnt - 1]->print();
    return true;
}
bool List::setRSAkey(User u, RSA* k)
{
    int ind = this->getIndex(u.name);
    this->users[ind]->key = k;
    if(this->users[ind]->key != NULL)
    {
        cout << "RSA set to user\n";
        return true;
    }
    cout << "RSA is null\n";
    return false;
}
bool List::redundantRegis(string userName)
{
    int ind = this->getIndex(userName);
    if(ind == -1)
        return false;
    return true;
}
class User List::login(string userName, int portN, struct sockaddr_in cli_addr)
{
    struct User aUser;
    int ind = this->getIndex(userName);
    users[ind]->login(userName, portN, cli_addr);
    onlineCnt++;
    std::cout << userName << " just logged in!\n";
    return *users[ind];
}
bool List::redAcctLogin(string userName)
{
    int ind = this->getIndex(userName);
    if(users[ind]->isOnline(userName))
        return true;
    return false;
}
bool List::redDeviceLogin(User const &myUser)
{
    if(myUser.status)
        return true;
    return false;
}
bool List::logout(User const &aUser)
{
    int ind = getIndex(aUser.name);
    users[ind]->logout();
    onlineCnt--;
    std::cout << aUser.name << " just logged out.\n";
    return true;
}
bool List::userNotExist(string userName)
{
    int ind = getIndex(userName);
    if(ind == -1)
        return true;
    return false;
}
bool List::notLoginLogout(User const &aUser)
{
    if(!aUser.status)
        return true;
    return false;
}
char* List::getList(User const &reqUser)
{
    int ind = -1;
    for(int i = 0; i < regCnt; i++)
    {
        if(users[i]->name == reqUser.name)
        {
            ind = i;
            break;
        }
    }

    if(ind == -1)
    {
        std::cout << "User not existent!\n";
        exit(1);
    }
    else
    {
        string buffer = "";
        buffer = buffer + to_string(this->users[ind]->accBal) + "\n" + to_string(this->onlineCnt) + "\n";
        for(int i = 0; i < this->regCnt; i++)
        {
            if(this->users[i]->status) // online
            {
                buffer = buffer + this->users[i]->name + "#" + this->users[i]->IP + "#" + to_string(this->users[i]->cliPort) + "\n";
            }
        }
        char* list = new char [BUFSIZE];
        strcpy(list, buffer.c_str());
        return list;
    }
}
bool List::transact(string const &payer, string const &payee, int const &amt)
{
    cout << "getting payer and payee indices\n";
    // find payer and payee indices
    int payerInd = getIndex(payer);
    int payeeInd = getIndex(payee);

    if(payerInd == payeeInd)
    {
        cout << "You cannot trasfer to yourself!\n";
        return false;
    }
    
    // modify payer and payee account balance
    if(users[payerInd]->payment(amt * (-1)) && users[payeeInd]->payment(amt))
    {
        std::cout << users[payerInd]->name << " just paid $" << amt << " to " << users[payeeInd]->name << "\n";
        return true;
    }
    return false;
}
bool List::transInsuf(string const &payer, string const &payee, int const &amt)
{
    int ind = getIndex(payer);
    if(users[ind]->sufBal(amt))
        return false;
    return true;
}
bool List::verifyTrans(char* buffer)
{
    cout << "message sent by payee: " << buffer << "\n";
    char transMsg [BUFSIZE] = {0}; // TRANS#A#100#B
    int cnt = 0;
    while(buffer[cnt] != '&') 
    {
        transMsg[cnt] = buffer[cnt];
        cnt++;
    }
    transMsg[cnt] = '\0';
    cnt++;
    cout << "transMsg:\n" << transMsg << "\n";
    char cipher1p [ECRTSIZE];
    for(int i = 0; i < ECRTSIZE; i++)
    {
        cipher1p[i] = buffer[cnt];
        cnt++;
    }
    char cipher2p [ECRTSIZE];
    for(int i = 0; i < ECRTSIZE; i++)
    {
        cipher2p[i] = buffer[cnt];
        cnt++;
    }

// parse transaction message
    char* stat = strtok(transMsg, "#"); // TRANS
    stat = strtok(NULL, "#"); // A
    string payer = stat;
    stat = strtok(NULL, "#");
    int amt = stoi(stat); // amt 
    stat = strtok(NULL, "\0"); // B
    string payee = stat;
    string ori = "";
    ori = payer + "#" + to_string(amt) + "#" + payee + "\0";
    char oriMsg [BUFSIZE];
    strcpy(oriMsg, ori.c_str());
    cout << "original message by payer:\n" << oriMsg << "\n";

// get payer/payee key
    int payerInd = getIndex(payer);
    int payeeInd = getIndex(payee);

    if(payeeInd == -1)
    {
        cout << "The payee does not exist!\n";
        return false; 
    }
    else if(payerInd == payeeInd)
    {
        cout << "You cannot trasfer to yourself!\n";
        return false;
    }


// decrypt with B's public key
    char dcrt1p [ECRTSIZE2] = {0};
    int code = RSA_public_decrypt(ECRTSIZE, (unsigned char*) cipher1p, (unsigned char *) dcrt1p, this->users[payeeInd]->key, RSA_PKCS1_PADDING);
    if(code < 0)
        ERR_print_errors_fp(stderr);
    char dcrt2p [ECRTSIZE2] = {0};
    code = RSA_public_decrypt(ECRTSIZE, (unsigned char*) cipher2p, (unsigned char *) dcrt2p, this->users[payeeInd]->key, RSA_PKCS1_PADDING);
    cout << "decrypted payee's message\n";
    cout << "decrypting payer's message\n";
    char cipher [BUFSIZE] = {0};
    cnt = 0;
    for(int i = 0; i < ECRTSIZE2; i++)
    {
        cipher[cnt] = dcrt1p[i];
        cnt++;
    }
    for(int i = 0; i < ECRTSIZE2; i++)
    {
        cipher[cnt] = dcrt2p[i];
        cnt++;
    }
    
// decrypt with A's public key
    cout << "will be decrypting payer's message...\n";
    char dcrt [BUFSIZE] = {0};
    code = RSA_public_decrypt(ECRTSIZE, (unsigned char *) cipher, (unsigned char *) dcrt, this->users[payerInd]->key, RSA_PKCS1_PADDING);
    cout << "decrypted payer's message:\n" << dcrt << "\n";

// verify A and B
    if(strcmp(dcrt, oriMsg) == 0)
    {
        std::cout << "Transaction identities verified!\n";
    }
    else
    {
        std::cout << "Transaction identities verification failed\n";
        pthread_mutex_unlock(&op_lock);
        return false;
    }

// transaction
    pthread_mutex_lock(&op_lock);
    if(!this->transInsuf(payer, payee, amt))
    {
        cout << "user balance sufficient, transacting\n";
        cout << "payer: " << payer << "\n";
        cout << "payee: " << payee << "\n";
        cout << "amt: " << amt << "\n";
        this->transact(payer, payee, amt);
        cout << "transaction complete\n";
        pthread_mutex_unlock(&op_lock);
        return true;
    }
    else
    {
        std::cout << "User does not have enough balance!\n";
        pthread_mutex_unlock(&op_lock);
        return false;
    }
}
//////////////////////////////////////////////////////////////////////////////
Client::Client()
{
    clientfd = 0;
    bzero((char *) &cli_addr, sizeof(cli_addr));
}
Client::Client(int fd, struct sockaddr_in addr, SSL* newssl)
{
    this->clientfd = fd;
    this->cli_addr = addr;
    this->ssl = newssl;
}
Client::~Client()
{
    bzero((char *) &cli_addr, sizeof(cli_addr));
}
int Client::getFD() const
{
    return this->clientfd;
}
struct sockaddr_in Client::getAddr() const
{
    return this->cli_addr;
}
SSL* Client::getSSL() const
{
    return this->ssl;
}