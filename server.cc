#include <iostream>
#include <vector>
#include <string>
#include <iterator>
#include <algorithm>

#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rsa.h>       
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct verification_error {

  int code;
  int depth;
  std::string msg;
  std::string subject;
  std::string issuer;

  verification_error(int c, 
    int d, 
    const char* m,
    const char* subj,
    const char* issu): 
      code(c),
      depth(d),
      msg(m),
      subject(subj),
      issuer(issu){};

} verification_error;

std::ostream& operator<<(std::ostream& os, const verification_error& error){

  os << "#" << error.depth << ":" << std::endl 
     << "s: " << error.subject << std::endl
     << "i: " << error.issuer << std::endl
     << "Error: " << error.msg << " (" << error.code << ")"
     << std::endl << std::endl;
}

// A vector of verification errors, is populated by
// our callback as triggered by OpenSSL 
std::vector<verification_error> verification_errors;

// Certificate and private key
const char* CERTIFICATE = "/etc/grid-security/hostcert.pem";
const char* PRIVATE_KEY = "/etc/grid-security/hostkey.pem";

// The server will listen on this port
const int PORT = 15001;

// SSL context
const SSL_METHOD *meth;
SSL_CTX* ctx;

// SSL object
SSL* ssl;

// Socket file descriptors
int listen_sd;
int sd;

// Error reporting
int err;

// The socket struct
struct sockaddr_in sa_serv;
struct sockaddr_in sa_cli;
size_t client_len;


// Peer certificate structures
X509* peer_cert;
STACK_OF(X509)* peer_stack;

// Prototypes
//
void print_certchain_information(STACK_OF(X509) *chain);
void print_certificate_information(X509* cert);

void check_err(int error, const std::string& msg){
  if (error ==-1){
    perror(msg.c_str());
    exit(1);
  }
}

void check_ssl(int ssl_error){
  if (ssl_error == -1){

    ERR_print_errors_fp(stderr);
    exit(2);
  }
}

void save_verification_error(int code, 
  int depth, 
  const char* msg,
  const char* subject,
  const char* issuer){

  verification_error e(code,depth,msg,subject,issuer);
  verification_errors.push_back(e);

}

int my_verify_callback(int ok, X509_STORE_CTX* ctx){

  X509* cert = X509_STORE_CTX_get_current_cert(ctx);

  char* subject_str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
  char* issuer_str = X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
  
  int verify_error = X509_STORE_CTX_get_error(ctx);
  int verify_error_depth = X509_STORE_CTX_get_error_depth(ctx);

  const char* verify_error_string = X509_verify_cert_error_string(verify_error);

  if (verify_error != X509_V_OK) {

    save_verification_error(
      verify_error,
      verify_error_depth, 
      verify_error_string,
      subject_str,
      issuer_str);
  }

  return 1;
  
}


void initialize_openssl(){
  
  OpenSSL_add_ssl_algorithms();
  SSL_library_init();
  SSL_load_error_strings();

  meth = SSLv23_server_method();
  ctx = SSL_CTX_new (meth);

  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }
  
  if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/grid-security/certificates") <= 0){
    ERR_print_errors_fp(stderr);
    exit(2);
  }
  
  if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE, SSL_FILETYPE_PEM) <= 0){
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY, SSL_FILETYPE_PEM) <= 0){
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  if (SSL_CTX_check_private_key(ctx) <= 0){
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, my_verify_callback);
  SSL_CTX_set_verify_depth(ctx, 100);

}

void initialize_socket(){
  
  listen_sd = socket (AF_INET, SOCK_STREAM, 0);
  memset (&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family      = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port        = htons (PORT);

  err = bind(listen_sd,
    (struct sockaddr*) &sa_serv,
    sizeof (sa_serv));

  check_err(err, "Socket bind error.");
  
  err = listen (listen_sd,5);
  check_err(err, "Socket listen error.");

}

void print_certificate_information(X509* cert){

  char* subject_str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
  char* issuer_str = X509_NAME_oneline(X509_get_issuer_name(cert),0,0);
  
  std::cout << "Subject: " << subject_str << std::endl;
  std::cout << "Issuer: " << issuer_str << std::endl;

  OPENSSL_free(subject_str);
  OPENSSL_free(issuer_str);

}

void print_certchain_information(STACK_OF(X509) *cert_chain){

  int stack_size = sk_X509_num(cert_chain);

  if (stack_size == 0){
    
    std::cout << "Empty stack" << std::endl;
    return;
  }


  for (int i=0; i < stack_size; i++){
    
    X509* cert = sk_X509_value(cert_chain,i);
    std::cout << "#" << i << ":" << std::endl;
    print_certificate_information(cert);
  }

}

void close_socket_and_cleanup(){
  close(sd);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

void print_verification_errors(){
  
  if ( verification_errors.size() > 0 ){

    std::cout << "Verification errors found:" << std::endl;

    std::copy(verification_errors.begin(), 
              verification_errors.end(),
              std::ostream_iterator<verification_error>(std::cout));
  } else {

    std::cout << "No validation errors." << std::endl;

  }

}

int main(){

  initialize_openssl();  
  initialize_socket();

  std::cout << "Test SSL server started..." << std::endl;
  // Accept on the socket
  client_len = sizeof(sa_cli);
  sd = accept (listen_sd, (struct sockaddr*) &sa_cli, (socklen_t*)&client_len);
  check_err(sd, "Socket accept error."); 
  
  std::cout << "Connection from " 
        << inet_ntoa(sa_cli.sin_addr) 
        << ", port " << sa_cli.sin_port
        << std::endl;

  // Enstabilish SSL context
  ssl = SSL_new(ctx);

  if (!ssl){
    std::cout << "Error creating the SSL context!" << std::endl;
    exit(1);
  }

  SSL_set_fd (ssl, sd);
  err = SSL_accept(ssl);

  check_ssl(err);

  std::cout << "SSL Connection entabilished using " << SSL_get_cipher(ssl)
    << std::endl;

  print_verification_errors(); 

  peer_cert = SSL_get_peer_certificate(ssl);
  peer_stack = SSL_get_peer_cert_chain(ssl);

  std::cout << std::endl << "Peer certificate: " << std::endl;
  print_certificate_information(peer_cert);

  std::cout << std::endl << "Peer cert chain: " << std::endl;
  print_certchain_information(peer_stack);

  sk_X509_free(peer_stack);

  close_socket_and_cleanup();
  std::cout << "Done." << std::endl;
}

