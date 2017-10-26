#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"


// my macros
#define CERTIFICATE_FILE "alice.pem"
#define PASS "password"
#define CIPHER_LIST "SHA1"

#define SUCCESS 0
#define FAIL 1
#define BUF_LEN 256
#define COMMON_NAME "Bob’s Server"
#define EMAIL "ece568bob@ecf.utoronto.ca"

void shut_down(int sock, SSL_CTX* ctx, SSL* ssl);
int check_cert(SSL* ssl);
void transmit_and_receive(SSL* ssl, char* request);

int main(int argc, char **argv)
{
  // int len, sock, port=PORT;
  int sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  // char buf[256];
  char *secret = "What's the question?";
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
  fprintf(stderr,"invalid port number");
  exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  SSL_CTX* ctx = initialize_ctx(CERTIFICATE_FILE, PASS);
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2); // need to confirm with TA
  SSL_CTX_set_cipher_list(ctx, CIPHER_LIST);

  SSL* ssl = SSL_new(ctx); // ssl object handle the channel/tunnel
  BIO* sbio = BIO_new_socket(sock, BIO_NOCLOSE); // abstract socket connection into tunnel
  SSL_set_bio(ssl,sbio,sbio); // bind
  
  if(SSL_connect(ssl)<=0) {
      printf(FMT_CONNECT_ERR);
      ERR_print_errors(bio_err);
      // need to confirm with TA
      SSL_free(ssl);
      destroy_ctx(ctx);
      close(sock);
      exit(0);
  }
  if(check_cert(ssl) == SUCCESS) {
    transmit_and_receive(ssl, secret);
  }

  shut_down(sock, ctx, ssl);
  return 0;
  // send(sock, secret, strlen(secret),0);
  // len = recv(sock, &buf, 255, 0);
  // buf[len]='\0';
  
  /* this is how you output something for the marker to pick up */
  // printf(FMT_OUTPUT, secret, buf);
  
  //close(sock);
  //return 1;
}

void shut_down(int sock, SSL_CTX* ctx, SSL* ssl) {
  if(!SSL_shutdown(ssl)) {
    // we are the 1st party notifying closure
    SSL_shutdown(ssl);
  }
  SSL_free(ssl);
  destroy_ctx(ctx);
  close(sock);
  exit(0);
}

int check_cert(SSL* ssl) {

  // check format
  if(SSL_get_verify_result(ssl) != X509_V_OK) {
    printf(FMT_NO_VERIFY);
    return FAIL;
  }

  X509* peer = SSL_get_peer_certificate(ssl);
  if(peer == NULL) {
    printf(FMT_NO_VERIFY);
    return FAIL;
  }
  
  // check common name first
  char common_name[BUF_LEN];
  X509_NAME* name = X509_get_subject_name(peer); 
  if(X509_NAME_get_text_by_NID(name, NID_commonName, common_name, BUF_LEN) == -1) {
    printf(FMT_CN_MISMATCH);
    return FAIL;
  }
  if(strcasecmp(common_name, COMMON_NAME)) {
    printf(FMT_CN_MISMATCH);
    return FAIL;
  }

  // check email
  char email[BUF_LEN];
  if(X509_NAME_get_text_by_NID(name, NID_pkcs9_emailAddress, email, BUF_LEN) == -1) {
    printf(FMT_EMAIL_MISMATCH);
    return FAIL;
  }
  if(strcasecmp(email, EMAIL)) {
    printf(FMT_EMAIL_MISMATCH);
    return FAIL;
  }

  // CA name
  X509_NAME* issuer_name = X509_get_issuer_name(peer);
  char ca_name[BUF_LEN];
  X509_NAME_get_text_by_NID(issuer_name, NID_commonName, ca_name, BUF_LEN);

  printf(FMT_SERVER_INFO, common_name, email, ca_name);
  return SUCCESS;

}

void transmit_and_receive(SSL* ssl, char* request) {
  int request_len = strlen(request);
  int len;
  char buf[BUF_LEN];

  len = SSL_write(ssl, buf, request_len);
  switch(SSL_get_error(ssl, len)) {
    case SSL_ERROR_NONE:
      if (len != request_len) {
        printf("Incomplete write!\n");
      }
      break;
    case SSL_ERROR_SYSCALL:
      printf(FMT_INCORRECT_CLOSE);
      return;
    default:
      printf("Unknown error!\n");
      return;
  }

  len = SSL_read(ssl, buf, BUF_LEN);
  switch(SSL_get_error(ssl, len)) {
    case SSL_ERROR_NONE:
      buf[len] = '\0'; // response may be less than buffer size
      printf(FMT_OUTPUT, request, buf);
      break;
    case SSL_ERROR_ZERO_RETURN: // sock closed
      break;
    case SSL_ERROR_SYSCALL: // premature close
      printf(FMT_INCORRECT_CLOSE);
      break;
    default:
      printf("Unknown error!\n");
      break;
  }
  return;
  // int not_finished = 1;
  // while(not_finished) {
  // }
}
