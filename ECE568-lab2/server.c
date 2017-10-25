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

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

// my macros
#define CERTIFICATE_FILE "bob.pem"
#define PASS "password"
#define CIPHER_LIST "SSLv2:SSLv3:TLSv1"
#define SUCCESS 0
#define FAIL 1
#define BUF_LEN 256

void http_serve(SSL* ssl, int s);
int check_cert(SSL* ssl);
void shut_down(int sock, SSL_CTX* ctx, SSL* ssl);

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  // create a shared context
  SSL_CTX* ctx = initialize_ctx(CERTIFICATE_FILE, PASS);
  if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) == 0) {
    printf("The OpenSSL installed does not support the ciphers in cipher list\n");
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_PEER, NULL);
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      BIO* sbio = BIO_new_socket(s, BIO_NOCLOSE);
      SSL* ssl = =SSL_new(ctx);
      SSL_set_bio(ssl,sbio,sbio);

      int rc = SSL_accept(ssl);
      if (rc <= 0) {
        printf(FMT_ACCEPT_ERR);
        ERR_print_errors(bio_err);

        SSL_free(ssl);
        destroy_ctx(ctx);
        close(s);
        exit(0);
      }

      http_serve(ssl, s);

      int len;
      char buf[256];
      char *answer = "42";

      len = recv(s, &buf, 255, 0);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      send(s, answer, strlen(answer), 0);
      close(sock);
      close(s);
      return 0;
    }
  }
  
  close(sock);
  return 1;
}

void http_serve(SSL* ssl, int s) {
  if (check_cert(ssl) == FAIL) {
    return;
  }
}

int check_cert(SSL* ssl) {
  // check format
  if(SSL_get_verify_result(ssl) != X509_V_OK) {
    printf(FMT_ACCEPT_ERR);
    ERR_print_errors(bio_err);
    return FAIL;
  }

  // check if user presents a certificate
  X509* peer = SSL_get_peer_certificate(ssl);
  if(peer == NULL) {
    printf(FMT_ACCEPT_ERR);
    ERR_print_errors(bio_err);
    return FAIL;
  }

  // get common name and email
  char common_name[BUF_LEN];
  char email[BUF_LEN];
  X509_NAME*  name = X509_get_subject_name(peer);
  if (X509_NAME_get_text_by_NID(name, NID_commonName, common_name, BUF_LEN) == -1) {
    printf(FMT_ACCEPT_ERR);
    ERR_print_errors(bio_err);
    return FAIL;
  }
  if (X509_NAME_get_text_by_NID(name, NID_pkcs9_emailAddress, email, BUF_LEN) == -1) {
    printf(FMT_ACCEPT_ERR);
    ERR_print_errors(bio_err);
    return FAIL;
  }

  printf(FMT_CLIENT_INFO, common_name, email);
  return SUCCESS;
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