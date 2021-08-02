#include<stdio.h> 
#include<unistd.h> 
#include<stdlib.h> 
#include<errno.h> 
#include<string.h> 
#include<sys/socket.h> 
#include<resolv.h> 
#include<netdb.h> 
#include<openssl/ssl.h> 
#include<openssl/err.h> 

#define FAIL -1
void mycallback(int, int, int, const void *, size_t, SSL *, void *);

int connect_establish(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}


SSL_CTX* InitCTX(void) {
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */
    SSL_load_error_strings(); /* Bring in and register error messages */
    method = TLSv1_2_client_method(); /* Create new client-method instance */
    ctx = SSL_CTX_new(method); /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_CTX_set_msg_callback(ctx, mycallback);
    return ctx;
}


void ShowCerts(SSL* ssl) {
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line); /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line); /* free the malloc'ed string */
        X509_free(cert); /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}


void mycallback(int write_p, int ver, int c_type, const void *buf, size_t len, SSL *ssl, void *arg){
    printf("Inside client callback\n");
    printf("val of write : %d, val of ver: %d, val of content type : %d\n", write_p, ver, c_type);
}

void handleConn(SSL *ssl){
    char buf[1024], req[1024];
    int bytes = 0;
    int sd = SSL_get_fd(ssl), a=1;
    while(1){
        printf("Enter some thing for server:");
        fgets(req, 1024, stdin);
        SSL_write(ssl, req, strlen(req));
        listen(sd, 1);
        bytes = SSL_read(ssl, buf, sizeof(buf));
        if(bytes > 0){
            buf[bytes-1] = 0;
            printf("Server msg received:--> %s\n", buf);
            a = (strcmp(buf, "quit") == 0)?0:1;
        }else{
            ERR_print_errors_fp(stderr);
            a = 0;
        }
        if(1-a)
	    break;
    }
    SSL_write(ssl, "quit\n", (int)strlen("quit\n"));
}


int main(int count, char *strings[]) {
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char *hostname, *portnum;
    if ( count != 3 )
    {
        printf("Need to specify the hostname and port number\n");
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
    ctx = InitCTX();
    server = connect_establish(hostname, atoi(portnum));
    ssl = SSL_new(ctx); /* create new SSL connection state */

    SSL_set_fd(ssl, server); /* attach the socket descriptor */
//    SSL_CTX_set_msg_callback(ctx, mycallback);
    if ( SSL_connect(ssl) == FAIL ) /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {
        //SSL_CTX_set_msg_callback(ctx, mycallback);
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl); /* get any certs */
        handleConn(ssl);
        SSL_free(ssl); /* release connection state */
    }
    close(server); /* close socket */
    SSL_CTX_free(ctx); /* release context */
    return 0;
}
