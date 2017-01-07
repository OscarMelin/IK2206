#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int clientSecureTunnel(char * server);
int serverSecureTunnel();
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;	

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;


  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/* KEY */
unsigned char key[32];
  
/* IV */
unsigned char iv[16];

int main(int argc, char *argv[]) {

  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  int maxfd;
  uint16_t nread, nwrite, plength;
//  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  progname = argv[0];
      

  /* Check command line options */
  while((option = getopt(argc, argv, "i:s:c:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        strncpy(remote_ip,optarg,15);
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

	do_debug("Successfully connected to interface %s\n", if_name);

	if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket()");
		exit(1);
	}  

	memset(&local, 0, sizeof(local));
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(port);
	
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = inet_addr(remote_ip);
  remote.sin_port = htons(port);
	
	if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
    perror("setsockopt()");
    exit(1);
  }
	
  if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
    perror("bind()");
    exit(1);
  }

  if (connect(sock_fd, (struct sockaddr *) &remote, sizeof(remote)) < 0) {
      perror("connect()");
      exit(1);
  }

  net_fd = sock_fd;
	
	if(cliserv == SERVER){		
		serverSecureTunnel();
	}
	else {
		clientSecureTunnel(remote_ip);
		printf("Out of clientSecureTunner\n");
	}
	
	
  
	/* use select() to handle two descriptors at once */
	maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
	
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	
  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)){
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

			/* ENCRYPT */
			unsigned char ciphertext[BUFSIZE];
			int ciphertext_len = encrypt (buffer, nread, key, iv, ciphertext);			
			/*********************************************/

			/* Adding MAC */
			unsigned char *mac = (unsigned char*) HMAC(EVP_sha256(), key, 32, ciphertext, ciphertext_len, NULL, NULL);

      int newLen = 32 + ciphertext_len;
      unsigned char newPacket[newLen];
      int i, j
;
      for (i = 0; i < 32; i++) 
          newPacket[i] = mac[i];
      

      for (i = 32, j = 0; i < plength; i++, j++)
          newPacket[i] = ciphertext[j];      
			/***********************************************/
	  
      /* write length + packet */
      plength = newLen;
	  	nwrite = cwrite(net_fd, (char *) &plength, sizeof(plength));
      nwrite = cwrite(net_fd, newPacket, plength);
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)){
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */
//			printf("net_fd\n");
	   
      /* Read length */      
      nread = read_n(net_fd, (char *) &plength, sizeof(plength));
      if (nread == 0) {
           /* ctrl-c at the other end */
            break;
      }
      net2tap++;

      /* read packet */
      nread = read_n(net_fd, buffer, plength);
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

			if(nread > 32){
				/* Checking MAC */
				int i, j, len = nread -32;
				unsigned char mac[32];
				unsigned char ciphertext[len];
				memset(mac, '\0', 32);
				memset(ciphertext, '\0', len);

				for (i = 0; i < 32; i++)
		        mac[i] = buffer[i];
		    
				for(i = 32, j = 0; i < plength; i++, j++)
					ciphertext[j] = buffer[i];

				unsigned char *compareMac = (unsigned char*) HMAC(EVP_sha256(), key, 32, ciphertext, len, NULL, NULL);

				int different = 0;			
				for(i = 0; i < 32; i++){
					if( *(compareMac+i) != mac[i]){
						different = 1;
						break;
					}
				}
				if(different){
				  do_debug("NET2TAP %lu: MACs doesn't match\n", net2tap);
				}else	{
				  do_debug("NET2TAP %lu: MAC verified correctly\n", net2tap);

					/* DECRYPT */ 
					unsigned char decryptedtext[BUFSIZE];
					int decryptedtext_len = decrypt(ciphertext, len, key, iv, decryptedtext);


				  /* Writing decrypted text to tunnel */
				  nwrite = cwrite(tap_fd, decryptedtext, decryptedtext_len);
				  do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
				}
			/**********************************************/
	  	}else{
				/* DECRYPT */ 
				unsigned char decryptedtext[BUFSIZE];
				int decryptedtext_len = decrypt(buffer, nread, key, iv, decryptedtext);

		    /* Writing decrypted text to tunnel */
		    nwrite = cwrite(tap_fd, decryptedtext, decryptedtext_len);
		    do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);

			}
		  
    }

  }
  
  return(0);
}

#define CERTF "server.crt"
#define KEYF "server.key"
#define CACERT "ca.crt"

#define CLCERTF "client.crt"
#define CLKEYF "client.key"
#define CLCACERT "ca.crt"

int serverSecureTunnel(){
	unsigned char bytestream[48]; //256 bit key + 128 bit IV to be used for AES256
  unsigned char tmpbuf[100];
  SSL_CTX *ctx;
  SSL *ssl;
  X509 *client_cert;
  char *str;
  SSL_METHOD *meth;
  int err;
  int listen_sd;
  int sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  size_t client_len;
  char ipstr[INET6_ADDRSTRLEN];

	/* Initiating TCP connection with a client */
	if( (listen_sd = socket(AF_INET, SOCK_STREAM, 0)) <= 0) 
		perror("Listen");

  memset(&sa_serv, '\0', sizeof(sa_serv)); //Initialize sa_serv to 0's, sa_serv is socket info for our endpoint
  sa_serv.sin_family = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port = htons(44333);          /* Server Port number */

	int enable = 1;
	if(setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(enable)) < 0){
    perror("setsockopt()");
    exit(1);
  }  	

  if( bind(listen_sd, (struct sockaddr *) &sa_serv, sizeof(sa_serv)) < 0 )
		perror("Bind");

  if (listen(listen_sd, 5) < 0 )
		perror("Listen");
    
  printf("Server listening for incoming connections... \n");    

  client_len = sizeof(sa_cli);
  if( (sd = accept(listen_sd, (struct sockaddr *) &sa_cli, (socklen_t *) &client_len)) < 0 )
		perror("Accept");    
  close(listen_sd);  // remember to delete this to change to multi client support

	void *addr = &(sa_cli.sin_addr);
	inet_ntop(AF_INET, addr, ipstr, sizeof ipstr);
  printf("Connection from %s, port %d\n", ipstr, ntohs(sa_cli.sin_port));

	/* Starting SSL part */
	SSL_load_error_strings();    
  SSLeay_add_ssl_algorithms();
  meth = (SSL_METHOD *) SSLv23_server_method();

	ctx = SSL_CTX_new(meth);
  if (ctx == NULL) {
      ERR_print_errors_fp(stdout);
      exit(2);
  }

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stdout);
      exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stdout);
      exit(4);
  }
  if (!SSL_CTX_check_private_key(ctx)) {
      fprintf(stdout, "Private key does not match the certificate public key\n");
      exit(5);
  }
	

	if( (ssl = SSL_new(ctx)) == NULL){
		printf("SSL context was NULL\n");
		exit(1);
	}

	SSL_set_fd(ssl, sd);
	printf("SSL accept waiting...\n");
	if(  (err = SSL_accept(ssl)) < 0 ){
		printf("SSL accept failed\n");
	 	exit(2); 
	}

 	printf("SSL connection using %s\n", SSL_get_cipher (ssl));

	client_cert = SSL_get_peer_certificate(ssl);
  if (client_cert != NULL) {
      printf("Client certificate:\n");

			if( (str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0)) == NULL){
				printf("Subject name was NULL\n");
				exit(3);
			}
      printf("\t subject: %s\n", str);
      OPENSSL_free (str);

			if( (str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0)) == NULL){
				printf("Issuer name was NULL\n");
				exit(4);
			}

      printf("\t issuer : %s\n", str);
      OPENSSL_free (str);

      /* We could do all sorts of certificate verification stuff here before
         deallocating the certificate. */

      X509_free(client_cert); //Frees the datastructure holding the client cert
  } else
      printf("Client does not have certificate.\n");

	unsigned char randomBytes[49];
	memset(randomBytes, '\0', 48);
	if (!RAND_bytes(randomBytes, sizeof randomBytes)) {
		printf("Impossible to generate random number to send to client\n");
		exit(-3);	
	}
	
	if((err = SSL_write(ssl, randomBytes, 48)) <= 0){
		printf("Impossible to send RGN to client\n");
		exit(-4);
	}
	randomBytes[49] = '\0';
	printf("RGN: %s\n", randomBytes);
	

}

int clientSecureTunnel(char * ip){
	unsigned char bytestream[48]; //256 bit key + 128 bit IV to be used for AES256
  unsigned char tmpbuf[100];
  SSL_CTX *ctx;
  SSL *ssl;
  X509 *server_cert;
  char *str;
  int err;
  int sd;
  struct sockaddr_in sa;
  SSL_METHOD *meth;
  char ipstr[INET6_ADDRSTRLEN];	

	/* Starting TCP connection to server */
	if( (sd = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
		perror("Socket");
    
  memset(&sa, '\0', sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = inet_addr(ip);  
  sa.sin_port = htons(44333);         

	if( connect(sd, (struct sockaddr *) &sa,sizeof(sa)) < 0 )
		perror("Connect");

	void *addr = &(sa.sin_addr);
	inet_ntop(AF_INET, addr, ipstr, sizeof ipstr);
  printf("Connected to %s, port %d\n", ipstr, ntohs(sa.sin_port));

	/* Start SSL part */
	SSLeay_add_ssl_algorithms();
  meth = (SSL_METHOD *) SSLv23_client_method();
  SSL_load_error_strings();
  if( (ctx = SSL_CTX_new(meth)) == NULL){
		printf("SSL context was NULL\n");
		exit(1);
	}	

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_load_verify_locations(ctx, CACERT, NULL);
  if (SSL_CTX_use_certificate_file(ctx, CLCERTF, SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stdout);
      exit(-2);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, CLKEYF, SSL_FILETYPE_PEM) <= 0) {
      ERR_print_errors_fp(stdout);
      exit(-3);
  }
  if (!SSL_CTX_check_private_key(ctx)) {
      printf("Private key does not match the certificate public key \n");
      exit(-4);
  }	

	if( (ssl = SSL_new(ctx)) == NULL){
		printf("SSL variable is NULL\n");
	}
    
  SSL_set_fd(ssl, sd);
  
	if((err = SSL_connect(ssl)) == 0){
		printf("SSL_connect faild: %d\n", err);
		exit(-1);
	}

  printf("SSL connection using %s\n", SSL_get_cipher (ssl));
  /* Get server's certificate (note: beware of dynamic allocation) - opt */

  server_cert = SSL_get_peer_certificate(ssl);
  if (server_cert != NULL) {
      printf("Server certificate:\n");

			if( (str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0)) == NULL){
				printf("Subject name was NULL\n");
				exit(3);
			}
      printf("\t subject: %s\n", str);
      OPENSSL_free (str);

			if( (str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0)) == NULL){
				printf("Issuer name was NULL\n");
				exit(4);
			}

      printf("\t issuer: %s\n", str);
      OPENSSL_free (str);

      /* We could do all sorts of certificate verification stuff here before
         deallocating the certificate. */

      
  } else
      printf("Server does not have certificate.\n");
		  
	X509_free(server_cert); //Frees the datastructure holding the client cert



	unsigned char randomBytes[48];
	if((err = SSL_read(ssl, randomBytes, 48)) <= 0){
		printf("Impossible to read RGN to client\n");
		exit(-4);
	}



	int i, j;
	for (i = 0; i < 32; i++) 
  	key[i] = randomBytes[i];
  
  for (i = 32, j = 0; i < 48; i++, j++) 
 		iv[j] = randomBytes[i];  

	//BIO_dump_fp (stdout, key, 32);

	//BIO_dump_fp (stdout, iv, 16);


	printf("Key and IV set\n");
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext){
	
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
	
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext){

	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;

}



