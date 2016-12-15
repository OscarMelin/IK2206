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
unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
  
/* IV */
unsigned char *iv = (unsigned char *)"01234567890123456";

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


int serverSecureTunnel(){
	int serverSocket, newSocket;
	struct sockaddr_in serverAddr;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size;
	char buffer[32];

	if( (serverSocket = socket(AF_INET,SOCK_STREAM,0)) <0 )
		perror("Socket");
  
	memset(&serverAddr, '\0', sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(4433);
	serverAddr.sin_addr.s_addr = INADDR_ANY;

	if( bind(serverSocket,(struct sockaddr *)&serverAddr,sizeof(serverAddr)) <0 )
      perror("Couldn't bind");

	if(listen(serverSocket,5)==0)
		printf("Listening\n");
	else
		perror("Listen");

	addr_size = sizeof serverStorage;
	if( (newSocket = accept(serverSocket, (struct sockaddr *) &serverStorage, &addr_size)) < 0)
		perror("Accept");
	printf("Accepted\n");
	int n =	recv(newSocket, buffer, 32, 0);
	printf("received: %s  read %d bytes\n",buffer, n);

	printf("Starting SSL handshake...\n");
	/* START SSL STUFF */

	BIO *sbio, *bbio, *acpt, *out;
  int len;
  char number[10];
  char tmpbuf[257];
  char *ciphertext;
  SSL_CTX *ctx;
  SSL *ssl;

  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  OpenSSL_add_all_algorithms();

  /* Might seed PRNG here */

  ctx = SSL_CTX_new(SSLv23_server_method());

  if (!SSL_CTX_use_certificate_file(ctx,"host.cert",SSL_FILETYPE_PEM)
      || !SSL_CTX_use_PrivateKey_file(ctx,"host.key",SSL_FILETYPE_PEM)
      || !SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Error setting up SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        return(0);
  }

  /* Might do other things here like setting verify locations and
   * DH and/or RSA temporary key callbacks
   */

  /* New SSL BIO setup as server */
  sbio=BIO_new_ssl(ctx,0);

  BIO_get_ssl(sbio, &ssl);

  if(!ssl) {
    fprintf(stderr, "Can't locate SSL pointer\n");
  /* whatever ... */
  }

  /* Don't want any retries */
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  /* Create the buffering BIO */

  bbio = BIO_new(BIO_f_buffer());

  /* Add to chain */
  sbio = BIO_push(bbio, sbio);

  acpt=BIO_new_accept("4433");

  /* By doing this when a new connection is established
   * we automatically have sbio inserted into it. The
   * BIO chain is now 'swallowed' by the accept BIO and
   * will be freed when the accept BIO is freed.
   */

  BIO_set_accept_bios(acpt,sbio);

  /* Setup accept BIO */
  printf("Setting up the accept BIO... ");
  if(BIO_do_accept(acpt) <= 0) {
    fprintf(stderr, "Error setting up accept BIO\n");
    ERR_print_errors_fp(stderr);
    return(0);
  }
  printf("SUCCESS!\n");

  /* Now wait for incoming connection */
  printf("Setting up the incoming connection... ");
  if(BIO_do_accept(acpt) <= 0) {
    fprintf(stderr, "Error in connection\n");
    ERR_print_errors_fp(stderr);
    return(0);
  }
  printf("SUCCESS!\n");

  /* We only want one connection so remove and free
   * accept BIO
   */

  sbio = BIO_pop(acpt);

  BIO_free_all(acpt);

  // wait for ssl handshake from the client
  printf("Waiting for SSL handshake...");
  if(BIO_do_handshake(sbio) <= 0) {
    fprintf(stderr, "Error in SSL handshake\n");
    ERR_print_errors_fp(stderr);
    return(0);
  }
  printf("SUCCESS!\n");
  
  // generate the random number for the challenge
  srand((unsigned)time(NULL));
  sprintf(number,"%d", rand());
  
  // send the random number to the client
  printf("Sending the random number challenge to the client. Number is %s... ", number);
  if(BIO_write(sbio, number, strlen(number)) <= 0) {
    fprintf(stderr, "Error in sending random number\n");
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  printf("SUCCESS!\n");

  BIO_flush(sbio);


}

int clientSecureTunnel(char * ip){

	int clientSocket;
    struct sockaddr_in server; 
	char buffer[32] = "Hello world\n";
     
    if( (clientSocket = socket(AF_INET , SOCK_STREAM , 0)) < 0){
		perror("Socket");    
		return ;
	}
    puts("Socket created");
     
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons( 4433 );
 
    //Connect to remote server
    if ( connect(clientSocket, (struct sockaddr *)&server , sizeof(server)) < 0){
        perror("Connect");
        return;
    }
	
	write(clientSocket, buffer, 32);

	printf("Starting SSL stuff\n");
	/* STARTING SSL STUFF */
	BIO *sbio, *bbio, *acpt, *out;
  int len;
  char number[10];
  char tmpbuf[257];
  char *ciphertext;
  SSL_CTX *ctx;
  SSL *ssl;


// initialize the libraries
  ERR_load_crypto_strings();
  ERR_load_SSL_strings();
  OpenSSL_add_all_algorithms();

  /* We would seed the PRNG here if the platform didn't
   * do it automatically
   */

  ctx = SSL_CTX_new(SSLv23_client_method());

  /* We'd normally set some stuff like the verify paths and
   * mode here because as things stand this will connect to
   * any server whose certificate is signed by any CA.
   */

  sbio = BIO_new_ssl_connect(ctx);

  BIO_get_ssl(sbio, &ssl);

  if(!ssl) {
   fprintf(stderr, "Can't locate SSL pointer\n");
   /* whatever ... */
  }

  /* Don't want any retries */
  SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
  /* We might want to do other things with ssl here */
   
  // set connection parameters
  BIO_set_conn_hostname(sbio, ip);
  BIO_set_conn_port(sbio, "443");
 
  // create a buffer to print to the screen
  //out = BIO_new_fp(stdout, BIO_NOCLOSE);

  // establish a connection to the server
  printf("Attempting to to connect to the server... ");
  if (BIO_do_connect(sbio) <= 0) {
    fprintf(stderr, "Error connecting to server\n");
    ERR_print_errors_fp(stderr);
    BIO_free_all(sbio);
    BIO_free(out);
    SSL_CTX_free(ctx);
    exit(1);
  }
  printf("SUCCESS!\n");

  // initiate the handshake with the server
  printf("Initiating SSL handshake with the server... ");
  if (BIO_do_handshake(sbio) <= 0) {
    fprintf(stderr, "Error establishing SSL connection\n");
    ERR_print_errors_fp(stderr);
    BIO_free_all(sbio);
    BIO_free(out);
    SSL_CTX_free(ctx);
    exit(1);
  }
  printf("SUCCESS!\n");

  // Get the random number from the server
  printf("Waiting for random number from server... ");
  memset(tmpbuf, '\0', 11);
  memset(number, '\0', 11);
  len = BIO_read(sbio, tmpbuf, 10);
  strcpy(number, tmpbuf);
  printf("SUCCESS!\nRandom number is: %s\n", number);
	
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



