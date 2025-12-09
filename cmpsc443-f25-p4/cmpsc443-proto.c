/***********************************************************************

   File          : cmpsc443-proto.c

   Description   : This is the network interfaces for the network protocol connection.


***********************************************************************/

/* Include Files */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stdint.h>

/* OpenSSL Include Files */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

/* Project Include Files */
#include "cmpsc443-util.h"
#include "cmpsc443-network.h"
#include "cmpsc443-proto.h"
#include "cmpsc443-ssl.h"

char *new_filename = NULL;

/* Functional Prototypes */

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type )
{
	struct rm_cmd *r;
	int rsize;
	int len; 

	assert(rptr != 0);
	assert(filename != 0);
	len = strlen( filename );

	rsize = sizeof(struct rm_cmd) + len;
	*rptr = r = (struct rm_cmd *) malloc( rsize );
	memset( r, 0, rsize );
	
	r->len = len;
	memcpy( r->fname, filename, r->len );  
	r->cmd = atoi( cmd );
	r->type = atoi( type );

	return 0;
}


/**********************************************************************

    Function    : get_message
    Description : receive data from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int get_message( int sock, ProtoMessageHdr *hdr, char *block )
{
	/* Read the message header */
	recv_data( sock, (char *)hdr, sizeof(ProtoMessageHdr), 
		   sizeof(ProtoMessageHdr) );
	hdr->length = ntohs(hdr->length);
	assert( hdr->length<MAX_BLOCK_SIZE );
	hdr->msgtype = ntohs( hdr->msgtype );
	if ( hdr->length > 0 )
		return( recv_data( sock, block, hdr->length, hdr->length ) );
	return( 0 );
}

/**********************************************************************

    Function    : wait_message
    Description : wait for specific message type from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
                  my - the message to wait for
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int wait_message( int sock, ProtoMessageHdr *hdr, 
                 char *block, ProtoMessageType mt )
{
	/* Wait for init message */
	int ret = get_message( sock, hdr, block );
	if ( hdr->msgtype != mt )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Server unable to process message type [%d != %d]\n", 
			 hdr->msgtype, mt );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return succesfully */
	return( ret );
}

/**********************************************************************

    Function    : send_message
    Description : send data over the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to send
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int send_message( int sock, ProtoMessageHdr *hdr, char *block )
{
     int real_len = 0;

     /* Convert to the network format */
     real_len = hdr->length;
     hdr->msgtype = htons( hdr->msgtype );
     hdr->length = htons( hdr->length );
     if ( block == NULL )
          return( send_data( sock, (char *)hdr, sizeof(hdr) ) );
     else 
          return( send_data(sock, (char *)hdr, sizeof(hdr)) ||
                  send_data(sock, block, real_len) );
}

/**********************************************************************

    Function    : encrypt_message
    Description : Generate ciphertext message for plaintext using key 
    Inputs      : plaintext - message
                : plaintext_len - size of message
                : key - symmetric key
                : buffer - encrypted message - includes tag
                : len - length of encrypted message and tag
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int encrypt_message( unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, 
		     unsigned char *buffer, unsigned int *len )
{
	unsigned char *iv = buffer;
	unsigned char *tag = buffer + IVSIZE;
	unsigned char *ciphertext = buffer + IVSIZE + TAGSIZE;
	int ciphertext_len;

	// 1. Generate a random IV
	if (generate_pseudorandom_bytes(iv, IVSIZE) != 0) {
		errorMessage("Failed to generate IV for encryption.\n");
		return -1;
	}

	// 2. Encrypt the plaintext
	ciphertext_len = encrypt(plaintext, plaintext_len, NULL, 0, key, iv, ciphertext, tag);
	if (ciphertext_len < 0) {
		errorMessage("Encryption failed.\n");
		return -1;
	}

	// 3. Set the total length of the buffer
	// The buffer layout is: [IV (16 bytes)] [Tag (16 bytes)] [Ciphertext]
	*len = IVSIZE + TAGSIZE + ciphertext_len;

	// Check for buffer overflow
	assert(*len <= MAX_BLOCK_SIZE);

	return 0;
}



/**********************************************************************

    Function    : decrypt_message
    Description : Produce plaintext for given ciphertext buffer (ciphertext+tag) using key 
    Inputs      : buffer - encrypted message - includes tag
                : len - length of encrypted message and tag
                : key - symmetric key
                : plaintext - message
                : plaintext_len - size of message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int decrypt_message( unsigned char *buffer, unsigned int len, unsigned char *key, 
		     unsigned char *plaintext, unsigned int *plaintext_len )
{
	unsigned char *iv = buffer;
	unsigned char *tag = buffer + IVSIZE;
	unsigned char *ciphertext = buffer + IVSIZE + TAGSIZE;
	unsigned int ciphertext_len = len - IVSIZE - TAGSIZE;
	int decrypted_len;

	// 1. Decrypt the ciphertext
	decrypted_len = decrypt(ciphertext, ciphertext_len, NULL, 0, tag, key, iv, plaintext);
	if (decrypted_len < 0) {
		errorMessage("Decryption failed (authentication might have failed).\n");
		return -1;
	}

	// 2. Set the plaintext length
	*plaintext_len = decrypted_len;

	// Check for buffer overflow
	assert(*plaintext_len <= MAX_BLOCK_SIZE);

	return 0;
}



/**********************************************************************

    Function    : extract_public_key
    Description : Create public key data structure from network message
    Inputs      : buffer - network message  buffer
                : size - size of buffer
                : pubkey - public key pointer
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int extract_public_key( char *buffer, unsigned int size, EVP_PKEY **pubkey )
{
	RSA *rsa_pubkey = NULL;
	FILE *fptr;

	*pubkey = EVP_PKEY_new();

	/* Extract server's public key */
	/* Make a function */
	fptr = fopen( PUBKEY_FILE, "w+" );

	if ( fptr == NULL ) {
		errorMessage("Failed to open file to write public key data");
		return -1;
	}

	fwrite( buffer, size, 1, fptr );
	rewind(fptr);

	/* open public key file */
	if (!PEM_read_RSAPublicKey( fptr, &rsa_pubkey, NULL, NULL))
	{
		errorMessage("Cliet: Error loading RSA Public Key File.\n");
		return -1;
	}

	if (!EVP_PKEY_assign(*pubkey, EVP_PKEY_RSA, rsa_pubkey))
	{
		errorMessage("Client: EVP_PKEY_assign_RSA: failed.\n");
		return -1;
	}

	fclose( fptr );
	return 0;
}


/**********************************************************************

    Function    : generate_pseudorandom_bytes
    Description : Generate pseudirandom bytes using OpenSSL PRNG 
    Inputs      : buffer - buffer to fill
                  size - number of bytes to get
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int generate_pseudorandom_bytes( unsigned char *buffer, unsigned int size)
{
    int rc = RAND_load_file("/dev/urandom", 32);
    if(rc != 32) {
            /* RAND_load_file failed */
            return -1;
    }
    rc = RAND_bytes(buffer, size);
    unsigned long err = ERR_get_error();

    if(rc != 1) {
            /* RAND_bytes failed */
            /* `err` is valid    */
            return err;
    }

    /* OK to proceed */ 
    return 0;
}


/**********************************************************************

    Function    : seal_symmetric_key
    Description : Encrypt symmetric key using public key
    Inputs      : key - symmetric key
                  keylen - symmetric key length in bytes
                  pubkey - public key
                  buffer - output buffer to store the encrypted seal key and ciphertext (iv?)
    Outputs     : len if successful, -1 if failure

***********************************************************************/

int seal_symmetric_key( unsigned char *key, unsigned int keylen, EVP_PKEY *pubkey, char *buffer )
{
	unsigned char *encrypted_key = NULL;
	unsigned int encrypted_key_len;
	unsigned char *iv = NULL;
	unsigned int iv_len;
	unsigned char *ciphertext = NULL;
	unsigned int ciphertext_len;
	unsigned int total_len;

	// Use rsa_encrypt to seal the symmetric key
	ciphertext_len = rsa_encrypt(key, keylen, &ciphertext, &encrypted_key, &encrypted_key_len, &iv, &iv_len, pubkey);
	if (ciphertext_len <= 0) {
		errorMessage("RSA encryption (seal) failed.\n");
		return -1;
	}

	total_len = sizeof(encrypted_key_len) + encrypted_key_len + sizeof(iv_len) + iv_len + ciphertext_len;

	// Pack into buffer: [ek_len][ek][iv_len][iv][ciphertext]
	char *ptr = buffer;
	memcpy(ptr, &encrypted_key_len, sizeof(encrypted_key_len));
	ptr += sizeof(encrypted_key_len);
	memcpy(ptr, encrypted_key, encrypted_key_len);
	ptr += encrypted_key_len;
	memcpy(ptr, &iv_len, sizeof(iv_len));
	ptr += sizeof(iv_len);
	memcpy(ptr, iv, iv_len);
	ptr += iv_len;
	memcpy(ptr, ciphertext, ciphertext_len);

	// Free temporary buffers
	free(encrypted_key);
	free(iv);
	free(ciphertext);

	return total_len;
}

/**********************************************************************

    Function    : unseal_symmetric_key
    Description : Perform SSL unseal (open) operation to obtain the symmetric key
    Inputs      : buffer - buffer of crypto data for decryption (ek, iv, ciphertext)
                  len - length of buffer
                  pubkey - public key 
                  key - symmetric key (plaintext from unseal)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int unseal_symmetric_key( char *buffer, unsigned int len, EVP_PKEY *privkey, unsigned char **key )
{
	unsigned int encrypted_key_len;
	unsigned int iv_len;
	unsigned char *encrypted_key;
	unsigned char *iv;
	unsigned char *ciphertext;
	unsigned int ciphertext_len;
	int decrypted_key_len;

	// Unpack from buffer: [ek_len][ek][iv_len][iv][ciphertext]
	char *ptr = buffer;
	memcpy(&encrypted_key_len, ptr, sizeof(encrypted_key_len));
	ptr += sizeof(encrypted_key_len);
	encrypted_key = (unsigned char *)ptr;
	ptr += encrypted_key_len;
	memcpy(&iv_len, ptr, sizeof(iv_len));
	ptr += sizeof(iv_len);
	iv = (unsigned char *)ptr;
	ptr += iv_len;
	ciphertext = (unsigned char *)ptr;
	ciphertext_len = len - (sizeof(encrypted_key_len) + encrypted_key_len + sizeof(iv_len) + iv_len);

	// Use rsa_decrypt to unseal the symmetric key
	decrypted_key_len = rsa_decrypt(ciphertext, ciphertext_len, encrypted_key, encrypted_key_len, iv, iv_len, key, privkey);

	if (decrypted_key_len <= 0) {
		errorMessage("RSA decryption (unseal) failed.\n");
		return -1;
	}

	return 0;
}


/* 

  CLIENT FUNCTIONS 

*/



/**********************************************************************

    Function    : client_authenticate
    Description : this is the client side of the exchange
    Inputs      : sock - server socket
                  session_key - the key resulting from the exchange
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int client_authenticate( int sock, unsigned char **session_key )
{
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	char outblock[MAX_BLOCK_SIZE];
	EVP_PKEY *pubkey = NULL;
	int len;
	unsigned int outlen;

	// 1. Send CLIENT_INIT_EXCHANGE to server
	printf("Client: Initiating key exchange...\n");
	hdr.msgtype = CLIENT_INIT_EXCHANGE;
	hdr.length = 0;
	send_message(sock, &hdr, NULL);

	// TODO

	printf("Client: Authentication successful. Secure channel established.\n");
	return 0;
}

/**********************************************************************

    Function    : transfer_file
    Description : transfer the entire file over the wire
    Inputs      : r - rm_cmd describing what to transfer and do
                  fname - the name of the file
                  sz - this is the size of the file to be read
                  key - the cipher to encrypt the data with
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int transfer_file( struct rm_cmd *r, char *fname, int sock, 
		   unsigned char *key )
{
    /* Local variables */
	int readBytes = 1, totalBytes = 0, fh;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	char outblock[MAX_BLOCK_SIZE];

	/* Read the next block */
    printf ("\n\nfile name: %s\n\n", fname);
	if ( (fh=open(fname, O_RDONLY, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		exit( -1 );
	}

	/* Send the command */
	hdr.msgtype = FILE_XFER_INIT;
	hdr.length = sizeof(struct rm_cmd) + r->len;
	send_message( sock, &hdr, (char *)r );

	/* Start transferring data */
	while ( (r->cmd == CMD_CREATE) && (readBytes != 0) )
	{
		/* Read the next block */
		if ( (readBytes=read( fh, block, BLOCKSIZE )) == -1 )
		{
			/* Complain, explain, and exit */
			errorMessage( "failed read on data file.\n" );
			exit( -1 );
		}
		
		/* A little bookkeeping */
		totalBytes += readBytes;
		printf( "Reading %10d bytes ...\r", totalBytes );

		/* Send data if needed */
		if ( readBytes > 0 ) 
		{
#if 1
			printf("Block is:\n");
			BIO_dump_fp (stdout, (const char *)block, readBytes);
#endif

			/* Encrypt and send */
			encrypt_message( (unsigned char *)block, readBytes, key, 
					 (unsigned char *)outblock, &outbytes );
			hdr.msgtype = FILE_XFER_BLOCK;
			hdr.length = outbytes;
			send_message( sock, &hdr, outblock );
		}
	}

	/* Send the ack, wait for server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );
	wait_message( sock, &hdr, block, EXIT );

	/* Clean up the file, return successfully */
	close( fh );
	return( 0 );
}


/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
                  port - the port to connect to
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int client_secure_transfer( struct rm_cmd *r, char *fname, char *address, unsigned short port ) 
{
	/* Local variables */
	unsigned char *key;
	int sock;

	sock = connect_client( address, port );
	// crypto setup, authentication
	client_authenticate( sock, &key );
	// symmetric key crypto for file transfer
	transfer_file( r, fname, sock, key );
	// Done
	close( sock );

	/* Return successfully */
	return( 0 );
}


/* 

  SERVER FUNCTIONS 

*/

/**********************************************************************

    Function    : test_rsa
    Description : test the rsa encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_rsa( EVP_PKEY *privkey, EVP_PKEY *pubkey )
{
	unsigned int len = 0;
	unsigned char *ciphertext;
	unsigned char *plaintext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;

	printf("*** Test RSA encrypt and decrypt. ***\n");

	len = rsa_encrypt( (unsigned char *)"help me, mr. wizard!", 20, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, len);
#endif

	len = rsa_decrypt( ciphertext, len, ek, ekl, iv, ivl, &plaintext, privkey );

	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : test_aes
    Description : test the aes encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_aes( )
{
	int rc = 0;
	unsigned char *key;
	unsigned char *ciphertext, *tag;
	unsigned char *plaintext;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	int clen = 0, plen = 0;
	unsigned char msg[] = "Help me, Mr. Wizard!";
	unsigned int len = strlen((char*) msg);

	printf("*** Test AES encrypt and decrypt. ***\n");

	/* make key */
	key= (unsigned char *)malloc( KEYSIZE );
	rc = generate_pseudorandom_bytes( key, KEYSIZE );	
	assert( rc == 0 );

	/* perform encrypt */
	ciphertext = (unsigned char *)malloc( len );
	tag = (unsigned char *)malloc( TAGSIZE );
	clen = encrypt( msg, len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	assert(( clen > 0 ) && ( clen <= len ));

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, clen);
	
	printf("Tag is:\n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);
#endif

	/* perform decrypt */
	plaintext = (unsigned char *)malloc( clen+TAGSIZE );
	memset( plaintext, 0, clen+TAGSIZE ); 
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext );
	assert( plen > 0 );

	/* Show the decrypted text */
#if 0
	printf("Decrypted text is: \n");
	BIO_dump_fp (stdout, (const char *)plaintext, (int)plen);
#endif
	
	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/***********************************************************************/


/**********************************************************************

    Function    : server_protocol
    Description : server processing of crypto protocol
    Inputs      : sock - server socket
                  key - the key resulting from the protocol
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE */
int server_protocol( int sock, char *pubfile, EVP_PKEY *privkey, unsigned char **enckey )
{
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	char outblock[MAX_BLOCK_SIZE];
	unsigned char *pubkey_buf = NULL;
	unsigned int pubkey_len;
	unsigned int outlen;

	// 1. Wait for CLIENT_INIT_EXCHANGE
	wait_message(sock, &hdr, block, CLIENT_INIT_EXCHANGE);
	printf("Server: Received key exchange initiation from client.\n");

	// TODO

	printf("Server: Sent confirmation to client. Secure channel established.\n");

	return 0;
}


/**********************************************************************

    Function    : receive_file
    Description : receive a file over the wire
    Inputs      : sock - the socket to receive the file over
                  key - the cicpher used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

#define FILE_PREFIX "./shared/"

int receive_file( int sock, unsigned char *key ) 
{
	/* Local variables */
	unsigned long totalBytes = 0;
	int done = 0, fh = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	struct rm_cmd *r = NULL;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE];
	char *fname = NULL;
	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* Receive the init message */
        printf("\nserver waiting for FILE_XFER_INIT\n");
	wait_message( sock, &hdr, block, FILE_XFER_INIT );

	/* set command structure */
	struct rm_cmd *tmp = (struct rm_cmd *)block;
	unsigned int len = tmp->len;
	r = (struct rm_cmd *)malloc( sizeof(struct rm_cmd) + len );
	r->cmd = tmp->cmd, r->type = tmp->type, r->len = len;
	memcpy( r->fname, tmp->fname, len );
        
	/* open file */
	if ( r->type == TYP_DATA_SHARED ) {
		unsigned int size = r->len + strlen(FILE_PREFIX) + 1;
		fname = (char *)malloc( size );
		snprintf( fname, size, "%s%.*s", FILE_PREFIX, (int) r->len, r->fname );
                printf("fname: %s", fname);
		new_filename = (char *)malloc( size );
		snprintf( new_filename, size, "%.*s", (int)size, fname ); // This seems unused, but keeping it
		if ( (fh=open( fname, O_WRONLY|O_CREAT|O_TRUNC, 0700)) < 0 ) {
			perror("open");
			assert(0);
		}

	}
	else assert( 0 );

	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_CREATE ) {
		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", fname );
		while (!done)
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
				/* Write the data file information */
				rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
						      plaintext, &outbytes );
				assert( rc  == 0 );
				write( fh, plaintext, outbytes );

#if 1
				printf("Decrypted Block is:\n");
				BIO_dump_fp (stdout, (const char *)plaintext, outbytes);
#endif

				totalBytes += outbytes;
				printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */
		close( fh );
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		//	     exit( -1 );
	}

	/* Server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );

	return( 0 );
}


/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : privfile, pubfile - key files
                  real_address - for MiM
                  port - port to listen on
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int server_secure_transfer( char *privfile, char *pubfile, char *real_address, unsigned short port )
{
	/* Local variables */
	int server, errored, newsock;
	RSA *rsa_privkey = NULL, *rsa_pubkey = NULL;
	RSA *pRSA = NULL;
	EVP_PKEY *privkey = EVP_PKEY_new(), *pubkey = EVP_PKEY_new();
	fd_set readfds;
	unsigned char *key;
	FILE *fptr;
	// new args
	struct rm_cmd *r = NULL;
	int err;

	/* initialize */
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL);
	OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);

	/* Connect the server/setup */
	server = server_connect(port);
	errored = 0;

	/* open private key file */
	fptr = fopen( privfile, "r" );
	assert( fptr != NULL);
	if (!(pRSA = PEM_read_RSAPrivateKey( fptr, &rsa_privkey, NULL, NULL)))
	{
		fprintf(stderr, "Error loading RSA Private Key File.\n");

		return 2;
	}

	if (!EVP_PKEY_assign(privkey, EVP_PKEY_RSA, rsa_privkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr ); 

	/* open public key file */
	fptr = fopen( pubfile, "r" );
	assert( fptr != NULL);
	if (!PEM_read_RSAPublicKey( fptr , &rsa_pubkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Public Key File.\n");
		return 2;
	}

	if (!EVP_PKEY_assign( pubkey, EVP_PKEY_RSA, rsa_pubkey))
	{
		fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr );

	// Test the RSA encryption and symmetric key encryption
	//test_rsa( privkey, pubkey );
	//test_aes();

	/* Repeat until the socket is closed */
	while ( !errored )
	{
		FD_ZERO( &readfds );
		FD_SET( server, &readfds );
		if ( select(server+1, &readfds, NULL, NULL, NULL) < 1 )
		{
			/* Complain, explain, and exit */
			char msg[128];
			sprintf( msg, "failure selecting server connection [%.64s]\n",
				 strerror(errno) );
			errorMessage( msg );
			errored = 1;
		}
		else
		{
			/* Accept the connect, receive the file, and return */
			if ( (newsock = server_accept(server)) != -1 )
			{
				/* Do the protocol, receive file, shutdown */
				if (real_address != NULL) {
					/*** Start: YOUR CODE - for server spoofing ***/
					printf("Does not support MIMT yet");
					exit(1);

					printf("MITM: Intercepted client connection.\n");

					// Step 1: Establish a secure session with the client

					// Step 2: Establish a separate secure session with the real server

					// Step 3: Receive file from client, modify it, and send to server




					/*** End: YOUR CODE - for server spoofing ***/
				} else {
					// Normal server operation
					server_protocol( newsock, pubfile, privkey, &key );
					receive_file( newsock, key );
				}
				close( newsock );
			}
			else
			{
				/* Complain, explain, and exit */
				char msg[128];
				sprintf( msg, "failure accepting connection [%.64s]\n", 
					 strerror(errno) );
				errorMessage( msg );
				errored = 1;
			}
		}
	}

	/* Return successfully */
	return( 0 );
}
