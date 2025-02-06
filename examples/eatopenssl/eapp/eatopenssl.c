#include <errno.h>
#include <unistd.h>
// #include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define FAIL    -1
#define DEFAULT_PORT 5051

#define SYSCALL(which, arg0, arg1, arg2, arg3, arg4)           \
  ({                                                           \
    register uintptr_t a0 asm("a0") = (uintptr_t)(arg0);       \
    register uintptr_t a1 asm("a1") = (uintptr_t)(arg1);       \
    register uintptr_t a2 asm("a2") = (uintptr_t)(arg2);       \
    register uintptr_t a3 asm("a3") = (uintptr_t)(arg3);       \
    register uintptr_t a4 asm("a4") = (uintptr_t)(arg4);       \
    register uintptr_t a7 asm("a7") = (uintptr_t)(which);      \
    asm volatile("ecall"                                       \
                 : "+r"(a0)                                    \
                 : "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7) \
                 : "memory");                                  \
    a0;                                                        \
  })

#define SYSCALL_3(which, arg0, arg1, arg2) \
  SYSCALL(which, arg0, arg1, arg2, 0, 0)

#define RUNTIME_SYSCALL_ATTEST_ENCLAVE      1003

int attest_enclave(void* report, void* data, size_t size) {
  return SYSCALL_3(RUNTIME_SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

// Generate RSA key
EVP_PKEY *generate_key ( ) {
    EVP_PKEY *private_key = EVP_PKEY_new ( );

    RSA *rsa = RSA_new ( );

    BIGNUM *bn = BN_new ( );

    BN_set_word ( bn, RSA_F4 );

    RSA_generate_key_ex ( rsa, 2048, bn, NULL );

    BN_free ( bn );

    EVP_PKEY_assign_RSA ( private_key, rsa );
 
    return private_key;
}

// Generate an X.509 certificate
X509 *generate_x509 ( EVP_PKEY *private_key ) {
    X509 *x509 = X509_new ( );

    ASN1_INTEGER_set ( X509_get_serialNumber ( x509 ), 1 );

    X509_gmtime_adj ( X509_get_notBefore(x509), 0 );
    X509_gmtime_adj ( X509_get_notAfter(x509), 365 * 24 * 60 * 60 );

    X509_set_pubkey ( x509, private_key );

    X509_NAME *name = X509_get_subject_name ( x509 );

    X509_NAME_add_entry_by_txt ( name, "C", MBSTRING_ASC, ( unsigned char* ) "US", -1, -1, 0 );
    X509_NAME_add_entry_by_txt ( name, "O", MBSTRING_ASC, ( unsigned char* ) "Example Org", -1, -1, 0 );
    X509_NAME_add_entry_by_txt ( name, "CN", MBSTRING_ASC, ( unsigned char* ) "localhost", -1, -1, 0 );

    char nonce[]      = "attestation";
    char buffer[2048] = { 0 };
    attest_enclave ( ( void* ) buffer, nonce, strlen ( nonce ) );
    
    printf ( "ATTESTATION GENERATED\n" );

    // Add Attestation (AT) Extension
    X509V3_CTX context;
    X509V3_set_ctx_nodb ( &context );

    X509V3_set_ctx ( &context, x509, x509, NULL, NULL, 0 );

    X509_EXTENSION *extension = X509V3_EXT_conf_nid ( NULL, &context, NID_netscape_comment, buffer );

    if ( extension != NULL ) {
        X509_add_ext ( x509, extension, -1 );
        X509_EXTENSION_free ( extension );
    }

    X509_set_issuer_name ( x509, name );
    X509_sign ( x509, private_key, EVP_sha256 ( ) );

    return x509;
}

void load_certificates ( SSL_CTX* context, char* certificate_file_path, char* key_file_path ) {
    /* set the local certificate from certificate_file_path */
    if ( SSL_CTX_use_certificate_file ( context, certificate_file_path, SSL_FILETYPE_PEM ) <= 0 ) {
        ERR_print_errors_fp ( stderr );
        abort ( );
    }

    /* set the private key from key_file_path (may be the same as certificate_file_path) */
    if ( SSL_CTX_use_PrivateKey_file ( context, key_file_path, SSL_FILETYPE_PEM ) <= 0 ) {
        ERR_print_errors_fp ( stderr );
        abort ( );
    }

    /* verify private key */
    if ( !SSL_CTX_check_private_key ( context ) ) {
        fprintf ( stderr, "Private key does not match the public certificate\n" );
        abort ( );
    }
}

void load_certificate_and_private_key ( SSL_CTX* context, X509 *certificate, EVP_PKEY *private_key ) {
    if ( SSL_CTX_use_certificate ( context, certificate ) <= 0 ) {
        ERR_print_errors_fp ( stderr );
        abort ( );
    }

    if ( SSL_CTX_use_PrivateKey ( context, private_key ) <= 0 ) {
        ERR_print_errors_fp ( stderr );
        abort ( );
    }

    /* verify private key */
    if ( !SSL_CTX_check_private_key ( context ) ) {
        fprintf ( stderr, "Private key does not match the public certificate\n" );
        abort ( );
    }
}


// Create the SSL socket and intialize the socket address structure
int open_listener ( int port_number ) {
    struct sockaddr_in address = {
        .sin_family      = AF_INET,
        .sin_port        = htons ( port_number ),
        .sin_addr.s_addr = INADDR_ANY
    };

    int socket_descriptor = socket ( PF_INET, SOCK_STREAM, 0 );

    int bind_status = bind ( socket_descriptor, ( struct sockaddress* ) &address, sizeof ( address ) );

    if ( bind_status != 0 ) {
        perror ( "can't bind port_number" );
        abort ( );
    }

    if ( listen ( socket_descriptor, 10 ) != 0 ) {
        perror ( "Can't configure listening port_number" );
        abort ( );
    }

    return socket_descriptor;
}

SSL_CTX* initialize_server_SSL_context ( ) {
    // load and register all cryptography algorithms, etc.
    OpenSSL_add_all_algorithms ( );
    
    // load all error message
    SSL_load_error_strings ( );

    // create new server-method instance 
    SSL_METHOD *method = TLSv1_2_server_method ( );

    // create new context from method
    SSL_CTX *context = SSL_CTX_new ( method ); 
    if ( context == NULL ) {
        ERR_print_errors_fp ( stderr );
        abort ( );
    }

    return context;
}

void show_certificates ( SSL* ssl ) {
    // Get certificates (if available)
    X509 *certificate = SSL_get_peer_certificate ( ssl );

    if ( certificate != NULL ) {
        printf("Server certificates:\n");

        char *subject_name = X509_NAME_oneline ( X509_get_subject_name ( certificate ), 0, 0 );
        printf ( "Subject: %s\n", subject_name );
        free ( subject_name );

        char *issuer_name = X509_NAME_oneline ( X509_get_issuer_name ( certificate ), 0, 0 );
        printf ( "Issuer: %s\n", issuer_name );
        free ( issuer_name );

        X509_free ( certificate );
    } else {
        printf ( "No certificates.\n" );
    }
}

// Serve the connection -- threadable 
int servlet ( SSL* ssl ) {
    int exit = 0;
    const char* server_response =   "<\Body>\
                                        <Name>aticleworld.com</Name>\
                                        <year>1.5</year>\
                                        <BlogType>Embedede and c\c++<\BlogType>\
                                        <Author>amlendra<Author>\
                                    <\Body>";

    const char *valid_message =    "hello";


    // do SSL-protocol accept
    if ( SSL_accept ( ssl ) == FAIL ) {
        ERR_print_errors_fp ( stderr );
    } else {
        char buffer[1024] = { 0 };

        // get any certificate
        show_certificates ( ssl );

        // get request
        int bytes = SSL_read ( ssl, buffer, sizeof ( buffer ) );
        buffer[bytes] = '\0';

        printf ( "Client msg: \"%s\"\n", buffer );

        if ( bytes > 0 ) {
            if ( strcmp ( valid_message, buffer ) == 0 ) {
                // send reply
                SSL_write ( ssl, server_response, strlen ( server_response ) );
                // printf ( "Message sent to client!\n" );
            } else if ( strcmp ( "end", buffer ) == 0 ) {
                exit = 1;
            } else {
                char response[1024] = { 0 };
                sprintf ( response, "Invalid message: %s", buffer );
                // send reply
                SSL_write ( ssl, response, strlen ( response ) );
            }
        } else {
            ERR_print_errors_fp ( stderr );
        }
    }
    // get socket connection
    int socket_descriptor = SSL_get_fd ( ssl );

    // release SSL state
    SSL_free ( ssl );

    // close connection
    close ( socket_descriptor );
    
    return exit;
}

int main ( int argc, char **argv ) {
    // initialize the SSL library
    SSL_library_init ( );

    // initialize SSL
    SSL_CTX *context = initialize_server_SSL_context ( ); 
    
    // create server socket
    int port_number = DEFAULT_PORT;

    int server = open_listener ( port_number );
    
    // load certificates
    // load_certificates ( context, "/root/eopenssl/cert.pem", "/root/eopenssl/key.pem" );

    EVP_PKEY *private_key = generate_key ( );
    X509 *certificate     = generate_x509 ( private_key );

    SSL_CTX_use_PrivateKey ( context, private_key );
    SSL_CTX_use_certificate ( context, certificate );

    while ( 1 ) {
        struct sockaddr_in address;

        socklen_t length = sizeof(address);

        // acc connection as usual
        int client = accept ( server, ( struct sockaddr* ) &address, &length );

        printf ( "Connection: %s:%d\n", inet_ntoa ( address.sin_addr ), ntohs ( address.sin_port ) );

        // get new SSL state with context
        SSL *ssl = SSL_new ( context );

        // set connection socket to SSL state
        SSL_set_fd ( ssl, client );

        // service connection
        int exit = servlet ( ssl );    
        
        if ( exit == 1 ) {
            break;
        }
    }

    // close server socket
    close ( server );

    EVP_PKEY_free ( private_key );

    X509_free ( certificate );

    // release context
    SSL_CTX_free ( context );

    return 0;
}