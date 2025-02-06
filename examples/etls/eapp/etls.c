#include <stdio.h>
#include <string.h> 
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tlse.c"

#define DEFAULT_PORT 5051
#define BUFFER_SIZE 0xFFFF

int main ( int argc , char *argv[] ) {
    int socket_descriptor = socket ( AF_INET , SOCK_STREAM , 0 );

    if ( socket_descriptor == -1 ) {
        printf ( "Could not create socket\n" );
        return -1;
    }
    
    int port_number = argc >= 2 ? atoi ( argv[2] ) : DEFAULT_PORT;
     
    struct sockaddr_in server = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port        = htons ( port_number )
    };
     
    int enable = 1;
    setsockopt ( socket_descriptor, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof ( int ) );

    if ( bind ( socket_descriptor, ( struct sockaddr* ) &server , sizeof ( server ) ) < 0 ) {
        printf ( "Bind failed\n" );
        return -2;
    }
     
    listen ( socket_descriptor, 3 );
     
    SSL *server_context = SSL_CTX_new ( SSLv3_server_method ( ) );

    if ( server_context == NULL ) {
        printf ( "Error creating server context\n" );
        return -3;
    }

    SSL_CTX_use_certificate_file ( server_context, "/root/etls/fullchain.pem", SSL_SERVER_RSA_CERT );
    SSL_CTX_use_PrivateKey_file ( server_context, "/root/etls/privkey.pem", SSL_SERVER_RSA_KEY );

    if ( SSL_CTX_check_private_key ( server_context ) == 0 ) {
        printf ( "Private key not loaded\n" );
        return -4;
    }

    while ( 1 ) {
        struct sockaddr_in client;
        int socket_length = sizeof ( struct sockaddr_in );

        int client_socket_descriptor = accept ( socket_descriptor, ( struct sockaddr* ) &client, &socket_length );

        if ( client_socket_descriptor < 0 ) {
            printf ( "Accept failed\n" );
            return -5;
        }

        SSL *client_context = SSL_new ( server_context );

        if ( client_context == NULL ) {
            printf ( "Error creating SSL client_context\n" );
            return -6;
        }

        SSL_set_fd ( client_context, client_socket_descriptor );

        if ( SSL_accept ( client_context ) ) {
            printf ( "Cipher %s\n", tls_cipher_name ( client_context ) );

            while ( 1 ) {
                char buffer[BUFFER_SIZE] = { 0 };

                printf ( "Reading message from client\n" );
                int ssl_read_result = SSL_read ( client_context, buffer, sizeof ( buffer ) );
                
                if ( ssl_read_result < 0 ) {
                    break;
                }
                
                printf ( "Received %s", buffer );

                int ssl_write_result = SSL_write ( client_context, buffer, strlen ( buffer ) );

                if ( ssl_write_result < 0) {
                    printf ( "Error in SSL write: %d\n", ssl_write_result );
                    return -7;
                }
            }
        } else {
            printf ( "Error in handshake\n");
        }
        
        SSL_shutdown ( client_context );

        shutdown ( client_socket_descriptor, SHUT_RDWR );

        close ( client_socket_descriptor );

        SSL_free ( client_context );
    }

    SSL_CTX_free ( server_context );

    return 0;
}
