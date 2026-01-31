#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define LOCAL_PORT_TO_CLIENT 8443
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT 5001

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

// TODO: Parse command-line arguments (-b/-r/-p) and override defaults.
// Keep behavior consistent with the project spec.
void parse_args(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    // PHASE 2: Add SSL/TLS
    // Step 2.1: Initialize OpenSSL library
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    printf("OpenSSL initialized\n");
    
    // Step 2.2: Create SSL context
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new(method);
    
    if (ssl_ctx == NULL) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Failed to create SSL context\n");
        exit(EXIT_FAILURE);
    }
    
    // Step 2.3: Load certificates
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Failed to load server.crt\n");
        exit(EXIT_FAILURE);
    }
    printf("Loaded server.crt\n");
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Failed to load server.key\n");
        exit(EXIT_FAILURE);
    }
    printf("Loaded server.key\n");
    
    // Step 2.3: Check private key matches certificate
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        fprintf(stderr, "Error: Private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }
    printf("Private key matches certificate\n");


    // Step 1.1: Create listening socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Step 1.1: setsockopt SO_REUSEADDR
    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Step 1.1: bind to port 8443
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LOCAL_PORT_TO_CLIENT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Step 1.1: listen
    if (listen(server_socket, 10) == -1) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", LOCAL_PORT_TO_CLIENT);

    while (1) {
        // Step 1.2: Accept connections
        client_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("accept failed");
            continue;
        }
        
        // Step 1.2: Print "Client connected"
        printf("Client connected\n");
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Step 2.4: Wrap client socket with SSL
        SSL *ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Error: Failed to create SSL structure\n");
            close(client_socket);
            continue;
        }
        
        SSL_set_fd(ssl, client_socket);
        
        // Perform TLS handshake
        int ssl_accept_ret = SSL_accept(ssl);
        if (ssl_accept_ret <= 0) {
            int err = SSL_get_error(ssl, ssl_accept_ret);
            fprintf(stderr, "SSL handshake failed with error %d\n", err);
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }
        
        printf("TLS handshake succeeded\n");
        
        // PHASE 4: Parse HTTP request
        // Step 4.1: Read full HTTP request until \r\n\r\n
        char buffer[BUFFER_SIZE * 4];  // Larger buffer for full request
        int total_read = 0;
        int found_end = 0;
        
        // Read until we find \r\n\r\n
        while (total_read < sizeof(buffer) - 1 && !found_end) {
            int bytes_read = SSL_read(ssl, buffer + total_read, sizeof(buffer) - total_read - 1);
            if (bytes_read <= 0) {
                printf("SSL_read error or connection closed\n");
                break;
            }
            total_read += bytes_read;
            buffer[total_read] = '\0';
            
            // Check if we have the end of headers
            if (strstr(buffer, "\r\n\r\n") != NULL) {
                found_end = 1;
            }
        }
        
        if (total_read > 0) {
            printf("Received full HTTP request (%d bytes):\n%s\n", total_read, buffer);
            
            // Step 4.2: Extract requested filename
            char request_copy[BUFFER_SIZE * 4];
            strncpy(request_copy, buffer, sizeof(request_copy) - 1);
            request_copy[sizeof(request_copy) - 1] = '\0';
            
            char *method = strtok(request_copy, " ");
            char *path = strtok(NULL, " ");
            char *http_version = strtok(NULL, "\r\n");
            
            char filename[256] = "";
            
            if (method && path) {
                printf("Method: %s, Path: %s\n", method, path);
                
                // Strip leading /
                if (path[0] == '/') {
                    path++;
                }
                
                // If path is empty (was just "/"), default to index.html
                if (strlen(path) == 0 || strcmp(path, "") == 0) {
                    strcpy(filename, "index.html");
                } else {
                    strncpy(filename, path, sizeof(filename) - 1);
                    filename[sizeof(filename) - 1] = '\0';
                }
                
                printf("Extracted filename: %s\n", filename);
                
                // PHASE 5: Serve real files
                // Step 5.1: Open requested file
                FILE *file = fopen(filename, "rb");
                
                if (file == NULL) {
                    printf("File not found: %s\n", filename);
                    // Send 404 error
                    const char *error_response = 
                        "HTTP/1.1 404 Not Found\r\n"
                        "Content-Type: text/html\r\n"
                        "Content-Length: 48\r\n"
                        "\r\n"
                        "<html><body><h1>404 Not Found</h1></body></html>";
                    
                    SSL_write(ssl, error_response, strlen(error_response));
                } else {
                    // Step 5.2: Read file into buffer - determine file size
                    fseek(file, 0, SEEK_END);
                    long file_size = ftell(file);
                    fseek(file, 0, SEEK_SET);
                    
                    printf("File size: %ld bytes\n", file_size);
                    
                    // Allocate buffer for file content
                    char *file_buffer = malloc(file_size);
                    if (file_buffer == NULL) {
                        printf("Failed to allocate memory for file\n");
                        fclose(file);
                    } else {
                        // Read raw bytes
                        size_t bytes_read = fread(file_buffer, 1, file_size, file);
                        fclose(file);
                        
                        printf("Read %zu bytes from file\n", bytes_read);
                        
                        // Step 5.3: Set correct Content-Type
                        const char *content_type = "application/octet-stream";  // default
                        
                        if (strstr(filename, ".html") != NULL) {
                            content_type = "text/html";
                        } else if (strstr(filename, ".txt") != NULL) {
                            content_type = "text/plain";
                        } else if (strstr(filename, ".jpg") != NULL || strstr(filename, ".jpeg") != NULL) {
                            content_type = "image/jpeg";
                        } else if (strstr(filename, ".m3u8") != NULL) {
                            content_type = "application/vnd.apple.mpegurl";
                        } else if (strstr(filename, ".ts") != NULL) {
                            content_type = "video/mp2t";
                        } else {
                            // Check if no extension
                            if (strchr(filename, '.') == NULL) {
                                content_type = "application/octet-stream";
                            }
                        }
                        
                        printf("Content-Type: %s\n", content_type);
                        
                        // Step 5.4: Send HTTP response
                        char response_header[512];
                        snprintf(response_header, sizeof(response_header),
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: %s\r\n"
                                "Content-Length: %ld\r\n"
                                "\r\n",
                                content_type, file_size);
                        
                        // Send header
                        int header_sent = SSL_write(ssl, response_header, strlen(response_header));
                        printf("Sent %d bytes of header\n", header_sent);
                        
                        // Send file content
                        int content_sent = SSL_write(ssl, file_buffer, file_size);
                        printf("Sent %d bytes of file content\n", content_sent);
                        
                        free(file_buffer);
                    }
                }
            } else {
                printf("Failed to parse request\n");
                // Send error response
                const char *error_response = 
                    "HTTP/1.1 400 Bad Request\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: 50\r\n"
                    "\r\n"
                    "<html><body><h1>400 Bad Request</h1></body></html>";
                
                SSL_write(ssl, error_response, strlen(error_response));
            }
        }
        
        // Clean up SSL connection
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
    }

    close(server_socket);
    
    // Clean up SSL context
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    
    return 0;
}

int file_exists(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file != NULL) {
        fclose(file);
        return 1;
    }
    return 0;
}

// TODO: Parse HTTP request, extract file path, and route to appropriate handler
// Consider: URL decoding, default files, routing logic for different file types
void handle_request(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // TODO: Read request from SSL connection
    bytes_read = 0;
    
    if (bytes_read <= 0) {
        return;
    }

    buffer[bytes_read] = '\0';
    char *request = malloc(strlen(buffer) + 1);
    strcpy(request, buffer);
    
    char *method = strtok(request, " ");
    char *file_name = strtok(NULL, " ");
    file_name++;
    if (strlen(file_name) == 0) {
        strcat(file_name, "index.html");
    }
    char *http_version = strtok(NULL, " ");

    if (file_exists(file_name)) {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    } else {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }
}

// TODO: Serve local file with correct Content-Type header
// Support: .html, .txt, .jpg, .m3u8, and files without extension
void send_local_file(SSL *ssl, const char *path) {
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file) {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";
        // TODO: Send response via SSL
        
        return;
    }

    char *response;
    if (strstr(path, ".html")) {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    } else {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    }

    // TODO: Send response header and file content via SSL
    

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // TODO: Send file data via SSL
        
    }

    fclose(file);
}

// TODO: Forward request to backend server and relay response to client
// Handle connection failures appropriately
void proxy_remote_file(SSL *ssl, const char *request) {
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1) {
        printf("Failed to create remote socket\n");
        return;
    }

    remote_addr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_HOST, &remote_addr.sin_addr);
    remote_addr.sin_port = htons(REMOTE_PORT);

    if (connect(remote_socket, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) == -1) {
        printf("Failed to connect to remote server\n");
        close(remote_socket);
        return;
    }

    send(remote_socket, request, strlen(request), 0);

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0) {
        // TODO: Forward response to client via SSL
        
    }

    close(remote_socket);
}
