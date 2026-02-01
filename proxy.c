#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>

#define BUFFER_SIZE 1024
#define LOCAL_PORT_TO_CLIENT 8443
#define REMOTE_HOST "127.0.0.1"
#define REMOTE_PORT 5001

int local_port = LOCAL_PORT_TO_CLIENT;
char remote_host[256] = REMOTE_HOST;
int remote_port = REMOTE_PORT;

void handle_request(SSL *ssl);
void send_local_file(SSL *ssl, const char *path);
void proxy_remote_file(SSL *ssl, const char *request);
int file_exists(const char *filename);

void send_404(SSL *ssl)
{
    const char *response =
        "HTTP/1.0 404 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 48\r\n"
        "\r\n"
        "<html><body><h1>404 Not Found</h1></body></html>";
    SSL_write(ssl, response, strlen(response));
}

void send_502(SSL *ssl)
{
    const char *response =
        "HTTP/1.0 502 Bad Gateway\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 54 \r\n"
        "\r\n"
        "<html><body><h1>502 Bad Gateway</h1></body></html>";
    SSL_write(ssl, response, strlen(response));
}

int ends_with(const char *str, const char *suffix)
{
    if (!str || !suffix)
        return 0;
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    if (suffix_len > str_len)
        return 0;
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

void decode_url(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if (*src == '%' && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

void parse_args(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc)
        {
            local_port = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
        {
            strncpy(remote_host, argv[++i], sizeof(remote_host) - 1);
            remote_host[sizeof(remote_host) - 1] = '\0';
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
        {
            remote_port = atoi(argv[++i]);
        }
    }
}

int main(int argc, char *argv[])
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    parse_args(argc, argv);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    printf("OpenSSL initialized\n");

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new(method);

    if (ssl_ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Failed to create SSL context\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Failed to load server.crt\n");
        exit(EXIT_FAILURE);
    }
    printf("Loaded server.crt\n");

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error: Failed to load server.key\n");
        exit(EXIT_FAILURE);
    }
    printf("Loaded server.key\n");

    if (!SSL_CTX_check_private_key(ssl_ctx))
    {
        fprintf(stderr, "Error: Private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }
    printf("Private key matches certificate\n");

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(local_port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) == -1)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Proxy server listening on port %d\n", local_port);

    while (1)
    {
        client_len = sizeof(client_addr);
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == -1)
        {
            perror("accept failed");
            continue;
        }

        printf("Client connected\n");
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        SSL *ssl = SSL_new(ssl_ctx);
        if (ssl == NULL)
        {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Error: Failed to create SSL structure\n");
            close(client_socket);
            continue;
        }

        SSL_set_fd(ssl, client_socket);

        int ssl_accept_ret = SSL_accept(ssl);
        if (ssl_accept_ret <= 0)
        {
            int err = SSL_get_error(ssl, ssl_accept_ret);
            fprintf(stderr, "SSL handshake failed with error %d\n", err);
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        printf("TLS handshake succeeded\n");

        char buffer[BUFFER_SIZE * 4];
        int total_read = 0;
        int found_end = 0;

        while (total_read < sizeof(buffer) - 1 && !found_end)
        {
            int bytes_read = SSL_read(ssl, buffer + total_read, sizeof(buffer) - total_read - 1);
            if (bytes_read <= 0)
            {
                printf("SSL_read error or connection closed\n");
                break;
            }
            total_read += bytes_read;
            buffer[total_read] = '\0';

            if (strstr(buffer, "\r\n\r\n") != NULL)
            {
                found_end = 1;
            }
        }

        if (total_read > 0)
        {
            printf("Received full HTTP request (%d bytes):\n%s\n", total_read, buffer);

            char request_copy[BUFFER_SIZE * 4];
            strncpy(request_copy, buffer, sizeof(request_copy) - 1);
            request_copy[sizeof(request_copy) - 1] = '\0';

            char *method = strtok(request_copy, " ");
            char *path = strtok(NULL, " ");
            char *http_version = strtok(NULL, "\r\n");

            char filename[256] = "";

            if (method && path)
            {
                printf("Method: %s, Path: %s\n", method, path);

                if (path[0] == '/')
                {
                    path++;
                }

                if (strlen(path) == 0 || strcmp(path, "") == 0)
                {
                    strcpy(filename, "index.html");
                }
                else
                {
                    char decode_path[256];
                    decode_url(decode_path, path);
                    strncpy(filename, decode_path, sizeof(filename) - 1);
                    filename[sizeof(filename) - 1] = '\0';
                }

                printf("Extracted filename: %s\n", filename);

                if (ends_with(filename, ".ts"))
                {
                    printf("Detected .ts file, proxying to backend\n");
                    proxy_remote_file(ssl, buffer);
                }
                else
                {
                    FILE *file = fopen(filename, "rb");

                    if (file == NULL)
                    {
                        printf("File not found: %s\n", filename);
                        send_404(ssl);
                    }
                    else
                    {
                        fseek(file, 0, SEEK_END);
                        long file_size = ftell(file);
                        fseek(file, 0, SEEK_SET);

                        printf("File size: %ld bytes\n", file_size);

                        char *file_buffer = malloc(file_size);
                        if (file_buffer == NULL)
                        {
                            printf("Failed to allocate memory for file\n");
                            fclose(file);
                        }
                        else
                        {
                            size_t bytes_read = fread(file_buffer, 1, file_size, file);
                            fclose(file);

                            printf("Read %zu bytes from file\n", bytes_read);

                            const char *content_type = "application/octet-stream";

                            if (strstr(filename, ".html") != NULL)
                            {
                                content_type = "text/html";
                            }
                            else if (strstr(filename, ".txt") != NULL)
                            {
                                content_type = "text/plain";
                            }
                            else if (strstr(filename, ".jpg") != NULL || strstr(filename, ".jpeg") != NULL)
                            {
                                content_type = "image/jpeg";
                            }
                            else if (strstr(filename, ".m3u8") != NULL)
                            {
                                content_type = "application/vnd.apple.mpegurl";
                            }
                            else if (strstr(filename, ".ts") != NULL)
                            {
                                content_type = "video/mp2t";
                            }
                            else
                            {
                                if (strchr(filename, '.') == NULL)
                                {
                                    content_type = "application/octet-stream";
                                }
                            }

                            printf("Content-Type: %s\n", content_type);

                            char response_header[512];
                            snprintf(response_header, sizeof(response_header),
                                     "HTTP/1.1 200 OK\r\n"
                                     "Content-Type: %s\r\n"
                                     "Content-Length: %ld\r\n"
                                     "\r\n",
                                     content_type, file_size);

                            int header_sent = SSL_write(ssl, response_header, strlen(response_header));
                            printf("Sent %d bytes of header\n", header_sent);

                            int content_sent = SSL_write(ssl, file_buffer, file_size);
                            printf("Sent %d bytes of file content\n", content_sent);

                            free(file_buffer);
                        }
                    }
                }
            }
            else
            {
                printf("Failed to parse request\n");
                send_404(ssl);
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
    }

    close(server_socket);

    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();

    return 0;
}

int file_exists(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file != NULL)
    {
        fclose(file);
        return 1;
    }
    return 0;
}

void handle_request(SSL *ssl)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    bytes_read = 0;

    if (bytes_read <= 0)
    {
        return;
    }

    buffer[bytes_read] = '\0';
    char *request = malloc(strlen(buffer) + 1);
    strcpy(request, buffer);

    char *method = strtok(request, " ");
    char *file_name = strtok(NULL, " ");
    file_name++;
    if (strlen(file_name) == 0)
    {
        strcat(file_name, "index.html");
    }
    char *http_version = strtok(NULL, " ");

    if (file_exists(file_name))
    {
        printf("Sending local file %s\n", file_name);
        send_local_file(ssl, file_name);
    }
    else
    {
        printf("Proxying remote file %s\n", file_name);
        proxy_remote_file(ssl, buffer);
    }
}

void send_local_file(SSL *ssl, const char *path)
{
    FILE *file = fopen(path, "rb");
    char buffer[BUFFER_SIZE];
    size_t bytes_read;

    if (!file)
    {
        printf("File %s not found\n", path);
        char *response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/html; charset=UTF-8\r\n\r\n"
                         "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
                         "<body><h1>404 Not Found</h1></body></html>";

        return;
    }

    char *response;
    if (strstr(path, ".html"))
    {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/html; charset=UTF-8\r\n\r\n";
    }
    else
    {
        response = "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain; charset=UTF-8\r\n\r\n";
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
    }

    fclose(file);
}

void proxy_remote_file(SSL *ssl, const char *request)
{
    int remote_socket;
    struct sockaddr_in remote_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (remote_socket == -1)
    {
        printf("Failed to create remote socket\n");
        send_502(ssl);
        return;
    }

    remote_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, remote_host, &remote_addr.sin_addr) <= 0)
    {
        printf("Invalid backend address\n");
        close(remote_socket);
        send_502(ssl);
        return;
    }
    remote_addr.sin_port = htons(remote_port);

    if (connect(remote_socket, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == -1)
    {
        printf("Failed to connect to remote server\n");
        close(remote_socket);
        send_502(ssl);
        return;
    }

    ssize_t sent = send(remote_socket, request, strlen(request), 0);
    if (sent < 0)
    {
        printf("Failed to send to backend\n");
        close(remote_socket);
        send_502(ssl);
        return;
    }

    while ((bytes_read = recv(remote_socket, buffer, sizeof(buffer), 0)) > 0)
    {
        int written = SSL_write(ssl, buffer, bytes_read);
        if (written <= 0)
        {
            fprintf(stderr, "Error writing to SSL client\n");
            break;
        }
        printf("Proxied %zd bytes from backend to client\n", bytes_read);
    }

    close(remote_socket);
}
