/*
 * TLS MITM Proxy - Certificate Utilities Implementation
 */

#include "../include/cert_utils.h"

/* Helper function to read file contents into memory buffer */
static char* read_file_to_memory(const char* filename, long* file_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = malloc(*file_size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, *file_size, file);
    fclose(file);

    if (read_size != *file_size) {
        free(buffer);
        return NULL;
    }

    buffer[*file_size] = '\0';
    return buffer;
}

/* Helper function to write buffer to file */
static int write_memory_to_file(const char* filename, const char* data, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        return 0;
    }

    size_t written = fwrite(data, 1, size, file);
    fclose(file);

    return (written == size) ? 1 : 0;
}

int init_openssl(void) {
    printf("Initializing OpenSSL libraries...\n");

    // Clear any existing errors
    ERR_clear_error();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    // Older OpenSSL versions require manual thread safety setup
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Initialize threading support for older OpenSSL versions
    // Note: For production use, you should implement proper locking callbacks
    // For now, we'll rely on the fact that our DLL usage is single-threaded per connection

    printf("Using older OpenSSL API (pre-1.1.0)\n");
#else
    // For DLL builds, use explicit initialization flags with thread safety
    uint64_t init_flags = OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                         OPENSSL_INIT_ADD_ALL_CIPHERS |
                         OPENSSL_INIT_ADD_ALL_DIGESTS;

    if (OPENSSL_init_ssl(init_flags, NULL) != 1) {
        fprintf(stderr, "Failed to initialize OpenSSL SSL\n");
        print_openssl_error();
        return 0;
    }

    if (OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL) != 1) {
        fprintf(stderr, "Failed to initialize OpenSSL crypto\n");
        print_openssl_error();
        return 0;
    }

    printf("Using newer OpenSSL API (1.1.0+)\n");
#endif

    // Verify OpenSSL is properly initialized
    if (SSLeay() == 0) {
        fprintf(stderr, "OpenSSL version check failed\n");
        return 0;
    }

    printf("OpenSSL initialized successfully with applink support\n");
    return 1;
}

void cleanup_openssl(void) {
    // Clear error queue before cleanup
    ERR_clear_error();

    // Free global CA resources safely
    if (ca_cert) {
        X509_free(ca_cert);
        ca_cert = NULL;
    }
    if (ca_key) {
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    // Cleanup for older OpenSSL versions
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
#else
    // Modern OpenSSL handles cleanup automatically, but we can help
    OPENSSL_cleanup();
#endif
}

void print_openssl_error(void) {
    unsigned long err;
    while ((err = ERR_get_error())) {
        char *str = ERR_error_string(err, NULL);
        fprintf(stderr, "OpenSSL Error: %s\n", str);
    }
}

int load_or_generate_ca_cert(void) {
    printf("Checking for CA certificate and key files: %s and %s\n", CA_CERT_FILE, CA_KEY_FILE);

    // Try to read files into memory
    long cert_size = 0, key_size = 0;
    char* cert_data = read_file_to_memory(CA_CERT_FILE, &cert_size);
    char* key_data = read_file_to_memory(CA_KEY_FILE, &key_size);

    if (!cert_data || !key_data) {
        printf("Certificate or key file not found. Will generate new ones.\n");
        if (cert_data) free(cert_data);
        if (key_data) free(key_data);
    } else {
        // Load existing CA cert and key using memory BIOs
        printf("Loading existing CA cert and key from %s and %s\n", CA_CERT_FILE, CA_KEY_FILE);

        BIO* cert_bio = BIO_new_mem_buf(cert_data, cert_size);
        BIO* key_bio = BIO_new_mem_buf(key_data, key_size);

        if (cert_bio && key_bio) {
            ca_cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
            ca_key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL);
        }

        if (cert_bio) BIO_free(cert_bio);
        if (key_bio) BIO_free(key_bio);
        free(cert_data);
        free(key_data);

        if (ca_cert && ca_key) {
            return 1; // Successfully loaded
        }

        // If we got here, something failed
        if (ca_cert) X509_free(ca_cert);
        if (ca_key) EVP_PKEY_free(ca_key);
        ca_cert = NULL;
        ca_key = NULL;
    }

    // Generate new CA cert and key
    printf("Generating new CA cert and key\n");

    // Generate key
    ca_key = EVP_PKEY_new();
    if (!ca_key) {
        print_openssl_error();
        return 0;
    }    // Generate RSA key using modern OpenSSL 3.0 API
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) {
        print_openssl_error();
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &ca_key) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

    EVP_PKEY_CTX_free(pkey_ctx);

    // Generate cert
    ca_cert = X509_new();
    if (!ca_cert) {
        print_openssl_error();
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

    // Set version, serial number, validity
    X509_set_version(ca_cert, 2); // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(ca_cert), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(ca_cert), 0); // Valid from now
    X509_gmtime_adj(X509_get_notAfter(ca_cert), 60 * 60 * 24 * 365 * 10); // Valid for 10 years

    // Set public key and issuer/subject
    X509_set_pubkey(ca_cert, ca_key);

    X509_NAME *name = X509_get_subject_name(ca_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"TLS MITM Proxy CA", -1, -1, 0);
    X509_set_issuer_name(ca_cert, name);

    // Add extensions
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca_cert, ca_cert, NULL, NULL, 0);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
    if (!ext) {
        print_openssl_error();
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        ca_cert = NULL;
        ca_key = NULL;
        return 0;
    }

    X509_add_ext(ca_cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the certificate
    if (!X509_sign(ca_cert, ca_key, EVP_sha256())) {
        print_openssl_error();
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        ca_cert = NULL;
        ca_key = NULL;
        return 0;    }

    // Write to files using memory BIOs
    BIO* cert_bio = BIO_new(BIO_s_mem());
    BIO* key_bio = BIO_new(BIO_s_mem());

    if (!cert_bio || !key_bio) {
        if (cert_bio) BIO_free(cert_bio);
        if (key_bio) BIO_free(key_bio);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        ca_cert = NULL;
        ca_key = NULL;
        return 0;
    }

    // Write certificate and key to memory BIOs
    if (PEM_write_bio_X509(cert_bio, ca_cert) != 1 ||
        PEM_write_bio_PrivateKey(key_bio, ca_key, NULL, NULL, 0, NULL, NULL) != 1) {
        BIO_free(cert_bio);
        BIO_free(key_bio);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        ca_cert = NULL;
        ca_key = NULL;
        return 0;
    }    // Get data from BIOs
    char* pem_cert_data;
    char* pem_key_data;
    long cert_len = BIO_get_mem_data(cert_bio, &pem_cert_data);
    long key_len = BIO_get_mem_data(key_bio, &pem_key_data);

    // Write to files
    int success = write_memory_to_file(CA_CERT_FILE, pem_cert_data, cert_len) &&
                  write_memory_to_file(CA_KEY_FILE, pem_key_data, key_len);

    BIO_free(cert_bio);
    BIO_free(key_bio);

    if (success) {
        printf("CA cert and key written to %s and %s\n", CA_CERT_FILE, CA_KEY_FILE);
        printf("IMPORTANT: Install this CA cert in your system/browser certificate store!\n");
        return 1;
    }

    fprintf(stderr, "Failed to write CA cert and key to files\n");
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    ca_cert = NULL;
    ca_key = NULL;

    return 0;
}

int generate_cert_for_host(const char *hostname, X509 **cert_out, EVP_PKEY **key_out) {
    X509 *cert;
    EVP_PKEY *key;
    X509_NAME *name;

    if (config.verbose) {
        printf("Generating certificate for %s\n", hostname);
    }

    // Generate key
    key = EVP_PKEY_new();
    if (!key) {
        print_openssl_error();
        return 0;
    }    // Generate key using modern OpenSSL 3.0 API
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) {
        print_openssl_error();
        EVP_PKEY_free(key);
        return 0;
    }

    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(key);
        return 0;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(key);
        return 0;
    }

    if (EVP_PKEY_keygen(pkey_ctx, &key) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(key);
        return 0;
    }

    EVP_PKEY_CTX_free(pkey_ctx);

    // Generate cert
    cert = X509_new();
    if (!cert) {
        print_openssl_error();
        EVP_PKEY_free(key);
        return 0;
    }

    // Set version, serial number, validity
    X509_set_version(cert, 2); // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)time(NULL));

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0); // Valid from now
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * CERT_EXPIRY_DAYS); // Valid for a year

    // Set public key
    X509_set_pubkey(cert, key);

    // Set subject name
    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)hostname, -1, -1, 0);

    // Set issuer name (from CA cert)
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // Add Subject Alternative Name extension
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);

    char san[MAX_HOSTNAME_LEN + 8];
    sprintf(san, "DNS:%s", hostname);
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (!ext) {
        print_openssl_error();
        X509_free(cert);
        EVP_PKEY_free(key);
        return 0;
    }

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);

    // Sign the certificate with our CA key
    if (!X509_sign(cert, ca_key, EVP_sha256())) {
        print_openssl_error();
        X509_free(cert);
        EVP_PKEY_free(key);
        return 0;
    }

    *cert_out = cert;
    *key_out = key;

    return 1;
}

SSL_CTX *create_server_ssl_context(void) {
    SSL_CTX *ctx;

    // Clear any previous OpenSSL errors
    ERR_clear_error();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_server_method());
#else
    ctx = SSL_CTX_new(TLS_server_method());
#endif

    if (!ctx) {
        fprintf(stderr, "Failed to create SSL server context\n");
        print_openssl_error();
        return NULL;
    }

    // Enhanced SSL context configuration with error checking
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;
    if (SSL_CTX_set_options(ctx, options) == 0) {
        if (config.verbose) {
            fprintf(stderr, "Warning: Failed to set some SSL context options\n");
            print_openssl_error();
        }
    }

    // Set cipher list for better security
    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA") != 1) {
        if (config.verbose) {
            fprintf(stderr, "Warning: Failed to set cipher list\n");
            print_openssl_error();
        }
    }

    // Set session cache mode
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

    return ctx;
}

SSL_CTX *create_client_ssl_context(void) {
    SSL_CTX *ctx;

    // Clear any previous OpenSSL errors
    ERR_clear_error();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_client_method());
#else
    ctx = SSL_CTX_new(TLS_client_method());
#endif

    if (!ctx) {
        fprintf(stderr, "Failed to create SSL client context\n");
        print_openssl_error();
        return NULL;
    }

    // Enhanced SSL context configuration with error checking
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;
    if (SSL_CTX_set_options(ctx, options) == 0) {
        if (config.verbose) {
            fprintf(stderr, "Warning: Failed to set some SSL context options\n");
            print_openssl_error();
        }
    }

    // Set cipher list for better security
    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA") != 1) {
        if (config.verbose) {
            fprintf(stderr, "Warning: Failed to set cipher list\n");
            print_openssl_error();
        }
    }

    // Disable certificate verification for outbound connections with proper error handling
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Set session cache mode
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);

    return ctx;
}
