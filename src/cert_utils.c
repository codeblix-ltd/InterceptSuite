/*
 * TLS MITM Proxy - Certificate Utilities Implementation
 */

#include "../include/cert_utils.h"

int init_openssl(void) {
    printf("Initializing OpenSSL libraries...\n");

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    printf("Using older OpenSSL API (pre-1.1.0)\n");
#else
    OPENSSL_init_ssl(0, NULL);
    printf("Using newer OpenSSL API (1.1.0+)\n");
#endif

    // Initialize the OPENSSL_Applink functionality (defined in applink.c)
    printf("Initializing OPENSSL_Applink...\n");
    OPENSSL_Applink();
    printf("OPENSSL_Applink initialized\n");

    return 1;
}

void cleanup_openssl(void) {
    if (ca_cert) X509_free(ca_cert);
    if (ca_key) EVP_PKEY_free(ca_key);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_free_strings();
    EVP_cleanup();
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
    FILE *cert_file = fopen(CA_CERT_FILE, "r");
    FILE *key_file = fopen(CA_KEY_FILE, "r");

    if (!cert_file || !key_file) {
        printf("Certificate or key file not found. Will generate new ones.\n");
    }

    if (cert_file && key_file) {
        // Load existing CA cert and key
        printf("Loading existing CA cert and key from %s and %s\n", CA_CERT_FILE, CA_KEY_FILE);
        ca_cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
        fclose(cert_file);

        ca_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
        fclose(key_file);

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
    }

    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        print_openssl_error();
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

    if (!EVP_PKEY_assign_RSA(ca_key, rsa)) {
        print_openssl_error();
        RSA_free(rsa);
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
        return 0;
    }

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
        return 0;
    }

    // Write to files
    cert_file = fopen(CA_CERT_FILE, "w");
    key_file = fopen(CA_KEY_FILE, "w");

    if (cert_file && key_file) {
        PEM_write_X509(cert_file, ca_cert);
        PEM_write_PrivateKey(key_file, ca_key, NULL, NULL, 0, NULL, NULL);

        fclose(cert_file);
        fclose(key_file);

        printf("CA cert and key written to %s and %s\n", CA_CERT_FILE, CA_KEY_FILE);
        printf("IMPORTANT: Install this CA cert in your system/browser certificate store!\n");

        return 1;
    }

    fprintf(stderr, "Failed to write CA cert and key to files\n");
    if (cert_file) fclose(cert_file);
    if (key_file) fclose(key_file);

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
    }

    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        print_openssl_error();
        EVP_PKEY_free(key);
        return 0;
    }

    if (!EVP_PKEY_assign_RSA(key, rsa)) {
        print_openssl_error();
        RSA_free(rsa);
        EVP_PKEY_free(key);
        return 0;
    }

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_server_method());
#else
    ctx = SSL_CTX_new(TLS_server_method());
#endif

    if (!ctx) {
        print_openssl_error();
        return NULL;
    }

    // Allow all SSL/TLS protocols
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    return ctx;
}

SSL_CTX *create_client_ssl_context(void) {
    SSL_CTX *ctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_client_method());
#else
    ctx = SSL_CTX_new(TLS_client_method());
#endif

    if (!ctx) {
        print_openssl_error();
        return NULL;
    }

    // Disable certificate verification for outbound connections
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}
