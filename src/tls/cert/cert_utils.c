/*
 * InterceptSuite - Certificate Utilities Implementation

Open SSL applink needs to be handled for DLL build
Passing Memory instead of File operations directly
 */

#include "cert_utils.h"
#include "../../utils/utils.h"

#ifdef INTERCEPT_WINDOWS
#include <io.h>      // For _access and _unlink on Windows
#else
#include <unistd.h>  // For access and unlink on Unix/Linux
#endif

/* Certificate cache data structures */
typedef struct cert_cache_entry {
    char hostname[256];
    X509 *cert;
    EVP_PKEY *key;
    time_t created_time;
    struct cert_cache_entry *next;
} cert_cache_entry_t;

static cert_cache_entry_t *cert_cache_head = NULL;
static const time_t CERT_CACHE_TTL = 3600; // 1 hour TTL

/* Static counter for unique certificate serial numbers */
static long serial_counter = 1;

/* Helper function to read file contents into memory buffer */
char * read_file_to_memory(const char * filename, long * file_size) {
  FILE * file = fopen(filename, "rb");
  if (!file) {
    return NULL;
  }

  fseek(file, 0, SEEK_END);
  * file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  char * buffer = malloc( * file_size + 1);
  if (!buffer) {
    fclose(file);
    return NULL;
  }

  size_t read_size = fread(buffer, 1, * file_size, file);
  fclose(file);

  if (read_size != * file_size) {
    free(buffer);
    return NULL;
  }

  buffer[ * file_size] = '\0';
  return buffer;
}

/* Helper function to write buffer to file */
int write_memory_to_file(const char* filename,
  const char* data, size_t data_size) {
  FILE * file = fopen(filename, "wb");
  if (!file) {
    return 0;
  }
  size_t written = fwrite(data, 1, data_size, file);
  fclose(file);

  return (written == data_size) ? 1 : 0;
}

int init_openssl(void) {
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

  #else
  // For DLL builds, use explicit initialization flags with thread safety
  uint64_t init_flags = OPENSSL_INIT_LOAD_SSL_STRINGS |
    OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
    OPENSSL_INIT_ADD_ALL_CIPHERS |
    OPENSSL_INIT_ADD_ALL_DIGESTS;

  if (OPENSSL_init_ssl(init_flags, NULL) != 1) {
    log_message("Failed to initialize OpenSSL SSL\n");
    print_openssl_error();
    return 0;
  }

  if (OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL) != 1) {
    log_message("Failed to initialize OpenSSL crypto\n");
    print_openssl_error();
    return 0;
  }

  #endif

  // Verify OpenSSL is properly initialized
  if (SSLeay() == 0) {
    log_message("OpenSSL version check failed\n");
    return 0;
  }

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
  char err_buf[256];

  while ((err = ERR_get_error())) {
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    log_message("TLS Error [%08lX]: %s", err, err_buf);

    // Also log the library and reason for better debugging
    int lib = ERR_GET_LIB(err);
    int reason = ERR_GET_REASON(err);
    const char* lib_str = ERR_lib_error_string(err);
    const char* reason_str = ERR_reason_error_string(err);

    if (lib_str && reason_str) {
      log_message("TLS Error Details: Library=%s, Reason=%s", lib_str, reason_str);
    }
  }
}

/* Certificate cache management functions */

// Initialize certificate cache
void init_cert_cache(void) {
    cert_cache_head = NULL;
}

// Cleanup all cached certificates
void cleanup_cert_cache(void) {
    cert_cache_entry_t *current = cert_cache_head;
    int cleaned_count = 0;

    while (current != NULL) {
        cert_cache_entry_t *next = current->next;
        X509_free(current->cert);
        EVP_PKEY_free(current->key);
        free(current);
        current = next;
        cleaned_count++;
    }
    cert_cache_head = NULL;
}

// Clean up expired entries from certificate cache
static void cleanup_expired_cert_cache(void) {
    cert_cache_entry_t **current = &cert_cache_head;
    time_t now = time(NULL);
    int cleaned_count = 0;

    while (*current != NULL) {
        if (now - (*current)->created_time > CERT_CACHE_TTL) {
            cert_cache_entry_t *expired = *current;
            *current = expired->next;
            X509_free(expired->cert);
            EVP_PKEY_free(expired->key);
            free(expired);
            cleaned_count++;
        } else {
            current = &(*current)->next;
        }
    }
}

// Look up certificate in cache
static cert_cache_entry_t* find_cached_cert(const char *hostname) {
    cleanup_expired_cert_cache(); // Clean up expired entries first

    cert_cache_entry_t *current = cert_cache_head;
    while (current != NULL) {
        if (strcmp(current->hostname, hostname) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Add certificate to cache
static void cache_cert(const char *hostname, X509 *cert, EVP_PKEY *key) {
    cert_cache_entry_t *entry = malloc(sizeof(cert_cache_entry_t));
    if (!entry) {
        log_message("Failed to allocate memory for certificate cache entry");
        return;
    }

    strncpy(entry->hostname, hostname, sizeof(entry->hostname) - 1);
    entry->hostname[sizeof(entry->hostname) - 1] = '\0';
    entry->cert = cert;
    entry->key = key;
    entry->created_time = time(NULL);
    entry->next = cert_cache_head;
    cert_cache_head = entry;

    // Increment reference counts since we're storing them in cache
    X509_up_ref(cert);
    EVP_PKEY_up_ref(key);
}

// New separate function for CA certificate generation
static int generate_new_ca_cert(void) {
  // Generate key
  ca_key = EVP_PKEY_new();
  if (!ca_key) {
    print_openssl_error();
    return 0;
  }

  // Generate RSA key using modern OpenSSL 3.0 API
  EVP_PKEY_CTX * pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
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

  X509_NAME * name = X509_get_subject_name(ca_cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"Intercept Suite", -1, -1, 0);
  X509_set_issuer_name(ca_cert, name);

  // Add extensions
  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, ca_cert, ca_cert, NULL, NULL, 0);

  X509_EXTENSION * ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints, "critical,CA:TRUE");
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

  return 1;
}

// New separate function for saving CA certificate to files
static int save_ca_cert_to_files(void) {
  // Write to files using memory BIOs
  BIO * cert_bio = BIO_new(BIO_s_mem());
  BIO * key_bio = BIO_new(BIO_s_mem());

  if (!cert_bio || !key_bio) {
    if (cert_bio) BIO_free(cert_bio);
    if (key_bio) BIO_free(key_bio);
    return 0;
  }

  // Write certificate and key to memory BIOs
  if (PEM_write_bio_X509(cert_bio, ca_cert) != 1 ||
      PEM_write_bio_PrivateKey(key_bio, ca_key, NULL, NULL, 0, NULL, NULL) != 1) {
    BIO_free(cert_bio);
    BIO_free(key_bio);
    return 0;
  }
  // Get data from BIOs
  char * pem_cert_data;
  char * pem_key_data;
  long cert_len = BIO_get_mem_data(cert_bio, &pem_cert_data);
  long key_len = BIO_get_mem_data(key_bio, &pem_key_data);

  // Initialize user data directory and get certificate paths
  if (!init_user_data_directory()) {
    BIO_free(cert_bio);
    BIO_free(key_bio);
    log_message("Failed to initialize user data directory\n");
    return 0;
  }

  const char* cert_path = get_ca_cert_path();
  const char* key_path = get_ca_key_path();

  if (!cert_path || !key_path) {
    BIO_free(cert_bio);
    BIO_free(key_bio);
    log_message("Failed to get certificate file paths\n");
    return 0;
  }
  // Write to files
  int success = write_memory_to_file(cert_path, pem_cert_data, (size_t)cert_len) &&
                write_memory_to_file(key_path, pem_key_data, (size_t)key_len);

  BIO_free(cert_bio);
  BIO_free(key_bio);

  if (!success) {
    log_message("Failed to write CA cert and key to files\n");
  }

  return success;
}

// Simplified main function
int load_or_generate_ca_cert(void) {
  // Initialize user data directory first
  if (!init_user_data_directory()) {
    log_message("Failed to initialize user data directory\n");
    return 0;
  }

  const char* cert_path = get_ca_cert_path();
  const char* key_path = get_ca_key_path();

  if (!cert_path || !key_path) {
    log_message("Failed to get certificate file paths\n");
    return 0;
  }

  // Try to read files into memory
  long cert_size = 0, key_size = 0;
  char * cert_data = read_file_to_memory(cert_path, &cert_size);
  char * key_data = read_file_to_memory(key_path, &key_size);
  if (!cert_data || !key_data) {
    log_message("Certificate or key file not found. Will generate new ones.\n");
    if (cert_data) free(cert_data);
    if (key_data) free(key_data);
  } else {
    // Load existing CA cert and key using memory BIOs
    if (config.verbose) {
      log_message("Loading existing CA cert and key from %s and %s\n", cert_path, key_path);
    }

    BIO * cert_bio = BIO_new_mem_buf(cert_data, cert_size);
    BIO * key_bio = BIO_new_mem_buf(key_data, key_size);

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
    if (config.verbose) {
      log_message("Failed to load existing certificates, generating new ones\n");
    }
    if (ca_cert) X509_free(ca_cert);
    if (ca_key) EVP_PKEY_free(ca_key);
    ca_cert = NULL;
    ca_key = NULL;
  }

  // Generate new CA cert and key
  if (!generate_new_ca_cert()) {
    log_message("Failed to generate new CA certificate\n");
    return 0;
  }

  // Save to files
  if (!save_ca_cert_to_files()) {
    log_message("Failed to save CA certificate to files\n");
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    ca_cert = NULL;
    ca_key = NULL;
    return 0;
  }

  return 1;
}


int generate_cert_for_host(const char * hostname, X509 ** cert_out, EVP_PKEY ** key_out) {
  X509 * cert;
  EVP_PKEY * key;
  X509_NAME * name;

  // Check cache first
  cert_cache_entry_t *cached = find_cached_cert(hostname);
  if (cached) {
    *cert_out = cached->cert;
    *key_out = cached->key;
    // Increment reference counts for the caller
    X509_up_ref(cached->cert);
    EVP_PKEY_up_ref(cached->key);
    return 1;
  }

  // Generate key
  key = EVP_PKEY_new();
  if (!key) {
    print_openssl_error();
    return 0;
  } // Generate key using modern OpenSSL 3.0 API
  EVP_PKEY_CTX * pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
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

  if (EVP_PKEY_keygen(pkey_ctx, & key) <= 0) {
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

  // Generate unique serial number: combine timestamp with counter
  long unique_serial = time(NULL) * 1000 + (serial_counter++);
  if (serial_counter > 999) {
    serial_counter = 1; // Reset counter to avoid overflow
  }
  ASN1_INTEGER_set(X509_get_serialNumber(cert), unique_serial);

  // Set validity period
  X509_gmtime_adj(X509_get_notBefore(cert), 0); // Valid from now
  X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * CERT_EXPIRY_DAYS); // Valid for a year

  // Set public key
  X509_set_pubkey(cert, key);

  // Set subject name
  name = X509_get_subject_name(cert);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char * ) hostname, -1, -1, 0);

  // Set issuer name (from CA cert)
  X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

  // Add Subject Alternative Name extension
  X509V3_CTX ctx;
  X509V3_set_ctx( & ctx, ca_cert, cert, NULL, NULL, 0);

  char san[MAX_HOSTNAME_LEN + 8];
  sprintf(san, "DNS:%s", hostname);
  X509_EXTENSION * ext = X509V3_EXT_conf_nid(NULL, & ctx, NID_subject_alt_name, san);
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

  // Cache the certificate for future use
  cache_cert(hostname, cert, key);

  * cert_out = cert;
  * key_out = key;

  return 1;
}

SSL_CTX * create_server_ssl_context(void) {
  SSL_CTX * ctx;

  // Clear any previous OpenSSL errors
  ERR_clear_error();

  #if OPENSSL_VERSION_NUMBER < 0x10100000L
  ctx = SSL_CTX_new(SSLv23_server_method());
  #else
  ctx = SSL_CTX_new(TLS_server_method());
  #endif

  if (!ctx) {
    log_message("Failed to create SSL server context\n");
    print_openssl_error();
    return NULL;
  }

  // Enhanced SSL context configuration with error checking
  long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;
  if (SSL_CTX_set_options(ctx, options) == 0) {
    if (config.verbose) {
      log_message("Warning: Failed to set some SSL context options\n");
      print_openssl_error();
    }
  }

  // Set cipher list for better security
  if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA") != 1) {
    if (config.verbose) {
      log_message("Warning: Failed to set cipher list\n");
      print_openssl_error();
    }
  }

  // Set session cache mode
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

  return ctx;
}

SSL_CTX * create_client_ssl_context(void) {
  SSL_CTX * ctx;

  // Clear any previous OpenSSL errors
  ERR_clear_error();

  #if OPENSSL_VERSION_NUMBER < 0x10100000L
  ctx = SSL_CTX_new(SSLv23_client_method());
  #else
  ctx = SSL_CTX_new(TLS_client_method());
  #endif

  if (!ctx) {
    log_message("Failed to create SSL client context\n");
    print_openssl_error();
    return NULL;
  }

  // Enhanced SSL context configuration with more permissive options for MITM
  long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;

  // Add options for better compatibility with servers
  options |= SSL_OP_ALL; // Enable various bug workarounds
  options |= SSL_OP_NO_COMPRESSION; // Disable compression for security

  if (SSL_CTX_set_options(ctx, options) == 0) {
    if (config.verbose) {
      log_message("Warning: Failed to set some SSL context options\n");
      print_openssl_error();
    }
  }

  // Use more permissive cipher list for maximum server compatibility
  // Include more cipher suites while still avoiding the most insecure ones
  if (SSL_CTX_set_cipher_list(ctx, "ALL:!aNULL:!eNULL:!EXPORT:!LOW:!SSLv2") != 1) {
    if (config.verbose) {
      log_message("Warning: Failed to set cipher list, using default");
      print_openssl_error();
    }
  }

  // Disable certificate verification completely for outbound connections
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  SSL_CTX_set_verify_depth(ctx, 0);

  // Disable certificate chain verification
  SSL_CTX_set_cert_verify_callback(ctx, NULL, NULL);

  // Set session cache mode
  SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);

  return ctx;
}

/*
 * ALPN callback function for server-side protocol selection
 * This function handles the Application Layer Protocol Negotiation
 */
int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                        const unsigned char *in, unsigned int inlen, void *arg) {
    // Define supported protocols in preference order
    static const unsigned char http2_proto[] = {2, 'h', '2'};
    static const unsigned char http11_proto[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    if (config.verbose) {
        log_message("ALPN: Client offered %u protocols", inlen);
    }

    // Parse client's protocol list
    const unsigned char *client_protos = in;
    unsigned int remaining = inlen;

    while (remaining > 0) {
        if (remaining < 1) break;

        unsigned char proto_len = *client_protos;
        if (remaining < proto_len + 1) break;

        if (config.verbose) {
            char proto_debug[64] = {0};
            if (proto_len < sizeof(proto_debug)) {
                memcpy(proto_debug, client_protos + 1, proto_len);
                log_message("ALPN: Client offered protocol: %s", proto_debug);
            }
        }

        // Check for HTTP/2 support first (preferred)
        if (proto_len == 2 && memcmp(client_protos + 1, "h2", 2) == 0) {
            *out = http2_proto + 1;  // Skip length byte
            *outlen = http2_proto[0];
            log_message("ALPN: Selected HTTP/2 protocol");
            return SSL_TLSEXT_ERR_OK;
        }

        // Check for HTTP/1.1 support (fallback)
        if (proto_len == 8 && memcmp(client_protos + 1, "http/1.1", 8) == 0) {
            *out = http11_proto + 1;  // Skip length byte
            *outlen = http11_proto[0];
            log_message("ALPN: Selected HTTP/1.1 protocol");
            return SSL_TLSEXT_ERR_OK;
        }

        client_protos += proto_len + 1;
        remaining -= proto_len + 1;
    }

    // No supported protocol found, default to HTTP/1.1
    *out = http11_proto + 1;
    *outlen = http11_proto[0];
    log_message("ALPN: No matching protocol, defaulting to HTTP/1.1");
    return SSL_TLSEXT_ERR_OK;
}

/*
 * Create client SSL context with ALPN support for HTTP/2 and HTTP/1.1
 */
SSL_CTX* create_client_ssl_context_with_alpn(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        log_message("Failed to create client SSL context with ALPN");
        print_openssl_error();
        return NULL;
    }

    // Set minimum TLS version to 1.0 for maximum compatibility (instead of 1.2)
    #if defined(SSL_CTX_set_min_proto_version)
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    #endif

    // Enhanced SSL options for better server compatibility
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;
    options |= SSL_OP_ALL; // Enable various bug workarounds
    options |= SSL_OP_NO_COMPRESSION; // Disable compression for security
    SSL_CTX_set_options(ctx, options);

    // Configure ALPN protocols (HTTP/2 and HTTP/1.1)
    const unsigned char alpn_protos[] = {
        2, 'h', '2',                    // HTTP/2
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'  // HTTP/1.1
    };

    if (SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos)) != 0) {
        log_message("Warning: Failed to set ALPN protocols for client context");
    } else {
        log_message("ALPN: Client context configured with HTTP/2 and HTTP/1.1 support");
    }

    // Use more permissive cipher list for maximum server compatibility
    if (SSL_CTX_set_cipher_list(ctx, "ALL:!aNULL:!eNULL:!EXPORT:!LOW:!SSLv2") != 1) {
        if (config.verbose) {
            log_message("Warning: Failed to set cipher list for ALPN client, using default");
            print_openssl_error();
        }
    }

    // Disable certificate verification completely for MITM scenarios
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify_depth(ctx, 0);
    SSL_CTX_set_cert_verify_callback(ctx, NULL, NULL);

    // Set session cache mode
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);

    if (config.verbose) {
        log_message("Enhanced ALPN client context created for maximum compatibility");
    }

    return ctx;
}

/*
 * Create server SSL context with ALPN support for MITM
 */
SSL_CTX* create_server_ssl_context_with_alpn(X509 *cert, EVP_PKEY *key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        log_message("Failed to create server SSL context with ALPN");
        print_openssl_error();
        return NULL;
    }

    // Set certificate and private key
    if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
        log_message("Failed to set certificate for ALPN server context");
        print_openssl_error();
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey(ctx, key) <= 0) {
        log_message("Failed to set private key for ALPN server context");
        print_openssl_error();
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Verify certificate and key match
    if (!SSL_CTX_check_private_key(ctx)) {
        log_message("Certificate and private key do not match for ALPN server context");
        print_openssl_error();
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set ALPN callback for protocol negotiation
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_callback, NULL);

    // Set supported protocols for server advertisement
    const unsigned char alpn_protos[] = {
        2, 'h', '2',                    // HTTP/2
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'  // HTTP/1.1
    };

    if (SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos)) != 0) {
        log_message("Warning: Failed to set ALPN protocols for server context");
    } else {
        log_message("ALPN: Server context configured with HTTP/2 and HTTP/1.1 support");
    }

    // Set cipher list optimized for HTTP/2
    if (SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS") != 1) {
        if (config.verbose) {
            log_message("Warning: Failed to set HTTP/2 compatible cipher list for server");
            print_openssl_error();
        }
    }

    // Set TLS version constraints for HTTP/2 compatibility
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    return ctx;
}

/**
 * Regenerates the CA certificate and private key
 *
 * This function performs the following steps:
 * 1. Clears certificate cache from memory
 * 2. Frees existing global certificate variables
 * 3. Deletes certificate files from disk
 * 4. Generates new CA certificate and key
 * 5. Saves new certificates to files
 *
 * @return 1 on success, 0 on failure
 */
int regenerate_ca_certificate(void) {
    // Step 1: Clear certificate cache to ensure memory-resident certificates are updated
    cleanup_cert_cache();

    // Step 2: Clear global certificates from memory
    if (ca_cert) {
        X509_free(ca_cert);
        ca_cert = NULL;
    }
    if (ca_key) {
        EVP_PKEY_free(ca_key);
        ca_key = NULL;
    }

    // Step 3: Delete existing certificate files
    const char* cert_file = get_ca_cert_path();
    const char* key_file = get_ca_key_path();

    if (cert_file && key_file) {
        #ifdef INTERCEPT_WINDOWS
        // Windows file operations
        if (_access(cert_file, 0) == 0) {
            if (_unlink(cert_file) != 0) {
                // Log error but continue - file might be in use
                if (config.verbose) {
                    log_message("Warning: Could not delete existing certificate file");
                }
            }
        }
        if (_access(key_file, 0) == 0) {
            if (_unlink(key_file) != 0) {
                // Log error but continue - file might be in use
                if (config.verbose) {
                    log_message("Warning: Could not delete existing key file");
                }
            }
        }
        #else
        // Unix/Linux file operations
        if (access(cert_file, F_OK) == 0) {
            if (unlink(cert_file) != 0) {
                // Log error but continue - file might be in use
                if (config.verbose) {
                    log_message("Warning: Could not delete existing certificate file");
                }
            }
        }
        if (access(key_file, F_OK) == 0) {
            if (unlink(key_file) != 0) {
                // Log error but continue - file might be in use
                if (config.verbose) {
                    log_message("Warning: Could not delete existing key file");
                }
            }
        }
        #endif
    }

    // Step 4: Generate new CA certificate and key
    if (!generate_new_ca_cert()) {
        log_message("Failed to generate new CA certificate and key");
        return 0; // Failed to generate new certificate
    }

    // Step 5: Save new certificates to files
    if (!save_ca_cert_to_files()) {
        // Clean up on failure
        if (ca_cert) {
            X509_free(ca_cert);
            ca_cert = NULL;
        }
        if (ca_key) {
            EVP_PKEY_free(ca_key);
            ca_key = NULL;
        }
        log_message("Failed to save new CA certificate to files");
        return 0; // Failed to save certificates
    }

    return 1; // Success
}
