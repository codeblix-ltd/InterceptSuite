/*
 * InterceptSuite Proxy - Certificate Export Module
 * Author - Sourav Kalal /AnoF-Cyber
 *
 * This file provides certificate and key export functionality,
 * allowing users to extract CA certificates and private keys.
 */

#include "cert_export.h"
#include "cert_utils.h"
#include "../../utils/utils.h"

/* External references from main.c */
extern status_callback_t g_status_callback;

/* Export certificate function */
INTERCEPT_API intercept_bool_t export_certificate(const char* output_directory, int export_type) {
  if (!output_directory || strlen(output_directory) == 0) {
    if (g_status_callback) {
      log_message("ERROR: Invalid output directory");
    }
    return FALSE;
  }

  // Ensure certificates are loaded/generated
  if (!load_or_generate_ca_cert()) {
    if (g_status_callback) {
      log_message("ERROR: Failed to load or generate CA certificate");
    }
    return FALSE;
  }

  // Ensure output directory exists
  if (!ensure_directory_exists(output_directory)) {
    if (g_status_callback) {
      log_message("ERROR: Failed to create output directory");
    }
    return FALSE;
  }

  const char* source_cert_path = get_ca_cert_path();
  const char* source_key_path = get_ca_key_path();

  if (!source_cert_path || !source_key_path) {
    if (g_status_callback) {
      g_status_callback("ERROR: Failed to get certificate paths");
    }
    return FALSE;
  }

  char output_path[USER_DATA_MAX_PATH];
  int success = 0;

  if (export_type == 1) {
    // Export private key (PEM format - direct copy)
    snprintf(output_path, sizeof(output_path), "%s%sIntercept_Suite_key.key",
             output_directory,
#ifdef INTERCEPT_WINDOWS
             "\\"
#else
             "/"
#endif
    );

    // Read source key file
    long key_size = 0;
    char* key_data = read_file_to_memory(source_key_path, &key_size);
    if (!key_data) {
      if (g_status_callback) {
        g_status_callback("ERROR: Failed to read source key file");
      }
      return FALSE;
    }

    // Write to output location
    success = write_memory_to_file(output_path, key_data, (size_t)key_size);
    free(key_data);

    if (success && g_status_callback) {
      char message[512];
      snprintf(message, sizeof(message), "Private key exported to: %s", output_path);
      g_status_callback(message);
    }

  } else if (export_type == 0) {
    // Export certificate (convert PEM to DER)
    snprintf(output_path, sizeof(output_path), "%s%sIntercept_Suite_Cert.der",
             output_directory,
#ifdef INTERCEPT_WINDOWS
             "\\"
#else
             "/"
#endif
    );

    // Read source certificate file
    long cert_size = 0;
    char* cert_data = read_file_to_memory(source_cert_path, &cert_size);
    if (!cert_data) {
      if (g_status_callback) {
        g_status_callback("ERROR: Failed to read source certificate file");
      }
      return FALSE;
    }

    // Load certificate from PEM data
    BIO* cert_bio = BIO_new_mem_buf(cert_data, cert_size);
    X509* cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    BIO_free(cert_bio);
    free(cert_data);

    if (!cert) {
      if (g_status_callback) {
        g_status_callback("ERROR: Failed to parse certificate");
      }
      return FALSE;
    }

    // Convert to DER format
    BIO* der_bio = BIO_new(BIO_s_mem());
    if (!der_bio || i2d_X509_bio(der_bio, cert) != 1) {
      if (g_status_callback) {
        g_status_callback("ERROR: Failed to convert certificate to DER format");
      }
      X509_free(cert);
      if (der_bio) BIO_free(der_bio);
      return FALSE;
    }

    // Get DER data from BIO
    char* der_data;
    long der_size = BIO_get_mem_data(der_bio, &der_data);

    // Write DER data to output file
    success = write_memory_to_file(output_path, der_data, (size_t)der_size);

    BIO_free(der_bio);
    X509_free(cert);

    if (success && g_status_callback) {
      char message[512];
      snprintf(message, sizeof(message), "Certificate exported to: %s", output_path);
      g_status_callback(message);
    }

  } else {
    if (g_status_callback) {
      g_status_callback("ERROR: Invalid export type. Use 0 for certificate, 1 for private key");
    }
    return FALSE;
  }

  if (!success && g_status_callback) {
    g_status_callback("ERROR: Failed to write exported file");
  }

  return success ? TRUE : FALSE;
}
