/*
 * InterceptSuite Proxy - Certificate Export Module
 * Author - Sourav Kalal /AnoF-Cyber
 *
 * This file provides certificate and key export functionality,
 * allowing users to extract CA certificates and private keys.
 */

#ifndef CERT_EXPORT_H
#define CERT_EXPORT_H

#include "../proxy/tls_proxy.h"

/* Function prototypes for certificate export */
INTERCEPT_API intercept_bool_t export_certificate(const char* output_directory, int export_type);

#endif /* CERT_EXPORT_H */
