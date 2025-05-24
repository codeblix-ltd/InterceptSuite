/*
 * OpenSSL AppLink integration for Windows DLL
 * This file ensures that OpenSSL's file I/O operations work correctly
 * when OpenSSL is used from within a Windows DLL.
 * 
 * Based on OpenSSL documentation and Stack Overflow solution:
 * https://stackoverflow.com/questions/46637193/openssl-uplink-error-when-called-from-shared-library
 */

#ifdef _WIN32
#include <openssl/applink.c>

// Export the applink function to make it available to OpenSSL
__declspec(dllexport) void **OPENSSL_Applink(void);

// Force the applink function to be linked and available
void force_applink_linkage(void) {
    // This function ensures that OPENSSL_Applink is included in the DLL
    // even if the linker tries to optimize it out
    volatile void **table = OPENSSL_Applink();
    (void)table; // Suppress unused variable warning
}
#endif
