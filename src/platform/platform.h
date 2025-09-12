#ifndef PLATFORM_H
#define PLATFORM_H

/* Detect Windows if not explicitly defined */
#if !defined(INTERCEPT_WINDOWS) && (defined(_WIN32) || defined(_WIN64))
    #define INTERCEPT_WINDOWS
#endif

#ifdef INTERCEPT_WINDOWS
    /* Windows-specific includes */
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif

    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <process.h>
    #include <iphlpapi.h>
    typedef SOCKET socket_t;
    typedef CRITICAL_SECTION mutex_t;
    typedef BOOL intercept_bool_t;
    typedef HANDLE event_t;
    typedef HANDLE thread_t;
    typedef HANDLE THREAD_HANDLE;    typedef DWORD THREAD_RETURN_TYPE;
    #define THREAD_CALL WINAPI
    #define INVALID_THREAD_ID NULL
    #define SOCKET_ERROR_VAL INVALID_SOCKET
    #define SOCKET_OPTS_ERROR SOCKET_ERROR
    #define CLOSE_SOCKET(s) closesocket(s)
    #define INIT_MUTEX(m) InitializeCriticalSection(&(m))
    #define LOCK_MUTEX(m) EnterCriticalSection(&(m))
    #define UNLOCK_MUTEX(m) LeaveCriticalSection(&(m))
    #define DESTROY_MUTEX(m) DeleteCriticalSection(&(m))
    #define CREATE_EVENT() CreateEvent(NULL, TRUE, FALSE, NULL)
    #define SET_EVENT(e) SetEvent(e)
    #define WAIT_EVENT(e, timeout) WaitForSingleObject((e), (timeout))
    #define CLOSE_EVENT(e) CloseHandle(e)
    #define SLEEP_MS(ms) Sleep(ms)
    #define SLEEP(ms) Sleep(ms)
    #define THREAD_RETURN return 0
    #define CREATE_THREAD(id, func, arg) ((id = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL)) ? 0 : GetLastError())
    #define JOIN_THREAD(id) WaitForSingleObject(id, INFINITE)
    #define GET_SOCKET_ERROR() WSAGetLastError()
    #define GET_LAST_ERROR() GetLastError()

#else
    /* POSIX-specific includes */
    #include <unistd.h>
    #include <pthread.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>  /* For TCP_NODELAY */
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <errno.h>
    #include <signal.h>
    #include <sys/time.h>
    #include <time.h>
    #include <stdlib.h>
    #include <stdbool.h>
    typedef int socket_t;
    typedef pthread_mutex_t mutex_t;
    typedef int event_t;  /* Simplified event type for cross-platform compatibility */    typedef pthread_t thread_t;
    typedef pthread_t THREAD_HANDLE;
    typedef void* THREAD_RETURN_TYPE;
    typedef bool intercept_bool_t;
    #define THREAD_CALL
    #define INVALID_THREAD_ID ((pthread_t)0)
    #define SOCKET_ERROR_VAL (-1)
    #define SD_BOTH SHUT_RDWR
    #define SOCKET_OPTS_ERROR (-1)
    #define CLOSE_SOCKET(s) close(s)
    #define INIT_MUTEX(m) pthread_mutex_init(&(m), NULL)
    #define LOCK_MUTEX(m) pthread_mutex_lock(&(m))
    #define UNLOCK_MUTEX(m) pthread_mutex_unlock(&(m))
    #define DESTROY_MUTEX(m) pthread_mutex_destroy(&(m))
    #define CREATE_EVENT() 1  /* Simplified for cross-platform compatibility - returns valid event ID */
    #define SET_EVENT(e) do { /* No-op for simplified implementation */ } while(0)
    #define WAIT_EVENT(e, timeout_ms) 0  /* Simplified - returns success */
    #define CLOSE_EVENT(e) do { /* No-op for simplified implementation */ } while(0)
    #define SLEEP_MS(ms) usleep((ms) * 1000)
    #define THREAD_RETURN return NULL
    #define CREATE_THREAD(id, func, arg) pthread_create(&id, NULL, func, arg)
    #define JOIN_THREAD(id) pthread_join(id, NULL)
    #define SLEEP(ms) usleep((ms) * 1000)
    #define GET_SOCKET_ERROR() errno
    #define GET_LAST_ERROR() errno

    typedef int BOOL;
    #define TRUE 1
    #define FALSE 0
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR (-1)

#endif

/* Platform-independent function declarations */
#ifdef __cplusplus
extern "C" {
#endif

/* Cross-platform socket close function */
static inline int close_socket(socket_t sock) {
#ifdef INTERCEPT_WINDOWS
    return closesocket(sock);
#else
    return close(sock);
#endif
}

#ifdef __cplusplus
}
#endif

#ifndef __cdecl
    #define __cdecl
#endif

#endif // PLATFORM_H