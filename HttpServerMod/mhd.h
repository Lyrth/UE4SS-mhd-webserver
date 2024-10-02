
// imported types

typedef unsigned long long UINT_PTR,*PUINT_PTR;
typedef UINT_PTR SOCKET;
typedef int socklen_t;
typedef unsigned int u_int;
typedef struct fd_set
{
 u_int fd_count;
 SOCKET fd_array[64];
} fd_set;
typedef long off32_t;
typedef off32_t off_t;



// generated with `gcc -P -D_WIN32=1 -DMHD_USE_THREADS -DMHD_PLATFORM_H=1 -E microhttpd.h | sed '/dc830e998579/,/dc830e99857a/d' >mhd.h`

enum MHD_Result
{
  MHD_NO = 0,
  MHD_YES = 1
} ;
typedef SOCKET MHD_socket;
extern const char *
MHD_get_reason_phrase_for (unsigned int code);
extern size_t
MHD_get_reason_phrase_len_for (unsigned int code);
struct MHD_Daemon;
struct MHD_Connection;
struct MHD_Response;
struct MHD_PostProcessor;
enum MHD_FLAG
{
  MHD_NO_FLAG = 0,
  MHD_USE_ERROR_LOG = 1,
  MHD_USE_DEBUG = 1,
  MHD_USE_TLS = 2,
  MHD_USE_SSL = 2,
  MHD_USE_THREAD_PER_CONNECTION = 4,
  MHD_USE_INTERNAL_POLLING_THREAD = 8,
  MHD_USE_SELECT_INTERNALLY = 8,
  MHD_USE_IPv6 = 16,
  MHD_USE_PEDANTIC_CHECKS = 32,
  MHD_USE_POLL = 64,
  MHD_USE_POLL_INTERNAL_THREAD = MHD_USE_POLL | MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_POLL_INTERNALLY = MHD_USE_POLL | MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_SUPPRESS_DATE_NO_CLOCK = 128,
  MHD_SUPPRESS_DATE_NO_CLOCK = 128,
  MHD_USE_NO_LISTEN_SOCKET = 256,
  MHD_USE_EPOLL = 512,
  MHD_USE_EPOLL_LINUX_ONLY = 512,
  MHD_USE_EPOLL_INTERNAL_THREAD = MHD_USE_EPOLL
                                  | MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_EPOLL_INTERNALLY = MHD_USE_EPOLL | MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_EPOLL_INTERNALLY_LINUX_ONLY = MHD_USE_EPOLL
                                        | MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_ITC = 1024,
  MHD_USE_PIPE_FOR_SHUTDOWN = 1024,
  MHD_USE_DUAL_STACK = MHD_USE_IPv6 | 2048,
  MHD_USE_TURBO = 4096,
  MHD_USE_EPOLL_TURBO = 4096,
  MHD_ALLOW_SUSPEND_RESUME = 8192 | MHD_USE_ITC,
  MHD_USE_SUSPEND_RESUME = 8192 | MHD_USE_ITC,
  MHD_USE_TCP_FASTOPEN = 16384,
  MHD_ALLOW_UPGRADE = 32768,
  MHD_USE_AUTO = 65536,
  MHD_USE_AUTO_INTERNAL_THREAD = MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_POST_HANDSHAKE_AUTH_SUPPORT = 1U << 17,
  MHD_USE_INSECURE_TLS_EARLY_DATA = 1U << 18,
  MHD_USE_NO_THREAD_SAFETY = 1U << 19
};
typedef void
(*MHD_LogCallback)(void *cls,
                   const char *fm,
                   va_list ap);
typedef int
(*MHD_PskServerCredentialsCallback)(void *cls,
                                    const struct MHD_Connection *connection,
                                    const char *username,
                                    void **psk,
                                    size_t *psk_size);
enum MHD_DAuthBindNonce
{
  MHD_DAUTH_BIND_NONCE_NONE = 0,
  MHD_DAUTH_BIND_NONCE_REALM = 1 << 0,
  MHD_DAUTH_BIND_NONCE_URI = 1 << 1,
  MHD_DAUTH_BIND_NONCE_URI_PARAMS = 1 << 2,
  MHD_DAUTH_BIND_NONCE_CLIENT_IP = 1 << 3
} ;
enum MHD_OPTION
{
  MHD_OPTION_END = 0,
  MHD_OPTION_CONNECTION_MEMORY_LIMIT = 1,
  MHD_OPTION_CONNECTION_LIMIT = 2,
  MHD_OPTION_CONNECTION_TIMEOUT = 3,
  MHD_OPTION_NOTIFY_COMPLETED = 4,
  MHD_OPTION_PER_IP_CONNECTION_LIMIT = 5,
  MHD_OPTION_SOCK_ADDR = 6,
  MHD_OPTION_URI_LOG_CALLBACK = 7,
  MHD_OPTION_HTTPS_MEM_KEY = 8,
  MHD_OPTION_HTTPS_MEM_CERT = 9,
  MHD_OPTION_HTTPS_CRED_TYPE = 10,
  MHD_OPTION_HTTPS_PRIORITIES = 11,
  MHD_OPTION_LISTEN_SOCKET = 12,
  MHD_OPTION_EXTERNAL_LOGGER = 13,
  MHD_OPTION_THREAD_POOL_SIZE = 14,
  MHD_OPTION_ARRAY = 15,
  MHD_OPTION_UNESCAPE_CALLBACK = 16,
  MHD_OPTION_DIGEST_AUTH_RANDOM = 17,
  MHD_OPTION_NONCE_NC_SIZE = 18,
  MHD_OPTION_THREAD_STACK_SIZE = 19,
  MHD_OPTION_HTTPS_MEM_TRUST = 20,
  MHD_OPTION_CONNECTION_MEMORY_INCREMENT = 21,
  MHD_OPTION_HTTPS_CERT_CALLBACK = 22,
  MHD_OPTION_TCP_FASTOPEN_QUEUE_SIZE = 23,
  MHD_OPTION_HTTPS_MEM_DHPARAMS = 24,
  MHD_OPTION_LISTENING_ADDRESS_REUSE = 25,
  MHD_OPTION_HTTPS_KEY_PASSWORD = 26,
  MHD_OPTION_NOTIFY_CONNECTION = 27,
  MHD_OPTION_LISTEN_BACKLOG_SIZE = 28,
  MHD_OPTION_STRICT_FOR_CLIENT = 29,
  MHD_OPTION_GNUTLS_PSK_CRED_HANDLER = 30,
  MHD_OPTION_HTTPS_CERT_CALLBACK2 = 31,
  MHD_OPTION_SERVER_INSANITY = 32,
  MHD_OPTION_SIGPIPE_HANDLED_BY_APP = 33,
  MHD_OPTION_TLS_NO_ALPN = 34,
  MHD_OPTION_DIGEST_AUTH_RANDOM_COPY = 35,
  MHD_OPTION_DIGEST_AUTH_NONCE_BIND_TYPE = 36,
  MHD_OPTION_HTTPS_PRIORITIES_APPEND = 37,
  MHD_OPTION_CLIENT_DISCIPLINE_LVL = 38,
  MHD_OPTION_APP_FD_SETSIZE = 39,
  MHD_OPTION_SOCK_ADDR_LEN = 40
  ,
  MHD_OPTION_DIGEST_AUTH_DEFAULT_NONCE_TIMEOUT = 41
  ,
  MHD_OPTION_DIGEST_AUTH_DEFAULT_MAX_NC = 42
} ;
enum MHD_DisableSanityCheck
{
  MHD_DSC_SANE = 0
} ;
struct MHD_OptionItem
{
  enum MHD_OPTION option;
  intptr_t value;
  void *ptr_value;
};
enum MHD_ValueKind
{
  MHD_RESPONSE_HEADER_KIND = 0,
  MHD_HEADER_KIND = 1,
  MHD_COOKIE_KIND = 2,
  MHD_POSTDATA_KIND = 4,
  MHD_GET_ARGUMENT_KIND = 8,
  MHD_FOOTER_KIND = 16
} ;
enum MHD_RequestTerminationCode
{
  MHD_REQUEST_TERMINATED_COMPLETED_OK = 0,
  MHD_REQUEST_TERMINATED_WITH_ERROR = 1,
  MHD_REQUEST_TERMINATED_TIMEOUT_REACHED = 2,
  MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN = 3,
  MHD_REQUEST_TERMINATED_READ_ERROR = 4,
  MHD_REQUEST_TERMINATED_CLIENT_ABORT = 5
} ;
enum MHD_ConnectionNotificationCode
{
  MHD_CONNECTION_NOTIFY_STARTED = 0,
  MHD_CONNECTION_NOTIFY_CLOSED = 1
} ;
union MHD_ConnectionInfo
{
  int cipher_algorithm;
  int protocol;
  int suspended;
  unsigned int connection_timeout;
  unsigned int http_status;
  MHD_socket connect_fd;
  size_t header_size;
  void * tls_session;
  void * client_cert;
  struct sockaddr *client_addr;
  struct MHD_Daemon *daemon;
  void *socket_context;
};
struct MHD_IoVec
{
  const void *iov_base;
  size_t iov_len;
};
enum MHD_ConnectionInfoType
{
  MHD_CONNECTION_INFO_CIPHER_ALGO,
  MHD_CONNECTION_INFO_PROTOCOL,
  MHD_CONNECTION_INFO_CLIENT_ADDRESS,
  MHD_CONNECTION_INFO_GNUTLS_SESSION,
  MHD_CONNECTION_INFO_GNUTLS_CLIENT_CERT,
  MHD_CONNECTION_INFO_DAEMON,
  MHD_CONNECTION_INFO_CONNECTION_FD,
  MHD_CONNECTION_INFO_SOCKET_CONTEXT,
  MHD_CONNECTION_INFO_CONNECTION_SUSPENDED,
  MHD_CONNECTION_INFO_CONNECTION_TIMEOUT,
  MHD_CONNECTION_INFO_REQUEST_HEADER_SIZE,
  MHD_CONNECTION_INFO_HTTP_STATUS
} ;
enum MHD_DaemonInfoType
{
  MHD_DAEMON_INFO_KEY_SIZE,
  MHD_DAEMON_INFO_MAC_KEY_SIZE,
  MHD_DAEMON_INFO_LISTEN_FD,
  MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY,
  MHD_DAEMON_INFO_EPOLL_FD = MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY,
  MHD_DAEMON_INFO_CURRENT_CONNECTIONS,
  MHD_DAEMON_INFO_FLAGS,
  MHD_DAEMON_INFO_BIND_PORT
} ;
typedef void
(*MHD_PanicCallback) (void *cls,
                      const char *file,
                      unsigned int line,
                      const char *reason);
typedef enum MHD_Result
(*MHD_AcceptPolicyCallback)(void *cls,
                            const struct sockaddr *addr,
                            socklen_t addrlen);
typedef enum MHD_Result
(*MHD_AccessHandlerCallback)(void *cls,
                             struct MHD_Connection *connection,
                             const char *url,
                             const char *method,
                             const char *version,
                             const char *upload_data,
                             size_t *upload_data_size,
                             void **req_cls);
typedef void
(*MHD_RequestCompletedCallback) (void *cls,
                                 struct MHD_Connection *connection,
                                 void **req_cls,
                                 enum MHD_RequestTerminationCode toe);
typedef void
(*MHD_NotifyConnectionCallback) (void *cls,
                                 struct MHD_Connection *connection,
                                 void **socket_context,
                                 enum MHD_ConnectionNotificationCode toe);
typedef enum MHD_Result
(*MHD_KeyValueIterator)(void *cls,
                        enum MHD_ValueKind kind,
                        const char *key,
                        const char *value);
typedef enum MHD_Result
(*MHD_KeyValueIteratorN)(void *cls,
                         enum MHD_ValueKind kind,
                         const char *key,
                         size_t key_size,
                         const char *value,
                         size_t value_size);
typedef ssize_t
(*MHD_ContentReaderCallback) (void *cls,
                              uint64_t pos,
                              char *buf,
                              size_t max);
typedef void
(*MHD_ContentReaderFreeCallback) (void *cls);
typedef enum MHD_Result
(*MHD_PostDataIterator)(void *cls,
                        enum MHD_ValueKind kind,
                        const char *key,
                        const char *filename,
                        const char *content_type,
                        const char *transfer_encoding,
                        const char *data,
                        uint64_t off,
                        size_t size);
extern struct MHD_Daemon *
MHD_start_daemon_va (unsigned int flags,
                     uint16_t port,
                     MHD_AcceptPolicyCallback apc, void *apc_cls,
                     MHD_AccessHandlerCallback dh, void *dh_cls,
                     va_list ap);
extern struct MHD_Daemon *
MHD_start_daemon (unsigned int flags,
                  uint16_t port,
                  MHD_AcceptPolicyCallback apc, void *apc_cls,
                  MHD_AccessHandlerCallback dh, void *dh_cls,
                  ...);
extern MHD_socket
MHD_quiesce_daemon (struct MHD_Daemon *daemon);
extern void
MHD_stop_daemon (struct MHD_Daemon *daemon);
extern enum MHD_Result
MHD_add_connection (struct MHD_Daemon *daemon,
                    MHD_socket client_socket,
                    const struct sockaddr *addr,
                    socklen_t addrlen);
extern enum MHD_Result
MHD_get_fdset (struct MHD_Daemon *daemon,
               fd_set *read_fd_set,
               fd_set *write_fd_set,
               fd_set *except_fd_set,
               MHD_socket *max_fd);
extern enum MHD_Result
MHD_get_fdset2 (struct MHD_Daemon *daemon,
                fd_set *read_fd_set,
                fd_set *write_fd_set,
                fd_set *except_fd_set,
                MHD_socket *max_fd,
                unsigned int fd_setsize);
extern enum MHD_Result
MHD_get_timeout (struct MHD_Daemon *daemon,
                 unsigned long long *timeout);
extern void
MHD_free (void *ptr);
extern enum MHD_Result
MHD_get_timeout64 (struct MHD_Daemon *daemon,
                   uint64_t *timeout);
extern int64_t
MHD_get_timeout64s (struct MHD_Daemon *daemon);
extern int
MHD_get_timeout_i (struct MHD_Daemon *daemon);
extern enum MHD_Result
MHD_run (struct MHD_Daemon *daemon);
extern enum MHD_Result
MHD_run_wait (struct MHD_Daemon *daemon,
              int32_t millisec);
extern enum MHD_Result
MHD_run_from_select (struct MHD_Daemon *daemon,
                     const fd_set *read_fd_set,
                     const fd_set *write_fd_set,
                     const fd_set *except_fd_set);
extern enum MHD_Result
MHD_run_from_select2 (struct MHD_Daemon *daemon,
                      const fd_set *read_fd_set,
                      const fd_set *write_fd_set,
                      const fd_set *except_fd_set,
                      unsigned int fd_setsize);
extern int
MHD_get_connection_values (struct MHD_Connection *connection,
                           enum MHD_ValueKind kind,
                           MHD_KeyValueIterator iterator,
                           void *iterator_cls);
extern int
MHD_get_connection_values_n (struct MHD_Connection *connection,
                             enum MHD_ValueKind kind,
                             MHD_KeyValueIteratorN iterator,
                             void *iterator_cls);
extern enum MHD_Result
MHD_set_connection_value (struct MHD_Connection *connection,
                          enum MHD_ValueKind kind,
                          const char *key,
                          const char *value);
extern enum MHD_Result
MHD_set_connection_value_n (struct MHD_Connection *connection,
                            enum MHD_ValueKind kind,
                            const char *key,
                            size_t key_size,
                            const char *value,
                            size_t value_size);
extern void
MHD_set_panic_func (MHD_PanicCallback cb, void *cls);
extern size_t
MHD_http_unescape (char *val);
extern const char *
MHD_lookup_connection_value (struct MHD_Connection *connection,
                             enum MHD_ValueKind kind,
                             const char *key);
extern enum MHD_Result
MHD_lookup_connection_value_n (struct MHD_Connection *connection,
                               enum MHD_ValueKind kind,
                               const char *key,
                               size_t key_size,
                               const char **value_ptr,
                               size_t *value_size_ptr);
extern enum MHD_Result
MHD_queue_response (struct MHD_Connection *connection,
                    unsigned int status_code,
                    struct MHD_Response *response);
extern void
MHD_suspend_connection (struct MHD_Connection *connection);
extern void
MHD_resume_connection (struct MHD_Connection *connection);
enum MHD_ResponseFlags
{
  MHD_RF_NONE = 0,
  MHD_RF_HTTP_1_0_COMPATIBLE_STRICT = 1 << 0,
  MHD_RF_HTTP_VERSION_1_0_ONLY = 1 << 0,
  MHD_RF_HTTP_1_0_SERVER = 1 << 1,
  MHD_RF_HTTP_VERSION_1_0_RESPONSE = 1 << 1,
  MHD_RF_INSANITY_HEADER_CONTENT_LENGTH = 1 << 2,
  MHD_RF_SEND_KEEP_ALIVE_HEADER = 1 << 3,
  MHD_RF_HEAD_ONLY_RESPONSE = 1 << 4
} ;
enum MHD_ResponseOptions
{
  MHD_RO_END = 0
} ;
extern enum MHD_Result
MHD_set_response_options (struct MHD_Response *response,
                          enum MHD_ResponseFlags flags,
                          ...);
extern struct MHD_Response *
MHD_create_response_from_callback (uint64_t size,
                                   size_t block_size,
                                   MHD_ContentReaderCallback crc, void *crc_cls,
                                   MHD_ContentReaderFreeCallback crfc);
__attribute__((deprecated ("MHD_create_response_from_data() is deprecated, " "use MHD_create_response_from_buffer()"))) extern struct MHD_Response *
MHD_create_response_from_data (size_t size,
                               void *data,
                               int must_free,
                               int must_copy);
enum MHD_ResponseMemoryMode
{
  MHD_RESPMEM_PERSISTENT,
  MHD_RESPMEM_MUST_FREE,
  MHD_RESPMEM_MUST_COPY
} ;
extern struct MHD_Response *
MHD_create_response_from_buffer (size_t size,
                                 void *buffer,
                                 enum MHD_ResponseMemoryMode mode);
extern struct MHD_Response *
MHD_create_response_from_buffer_static (size_t size,
                                        const void *buffer);
extern struct MHD_Response *
MHD_create_response_from_buffer_copy (size_t size,
                                      const void *buffer);
extern struct MHD_Response *
MHD_create_response_from_buffer_with_free_callback (size_t size,
                                                    void *buffer,
                                                    MHD_ContentReaderFreeCallback
                                                    crfc);
extern struct MHD_Response *
MHD_create_response_from_buffer_with_free_callback_cls (size_t size,
                                                        const void *buffer,
                                                        MHD_ContentReaderFreeCallback
                                                        crfc,
                                                        void *crfc_cls);
extern struct MHD_Response *
MHD_create_response_from_fd (size_t size,
                             int fd);
extern struct MHD_Response *
MHD_create_response_from_pipe (int fd);
extern struct MHD_Response *
MHD_create_response_from_fd64 (uint64_t size,
                               int fd);
__attribute__((deprecated ("Function MHD_create_response_from_fd_at_offset() is " "deprecated, use MHD_create_response_from_fd_at_offset64()"))) extern struct MHD_Response *
MHD_create_response_from_fd_at_offset (size_t size,
                                       int fd,
                                       off_t offset);
extern struct MHD_Response *
MHD_create_response_from_fd_at_offset64 (uint64_t size,
                                         int fd,
                                         uint64_t offset);
extern struct MHD_Response *
MHD_create_response_from_iovec (const struct MHD_IoVec *iov,
                                unsigned int iovcnt,
                                MHD_ContentReaderFreeCallback free_cb,
                                void *cls);
extern struct MHD_Response *
MHD_create_response_empty (enum MHD_ResponseFlags flags);
enum MHD_UpgradeAction
{
  MHD_UPGRADE_ACTION_CLOSE = 0,
  MHD_UPGRADE_ACTION_CORK_ON = 1,
  MHD_UPGRADE_ACTION_CORK_OFF = 2
} ;
struct MHD_UpgradeResponseHandle;
extern enum MHD_Result
MHD_upgrade_action (struct MHD_UpgradeResponseHandle *urh,
                    enum MHD_UpgradeAction action,
                    ...);
typedef void
(*MHD_UpgradeHandler)(void *cls,
                      struct MHD_Connection *connection,
                      void *req_cls,
                      const char *extra_in,
                      size_t extra_in_size,
                      MHD_socket sock,
                      struct MHD_UpgradeResponseHandle *urh);
extern struct MHD_Response *
MHD_create_response_for_upgrade (MHD_UpgradeHandler upgrade_handler,
                                 void *upgrade_handler_cls);
extern void
MHD_destroy_response (struct MHD_Response *response);
extern enum MHD_Result
MHD_add_response_header (struct MHD_Response *response,
                         const char *header,
                         const char *content);
extern enum MHD_Result
MHD_add_response_footer (struct MHD_Response *response,
                         const char *footer,
                         const char *content);
extern enum MHD_Result
MHD_del_response_header (struct MHD_Response *response,
                         const char *header,
                         const char *content);
extern int
MHD_get_response_headers (struct MHD_Response *response,
                          MHD_KeyValueIterator iterator,
                          void *iterator_cls);
extern const char *
MHD_get_response_header (struct MHD_Response *response,
                         const char *key);
extern struct MHD_PostProcessor *
MHD_create_post_processor (struct MHD_Connection *connection,
                           size_t buffer_size,
                           MHD_PostDataIterator iter, void *iter_cls);
extern enum MHD_Result
MHD_post_process (struct MHD_PostProcessor *pp,
                  const char *post_data,
                  size_t post_data_len);
extern enum MHD_Result
MHD_destroy_post_processor (struct MHD_PostProcessor *pp);
enum MHD_DigestBaseAlgo
{
  MHD_DIGEST_BASE_ALGO_INVALID = 0,
  MHD_DIGEST_BASE_ALGO_MD5 = (1 << 0),
  MHD_DIGEST_BASE_ALGO_SHA256 = (1 << 1),
  MHD_DIGEST_BASE_ALGO_SHA512_256 = (1 << 2)
} ;
enum MHD_DigestAuthAlgo3
{
  MHD_DIGEST_AUTH_ALGO3_INVALID = 0,
  MHD_DIGEST_AUTH_ALGO3_MD5 =
    MHD_DIGEST_BASE_ALGO_MD5 | (1 << 6),
  MHD_DIGEST_AUTH_ALGO3_MD5_SESSION =
    MHD_DIGEST_BASE_ALGO_MD5 | (1 << 7),
  MHD_DIGEST_AUTH_ALGO3_SHA256 =
    MHD_DIGEST_BASE_ALGO_SHA256 | (1 << 6),
  MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION =
    MHD_DIGEST_BASE_ALGO_SHA256 | (1 << 7),
  MHD_DIGEST_AUTH_ALGO3_SHA512_256 =
    MHD_DIGEST_BASE_ALGO_SHA512_256 | (1 << 6),
  MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION =
    MHD_DIGEST_BASE_ALGO_SHA512_256 | (1 << 7)
};
extern size_t
MHD_digest_get_hash_size (enum MHD_DigestAuthAlgo3 algo3);
enum MHD_DigestAuthMultiAlgo3
{
  MHD_DIGEST_AUTH_MULT_ALGO3_INVALID = MHD_DIGEST_AUTH_ALGO3_INVALID,
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5 = MHD_DIGEST_AUTH_ALGO3_MD5,
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5_SESSION = MHD_DIGEST_AUTH_ALGO3_MD5_SESSION,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256 = MHD_DIGEST_AUTH_ALGO3_SHA256,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256 = MHD_DIGEST_AUTH_ALGO3_SHA512_256,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_NON_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA256 | MHD_DIGEST_AUTH_ALGO3_SHA512_256,
  MHD_DIGEST_AUTH_MULT_ALGO3_ANY_NON_SESSION =
    (0x3F) | (1 << 6),
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_SESSION =
    MHD_DIGEST_AUTH_ALGO3_SHA256_SESSION
    | MHD_DIGEST_AUTH_ALGO3_SHA512_256_SESSION,
  MHD_DIGEST_AUTH_MULT_ALGO3_ANY_SESSION =
    (0x3F) | (1 << 7),
  MHD_DIGEST_AUTH_MULT_ALGO3_MD5_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_MD5 | MHD_DIGEST_AUTH_MULT_ALGO3_MD5_SESSION,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_SHA256
    | MHD_DIGEST_AUTH_MULT_ALGO3_SHA256_SESSION,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256
    | MHD_DIGEST_AUTH_MULT_ALGO3_SHA512_256_SESSION,
  MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_ANY =
    MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_NON_SESSION
    | MHD_DIGEST_AUTH_MULT_ALGO3_SHA_ANY_SESSION,
  MHD_DIGEST_AUTH_MULT_ALGO3_ANY =
    (0x3F) | (1 << 6) | (1 << 7)
};
extern enum MHD_Result
MHD_digest_auth_calc_userhash (enum MHD_DigestAuthAlgo3 algo3,
                               const char *username,
                               const char *realm,
                               void *userhash_bin,
                               size_t bin_buf_size);
extern enum MHD_Result
MHD_digest_auth_calc_userhash_hex (enum MHD_DigestAuthAlgo3 algo3,
                                   const char *username,
                                   const char *realm,
                                   char *userhash_hex,
                                   size_t hex_buf_size);
enum MHD_DigestAuthUsernameType
{
  MHD_DIGEST_AUTH_UNAME_TYPE_MISSING = 0,
  MHD_DIGEST_AUTH_UNAME_TYPE_STANDARD = (1 << 2),
  MHD_DIGEST_AUTH_UNAME_TYPE_EXTENDED = (1 << 3),
  MHD_DIGEST_AUTH_UNAME_TYPE_USERHASH = (1 << 1),
  MHD_DIGEST_AUTH_UNAME_TYPE_INVALID = (1 << 0)
} ;
enum MHD_DigestAuthQOP
{
  MHD_DIGEST_AUTH_QOP_INVALID = 0,
  MHD_DIGEST_AUTH_QOP_NONE = 1 << 0,
  MHD_DIGEST_AUTH_QOP_AUTH = 1 << 1,
  MHD_DIGEST_AUTH_QOP_AUTH_INT = 1 << 2
} ;
enum MHD_DigestAuthMultiQOP
{
  MHD_DIGEST_AUTH_MULT_QOP_INVALID = MHD_DIGEST_AUTH_QOP_INVALID,
  MHD_DIGEST_AUTH_MULT_QOP_NONE = MHD_DIGEST_AUTH_QOP_NONE,
  MHD_DIGEST_AUTH_MULT_QOP_AUTH = MHD_DIGEST_AUTH_QOP_AUTH,
  MHD_DIGEST_AUTH_MULT_QOP_AUTH_INT = MHD_DIGEST_AUTH_QOP_AUTH_INT,
  MHD_DIGEST_AUTH_MULT_QOP_ANY_NON_INT =
    MHD_DIGEST_AUTH_QOP_NONE | MHD_DIGEST_AUTH_QOP_AUTH,
  MHD_DIGEST_AUTH_MULT_QOP_AUTH_ANY =
    MHD_DIGEST_AUTH_QOP_AUTH | MHD_DIGEST_AUTH_QOP_AUTH_INT
} ;
struct MHD_DigestAuthInfo
{
  enum MHD_DigestAuthAlgo3 algo3;
  enum MHD_DigestAuthUsernameType uname_type;
  char *username;
  size_t username_len;
  char *userhash_hex;
  size_t userhash_hex_len;
  uint8_t *userhash_bin;
  char *opaque;
  size_t opaque_len;
  char *realm;
  size_t realm_len;
  enum MHD_DigestAuthQOP qop;
  size_t cnonce_len;
  uint32_t nc;
};
extern struct MHD_DigestAuthInfo *
MHD_digest_auth_get_request_info3 (struct MHD_Connection *connection);
struct MHD_DigestAuthUsernameInfo
{
  enum MHD_DigestAuthAlgo3 algo3;
  enum MHD_DigestAuthUsernameType uname_type;
  char *username;
  size_t username_len;
  char *userhash_hex;
  size_t userhash_hex_len;
  uint8_t *userhash_bin;
};
extern struct MHD_DigestAuthUsernameInfo *
MHD_digest_auth_get_username3 (struct MHD_Connection *connection);
enum MHD_DigestAuthResult
{
  MHD_DAUTH_OK = 1,
  MHD_DAUTH_ERROR = 0,
  MHD_DAUTH_WRONG_HEADER = -1,
  MHD_DAUTH_WRONG_USERNAME = -2,
  MHD_DAUTH_WRONG_REALM = -3,
  MHD_DAUTH_WRONG_URI = -4,
  MHD_DAUTH_WRONG_QOP = -5,
  MHD_DAUTH_WRONG_ALGO = -6,
  MHD_DAUTH_TOO_LARGE = -15,
  MHD_DAUTH_NONCE_STALE = -17,
  MHD_DAUTH_NONCE_OTHER_COND = -18,
  MHD_DAUTH_NONCE_WRONG = -33,
  MHD_DAUTH_RESPONSE_WRONG = -34
};
extern enum MHD_DigestAuthResult
MHD_digest_auth_check3 (struct MHD_Connection *connection,
                        const char *realm,
                        const char *username,
                        const char *password,
                        unsigned int nonce_timeout,
                        uint32_t max_nc,
                        enum MHD_DigestAuthMultiQOP mqop,
                        enum MHD_DigestAuthMultiAlgo3 malgo3);
extern enum MHD_Result
MHD_digest_auth_calc_userdigest (enum MHD_DigestAuthAlgo3 algo3,
                                 const char *username,
                                 const char *realm,
                                 const char *password,
                                 void *userdigest_bin,
                                 size_t bin_buf_size);
extern enum MHD_DigestAuthResult
MHD_digest_auth_check_digest3 (struct MHD_Connection *connection,
                               const char *realm,
                               const char *username,
                               const void *userdigest,
                               size_t userdigest_size,
                               unsigned int nonce_timeout,
                               uint32_t max_nc,
                               enum MHD_DigestAuthMultiQOP mqop,
                               enum MHD_DigestAuthMultiAlgo3 malgo3);
extern enum MHD_Result
MHD_queue_auth_required_response3 (struct MHD_Connection *connection,
                                   const char *realm,
                                   const char *opaque,
                                   const char *domain,
                                   struct MHD_Response *response,
                                   int signal_stale,
                                   enum MHD_DigestAuthMultiQOP mqop,
                                   enum MHD_DigestAuthMultiAlgo3 algo,
                                   int userhash_support,
                                   int prefer_utf8);
extern char *
MHD_digest_auth_get_username (struct MHD_Connection *connection);
enum MHD_DigestAuthAlgorithm
{
  MHD_DIGEST_ALG_AUTO = 0,
  MHD_DIGEST_ALG_MD5,
  MHD_DIGEST_ALG_SHA256
} ;
extern int
MHD_digest_auth_check2 (struct MHD_Connection *connection,
                        const char *realm,
                        const char *username,
                        const char *password,
                        unsigned int nonce_timeout,
                        enum MHD_DigestAuthAlgorithm algo);
extern int
MHD_digest_auth_check (struct MHD_Connection *connection,
                       const char *realm,
                       const char *username,
                       const char *password,
                       unsigned int nonce_timeout);
extern int
MHD_digest_auth_check_digest2 (struct MHD_Connection *connection,
                               const char *realm,
                               const char *username,
                               const uint8_t *digest,
                               size_t digest_size,
                               unsigned int nonce_timeout,
                               enum MHD_DigestAuthAlgorithm algo);
extern int
MHD_digest_auth_check_digest (struct MHD_Connection *connection,
                              const char *realm,
                              const char *username,
                              const uint8_t digest[16],
                              unsigned int nonce_timeout);
extern enum MHD_Result
MHD_queue_auth_fail_response2 (struct MHD_Connection *connection,
                               const char *realm,
                               const char *opaque,
                               struct MHD_Response *response,
                               int signal_stale,
                               enum MHD_DigestAuthAlgorithm algo);
extern enum MHD_Result
MHD_queue_auth_fail_response (struct MHD_Connection *connection,
                              const char *realm,
                              const char *opaque,
                              struct MHD_Response *response,
                              int signal_stale);
struct MHD_BasicAuthInfo
{
  char *username;
  size_t username_len;
  char *password;
  size_t password_len;
};
extern struct MHD_BasicAuthInfo *
MHD_basic_auth_get_username_password3 (struct MHD_Connection *connection);
extern enum MHD_Result
MHD_queue_basic_auth_required_response3 (struct MHD_Connection *connection,
                                         const char *realm,
                                         int prefer_utf8,
                                         struct MHD_Response *response);
extern char *
MHD_basic_auth_get_username_password (struct MHD_Connection *connection,
                                      char **password);
extern enum MHD_Result
MHD_queue_basic_auth_fail_response (struct MHD_Connection *connection,
                                    const char *realm,
                                    struct MHD_Response *response);
extern const union MHD_ConnectionInfo *
MHD_get_connection_info (struct MHD_Connection *connection,
                         enum MHD_ConnectionInfoType info_type,
                         ...);
enum MHD_CONNECTION_OPTION
{
  MHD_CONNECTION_OPTION_TIMEOUT
} ;
extern enum MHD_Result
MHD_set_connection_option (struct MHD_Connection *connection,
                           enum MHD_CONNECTION_OPTION option,
                           ...);
union MHD_DaemonInfo
{
  size_t key_size;
  size_t mac_key_size;
  MHD_socket listen_fd;
  uint16_t port;
  int epoll_fd;
  unsigned int num_connections;
  enum MHD_FLAG flags;
};
extern const union MHD_DaemonInfo *
MHD_get_daemon_info (struct MHD_Daemon *daemon,
                     enum MHD_DaemonInfoType info_type,
                     ...);
extern const char *
MHD_get_version (void);
extern uint32_t
MHD_get_version_bin (void);
enum MHD_FEATURE
{
  MHD_FEATURE_MESSAGES = 1,
  MHD_FEATURE_TLS = 2,
  MHD_FEATURE_SSL = 2,
  MHD_FEATURE_HTTPS_CERT_CALLBACK = 3,
  MHD_FEATURE_IPv6 = 4,
  MHD_FEATURE_IPv6_ONLY = 5,
  MHD_FEATURE_POLL = 6,
  MHD_FEATURE_EPOLL = 7,
  MHD_FEATURE_SHUTDOWN_LISTEN_SOCKET = 8,
  MHD_FEATURE_SOCKETPAIR = 9,
  MHD_FEATURE_TCP_FASTOPEN = 10,
  MHD_FEATURE_BASIC_AUTH = 11,
  MHD_FEATURE_DIGEST_AUTH = 12,
  MHD_FEATURE_POSTPROCESSOR = 13,
  MHD_FEATURE_HTTPS_KEY_PASSWORD = 14,
  MHD_FEATURE_LARGE_FILE = 15,
  MHD_FEATURE_THREAD_NAMES = 16,
  MHD_THREAD_NAMES = 16,
  MHD_FEATURE_UPGRADE = 17,
  MHD_FEATURE_RESPONSES_SHARED_FD = 18,
  MHD_FEATURE_AUTODETECT_BIND_PORT = 19,
  MHD_FEATURE_AUTOSUPPRESS_SIGPIPE = 20,
  MHD_FEATURE_SENDFILE = 21,
  MHD_FEATURE_THREADS = 22,
  MHD_FEATURE_HTTPS_CERT_CALLBACK2 = 23,
  MHD_FEATURE_HTTPS_COOKIE_PARSING = 24,
  MHD_FEATURE_DIGEST_AUTH_RFC2069 = 25,
  MHD_FEATURE_DIGEST_AUTH_MD5 = 26,
  MHD_FEATURE_DIGEST_AUTH_SHA256 = 27,
  MHD_FEATURE_DIGEST_AUTH_SHA512_256 = 28,
  MHD_FEATURE_DIGEST_AUTH_AUTH_INT = 29,
  MHD_FEATURE_DIGEST_AUTH_ALGO_SESSION = 30,
  MHD_FEATURE_DIGEST_AUTH_USERHASH = 31,
  MHD_FEATURE_EXTERN_HASH = 32,
  MHD_FEATURE_DEBUG_BUILD = 33,
  MHD_FEATURE_FLEXIBLE_FD_SETSIZE = 34
};
extern enum MHD_Result
MHD_is_feature_supported (enum MHD_FEATURE feature);
