#ifndef SSL_H
#define SSL_H

#include "net.h"

enum TlsVersion {
    TLS_AUTOMATIC = 0,
    TLS_1_1,
    TLS_1_2,
    TLS_1_3
};

SSL_CTX *ssl_init(enum TlsVersion tls_version);

status ssl_connect(connection *, char *);
status ssl_close(connection *);
status ssl_read(connection *, size_t *);
status ssl_write(connection *, char *, size_t, size_t *);
size_t ssl_readable(connection *);

#endif /* SSL_H */
