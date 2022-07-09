/* ------------------------------------------------------------------
 * SocksHub - Proxy Task Source Code
 * ------------------------------------------------------------------ */

#include "sockshub.h"

/**
 * Estabilish connection with endpoint
 */
static int setup_endpoint_stream ( struct proxy_t *proxy, struct stream_t *stream,
    const struct sockaddr_storage *saddr )
{
    int sock;
    struct stream_t *neighbour;

    /* Connect remote endpoint asynchronously */
    if ( ( sock = connect_async ( proxy, saddr ) ) < 0 )
    {
        return sock;
    }

    /* Try allocating neighbour stream */
    if ( !( neighbour = insert_stream ( proxy, sock ) ) )
    {
        force_cleanup ( proxy, stream );
        neighbour = insert_stream ( proxy, sock );
    }

    /* Check for neighbour stream */
    if ( !neighbour )
    {
        shutdown_then_close ( proxy, sock );
        return -2;
    }

    /* Set neighbour role */
    neighbour->role = S_PORT_B;
    neighbour->level = LEVEL_CONNECTING;
    neighbour->events = POLLIN | POLLOUT;

    /* Build up a new relation */
    neighbour->neighbour = stream;
    stream->neighbour = neighbour;

    return 0;
}

/**
 * Handle new stream creation
 */
static int handle_new_stream ( struct proxy_t *proxy, struct stream_t *stream )
{
    struct stream_t *util;

    if ( ~stream->revents & POLLIN )
    {
        return -1;
    }

    /* Accept incoming connection */
    if ( !( util = accept_new_stream ( proxy, stream->fd ) ) )
    {
        return -2;
    }

    /* Setup new stream */
    util->role = S_PORT_A;
    util->level = LEVEL_SOCKS_VER;
    util->events = POLLIN;

    return 0;
}

/**
 * Handle stream A socks handshake and request
 */
static int handle_stream_socks_a ( struct proxy_t *proxy, struct stream_t *stream )
{
    int status;
    uint16_t port;
    size_t len;
    size_t hostlen;
    char straddr[STRADDR_SIZE];
    char straddr0[STRADDR_SIZE];
    char straddr1[STRADDR_SIZE];
    char hostname[256];
    uint8_t arr[DATA_QUEUE_CAPACITY];
    struct socks_server_t *server = NULL;

    /* Expect socket ready to be read */
    if ( ~stream->revents & POLLIN )
    {
        return -1;
    }

    /* Receive data chunk */
    if ( ( ssize_t ) ( len = recv ( stream->fd, arr, sizeof ( arr ), 0 ) ) < 2 )
    {
        failure ( "cannot receive data (%i) from socket:%i:\n", errno, stream->fd );
        return -1;
    }

    /* Print progress */
    verbose ( "received %i byte(s) in handshake from socket:%i\n", ( int ) len, stream->fd );

    /* Enqueue input data */
    if ( queue_push ( &stream->queue, arr, len ) < 0 )
    {
        return -1;
    }

    /* Choose the action */
    switch ( stream->level )
    {
    case LEVEL_SOCKS_VER:
        /* Print current stage */
        verbose ( "processing socks SERVER/VERSION stage on socket:%i...\n", stream->fd );

        /* Assert minimum data length */
        if ( check_enough_data ( proxy, stream, 1 ) < 0 )
        {
            return 0;
        }

        /* Check for SOCKS5 version */
        if ( stream->queue.arr[0] != 5 )
        {
            failure ( "invalid socks version (0x%.2x) from socket:%i\n", stream->queue.arr[0],
                stream->fd );
            return -1;
        }

        /* User - pass auth or no auth */
        if ( len > 2 && stream->queue.arr[1] == 1 && stream->queue.arr[2] == 2 )
        {
            arr[0] = 5; /* SOCKS5 version */
            arr[1] = 2; /* User - pass auth */
            stream->level = LEVEL_SOCKS_AUTH;

        } else
        {
            arr[0] = 5; /* SOCKS5 version */
            arr[1] = 0; /* No auth */
            stream->level = LEVEL_SOCKS_REQ;
        }

        /* Enqueue response */
        if ( queue_set ( &stream->queue, arr, 2 ) < 0 )
        {
            return -1;
        }

        /* Update levels and events flags */
        stream->events = POLLOUT;
        break;
    case LEVEL_SOCKS_AUTH:
        /* Print current stage */
        verbose ( "processing socks SERVER/AUTH stage on socket:%i...\n", stream->fd );

        /* Auth passed no matter what credentials */
        arr[0] = 5;     /* SOCKS5 version */
        arr[1] = 0;     /* Auth success */

        /* Enqueue response */
        if ( queue_set ( &stream->queue, arr, 2 ) < 0 )
        {
            return -1;
        }

        /* Update levels and events flags */
        stream->level = LEVEL_SOCKS_REQ;
        stream->events = POLLOUT;
        break;
    case LEVEL_SOCKS_REQ:
        /* Print current stage */
        verbose ( "processing socks SERVER/REQUEST stage on socket:%i...\n", stream->fd );

        /* Assert minimum data length */
        if ( check_enough_data ( proxy, stream, 4 ) < 0 )
        {
            return 0;
        }

        /* Expect SOCKS5 version */
        if ( stream->queue.arr[0] != 5 )
        {
            failure ( "invalid socks version (0x%.2x) on socket:%i\n", stream->queue.arr[0],
                stream->fd );
            return -1;
        }

        /* Expect request opcode */
        if ( stream->queue.arr[1] != 1 || stream->queue.arr[2] != 0 )
        {
            failure ( "invalid socks opcode (0x%.2x 0x%.2x) from socket:%i\n",
                stream->queue.arr[1], stream->queue.arr[2], stream->fd );
            return -1;
        }

        /* Direct connect or by hostname */
        if ( stream->queue.arr[3] == 1 )
        {
            /* Print progress */
            verbose ( "got connect by ipv4 address request from socket:%i\n", stream->fd );

            failure ( "connect by ipv4 address not supported for socket:%i\n", stream->fd );
            return -1;

        } else if ( stream->queue.arr[3] == 3 )
        {
            /* Print progress */
            verbose ( "got connect by hostname request from socket:%i\n", stream->fd );

            /* Assert minimum data length */
            if ( check_enough_data ( proxy, stream, 5 ) < 0 )
            {
                return 0;
            }

            /* Parse hostname length */
            hostlen = stream->queue.arr[4];

            /* Assert maximum data length */
            if ( hostlen >= sizeof ( hostname ) )
            {
                failure ( "hostname is too long by socket:%i.\n", stream->fd );
                return -1;
            }

            /* Assert minimum data length */
            if ( check_enough_data ( proxy, stream, hostlen + 7 ) < 0 )
            {
                return 0;
            }

            /* Parse hostname then port number */
            port = ( ( stream->queue.arr[5 + hostlen] ) << 8 ) | stream->queue.arr[6 + hostlen];
            memcpy ( hostname, stream->queue.arr + 5, hostlen );
            hostname[hostlen] = '\0';

            /* Print progress */
            verbose ( "connect by hostname to (%s:%i) requested from socket:%i...\n", hostname,
                port, stream->fd );

        } else if ( stream->queue.arr[3] == 4 )
        {
            /* Print progress */
            verbose ( "got connect by ipv6 address request from socket:%i\n", stream->fd );

            failure ( "connect by ipv6 address not supported for socket:%i\n", stream->fd );
            return -1;

        } else
        {
            verbose ( "unknown connect mode (0x%.2x) requested from socket:%i...\n",
                stream->queue.arr[3], stream->fd );
            return -1;
        }

        /* Select proxy server */
        if ( proxy->primary_filter_enabled && hostlen + 3 < sizeof ( arr ) )
        {
            arr[0] = ',';
            memcpy ( arr + 1, hostname, hostlen );
            arr[hostlen + 1] = ',';
            arr[hostlen + 2] = '\0';

            if ( strstr ( proxy->primary_filter, ( char * ) arr ) )
            {
                server = &proxy->primary;

            } else if ( proxy->secondary_provided )
            {
                server = &proxy->secondary;
            }

        } else
        {
            server = &proxy->primary;
        }

        /* Check if proxy server has been chosen */
        if ( !server )
        {
            verbose ( "no proxy server matched for hostanme (%s) for socket:%i...\n", hostname,
                stream->fd );
            return -1;
        }

        /* Format proxy server address chosen */
        if ( proxy->verbose )
        {
            format_ip_port ( &server->saddr, straddr, sizeof ( straddr ) );
        }

        /* Connect endpoint */
        if ( proxy->gateway_enabled )
        {
            format_ip_port ( &proxy->gateway.saddr, straddr0, sizeof ( straddr0 ) );

            if ( proxy->bridge_enabled && server == &proxy->primary )
            {
                format_ip_port ( &proxy->bridge.saddr, straddr1, sizeof ( straddr1 ) );
                verbose ( "connect (%s:%i) over (%s,%s,%s) using socket:%i...\n", hostname, port,
                    straddr0, straddr1, straddr, stream->fd );
            } else
            {
                verbose ( "connect (%s:%i) over (%s,%s) using socket:%i...\n", hostname, port,
                    straddr0, straddr, stream->fd );
            }
            status = setup_endpoint_stream ( proxy, stream, &proxy->gateway.saddr );

        } else
        {
            verbose ( "connect (%s:%i) over (%s) using socket:%i...\n", hostname, port, straddr,
                stream->fd );
            status = setup_endpoint_stream ( proxy, stream, &server->saddr );
        }

        /* Check for error */
        if ( status < 0 )
        {
            return status;
        }

        /* Check for neighbour */
        if ( !stream->neighbour )
        {
            failure ( "neighbour stream not ready for socket:%i.\n", stream->fd );
            return -1;
        }

        /* Check hostname length */
        if ( hostlen > sizeof ( stream->neighbour->hostname ) )
        {
            failure ( "hostname is too long on socket:%i.\n", stream->fd );
            return -1;
        }

        /* Put endpoint data */
        stream->neighbour->server = server;
        memcpy ( stream->neighbour->hostname, hostname, hostlen );
        stream->neighbour->port = port;

        /* Print current stage */
        if ( proxy->gateway_enabled )
        {
            verbose ( "processing socks CLIENT/VERSION/0 stage on socket:%i...\n", stream->fd );
        } else
        {
            verbose ( "processing socks CLIENT/VERSION stage on socket:%i...\n", stream->fd );
        }

        /* Prepare request */
        arr[0] = 5;     /* SOCKS5 version */
        arr[1] = 1;     /* One auth method */
        if ( proxy->gateway_enabled )
        {
            arr[2] = 0; /* No auth method */
        } else
        {
            arr[2] = stream->neighbour->server->auth;   /* Auth method */
        }

        /* Enqueue request */
        if ( queue_set ( &stream->neighbour->queue, arr, 3 ) < 0 )
        {
            return -1;
        }

        /* Update levels and events flags */
        if ( proxy->gateway_enabled )
        {
            stream->neighbour->level = LEVEL_SOCKS_VER0;
        } else
        {
            stream->neighbour->level = LEVEL_SOCKS_VER;
        }
        stream->events = 0;
        stream->neighbour->events = POLLOUT;
        break;
    default:
        return -1;
    }

    return 0;
}

/**
 * Perform stream B socks request
 */
static int stream_socks_b_request ( struct proxy_t *proxy, struct stream_t *stream, uint8_t * arr,
    size_t arrsize )
{
    size_t hostlen;

    /* Print current stage */
    verbose ( "processing socks CLIENT/REQUEST stage on socket:%i...\n", stream->fd );

    /* Calculate hostname length */
    hostlen = strlen ( stream->hostname );

    /* Check hostname length */
    if ( hostlen + 7 > arrsize )
    {
        failure ( "endpoint hostname is too long for socket:%i\n", stream->fd );
        return -1;
    }

    /* Prepare request */
    arr[0] = 5; /* SOCKS5 version */
    arr[1] = 1; /* TCP/IP stream */
    arr[2] = 0; /* Reserved */
    arr[3] = 3; /* Connect by hostname */
    arr[4] = hostlen;   /* Hostname length */
    memcpy ( arr + 5, stream->hostname, hostlen );      /* Hostname content */
    arr[5 + hostlen] = stream->port >> 8;       /* Port 1st byte */
    arr[6 + hostlen] = stream->port & 0xff;     /* Port 2nd byte */

    /* Enqueue request */
    if ( queue_set ( &stream->queue, arr, hostlen + 7 ) < 0 )
    {
        return -1;
    }

    /* Update levels and events flags */
    stream->level = LEVEL_SOCKS_REQ;
    stream->events = POLLOUT;

    return 0;
}

/**
 * Handle stream B socks handshake and request
 */
static int handle_stream_socks_b ( struct proxy_t *proxy, struct stream_t *stream )
{
    int substage = 0;
    size_t ulen;
    size_t plen;
    size_t len;
    struct sockaddr_in *saddr_in;
    struct sockaddr_in6 *saddr_in6;
    struct sockaddr_storage *ptr_saddr;
    char straddr[STRADDR_SIZE];
    uint8_t arr[DATA_QUEUE_CAPACITY];

    /* Expect socket ready to be read */
    if ( ~stream->revents & POLLIN )
    {
        return -1;
    }

    /* Check for socks proxy server */
    if ( !stream->server )
    {
        failure ( "socks server not specified for socket:%i\n", stream->fd );
        return -1;
    }

    /* Receive data chunk */
    if ( ( ssize_t ) ( len = recv ( stream->fd, arr, sizeof ( arr ), 0 ) ) < 2 )
    {
        failure ( "cannot receive data (%i) from socket:%i\n", errno, stream->fd );
        return -1;
    }

    /* Print progress */
    verbose ( "received %i byte(s) in handshake from socket:%i\n", ( int ) len, stream->fd );

    /* Enqueue input data */
    if ( queue_push ( &stream->queue, arr, len ) < 0 )
    {
        return -1;
    }

    /* Update substage value */
    if ( stream->level == LEVEL_SOCKS_VER1 || stream->level == LEVEL_SOCKS_REQ1 )
    {
        substage = 1;
    }

    /* Choose the action */
    switch ( stream->level )
    {
    case LEVEL_SOCKS_VER0:
    case LEVEL_SOCKS_VER1:
        /* Print current stage */
        verbose ( "verifying socks CLIENT/VERSION/%i stage on socket:%i...\n", substage,
            stream->fd );

        /* Assert minimum data length */
        if ( check_enough_data ( proxy, stream, 2 ) < 0 )
        {
            return 0;
        }

        /* Expect SOCKS5 version */
        if ( stream->queue.arr[0] != 5 )
        {
            failure ( "invalid socks version (0x%.2x) on socket:%i\n",
                stream->queue.arr[0], stream->fd );
            return -1;
        }

        /* Expect no auth method */
        if ( stream->queue.arr[1] != 0 )
        {
            failure ( "invalid socks auth method (0x%.2x) on socket:%i\n", stream->queue.arr[1],
                stream->fd );
            return -1;
        }

        /* Print current stage */
        verbose ( "completed socks CLIENT/REQUEST/%i stage on socket:%i\n", substage, stream->fd );

        /* Print current stage */
        verbose ( "processing socks CLIENT/REQUEST/%i stage on socket:%i...\n", substage,
            stream->fd );

        /* Get destiantion host and port */
        if ( proxy->bridge_enabled && stream->server == &proxy->primary
            && stream->level == LEVEL_SOCKS_VER0 )
        {
            ptr_saddr = &proxy->bridge.saddr;
            verbose ( "using bridge after connected to the gateway...\n" );

        } else
        {
            ptr_saddr = &stream->server->saddr;
        }

        if ( proxy->verbose )
        {
            format_ip_port ( ptr_saddr, straddr, sizeof ( straddr ) );
        }

        verbose ( "connect to (%s) via proxy using socket:%i...\n", straddr, stream->fd );

        switch ( ptr_saddr->ss_family )
        {
        case AF_INET:
            saddr_in = ( struct sockaddr_in * ) ptr_saddr;
            /* Prepare request */
            arr[0] = 5; /* SOCKS5 version */
            arr[1] = 1; /* TCP/IP stream */
            arr[2] = 0; /* Reserved */
            arr[3] = 1; /* Connect IPv4 */
            memcpy ( arr + 4, &saddr_in->sin_addr, 4 ); /* IP 1st - 4th byte */
            arr[8] = ntohs ( saddr_in->sin_port ) >> 8; /* Port 1st byte */
            arr[9] = ntohs ( saddr_in->sin_port ) & 0xff;       /* Port 2nd byte */
            len = 10;
            break;
        case AF_INET6:
            saddr_in6 = ( struct sockaddr_in6 * ) ptr_saddr;
            /* Prepare request */
            arr[0] = 5; /* SOCKS5 version */
            arr[1] = 1; /* TCP/IP stream */
            arr[2] = 0; /* Reserved */
            arr[3] = 4; /* Connect IPv6 */
            memcpy ( arr + 4, &saddr_in6->sin6_addr, 16 );      /* IP 1st - 4th byte */
            arr[20] = ntohs ( saddr_in6->sin6_port ) >> 8;      /* Port 1st byte */
            arr[21] = ntohs ( saddr_in6->sin6_port ) & 0xff;    /* Port 2nd byte */
            len = 22;
            break;
        default:
            failure ( "invalid socket family (%i) on socket:%i\n", ptr_saddr->ss_family,
                stream->fd );
            return -1;
        }

        /* Enqueue request */
        if ( queue_set ( &stream->queue, arr, len ) < 0 )
        {
            return -1;
        }

        /* Update levels and events flags */
        if ( stream->level == LEVEL_SOCKS_VER0 )
        {
            stream->level = LEVEL_SOCKS_REQ0;
        } else
        {
            stream->level = LEVEL_SOCKS_REQ1;
        }
        stream->events = POLLOUT;
        break;
    case LEVEL_SOCKS_REQ0:
    case LEVEL_SOCKS_REQ1:
        /* Print current stage */
        verbose ( "veriyfing socks CLIENT/REQUEST/%i stage on socket:%i...\n", substage,
            stream->fd );

        /* Expect SOCKS5 version */
        if ( stream->queue.arr[0] != 5 )
        {
            failure ( "invalid socks version (0x%.2x) on socket:%i\n", stream->queue.arr[0],
                stream->fd );
            return -1;
        }

        /* Expect status success */
        if ( stream->queue.arr[1] != 0 )
        {
            failure ( "invalid socks status (0x%.2x) on socket:%i\n", stream->queue.arr[1],
                stream->fd );
            return -1;
        }

        /* Print current stage */
        verbose ( "completed socks CLIENT/REQUEST/%i stage on socket:%i\n", substage, stream->fd );

        /* Print current stage */
        verbose ( "processing socks CLIENT/VERSION stage on socket:%i...\n", stream->fd );

        /* Prepare request */
        arr[0] = 5;     /* SOCKS5 version */
        arr[1] = 1;     /* One auth method */
        if ( proxy->bridge_enabled && stream->server == &proxy->primary
            && stream->level == LEVEL_SOCKS_REQ0 )
        {
            arr[2] = 0; /* No auth method */

        } else
        {
            arr[2] = stream->server->auth;      /* Auth method */
        }

        /* Enqueue request */
        if ( queue_set ( &stream->queue, arr, 3 ) < 0 )
        {
            return -1;
        }

        /* Update levels and events flags */
        if ( proxy->bridge_enabled && stream->server == &proxy->primary
            && stream->level == LEVEL_SOCKS_REQ0 )
        {
            stream->level = LEVEL_SOCKS_VER1;
        } else
        {
            stream->level = LEVEL_SOCKS_VER;
        }
        stream->events = POLLOUT;
        break;
    case LEVEL_SOCKS_VER:
        /* Print current stage */
        verbose ( "verifying socks CLIENT/VERSION stage on socket:%i...\n", stream->fd );

        /* Assert minimum data length */
        if ( check_enough_data ( proxy, stream, 2 ) < 0 )
        {
            return 0;
        }

        /* Expect SOCKS5 version */
        if ( stream->queue.arr[0] != 5 )
        {
            failure ( "invalid socks status (0x%.2x) on socket:%i\n", stream->queue.arr[0],
                stream->fd );
            return -1;
        }

        /* Check the auth method */
        if ( stream->queue.arr[1] != stream->server->auth )
        {
            failure ( "invalid auth type (0x%.2x) requested on socket:%i\n", stream->queue.arr[1],
                stream->fd );
            return -1;
        }

        /* Print current stage */
        verbose ( "completed socks CLIENT/VERSION stage on socket:%i\n", stream->fd );

        /* Skip authentication if needed */
        if ( stream->server->auth == 0 )
        {
            verbose ( "skipped socks CLIENT/AUTH stage on socket:%i\n", stream->fd );
            return stream_socks_b_request ( proxy, stream, arr, sizeof ( arr ) );
        }

        /* Check for credentials auth method */
        if ( stream->queue.arr[1] != 2 )
        {
            failure ( "unsupported auth type (0x%.2x) requested on socket:%i\n",
                stream->queue.arr[1], stream->fd );
            return -1;
        }

        /* Print current stage */
        verbose ( "processing socks CLIENT/AUTH stage on socket:%i...\n", stream->fd );

        /* Calculate data lengths */
        ulen = strlen ( stream->server->user );
        plen = strlen ( stream->server->pass );
        len = ulen + plen + 3;
        if ( len > sizeof ( arr ) )
        {
            verbose ( "credentials are too long on socket:%i\n", stream->fd );
            return -1;
        }

        /* Prepare request */
        arr[0] = 1;     /* Credentials v1 */
        arr[1] = ulen;  /* Username length */
        memcpy ( arr + 2, stream->server->user, ulen ); /* Username bytestring */
        arr[ulen + 2] = plen;   /* Password length */
        memcpy ( arr + ulen + 3, stream->server->pass, plen );  /* Password bytestring */

        /* Enqueue request */
        if ( queue_set ( &stream->queue, arr, len ) < 0 )
        {
            return -1;
        }

        /* Update levels and events flags */
        stream->level = LEVEL_SOCKS_AUTH;
        stream->events = POLLOUT;
        break;
    case LEVEL_SOCKS_AUTH:
        /* Print current stage */
        verbose ( "verifying socks CLIENT/AUTH stage on socket:%i...\n", stream->fd );

        /* Assert minimum data length */
        if ( check_enough_data ( proxy, stream, 2 ) < 0 )
        {
            return 0;
        }

        /* Expect first auth method available */
        if ( stream->queue.arr[0] != 1 )
        {
            failure ( "invalid socks opcode (0x%.2x) on socket:%i\n", stream->queue.arr[0],
                stream->fd );
            return -1;
        }

        /* Expect auth status success */
        if ( stream->queue.arr[1] != 0 )
        {
            failure ( "invalid socks status (0x%.2x) on socket:%i\n", stream->queue.arr[1],
                stream->fd );
            return -1;
        }

        /* Print current stage */
        verbose ( "completed socks CLIENT/AUTH stage on socket:%i\n", stream->fd );

        /* Perform the request */
        return stream_socks_b_request ( proxy, stream, arr, sizeof ( arr ) );
    case LEVEL_SOCKS_REQ:
        /* Print current stage */
        verbose ( "verifying socks CLIENT/REQUEST stage on socket:%i...\n", stream->fd );

        /* Assert minimum data length */
        if ( check_enough_data ( proxy, stream, 2 ) < 0 )
        {
            return 0;
        }

        /* Expect SOCKS5 version */
        if ( stream->queue.arr[0] != 5 )
        {
            failure ( "invalid socks version (0x%.2x) on socket:%i\n", stream->queue.arr[0],
                stream->fd );
            return -1;
        }

        /* Expect status success */
        if ( stream->queue.arr[1] != 0 )
        {
            failure ( "invalid socks status (0x%.2x) on socket:%i\n", stream->queue.arr[1],
                stream->fd );
            return -1;
        }

        /* Print current stage */
        verbose ( "completed socks CLIENT/REQUEST stage on socket:%i\n", stream->fd );

        /* Queue fully consumed on current stream */
        queue_reset ( &stream->queue );

        /* Prepare response */
        arr[0] = 5;     /* SOCKS5 version */
        arr[1] = 0;     /* Request granted */
        arr[2] = 0;     /* Reserved */
        arr[3] = 1;     /* Address type: IPv4 */
        arr[4] = 0;     /* Address byte #1 */
        arr[5] = 0;     /* Address byte #2 */
        arr[6] = 0;     /* Address byte #3 */
        arr[7] = 0;     /* Address byte #4 */
        arr[8] = 0;     /* Port 1st byte */
        arr[9] = 0;     /* Port 2nd byte */

        /* Enqueue response */
        if ( queue_set ( &stream->neighbour->queue, arr, 10 ) < 0 )
        {
            return -1;
        }

        /* Update levels and events flags */
        stream->level = LEVEL_SOCKS_PASS;
        stream->events = 0;
        stream->neighbour->level = LEVEL_SOCKS_PASS;
        stream->neighbour->events = POLLOUT;
        break;
    default:
        return -1;
    }

    return 0;
}


/**
 * Handle stream events
 */
int handle_stream_events ( struct proxy_t *proxy, struct stream_t *stream )
{
    int status;

    if ( handle_forward_data ( proxy, stream ) >= 0 )
    {
        return 0;
    }

    if ( ( stream->role == S_PORT_A || stream->role == S_PORT_B ) &&
        stream->queue.len && ( stream->revents & POLLOUT ) )
    {
        if ( queue_shift ( &stream->queue, stream->fd ) < 0 )
        {
            remove_relation ( stream );
            return 0;
        }
        if ( stream->queue.len == 0 )
        {
            if ( stream->role == S_PORT_A && stream->level == LEVEL_SOCKS_PASS )
            {
                if ( !stream->neighbour )
                {
                    return -1;
                }
                stream->level = LEVEL_FORWARDING;
                stream->events = POLLIN;
                stream->neighbour->level = LEVEL_FORWARDING;
                stream->neighbour->events = POLLIN;
            } else
            {
                stream->events = POLLIN;
            }
        }
        return 0;
    }

    switch ( stream->role )
    {
    case L_ACCEPT:
        show_stats ( proxy );
        if ( handle_new_stream ( proxy, stream ) == -2 )
        {
            return -1;
        }
        return 0;
    case S_PORT_A:
        if ( ( status = handle_stream_socks_a ( proxy, stream ) ) >= 0 )
        {
            return 0;
        }
        if ( status == -2 )
        {
            return -1;
        }
        break;
    case S_PORT_B:
        if ( ( status = handle_stream_socks_b ( proxy, stream ) ) >= 0 )
        {
            return 0;
        }
        if ( status == -2 )
        {
            return -1;
        }
        break;
    }

    remove_relation ( stream );

    return 0;
}

/**
 * Proxy task entry point
 */
int proxy_task ( struct proxy_t *proxy )
{
    int status = 0;
    int sock;
    struct stream_t *stream;

    /* Set stream size */
    proxy->stream_size = sizeof ( struct stream_t );

    /* Reset current state */
    proxy->stream_head = NULL;
    proxy->stream_tail = NULL;
    memset ( proxy->stream_pool, '\0', sizeof ( proxy->stream_pool ) );

    /* Proxy events setup */
    if ( proxy_events_setup ( proxy ) < 0 )
    {
        return -1;
    }

    /* Setup listen socket */
    if ( ( sock = listen_socket ( proxy, &proxy->entrance ) ) < 0 )
    {
        if ( proxy->epoll_fd >= 0 )
        {
            close ( proxy->epoll_fd );
        }
        return -1;
    }

    /* Allocate new stream */
    if ( !( stream = insert_stream ( proxy, sock ) ) )
    {
        shutdown_then_close ( proxy, sock );
        if ( proxy->epoll_fd >= 0 )
        {
            close ( proxy->epoll_fd );
        }
        return -1;
    }

    /* Update listen stream */
    stream->role = L_ACCEPT;
    stream->events = POLLIN;

    verbose ( "proxy setup was successful\n" );

    /* Run forward loop */
    while ( ( status = handle_streams_cycle ( proxy ) ) >= 0 );

    /* Do not close reset pipe */
    stream->fd = -1;

    /* Remove all streams */
    remove_all_streams ( proxy );

    /* Close epoll fd if created */
    if ( proxy->epoll_fd >= 0 )
    {
        close ( proxy->epoll_fd );
        proxy->epoll_fd = -1;
    }

    verbose ( "done proxy uninitializing\n" );

    return status;
}
