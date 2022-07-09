/* ------------------------------------------------------------------
 * SocksHub - Proxy Task Header File
 * ------------------------------------------------------------------ */

#ifndef SOCKSHUB_H
#define SOCKSHUB_H

#include "defs.h"
#include "config.h"

#define L_ACCEPT                    0

#define LEVEL_SOCKS_VER             0
#define LEVEL_SOCKS_VER0            1
#define LEVEL_SOCKS_VER1            2
#define LEVEL_SOCKS_AUTH            3
#define LEVEL_SOCKS_REQ             5
#define LEVEL_SOCKS_REQ0            6
#define LEVEL_SOCKS_REQ1            7
#define LEVEL_SOCKS_PASS            8

/**
 * Data queue structure
 */
struct queue_t
{
    size_t len;
    uint8_t arr[DATA_QUEUE_CAPACITY];
};

/**
 * Socks Proxy Server Info
 */
struct socks_server_t
{
    struct sockaddr_storage saddr;
    int auth;
    char user[255];
    char pass[255];
};

/**
 * IP/TCP connection stream
 */
struct stream_t
{
    int role;
    int fd;
    int level;
    int allocated;
    int abandoned;
    short events;
    short levents;
    short revents;

    struct pollfd *pollref;
    struct stream_t *neighbour;
    struct stream_t *prev;
    struct stream_t *next;
    struct queue_t queue;

    char hostname[256];
    uint16_t port;
    struct socks_server_t *server;
};

/**
 * Proxy program params
 */
struct proxy_t
{
    size_t stream_size;
    int verbose;
    int epoll_fd;
    struct stream_t *stream_head;
    struct stream_t *stream_tail;
    struct stream_t stream_pool[POOL_SIZE];

    int gateway_enabled;
    struct socks_server_t gateway;

    int bridge_enabled;
    struct socks_server_t bridge;

    struct sockaddr_storage entrance;

    struct socks_server_t primary;
    int primary_filter_enabled;
    char primary_filter[4096];
    int secondary_provided;
    struct socks_server_t secondary;
};

/**
 * Proxy task entry point
 */
extern int proxy_task ( struct proxy_t *params );

/**
 * Select network proxy by given endpoint hostname and port
 */
extern int pickup_proxy ( const char *hostname, uint16_t port, uint32_t * proxy_addr,
    uint16_t * proxy_port );

#include "util.h"

#endif
