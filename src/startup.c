/* ------------------------------------------------------------------
 * SocksHub - Main Program File
 * ------------------------------------------------------------------ */

#include "sockshub.h"

/**
 * Show program usage message
 */
static void show_usage ( void )
{
    failure ( "usage: sockshub option [value]...\n\n"
        "       -v                Enable verbose logging\n"
        "       -d                Run in background\n"
        "       -g addr:port      Connect via gateway\n"
        "       -b addr:port      Bridge for primary server\n"
        "       -l addr:port      Listen for incoming data\n"
        "       -p addr:port      Primary socks5 server\n"
        "       -c user:pass      Primary socks5 credentials\n"
        "       -f filter         Primary hostname filter\n"
        "       -s addr:port      Secondary socks5 server\n"
        "       -q addr:port      Secondary socks5 credentials\n"
        "       -z                Use bridge for all servers\n"
        "       -x greeting       Secondary server greeting\n\n"
        "Note: Both IPv4 and IPv6 can be used\n\n" );
}

/**
 * Decode credentials
 */
int credentials_decode ( const char *input, char *user, size_t nuser, char *pass, size_t npass )
{
    size_t len;
    const char *ptr;

    /* Find credentials separator */
    if ( !( ptr = strchr ( input, ':' ) ) )
    {
        return -1;
    }

    /* Check username buffer size */
    if ( ( len = ptr - input ) >= nuser )
    {
        return -1;
    }

    /* Put username into buffer */
    memcpy ( user, input, len );
    user[len] = '\0';

    /* Skip credentials separator */
    ptr++;

    /* Check password buffer size */
    if ( ( len = input + strlen ( input ) - ptr ) >= npass )
    {
        return -1;
    }

    /* Put username into buffer */
    memcpy ( pass, ptr, len );
    pass[len] = '\0';

    return 0;
}

/**
 * Program entry point
 */
int main ( int argc, char *argv[] )
{
    int c;
    int option_index;
    int daemon_flag = 0;
    int listen_flag = 0;
    int primary_flag = 0;
    size_t len;
    struct proxy_t proxy = { 0 };

    setbuf ( stdout, NULL );

    /* Show program version */
    info ( "SocksHub - ver. " SOCKSHUB_VERSION "\n" );

    opterr = 0;

    /* Parse program arguments */
    for ( ;; )
    {
        if ( ( c = getopt_long ( argc, argv, "vdg:b:l:p:c:f:s:q:zx:", NULL, &option_index ) ) < 0 )
        {
            break;
        }

        switch ( c )
        {
        case 0:
            break;
        case 'v':
            proxy.verbose = 1;
            break;
        case 'd':
            daemon_flag = 1;
            break;
        case 'g':
            proxy.gateway_enabled = 1;
            if ( ip_port_decode ( optarg, &proxy.gateway.saddr ) < 0 )
            {
                show_usage (  );
                return 1;
            }
            break;
        case 'b':
            if ( strcmp ( optarg, "none" ) )
            {
                proxy.bridge_enabled = 1;
                if ( ip_port_decode ( optarg, &proxy.bridge.saddr ) < 0 )
                {
                    show_usage (  );
                    return 1;
                }
            }
            break;
        case 'l':
            if ( ip_port_decode ( optarg, &proxy.entrance ) < 0 )
            {
                show_usage (  );
                return 1;
            }
            listen_flag = 1;
            break;
        case 'p':
            if ( ip_port_decode ( optarg, &proxy.primary.saddr ) < 0 )
            {
                show_usage (  );
                return 1;
            }
            primary_flag = 1;
            break;
        case 'c':
            proxy.primary.auth = 2;
            if ( credentials_decode ( optarg, proxy.primary.user, sizeof ( proxy.primary.user ),
                    proxy.primary.pass, sizeof ( proxy.primary.pass ) ) < 0 )
            {
                show_usage (  );
                return 1;
            }
            break;
        case 'f':
            len = strlen ( optarg );
            if ( len >= sizeof ( proxy.primary_filter ) )
            {
                show_usage (  );
                return 1;
            }
            memcpy ( proxy.primary_filter, optarg, len + 1 );
            proxy.primary_filter_enabled = 1;
            break;
        case 's':
            if ( ip_port_decode ( optarg, &proxy.secondary.saddr ) < 0 )
            {
                show_usage (  );
                return 1;
            }
            proxy.secondary_provided = 1;
            break;
        case 'q':
            proxy.secondary.auth = 2;
            if ( credentials_decode ( optarg, proxy.secondary.user, sizeof ( proxy.secondary.user ),
                    proxy.secondary.pass, sizeof ( proxy.secondary.pass ) ) < 0 )
            {
                show_usage (  );
                return 1;
            }
            break;
        case 'z':
            proxy.bridge_both_servers = 1;
            break;
        case 'x':
            len = strlen ( optarg );
            if ( len >= sizeof ( proxy.secondary_greeting ) )
            {
                show_usage (  );
                return 1;
            }
            memcpy ( proxy.secondary_greeting, optarg, len + 1 );
            proxy.secondary_custom_greeting = 1;
            break;
        default:
            show_usage (  );
            return 1;
        }
    }

    /* Bridge can be used if gateway specified */
    if ( !proxy.gateway_enabled && proxy.bridge_enabled )
    {
        show_usage (  );
        return 1;
    }

    /* Check for mandatory options */
    if ( !listen_flag || !primary_flag )
    {
        show_usage (  );
        return 1;
    }

    /* Run in background if needed */
    if ( daemon_flag )
    {
        if ( daemon ( 0, 0 ) < 0 )
        {
            failure ( "cannot run in background (%i)\n", errno );
            return 1;
        }
    }

    /* Launch the proxy task */
    if ( proxy_task ( &proxy ) < 0 )
    {
        failure ( "exit status: %i\n", errno );
        return 1;
    }

    info ( "exit status: success\n" );
    return 0;
}
