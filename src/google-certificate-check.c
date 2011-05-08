#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <unbound.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/tls1.h>

static int host_ip(const char *str, unsigned char ip[4])
    {
    unsigned int in[4]; 
    int i;

    if (sscanf(str,"%u.%u.%u.%u", &in[0], &in[1], &in[2], &in[3]) == 4)
	{
	for (i = 0 ; i < 4 ; i++)
	    if (in[i] > 255)
		{
		fprintf(stderr,"invalid IP address\n");
		goto err;
		}
	ip[0] = in[0];
	ip[1] = in[1];
	ip[2] = in[2];
	ip[3] = in[3];
	}
    else
	{ /* do a gethostbyname */
	struct hostent *he;

	he=gethostbyname(str);
	if (he == NULL)
	    {
	    fprintf(stderr,"gethostbyname failure\n");
	    goto err;
	    }
	if (he->h_addrtype != AF_INET)
	    {
	    fprintf(stderr,"gethostbyname addr is not AF_INET\n");
	    return 0;
	    }
	ip[0] = he->h_addr_list[0][0];
	ip[1] = he->h_addr_list[0][1];
	ip[2] = he->h_addr_list[0][2];
	ip[3] = he->h_addr_list[0][3];
	}
    return(1);
 err:
    return(0);
    }

static int init_client_ip(int *sock, const unsigned char ip[4],
			  unsigned short port, int type)
    {
    unsigned long addr;
    struct sockaddr_in them;
    int s,i;

    memset(&them, 0, sizeof them);
    them.sin_family = AF_INET;
    them.sin_port = htons(port);
    addr = (unsigned long)((unsigned long)ip[0] << 24L)
	| ((unsigned long)ip[1] << 16L)
	| ((unsigned long)ip[2] << 8L)
	| ((unsigned long)ip[3]);
    them.sin_addr.s_addr = htonl(addr);
    if (type == SOCK_STREAM)
	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    else /* ( type == SOCK_DGRAM) */
	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (s < 0)
	{
	perror("socket");
	return 0;
	}

#if defined(SO_KEEPALIVE) && !defined(OPENSSL_SYS_MPE)
    if (type == SOCK_STREAM)
	{
	i = 0;
	i = setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char *)&i, sizeof i);
	if (i < 0)
	    {
	    perror("keepalive");
	    return 0;
	    }
	}
#endif

    printf("Connecting to %d.%d.%d.%d...", ip[0], ip[1], ip[2], ip[3]);
    fflush(stdout);
    if (connect(s, (struct sockaddr *)&them, sizeof them) == -1)
	{
	perror("connect");
	close(s);
	return 0;
	}

    puts("connected");
    *sock = s;
    return 1;
    }

static int init_client(int *sock, const char *host, int port, int type)
    {
    unsigned char ip[4];

    if (!host_ip(host,&(ip[0])))
	return 0;
    return init_client_ip(sock,ip,port,type);
    }

// TODO: clean up all the dangling resources.
static SSL *start_ssl(const char *hostname)
    {
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *meth = TLSv1_client_method();
    assert(meth);

    SSL_CTX *ctx = SSL_CTX_new(meth);
    assert(ctx);

    SSL *ssl = SSL_new(ctx);
    assert(ssl);

    int ret;
    ret = SSL_set_tlsext_host_name(ssl, hostname);
    assert(ret);

    int sock;
    ret = init_client(&sock, hostname, 443, SOCK_STREAM);
    if(!ret)
	return NULL;

    BIO *sbio = BIO_new_socket(sock, 0);
    SSL_set_bio(ssl, sbio, sbio);

    for( ; ; )
	{
	if (!SSL_in_init(ssl))
	    {
	    printf("SSL initialised, our work here is done\n");
	    break;
	    }
	fputs("Starting SSL...", stdout);
	fflush(stdout);
	ret = SSL_connect(ssl);
	assert(ret > 0);
	puts("started");
	}

    return ssl;
    }

static int check_name(const char *hostname, const char *cn)
    {
    if (!strcmp(hostname, cn))
	return 1;
    assert(!"write check for wildcards");
    return 0;
    }

static void show_day(const char *name, const unsigned int day)
    {
    char date[1024];
    time_t t = day * 24*60*60;
    struct tm *tm = gmtime(&t);
    strftime(date, sizeof date, "%e %b %Y", tm);

    printf("%s: %s\n", name, date);
    }

static void dump_chain(const SSL *ssl)
    {
    const STACK_OF(X509) *certs = SSL_get_peer_cert_chain(ssl);

    int n;
    for(n = 0 ; n < sk_X509_num(certs) ; ++n)
	{
	X509 *cert = sk_X509_value(certs, n);
	PEM_write_X509(stdout, cert);
	}
    }

static void ssl_name_check(const SSL *ssl, const char *hostname)
    {
    X509 *cert = SSL_get_peer_certificate(ssl);
    assert(cert);

    X509_NAME *subject = X509_get_subject_name(cert);
    assert(subject);

    fputs("Subject: ", stdout);
    X509_NAME_print_ex_fp(stdout, subject, 0, 0);
    putchar('\n');

    char common_name[1024];
    X509_NAME_get_text_by_NID(subject, NID_commonName, common_name,
			      sizeof common_name);
    printf("Common name: %s", common_name);
    int ret = check_name(hostname, common_name);
    if (ret)
	puts(" (pass)");
    else
	{
	puts(" (FAIL)");
	exit(1);
	}
    }

static void look_up_hash(const SSL *ssl)
    {
    X509 *cert = SSL_get_peer_certificate(ssl);
    assert(cert);

    unsigned char hash[20];
    unsigned int hash_len = sizeof hash;
    int ret = X509_digest(cert, EVP_sha1(), hash, &hash_len);
    assert(ret);

    char hash_hex[40];
    int n;
    for (n = 0 ; n < 20 ; ++n)
	sprintf(&hash_hex[2*n], "%02x", hash[n]);
    printf("Certificate hash: %s\n", hash_hex);

    fputs("Looking up certificate hash...", stdout);
    fflush(stdout);

    char lookup_name[1024];
    sprintf(lookup_name, "%s.certs.googlednstest.com", hash_hex);

    struct ub_ctx *ub_ctx = ub_ctx_create();
    assert(ub_ctx);

    ret = ub_ctx_resolvconf(ub_ctx, NULL);
    assert(ret == 0);

    struct ub_result *result;
    ret = ub_resolve(ub_ctx, lookup_name, ns_t_txt, ns_c_in, &result);
    assert(ret == 0);

    if (result->rcode == ns_r_nxdomain)
	{
	puts("CERTIFICATE NEVER SEEN!");
	exit(3);
	}
    else if (result->rcode != ns_r_noerror)
	{
	printf("failed: %d\n", result->rcode);
	exit(2);
	}

    assert(result->data[0]);
    assert(result->len[0] > 1);
    unsigned int len = result->data[0][0];
    assert(result->len[0] == len + 1);

    char tmp[256];
    memcpy(tmp, &result->data[0][1], len);
    tmp[len] = '\0';

    printf("found %s\n", tmp);

    unsigned int first, last, days;
    ret = sscanf(tmp, "%u %u %u", &first, &last, &days);
    assert(ret == 3);

    show_day("First seen", first);
    show_day("Last seen ", last);

    float percent = (100. * days) / (last - first + 1);
    printf("Times seen: %d/%d (%g%%)\n", days, last - first + 1, percent);

    assert(!result->data[1]);
    }

int main(int argc, char **argv)
    {
    const char *hostname = argv[1];

    if (argc < 2)
	{
	fprintf(stderr, "%s <host name>\n", argv[0]);
	exit(-1);
	}

    SSL *ssl = start_ssl(hostname);
    if(!ssl)
	return 4;

    dump_chain(ssl);
    ssl_name_check(ssl, hostname);
    look_up_hash(ssl);

    return 0;
    }
