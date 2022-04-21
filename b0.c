/* Dear contributors: for the ease of editing, compiling,
 * debugging etc., please keep the code in ONE SINGLE file.
 * Thanks in advance.
 *
 * 
 * A pointer `p` is accessible means that we can successfully
 * read and write `*p`.
 *
 *
 * All sockets established here only connect to localhost.
 * Server & mah ports are fixed.
 *
 *
 * Sever: listens from mah for webhooks.
 * Client: put stuff to mah.
 *
 *
 * TODO: test with static checkers like valgrind,
 * and resource leak checkers, e.g. for close() and free().
 *
 *
 *
 * argc == 1: listen only
 * argc == 2: broadcast, like the old s.py. for weibo.
 * otherwise: verify & listen
 *
 */

#if 0
j0: respond to text message
j1: broadcast (special)
    Will be implemented later.
    At present we use the old Python implementation first.
j2: respond to <imageId>
.a -> int, 0 for success
j0.a(

m: manager
u: utility

args:
  mn (member name)

callbacks: (ca, ...)
  rt (reply text)
     s: str
  sv (send voice)
     fn: str (amr filename)

utilities:
  sd (get selenium driver)
#endif

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/* JSON */
#define C ","
#define S ":"
#define Q(s) "\"" s "\""
#define P(a, b) Q(a) S Q(b)


static struct {
    const char *ip;
    int server_port;
    int mah_port;
} conf;


static void configure(
        void
)
{
    conf.ip = "0.0.0.0";
    conf.server_port = 12321;
    conf.mah_port = 8080;
}




/* similiar, but if matches, returns 
 * <match point> + strlen(#sub),
 * pointing to the next character after match */
static char *strstr2(
        const char *s,
        const char *sub
)
{
    char *m = strstr(s, sub);
    if (m)
        m += strlen(sub);

    return m;
}



static void strip(char *s)
{
    char *p;
    size_t n;

    if (s == NULL)
    {
        fprintf(stderr, "Are you kidding?\n");
        return;
    }

    /* strip head */
    for (p = s; isspace((int)*p); ++p);
    n = strlen(p);
    memmove(s, p, n);

    /* strip tail */
    p = s + n - 1;
    for (; isspace((int)*p) && p != s; --p)
        *p = 0;
}





/* 0: true */
static int startswith(
        const char *s,
        const char *sub
)
{
    const char *p, *q;
  
    if (s == NULL || sub == NULL)
        return -1;

    for (p = s, q = sub; ; ++p, ++q)
    {
        if (*p != *q)
        {
            if (*q)
                return -1;
            else
                return 0;
        }

        /* *p == *q
         * *p == 0 -> *q == 0
         */
        if (*p != 0)
            continue;
        else
            /* *p == *q == 0 */
            return 0;
    }
}



/* allocate memory and set first value as 0
 * safer for string operations
 */
static void *alloc0(
        const size_t siz
)
{
    char *c = malloc(siz);

    if (c)
        *c = 0;

    return c;
}


static void close2(
        int *fd
)
{
    if (fd == NULL)
        return;

    close(*fd);
    *fd = -1;
}


static void free2(
        char **p /* accessible */
)
{
    if (p == NULL)
        return;

    free(*p);
    *p = NULL;
}


static void realloc2(
    void **p,  /* accessible */
    size_t siz /* > 0 */
)
{
    *p = realloc(*p, siz);
}



static void strcat_realloc(
    char **p, /* allocated, accessible */
    const char *s2 /* accessible */
)
{
    size_t s = strlen(*p) + strlen(s2) + 1;
    realloc2((void **) p, s);
    strcat(*p, s2);
}


static void zeromem(
    void *p,
    const size_t n
)
{
    memset(p, 0, n);
}



/* The return value points to a statically allocated
   string which might be overwritten by subsequent calls.
 */
static const char *timestr(void)
{
    static char buf[128];
    time_t t = time(0);
    
    snprintf(buf, 128, "%d", (int) t);
    
    return buf;
}


static struct sockaddr_in
ipv4addr(
    const int po    /* port */
)
{
    struct sockaddr_in a;
    
    zeromem(&a, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr(conf.ip);
    a.sin_port = htons(po);
    
    return a;
}


static int socket2(
        /* 0: server
         * otherwise: client */
        const int is_server 
)
{
    int s, r;
    struct sockaddr_in a;

    s = socket(AF_INET, SOCK_STREAM, 0);

    /* socket() fails */

    if (s < 0)
    {
        perror("socket()");
        return -1;
    }


    /* bind/connect */

    if (is_server == 0)
    {
        a = ipv4addr(conf.server_port);
        r = bind(s, (struct sockaddr *) &a, sizeof a);
    
        if (r >= 0)
        {
            if (listen(s, 10) != 0)
            {
                perror("listen()");
                r = -1;
            }
        }
        else
            perror("bind()");
    }
    else
    {
        a = ipv4addr(conf.mah_port);
        r = connect(s, (struct sockaddr *) &a, sizeof a);
    }

    /* failed */

    if (r < 0)
    {
        perror("r < 0");
        close2(&s);
        return -2;
    }

    /* success */

    return s;
}


typedef struct {
    /* content-length
     * left to be read. will get smaller gradually
     * negative for unknown length
     */
    int len;

    /* header_skipped
     * 0 for not skipped
     */
    int s;
} http_parse_state;


static http_parse_state empty_hps(void)
{
    http_parse_state s;

    s.len = -1;
    s.s = 0;

    return s;
}


/* returns 0 for success */
static int parse_content_length(
    const char *buf,
    int *content_length /* OUT only */
)
{
    int len;
    const char *s = strstr(buf, "\nContent-Length: ");
    
    if (!s)
        return 1;
    
    if (1 != sscanf(s + 1, "Content-Length: %d", &len))
        return -1;
    
    if (len < 0)
        return -1;

    *content_length = len;
    return 0;
}


/* tell when can we close the socket through #eof
 * 
 * returns 0 if should stop
 */
static int can_we_stop(
    const char *buf,
    const size_t n,
    http_parse_state *s
)
{
    const char *bs;
    size_t bn;
   
    if (0 != strstr(buf, "HTTP/1.1 200 OK"))
        /* OK. close immediately */
        return 0;

    if (s->len == -1)
        parse_content_length(buf, &s->len);
    
    if (s->len < 0) /* will be more headers */
        return 1;
    
    /* s.len >= 0 */
    
    if (s->s == 0)
    {
        /* try to skip header */
        bs = strstr(buf, "\r\n\r\n");
        if (bs == NULL)
            /* there will be more headers */
            return 2;
        
        /* skip header */
        s->s = 1;
        bs += 4;
        /* adjust #n so that #n' + #s = #buf + #n
         * (s = bs, n = bn)
         * 
         * #n' = (#buf - #s) + #n
         * #n  = #n' + (#s - #buf)
         * #n' = #n - (#s - #buf)
         */
        bn = n - (bs - buf);
    }
    else
    {
        bs = buf;
        bn = n;
    }
    
    /* s->s == 1; read data */
    s->len -= (int) bn;
    
    if (s->len > 0)
        return 3;
    
    return 0;
}


/* smartly close socket earlier by 
 * interpreting Content-Length in the header
 *
 * assume that we can always find Content-Length,
 * and we are handling zero-terminated stuff all the time
 *
 * will print response to stdout
 * will close socket and #fd for you
 */
static void readhttp(
    int *con, /* socket to read, can't be NULL */
    int *fd, /* fd to dump, may be invalid (< 0) */
    char **out /* can be realloc()'d. can be NULL */
)
{
    char buf[1024];
    size_t n;
    http_parse_state s = empty_hps();
    
    while ((n = read(*con, buf, 1023)) > 0)
    {
        buf[n] = 0;
        
        printf("\n--read %d bytes\n", (int) n);
       
        if (fd)
            write(*fd, buf, n);

        if (out)
            strcat_realloc(out, buf);

        fwrite(buf, 1, n, stdout);
        
        if (can_we_stop(buf, n, &s) == 0)
            break;
    }

    puts("closing socket");

    shutdown(*fd, SHUT_RDWR);
    close2(con);

    if (fd)
        close2(fd);
}


static int get_logfd(void)
{
    int fd;
    char fn[200];
    snprintf(fn, sizeof fn, "log.na/%s", timestr());
    
    printf("\n--try opening log file at %s\n", fn);

    fd = open(fn, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR);

    return fd;
}


static int stop_flag = -1; /* == 0 if stop */


/* sa_handler
 * 
 * close socket so that port won't get occupied at reboot
 */
static void sah(int signum)
{
    const char msg[] = "\n--SIGINT or SIGTERM, set stop flag\n";
    (void) signum;
    
    stop_flag = 0;
    
    write(0, /* stdout */
          msg, sizeof msg);
}


/* don't work. maybe because of read() */
static void regsig(void)
{
    struct sigaction a;
    
    zeromem(&a, sizeof a);
    a.sa_handler = sah;
    sigemptyset(&(a.sa_mask));
    
    if (sigaction(SIGINT, &a, NULL) != 0)
        perror("\nsigaction()");
    else
        puts("\n--sigaction() success");
    
    if (sigaction(SIGTERM, &a, NULL) != 0)
        perror("\nsigaction()");
    else
        puts("\n--sigaction() success");
}



static int accept_in(
        const int s, /* sockfd */
        struct sockaddr_in *a2
)
{
    int con;
    socklen_t l = sizeof *a2;

    con = accept(s, (struct sockaddr *) a2, &l);
    return con;
}


static int accept2(
        const int s,
        int addr_inited /* 0 for true */
)
{
    static int addr;
    int con;
    struct sockaddr_in a2;

    con = accept_in(s, &a2); 

    /* accept() failure */

    if (con < 0)
    {
        perror("con < 0");
        return con;
    }

    /* accept() success */

    printf("%d %d ",
            (int) a2.sin_port,
            (int) a2.sin_addr.s_addr);

    /* first time connect */

    if (addr_inited != 0)
    {
        addr = a2.sin_addr.s_addr;
        printf("first time accepted\n\n");
        return con;
    }

    /* not first time, check addr */

    /* reject */

    if (a2.sin_addr.s_addr != addr)
    {
        /* accept only this known address */
        printf("rejected\n\n");
        close2(&con);
        return -1;
    }

    /* accept */
    
    printf("accepted\n\n");
    return con;
}



static void mah_send_header(
        const int s,
        const char *method,
        const char *path,
        const int content_length /* -1 for don't send */
            /* mah will not response
             * if Content-Length is not sent */
)
{
    char *b;

    /* invalid socket */
    if (s < 0)
        return;

    /* send */
    dprintf(s, 
            "%s /%s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Accept-Encoding: identity\r\n",
            method, path,
            conf.ip, conf.mah_port
            );

    if (content_length != -1)
        dprintf(s,
                "Content-Length: %d\r\n",
                content_length);

    dprintf(s, 
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Connection: close\r\n"
            "\r\n");
}



static void grpmsg2json(
        char *buf,
        size_t siz,
        const char *group_no,
        const char *msg /* escaped */
)
{
    /*
{
    'target': group_no,
    'messageChain': [
        {'type': 'Plain', 'text': text}
    ]
}
    */

    snprintf(buf, siz,
"{"
    Q("target") S "%s" C 
    Q("messageChain") S
        "["
            "{"
                P("type", "Plain") C
                P("text", "%s")
            "}"
        "]"
"}",
        group_no,
        msg);
}




/* returns a static buffer */
static const char *i2s(
        int i
)
{
    static char buf[40];

    if (snprintf(buf, sizeof buf, "%d", i) <= 0)
        buf[0] = 0;
    
    return buf;
}




static void sendmsg_grp(
        const char *group_no,
        const char *msg /* escaped */
)
{
    int sock;
    char buf[4096];
    size_t n;
    /* QQ message should not be too long, esp. those from bot */

    /* reject empty input */

    if (group_no == NULL)
        return;

    if (msg == NULL)
        return;

    /* create socket */

    sock = socket2(1);

    if (sock < 0)
    {
        perror("socket2(1)");
        return;
    }

    /* prepare message */
    grpmsg2json(buf, sizeof buf, group_no, msg);

    n = strlen(buf);

    /* send */
    mah_send_header(sock, "POST", "sendGroupMessage", n);
    write(sock, buf, n);

    /* waiting for response */
    puts("message sent, waiting for response from mah");
    readhttp(&sock, NULL, NULL);
}





static int grpmsg_extract_grpid(const char *msg)
{
    const char *p;
    int grpid = -1;

    p = strstr2(msg, "\"group\":{\"id\":");
    
    if (0 == p)
        return -1;

    if (1 != sscanf(p, "%d", &grpid))
        return -1;

    if (grpid <= 0)
        return -1;

    return grpid;
}



/* "bar...str..."
 *  ^
 *  #s
 *
 * not support escape characters
 */
static void json_extract_str(
        const char *str,
        char *buf,
        size_t bufsiz)
{
    char *p;

    strncpy(buf, str, bufsiz);
    buf[bufsiz - 1] = 0;

    for (p = buf; *p && *p != '\"'; ++p);
    *p = 0;
}


static int grpmsg_extract_membername(
        const char *msg,
        char *buf,
        size_t bufsiz)
{
    const char *p;
    
    p = strstr2(msg, "\"sender:\"{\"id\":");

    if (!p)
        return -1;

    p = strstr2(p, "\"memberName\":\"");
    
    if (!p)
        return -1;
   
    json_extract_str(
            p, buf, bufsiz
    ); 

    return 0;
}






static const char *process_grpmsg_img(
        const char *msg,
        const char *member_name
)
{
    char imgid[100];
    const char *p;
    
    p = strstr2(msg, "{\"type\":\"Image\",\"imageId\":\"");

    if (p == NULL)
        return NULL;


    json_extract_str(p, imgid, sizeof imgid);

    if (0 == startswith(imgid,
                "{28D3C652-4B39-743A-BD92-22E2AEE2B940}"))
        return "吃";
    
    if (0 == startswith(imgid,
                "{E01253FE-83B3-05BD-9277-41A01DCAF865}"))
        return "吃";

    return NULL;
}



/* returns a static buffer */
static const char *get_random_sl(
        const char *db /* name. e.g. sl, br */
)
{
    static char buf[4096];

    /* TODO */

    return NULL;
}



/* returns 0: success */

typedef int (*txt_grpmsg_handler)(
        const char *,
        const char *,
        char *,
        size_t
);


#define TXT_GRPMSG_HANDLER_FN(n) txt_grpmsg_handler##n
#define DEF_TXT_GRPMSG_HANDLER(n) \
    static int TXT_GRPMSG_HANDLER_FN(n)( \
            const char *msg, /* won't be too long. stripped */ \
            const char *member_name, \
            char *buf, /* reply msg */ \
            size_t bufsiz \
    )


DEF_TXT_GRPMSG_HANDLER(1)
{
    return -1;
}

DEF_TXT_GRPMSG_HANDLER(2)
{
    return -1;
}

DEF_TXT_GRPMSG_HANDLER(3)
{
    return -1;
}

DEF_TXT_GRPMSG_HANDLER(4)
{
    return -1;
}

DEF_TXT_GRPMSG_HANDLER(5)
{
    return -1;
}

DEF_TXT_GRPMSG_HANDLER(6)
{
    return -1;
}


/* returns a static buffer */
static const char *process_grpmsg_txt(
        const char *msg,
        const char *membername
)
{
    static char reply[4096];
    char buf[4096]; /* message content */
    const char *p;
    const txt_grpmsg_handler handlers[] =
    {
        TXT_GRPMSG_HANDLER_FN(1),
        TXT_GRPMSG_HANDLER_FN(2),
        TXT_GRPMSG_HANDLER_FN(3),
        TXT_GRPMSG_HANDLER_FN(4),
        TXT_GRPMSG_HANDLER_FN(5),
        TXT_GRPMSG_HANDLER_FN(6),
        NULL
    }, *h;

    p = strstr2(msg, "{\"type\":\"Plain\",\"text\":\"");

    if (p == NULL)
        return NULL;

    json_extract_str(p, buf, sizeof buf);
    strip(buf);

    /* buf: message content */

    for (h = handlers; *h; ++h)
    {
        if (0 == (*h)(buf, membername, reply, sizeof reply))
            return reply;
    }

    return NULL;
}



/* process message from mah
 * #msg points to data body (JSON)
 */
static void process_grpmsg(const char *msg)
{
    char *p;
    int grpid = -1;
    const char *grpid_str;
    const char *replymsg = NULL;
    char membername[40];
    char buf[1024];

    /* empty message, do not handle */

    if (msg == NULL)
        return;

    if (*msg == 0)
        return;

    /* check if is GroupMessage */

    p = strstr2(msg, "{\"type\":\"");
    
    /* not GroupMessage, do not handle */
    
    if (p == NULL)
        return;

    if (0 != startswith(p, "GroupMessage"))
        return;

    /* extract information */
    grpid = grpmsg_extract_grpid(msg);

    if (grpid <= 0)
        return;


    if (0 != grpmsg_extract_membername(
                msg, membername,
                sizeof membername))
        return;

    grpid_str = i2s(grpid);

    /* reply */
    replymsg = process_grpmsg_txt(msg, membername);

    if (p)
    {
        sendmsg_grp(grpid_str, replymsg);
        return;
    }

    replymsg = process_grpmsg_img(msg, membername);
    
    if (p)
    {   
        sendmsg_grp(grpid_str, replymsg);
        return;
    }
}



/* receive and process message from mah */
static void recv_msg(int con)
{
    int fd;
    char *s, *p;

    fd = get_logfd();
    
    if (fd < 0)
        puts("\n--CRITICAL: open() failed, what the fuck?");

    s = alloc0(2048);
    readhttp(&con, &fd, &s);
    
    puts("\n---End\n\n");

    p = strstr(s, "\r\n\r\n") + 4;
    /* p points to message body */
    process_grpmsg(p);
    free2(&s);
}



static void event_loop(
        const int s /* sockfd for server listening */
)
{
    int addr_inited = 1; /* 0 for true */

    while (1)
    {
        int con;

        if (stop_flag == 0)
        {
            puts("\n--stop flag set");
            break;
        }

        con = accept2(s, addr_inited);

        if (con < 0)
            continue;
        
        addr_inited = 0;
        recv_msg(con);
        close2(&con);
    }
}


/* read a file
 * no \0 in file content
 *
 * return an allocated string, don't forget to free()
 */
static char *freadstr_alloc(
        const char *filename
)
{
    int fd;
    char *p, buf[1024];
    size_t n;

    fd = open(filename, O_RDONLY);

    if (fd <= 0)
        return NULL;

    p = alloc0(1024);

    while ((n = read(fd, buf, 1023)) > 0)
    {
        buf[n] = 0;
        strcat_realloc(&p, buf);
    }

    close2(&fd);

    return p;
}





/* post to mah and return response
 *
 * returns an allocated string, don't forget to free
 */
static char *mah_post(
        const char *what,
        const char *body /* \0 terminated */
)
{
    int s = socket2(1);
    char *b;

    if (s < 0)
    {
        perror("--failed to create socket for mah post");
        return NULL;
    }

    /* request */

    mah_send_header(
            s, "POST", what,
            (int) strlen(body)
            );

    write(s, body, strlen(body));

    shutdown(s, SHUT_WR);

    /* response */

    puts("--reading response\n");
    b = alloc0(1024);
    readhttp(&s, NULL, &b);

    return b;
}


/* mirai identification
 *
 * will fail if the verify key is too long for #buf to hold, or contains escape letters
 */
static void verify(void)
{
    char buf[1024];
    char *s;

    s = freadstr_alloc("verifykey");

    if (s == NULL)
    {
        fprintf(stderr, "CRITICAL: verifykey not exists\n");
        return;
    }

    strip(s);
    snprintf(buf, sizeof buf, "{\"verifyKey\": \"%s\"}", s);
    free2(&s); 

    puts("sending verification request");
    s = mah_post("verify", buf);
    free2(&s);
}


int main(int argc, char *argv[])
{
    int s;

    configure();

    errno = 0;   
    s = socket2(0);
    
    if (s < 0)
    {
        perror("failed to create server socket");

        if (errno == EADDRINUSE)
        {
            puts("trying alternative port");
            ++conf.server_port;
            s = socket2(0);

            if (s < 0)
            {
                perror("failed again");
                return -3;
            }
        }
        else
            return -1;
    }
    
    regsig();
    
    puts("initialisation success");
  
    if (argc != 1)
        verify(); 

    puts("entering event loop");
    event_loop(s);

    close2(&s);
    return 0;
}
