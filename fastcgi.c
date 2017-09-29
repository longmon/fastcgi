#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <limits.h>

#define MAX_ACCEPT_EVENTS 128
#define FCGI_KEEP_CONN 1
#define FCGI_MAX_LENGTH oxffff
#define FCGI_VERSION_1 1

#define FCGI_REQUEST_COMPLETE    0
#define FCGI_CANT_MPX_CONN       1
#define FCGI_OVERLOADED          2
#define FCGI_UNKNOWN_ROLE        3

//请求类型
#define FCGI_BEGIN_REQUEST		  1 /* [in]                              */
#define FCGI_ABORT_REQUEST		  2 /* [in]  (not supported)             */
#define FCGI_END_REQUEST		  3 /* [out]                             */
#define FCGI_PARAMS				  4 /* [in]  environment variables       */
#define FCGI_STDIN				  5 /* [in]  post data                   */
#define FCGI_STDOUT				  6 /* [out] response                    */
#define FCGI_STDERR				  7 /* [out] errors                      */
#define FCGI_DATA				  8 /* [in]  filter data (not supported) */
#define FCGI_GET_VALUES			  9 /* [in]                              */
#define FCGI_GET_VALUES_RESULT	 10  /* [out]                             */
//Webebtk 
#define FCGI_RESPONDER   1
#define FCGI_AUTHORIZER  2
#define FCGI_FILTER      3

typedef struct _fcgi_header {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} fcgi_header;

typedef struct 
{
    unsigned char roleB1;       //web服务器所期望php-fpm扮演的角色，具体取值下面有
    unsigned char roleB0;
    unsigned char flags;        //确定php-fpm处理完一次请求之后是否关闭
    unsigned char reserved[5];  //保留字段
} fcgi_begin_request_body;

typedef struct 
{
    unsigned char appStatusB3;      //结束状态，0为正常
    unsigned char appStatusB2;
    unsigned char appStatusB1;
    unsigned char appStatusB0;
    unsigned char protocolStatus;   //协议状态
    unsigned char reserved[3];
} fcgi_end_request_body;

int socket_bind_listen(const char *unix_socket_path );

int socket_accept( int fid );

int make_socket_nonblock( int fid );

int fcgi_read_handler( int fd );

int safe_read( int fd, void *buf, int len );

int fcgi_response( int fd, const char *content );

int debug( const char *data, const char *logFile );

int main() {
    int sck = socket_bind_listen("/tmp/fastcgi.sock");
    if( sck < 0 ){
        return -1;
    }
    make_socket_nonblock( sck );

    if( socket_accept( sck ) < 0 ){
        return -2;
    }
    return 0;
}

int socket_bind_listen( const char *unix_socket_path ) {
    int fid, len, s;
    struct sockaddr_un un;
    unlink(unix_socket_path);
    fid = socket(AF_UNIX, SOCK_STREAM, 0);
    if( fid < 0 ){
        perror("create socket");
        return -1;
    }
    
    memset(&un, 0, sizeof(struct sockaddr_un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, unix_socket_path);

    len = offsetof(struct sockaddr_un, sun_path)+strlen(unix_socket_path);

    s = bind( fid, (struct sockaddr *)&un, len);
    if( s < 0 ){
        close(fid);
        perror("bind socket");
        return -2;
    }
    chmod(unix_socket_path, 0777);
    if( listen( fid, 128 ) < 0 ){
        close(fid);
        perror("listen error");
        return -3;
    }
    return fid;
}

int socket_accept( int fid ) {
    int epoll_fd = 0, s;
    struct epoll_event event;
    struct epoll_event events[MAX_ACCEPT_EVENTS] = {0};

    epoll_fd = epoll_create1(0);
    if( epoll_fd < 0 )
    {
        perror("create_epoll error");
        return -1;
    }
    event.data.fd = fid;
    event.events = EPOLLIN|EPOLLET;
    s = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fid, &event);
    if( s == -1 ) {
        perror("epoll ctl error");
        return -2;
    }
    for(;;) {
        int n,i;
        n = epoll_wait( epoll_fd, events, MAX_ACCEPT_EVENTS, -1);
        for( i = 0; i < n; i++ ) {
            if( (events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!events[i].events &EPOLLIN) ) {
                epoll_ctl( epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                close(events[i].data.fd);
                continue;
            } else if( events[i].data.fd == fid ) {
                for(;;) {
                    struct sockaddr_in inaddr;
                    socklen_t inlen;
                    inlen = sizeof(inaddr);
                    int socket_in = accept( fid, (struct sockaddr*)&inaddr, &inlen);
                    if( socket_in == -1 ){
                        break;
                    }
                    make_socket_nonblock(socket_in);
                    event.data.fd = socket_in;
                    event.events = EPOLLIN|EPOLLET;
                    if( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_in, &event ) < 0 ){
                        perror("socket in add epoll error");
                        close(socket_in);
                        break;
                    }
                }
                continue;
            }else {
                int done = 0;
                for(;;){
                    if(fcgi_read_handler(events[i].data.fd) < 0 ) {
                        break;
                    }
                    fcgi_response(events[i].data.fd, "Content-type: text/html\r\n\r\ni have a recved your msg!");
                }
                if( done == 1 ){
                    printf("socket read done\n");
                    epoll_ctl( epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                    close(events[i].data.fd);
                }
            }
        }
    }
    close(epoll_fd);
    close(fid);
    return 0;
}

int make_socket_nonblock( int fid ) {
    int flag = fcntl(fid, F_GETFL, 0);
    if( flag < 0 ){
        perror("fcntl get error");
        return -1;
    }
    flag = flag | O_NONBLOCK;
    if( fcntl( fid, F_SETFL, flag ) < 0 ) {
        perror("fcntl set error");
        return -2;
    }
    return 0;
}

int fcgi_read_handler( int fd ) {
    fcgi_header hdr;
    unsigned char buf[FCGI_MAX_LENGTH+8];
    int contentLength, paddingLength, hdrLength;
    hdrLength = sizeof(fcgi_header);
    memset(&hdr, 0, hdrLength);
    int requestId = 0;

    if(safe_read( fd, &hdr, hdrLength ) != hdrLength || hdr->version < FCGI_VERSION_1 ){
        return -1;
    }
    contentLength = (hdr.contentLengthB1 << 8)|hdr.contentLengthB0;
    paddingLength = hdr.paddingLength;
    while( hdr.type == FCGI_STDIN && contentLength == 0 ) {
        if(safe_read( fd, &hdr, hdrLength ) != hdrLength || hdr->version < FCGI_VERSION_1 ){
            return -1;
        }
        contentLength = (hdr.contentLengthB1 << 8)|hdr.contentLengthB0;
        paddingLength = hdr.paddingLength;
    }
    if( contentLegnth + paddingLength > FCGI_MAX_LENGTH ) {
        return -1;
    }
    requestId = (hdr.requestIdB1 << 8 ) | hdr.requestIdB0;
    if( hdr.type == FCGI_BEGIN_REQUEST && contentLength == sizeof( fcgi_begin_request_body ) ) {
        if( safe_read( fd, buf, contentLength + paddingLength ) != contentLength + paddingLength ) {
            return -1;
        }
        
    }

}

int safe_read( int fd, void *buf, int len ) {
    int n;
    if( fd <= 0 ){
        return 0;
    }
    n = read( fd, buf, len );
    if( n < 0 ) {
        if ( errno != EAGAIN ){
            perror("read error");
        }
        return -1;
    } else if( n == 0 ) {
        return 0;
    }
    return n;
}

int fcgi_response( int fd, const char *content ){
    int len = strlen(content);
    int count = 0;
    if( (count = write(fd, content, len)) <= 0 ){
        perror("write error");
        return -1;
    }
    return count;
}

int debug( const char *data, const char *logFile ) {
    FILE *fp;
    fp = fopen(logFile,"a+");
    if( !fp ) {
        perror("fopen");
        return -1;
    }
    printf("data len %d\n", strlen(data));
    fwrite(data, sizeof(char),strlen(data), fp );
    fwrite("\n", sizeof(char), 1, fp);
    fclose(fp);
}
