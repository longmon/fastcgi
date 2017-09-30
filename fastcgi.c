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
#include "fastcgi.h"

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

int socket_accept( int fd ) {
    struct sockaddr_in inaddr;
    socklen_t inlen;
    inlen = sizeof(inaddr);
    int sock_in;
    for(;;){
        sock_in = accept(fd, (struct sockaddr*)&inaddr, &inlen );
        if( sock_in > 0 ){
            fcgi_request req;
            memset(&req, 0, sizeof(fcgi_request));
            req.fd = sock_in;
            fcgi_request_handler( &req );
        }
    }
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

int fcgi_request_handler( fcgi_request *req ) {
    unsigned char buf[FCGI_MAX_LENGTH+8];
    int contentLength, paddingLength, hdrLength;
    hdrLength = sizeof(fcgi_header);

    if(safe_read( req->fd, &(req->hdr), hdrLength ) != hdrLength || req->hdr.version < FCGI_VERSION_1 ){
        return -1;
    }
    contentLength = (req->hdr.contentLengthB1 << 8)|req->hdr.contentLengthB0;
    paddingLength = req->hdr.paddingLength;
    while( req->hdr.type == FCGI_STDIN && contentLength == 0 ) {
        if(safe_read( req->fd, &(req->hdr), hdrLength ) != hdrLength || req->hdr.version < FCGI_VERSION_1 ){
            return -1;
        }
        contentLength = (req->hdr.contentLengthB1 << 8)| req->hdr.contentLengthB0;
        paddingLength = req->hdr.paddingLength;
    }
    if( contentLength + paddingLength > FCGI_MAX_LENGTH ) {
        return -1;
    }
    req->reqid = (req->hdr.requestIdB1 << 8 ) | req->hdr.requestIdB0;
    if( req->hdr.type == FCGI_BEGIN_REQUEST && contentLength == sizeof( fcgi_begin_request_body ) ) {
        if( safe_read( req->fd, buf, contentLength + paddingLength ) != (contentLength + paddingLength) ) {
            return -1;
        }
        req->role = (((fcgi_begin_request_body*)buf)->roleB1 << 8) | ((fcgi_begin_request_body*)buf)->roleB0;
        req->keep = ((fcgi_begin_request_body*)buf)->flags & FCGI_KEEP_CONN;

        //======================================
        //****to do deal with request role*****
        //======================================

        if(safe_read( req->fd, &(req->hdr), hdrLength ) != hdrLength || req->hdr.version < FCGI_VERSION_1 ){
            return -1;
        }
        contentLength = (req->hdr.contentLengthB1 << 8) | req->hdr.contentLengthB0;
        paddingLength = req->hdr.paddingLength;

        while( req->hdr.type == FCGI_PARAMS && contentLength > 0 ){
            if( contentLength + paddingLength > FCGI_MAX_LENGTH ){
                return -1;
            }
            if( safe_read(req->fd, buf, contentLength+paddingLength) != contentLength+paddingLength ) {
                return -1;
            }
            debug("debug.php", buf, contentLength+paddingLength );
            
            if(safe_read( req->fd, &(req->hdr), hdrLength ) != hdrLength || req->hdr.version < FCGI_VERSION_1 ){
                return -1;
            }
            contentLength = (req->hdr.contentLengthB1 << 8) | req->hdr.contentLengthB0;
            paddingLength = req->hdr.paddingLength;
        }

        char *msgBody = "Content-type: text/html\r\n\r\ni have a recved your msg!";
        fcgi_response( req, FCGI_STDOUT, msgBody, strlen(msgBody) );

        fcgi_end_request(req);

    } else if( req->hdr.type == FCGI_GET_VALUES ){
        printf("FCGI_GET_VALUES ===============> \n");
    } else {
        return 0;
    }
    return 0;
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

int fcgi_response( fcgi_request *req, int type, void *buf, int len ){

    if( !buf || !len ) {
        return -1;
    }
    fcgi_make_header(&(req->hdr), type, req->reqid, len );
    int count = 0;
    if( (count = safe_write(req->fd, (void *)&(req->hdr), sizeof(req->hdr))) <= 0 ){
        return -1;
    }
    if( (count = safe_write(req->fd, buf, len)) <= 0 ) {
        return -1;
    }
    return count;
}

int debug( const char *logFile, void *data, int len ) {
    FILE *fp;
    fp = fopen(logFile,"a+");
    if( !fp ) {
        perror("fopen");
        return -1;
    }
    fwrite(data, sizeof(char), len, fp );
    fwrite("\n", sizeof(char), 1, fp);
    fclose(fp);
}

int fcgi_make_header( fcgi_header *hdr, unsigned char type, int reqid, int contentLength ) {
    hdr->version    = FCGI_VERSION_1;
    hdr->type       = type;
    hdr->requestIdB1= (reqid >> 8) & 0xff;
    hdr->requestIdB0= reqid & 0xff;
    hdr->contentLengthB1 = (contentLength >> 8) & 0xff;
    hdr->contentLengthB0 = contentLength & 0xff;
    hdr->paddingLength = 0;
    hdr->reserved = 0;
    return 0;
}

void fcgi_end_request( fcgi_request *req ) 
{
    fcgi_end_req_record ereq_rec;
    ereq_rec.body.protocolStatus = FCGI_REQUEST_COMPLETE;
    ereq_rec.body.appStatusB3 = 0;
    ereq_rec.body.appStatusB2 = 0;
    ereq_rec.body.appStatusB1 = 0;
    ereq_rec.body.appStatusB0 = 0;
    fcgi_make_header( &(ereq_rec.hdr), FCGI_END_REQUEST, req->reqid, sizeof(fcgi_end_request_body) );
    safe_write(req->fd, (void *)&ereq_rec, sizeof(ereq_rec));
    if( !(req->keep & FCGI_KEEP_CONN) ) {
        close(req->fd);
    }
    return;
}

int safe_write( int fd, void *buffer, int len )
{
    int count;
    if( !buffer || len <= 0 ){
        return -1;
    }
    count = write( fd, buffer, len );
    if( count <= 0 ){
        perror("write error");
        return -2;
    }
    return count;
}
/**
typedef struct {
    unsigned char nameLengthB3;  // nameLengthB3  >> 7 == 1 
    unsigned char nameLengthB2;
    unsigned char nameLengthB1;
    unsigned char nameLengthB0;
    unsigned char valueLengthB3; //valueLengthB3 >> 7 == 1
    unsigned char valueLengthB2;
    unsigned char valueLengthB1;
    unsigned char valueLengthB0;
    unsigned char nameData[nameLength
            ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
    unsigned char valueData[valueLength
            ((B3 & 0x7f) << 24) + (B2 << 16) + (B1 << 8) + B0];
} FCGI_NameValuePair44;
*/
size_t fcgi_get_params_len( int *result, unsigned char *p, unsigned char *end ) 
{
    size_t ret;
    if( p < end ) {
        *result = p[0];//将第一字节赋值给result
        if( *result >> 7 == 1 ) { //高位右移7位得到1，表明需要4字节，否则需要一字节
            if( p + 3 < end ){ 
                *result = (*result & 0x7f) << 24;
                *result |= p[1] << 16;
                *result |= p[2] << 8;
                *result |= p[3];
                ret = 4;
            }
        } else { //长度用一个字节表示了
            ret = 1;
        }
    }
    if( *result < 0 ){
        ret = 0;
    }
    return ret;
}

int fcgi_get_params(unsigned char *p, unsigned char *end) {
    int name_len;
    int val_len;
    sise_t bytes_consumed;
    int ret = 1;
    while( p < end ) {
        bytes_consumed = fcgi_get_params_len( &name_len, p, end);
        if( !bytes_consumed ){
            ret = 0;
            break;
        }
        printf("name_len:%d\n", name_len);
        p += bytes_consumed;
        bytes_consumed = fcgi_get_params_len( &val_len, p, end);
        if( !bytes_consumed ){
            ret = 0;
            break;
        }
        printf("vaL_len:%d\n", val_len);
        p += bytes_consumed;

    }
}

int fcgi_get_params_name( unsigned char *name, int name_len, unsigned char *p, unsigned char *end ) {
    
}

