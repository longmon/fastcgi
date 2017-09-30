#ifndef _FASTCGI_HEAD_
#define _FASTCGI_HEAD_

    #define MAX_ACCEPT_EVENTS 128
    #define FCGI_KEEP_CONN 1
    #define FCGI_MAX_LENGTH 0xfff
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

    typedef struct {
        unsigned char roleB1;       //web服务器所期望php-fpm扮演的角色，具体取值下面有
        unsigned char roleB0;
        unsigned char flags;        //确定php-fpm处理完一次请求之后是否关闭
        unsigned char reserved[5];  //保留字段
    } fcgi_begin_request_body;

    typedef struct {
        unsigned char appStatusB3;      //结束状态，0为正常
        unsigned char appStatusB2;
        unsigned char appStatusB1;
        unsigned char appStatusB0;
        unsigned char protocolStatus;   //协议状态
        unsigned char reserved[3];
    } fcgi_end_request_body;

    typedef struct {
        fcgi_header hdr;
        fcgi_end_request_body body;
    } fcgi_end_req_record;

    typedef struct {
        int fd;
        int reqid;
        int keep;
        int role;
        fcgi_header hdr;
    } fcgi_request;

    int socket_bind_listen(const char *unix_socket_path );

    int socket_accept( int fid );

    int make_socket_nonblock( int fid );

    int fcgi_request_handler( fcgi_request *req );

    int safe_read( int fd, void *buf, int len );

    int fcgi_response( fcgi_request *req , int type, void *buf, int len );

    int debug( const char *logFile, void *data, int len );

    int fcgi_make_header( fcgi_header *hdr, unsigned char type, int reqid, int contentLength);

    void fcgi_end_request( fcgi_request *req );

    int safe_write( int fd, void *buffer, int len );

    size_t fcgi_get_params_len( int *result, unsigned char *p, unsigned char *end );

    int fcgi_get_params(unsigned char *p, unsigned char *end);

#endif