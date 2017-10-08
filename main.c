#include "fastcgi.h"
int main() {
    int sck = socket_bind_listen("/tmp/fastcgi.sock");
    if( sck < 0 ){
        return -1;
    }
    if( socket_accept( sck ) < 0 ){
        return -2;
    }
    return 0;
}