/*
 *HTTP-Radius authentication
 *2014-03-06 created by qudreams
 *All rights reserved.
 */

#ifndef NGX_HTTP_AUTH_RADIUS_H
#define NGX_HTTP_AUTH_RADIUS_H

#include <ngx_config.h> 
#include <ngx_core.h> 
#include <ngx_http.h>

#include <errno.h> 
#include <stdio.h> 
#include <ctype.h> 
#include <netdb.h> 
#include <time.h> 
#include <getopt.h>
#include <assert.h>
#include <stdint.h>

#include <radius.h>
#include <libradius.h> 
#include <packet.h> 
/*Microsoft CHAP*/ 
#include <mschap.h> 
#include <smbdes.h> 
/*end Microsoft*/ 
#include <radclient.h> 
//eap
#include <radeapclient.h> 

#define RADIUS_PWD_LEN      128
#define RADIUS_SECRET_LEN   64
#define MAX_SESSION_ID_LEN  128
#define RADIUS_USERNAME_LEN 253

#define NGX_HTTP_AUTH_RADIUS_OK                 0
#define NGX_HTTP_AUTH_RADIUS_REJECT             -1
#define NGX_HTTP_AUTH_RADIUS_TIMEDOUT           -2
#define NGX_HTTP_AUTH_RADIUS_INTERNAL_ERROR     -3 

typedef struct ngx_http_auth_radius_request_s ngx_http_auth_radius_request_t;
typedef struct ngx_http_auth_radius_proxy_s ngx_http_auth_radius_proxy_t;
typedef struct ngx_http_auth_radius_connection_s ngx_http_auth_radius_connection_t;
typedef struct ngx_http_auth_radius_ctx_s ngx_http_auth_radius_ctx_t;
typedef struct ngx_http_auth_radius_server_s ngx_http_auth_radius_server_t;
typedef struct ngx_http_auth_radius_loc_conf_s ngx_http_auth_radius_loc_conf_t;

typedef void (*ngx_http_auth_radius_handler_pt)(ngx_http_auth_radius_request_t*);

struct ngx_http_auth_radius_request_s {
    ngx_queue_t                         queue;
	RADIUS_PACKET*                      request;
	RADIUS_PACKET*                      reply;
    
	char                                password[RADIUS_PWD_LEN];	
	time_t                              timestamp;
    time_t                              expire;

    /*the times that we have tried to send it*/	
	int8_t                              tries;
	uint8_t                             done;	
    ngx_int_t                           error_code;
    ngx_http_auth_radius_handler_pt     handler;
    ngx_pool_t*                         pool; //pointer to the ngx_http_request_t->pool
    void*                               data; //pointer to ngx_http_auth_radius_ctx_t
};

struct ngx_http_auth_radius_connection_s {
	ngx_connection_t*               c;
	time_t                          last_used;
	void*                           data;
};

struct ngx_http_auth_radius_proxy_s {
	ngx_event_t                     resend_event; /*resend timeout*/
	ngx_log_t*                      log;
	fr_packet_list_t*               request_packets;
	ngx_queue_t                     requests;	
	ngx_uint_t                      log_level;
	ngx_int_t                       conn_counter;
    /*udp connections.Note: it's just a socket.we don't connect udp-server*/
	fr_hash_table_t*                udp_connections; 
    ngx_pool_t*                     pool;
};

struct ngx_http_auth_radius_ctx_s {
    ngx_http_request_t*             r;
    ngx_http_auth_radius_request_t* rr; /*radius request*/ 
    ngx_http_auth_radius_proxy_t*   proxy;
    ngx_http_auth_radius_loc_conf_t* rlcf;    
};


struct ngx_http_auth_radius_server_s {
    ngx_str_t           alias; //the alias name
    ngx_str_t           url;//the url of radius server like [host]:[port]
    ngx_url_t           parsed_url; //parsed url 
    ngx_int_t           auth_timeout;//radius authentication time-out
    ngx_int_t           resend_limit;//the limit of times to resend radius request.
    ngx_str_t           share_secret; //share secret
};

typedef struct {
    ngx_array_t*        servers;
    ngx_str_t           dict_dir; //radius dictionary directory
} ngx_http_auth_radius_main_conf_t;

struct ngx_http_auth_radius_loc_conf_s {
    ngx_http_auth_radius_server_t* server;//pointer to radius server
    ngx_int_t                      auth_type;
    ngx_str_t                      realm;
};


ngx_int_t 
ngx_http_auth_radius_dict_init(const ngx_str_t* dict_dir,ngx_log_t* log);

ngx_http_auth_radius_connection_t* 
ngx_http_auth_radius_connect(int family,ngx_pool_t* pool,ngx_log_t* log);

ngx_http_auth_radius_connection_t* 
ngx_http_auth_radius_create_connection(ngx_http_auth_radius_proxy_t* proxy,int sf);

void 
ngx_auth_radius_recv_response(ngx_event_t* rev);

ngx_http_auth_radius_request_t* 
ngx_http_auth_radius_create_request(ngx_http_auth_radius_proxy_t* proxy,
        ngx_http_request_t* r);

void 
ngx_http_auth_radius_destroy_request(ngx_http_auth_radius_proxy_t* proxy,
        ngx_http_auth_radius_request_t* r);

ngx_int_t 
ngx_auth_radius_send_request(ngx_http_request_t* r);

ngx_http_auth_radius_proxy_t* 
ngx_http_auth_radius_create_proxy(ngx_pool_t* pool);

void 
ngx_http_auth_radius_close_connection(ngx_http_auth_radius_connection_t* uc);

void 
ngx_auth_radius_resend_handler(ngx_event_t* ev);

ngx_int_t
ngx_http_auth_radius_set_realm(ngx_http_request_t* r,const ngx_str_t* realm);

ngx_int_t
ngx_http_auth_radius_authenticate(ngx_http_request_t* r);

extern ngx_module_t ngx_http_auth_radius_module;

#endif
