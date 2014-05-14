/*
 *ngx_http_auth_radius_module.c: 2014-03-02 created for HTTP-radius authentication
 *all rights reserved to qudreams.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <radclient.h>
#include "ngx_http_auth_radius.h"


#define     AUTH_RADIUS_UNKNOWN     -1

static u_char* auth_radius_types[] = {
    (u_char*)"PAP",
    (u_char*)"CHAP",
    (u_char*)"MSCHAP",
    (u_char*)"MSCHAP2",
    (u_char*)"EAPMD5"
};

static void* ngx_http_auth_radius_create_main_conf(ngx_conf_t* cf);
static char* ngx_http_auth_radius_init_main_conf(ngx_conf_t*cf,void* conf);
static void* ngx_http_auth_radius_create_loc_conf(ngx_conf_t* cf); 
static char* ngx_http_auth_radius_merge_loc_conf(ngx_conf_t*cf,void* prev,void* conf);

static char* ngx_http_auth_radius_block(ngx_conf_t* cf,ngx_command_t* cmd,void* conf);
static char* ngx_http_auth_radius_server(ngx_conf_t* cf,ngx_command_t* cmd,void* conf);
static char* ngx_http_auth_radius(ngx_conf_t* cf,ngx_command_t* cmd,void* conf);

static ngx_int_t ngx_http_auth_radius_init(ngx_conf_t* cf);
static ngx_int_t ngx_http_auth_radius_handler(ngx_http_request_t* r);


static ngx_command_t ngx_http_auth_radius_cmds[] = {
    {
        ngx_string("radius_server"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
        ngx_http_auth_radius_block,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL },
    {
        ngx_string("radius_dict_directory"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_auth_radius_main_conf_t,dict_dir),
        NULL },
    {
        ngx_string("auth_radius_server"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF| NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
        ngx_http_auth_radius_server,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    {
        ngx_string("auth_radius"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF| NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_auth_radius,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL }
};


static ngx_http_module_t ngx_http_auth_radius_module_ctx = {
    NULL,                                   /*preconfiguration*/
    ngx_http_auth_radius_init,              /*postconfiguration*/
    ngx_http_auth_radius_create_main_conf,  /*create main configuration*/
    ngx_http_auth_radius_init_main_conf,    /*init main configuration*/
    NULL,                                   /*create server configuration*/
    NULL,                                   /*merge server configuration*/ 
    ngx_http_auth_radius_create_loc_conf,   /*create location configuration*/
    ngx_http_auth_radius_merge_loc_conf      /*merge location configuration*/
};


ngx_module_t ngx_http_auth_radius_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_radius_module_ctx,
    ngx_http_auth_radius_cmds,
    NGX_HTTP_MODULE,
    NULL,                   /*init master*/
    NULL,                   /*init module*/
    NULL,                   /*init process*/
    NULL,                   /*init thread*/
    NULL,                   /*exit thread*/
    NULL,                   /*exit process*/
    NULL,                    /*exit master*/ 
    NGX_MODULE_V1_PADDING
};


static ngx_http_auth_radius_proxy_t* auth_radius_proxy = NULL;

static void*
ngx_http_auth_radius_create_main_conf(ngx_conf_t* cf) {
    ngx_http_auth_radius_main_conf_t* rmcf = NULL;
    
    rmcf = ngx_pcalloc(cf->pool,sizeof(*rmcf));
    if(rmcf != NULL) {
        ngx_str_null(&rmcf->dict_dir);
    }

    return rmcf;
}


static char*
ngx_http_auth_radius_init_main_conf(ngx_conf_t* cf,void* conf) {
    ngx_http_auth_radius_main_conf_t* rmcf = conf;

    if(ngx_http_auth_radius_dict_init(&rmcf->dict_dir,
        cf->log) == NGX_ERROR) {

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static void*
ngx_http_auth_radius_create_loc_conf(ngx_conf_t* cf) {

    ngx_http_auth_radius_loc_conf_t* rlcf = NULL;

    rlcf = ngx_pcalloc(cf->pool,sizeof(*rlcf));
    if(rlcf != NULL) {
        rlcf->server = NGX_CONF_UNSET_PTR;
        rlcf->auth_type = NGX_CONF_UNSET;
    }

    return rlcf;
}


static char*
ngx_http_auth_radius_merge_loc_conf(ngx_conf_t* cf,
        void* prev,void* conf) 
{
    ngx_http_auth_radius_loc_conf_t* child = conf;
    ngx_http_auth_radius_loc_conf_t* parent = prev;

    ngx_conf_merge_ptr_value(child->server,
            parent->server,NULL);
    ngx_conf_merge_value(child->auth_type,
            parent->auth_type,PAP);

    return NGX_CONF_OK;
}


static char*
ngx_http_auth_radius_server_block(ngx_conf_t* cf,
        ngx_command_t* dummy,void* conf) 
{
    ngx_str_t* val = NULL;
    ngx_http_auth_radius_main_conf_t* rmcf = conf; 
    ngx_http_auth_radius_server_t* server = NULL;
    ngx_http_auth_radius_server_t* servers = NULL;

    servers = (ngx_http_auth_radius_server_t*)rmcf->servers->elts;
    server = servers + rmcf->servers->nelts - 1;

    if(cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_ERR,cf,0,
                "ngx_http_auth_radius: directive parameter is incorrect");
        return NGX_CONF_ERROR;
    }
    
    val = cf->args->elts;
    if(ngx_strncmp(val[0].data,(u_char*)"auth_timeout",val[0].len) == 0) {
        server->auth_timeout = ngx_atoi(val[1].data,val[1].len); 
    } else if(ngx_strncmp(val[0].data,(u_char*)"resend_limit",val[0].len) == 0) {
        server->resend_limit = ngx_atoi(val[1].data,val[1].len);
    } else if(ngx_strncmp(val[0].data,(u_char*)"url",val[0].len) == 0) {
        server->url = val[1];
    } else if(ngx_strncmp(val[0].data,(u_char*)"share_secret",val[0].len) == 0) {
        server->share_secret.data = ngx_pcalloc(cf->pool,val[1].len + 1);
        if(server->share_secret.data == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR,cf,0,
                "ngx_http_auth_radius: \
                out of memory to allocate memory for share secret");
            return NGX_CONF_ERROR;
        }

        ngx_memcpy(server->share_secret.data,val[1].data,val[1].len);
        server->share_secret.len = val[1].len;
    }

    return NGX_CONF_OK;
}


static char* 
ngx_http_auth_radius_block(ngx_conf_t* cf,
        ngx_command_t* cmd,void* conf)
{
    ngx_http_auth_radius_main_conf_t* rmcf = conf;
    ngx_conf_t saved = *cf; 
    ngx_str_t     *value,name;
    ngx_http_auth_radius_server_t* server = NULL;
    char* rv = NULL;

    value = cf->args->elts;
    name = value[1];
    if(name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG,cf,0,
                "ngx_auth_radius: Missing radius server name");
        return NGX_CONF_ERROR;
    }

    if(rmcf->servers == NULL) {
        rmcf->servers = ngx_array_create(cf->pool,5,sizeof(*server));
        if(rmcf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    server = ngx_array_push(rmcf->servers);
    if(server == NULL) {
        return NGX_CONF_ERROR;
    }

    server->alias = name;
    cf->handler = ngx_http_auth_radius_server_block;
    cf->handler_conf = conf;
    rv = ngx_conf_parse(cf,NULL);
    *cf = saved;

    if(rv == NGX_CONF_OK) {
        if(server->url.data == NULL) {
            ngx_conf_log_error(NGX_LOG_ERR,cf,0,
                    "ngx_http_auth_radius: server url haven't been set.");
            return NGX_CONF_ERROR;
        }
                                                                           
        server->parsed_url.url = server->url;
        server->parsed_url.default_port = 1812;
        if(ngx_parse_url(cf->pool,&server->parsed_url) == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_ERR,cf,0,
                "ngx_http_auth_radius: illegal server ulr: %V",
                &server->url);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_radius_parse_auth_type(const ngx_str_t* type_name) {
    ngx_int_t auth_type = AUTH_RADIUS_UNKNOWN;
    ngx_uint_t i = 0;
    u_char* name = NULL;

    for(i = 0;i < sizeof(auth_radius_types) / sizeof(u_char*);i++) {
        name = *(auth_radius_types + i); 
        
        if(ngx_strncasecmp(type_name->data,name,type_name->len) == 0) {
            auth_type = i;                      
            break;
        }
    }
    
    return auth_type;
}


static char*
ngx_http_auth_radius(ngx_conf_t* cf,ngx_command_t* cmd,void* conf) {
    ngx_http_auth_radius_loc_conf_t* rlcf = conf;
    ngx_str_t* value = cf->args->elts;
    u_char* p = NULL;

    if(value[1].len == 3 && ngx_strncmp(value[1].data,"off",3) == 0) {
        ngx_str_set(&rlcf->realm,"");
        return NGX_CONF_OK;
    }

    rlcf->realm.len = sizeof("Basic realm=\"") - 1 + value[1].len + 1;
    rlcf->realm.data = ngx_pcalloc(cf->pool,rlcf->realm.len); 
    if(rlcf->realm.data == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(rlcf->realm.data,"Basic realm=\"",sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p,value[1].data,value[1].len);
    *p = '"';

    return NGX_CONF_OK;
}


static char*
ngx_http_auth_radius_server(ngx_conf_t* cf,ngx_command_t* cmd,void* conf) {
    ngx_http_auth_radius_loc_conf_t* rlcf = conf;
    ngx_http_auth_radius_main_conf_t* rmcf = NULL;
    ngx_http_auth_radius_server_t* server = NULL;
    ngx_http_auth_radius_server_t* servers = NULL;
    ngx_str_t* host_name = NULL;
    ngx_str_t* type_name = NULL;
    ngx_uint_t i = 0;

    rmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_auth_radius_module);

    host_name = (ngx_str_t*)(cf->args->elts) + 1;
    type_name = (ngx_str_t*)(cf->args->elts) + 2;

    servers = (ngx_http_auth_radius_server_t*)(rmcf->servers->elts);

    for(i = 0;i < rmcf->servers->nelts;i++) {
        server = servers + i;
        if(ngx_memcmp(server->alias.data,host_name->data,host_name->len) == 0) {
            rlcf->server = server;
            rlcf->auth_type = ngx_http_auth_radius_parse_auth_type(type_name);

            if(rlcf->auth_type == AUTH_RADIUS_UNKNOWN) {
                break;
            }

            return NGX_CONF_OK;;
        }
    }
    
    return NGX_CONF_ERROR;
}


static ngx_int_t
ngx_http_auth_radius_init(ngx_conf_t* cf) {
    ngx_http_core_main_conf_t* cmcf = NULL;
    ngx_http_handler_pt* h = NULL;
    
    
    auth_radius_proxy = ngx_http_auth_radius_create_proxy(cf->pool);
    if(auth_radius_proxy == NULL) {
        ngx_conf_log_error(NGX_LOG_ERR,cf,NGX_ENOMEM,
                "ngx_http_auth_radius: failed to create radius proxy");

        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);
    
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if(h == NULL) {
        return NGX_ERROR;
    }
    
    *h = ngx_http_auth_radius_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_radius_handler(ngx_http_request_t* r) {
    ngx_http_auth_radius_loc_conf_t* rlcf = NULL;
    ngx_int_t rc = NGX_OK; 
    ngx_http_auth_radius_ctx_t* ctx = NULL;
    ngx_http_auth_radius_request_t* rr = NULL;

    rlcf = ngx_http_get_module_loc_conf(r,ngx_http_auth_radius_module);
    if(rlcf == NULL || rlcf->realm.len == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r,ngx_http_auth_radius_module);
    if(ctx == NULL) {
        rc = ngx_http_auth_basic_user(r);
        if(rc == NGX_DECLINED) {
            return ngx_http_auth_radius_set_realm(r,&rlcf->realm);
        }

        if(rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, 
                r->connection->log, 0, "http_auth_radius: Username is \"%V\"",
                    &r->headers_in.user);
        if (r->headers_in.passwd.len == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, 
                r->connection->log, 0, "http_auth_radius: Password is empty");
            return ngx_http_auth_radius_set_realm(r,&rlcf->realm);
        }

        ctx = ngx_pcalloc(r->pool,sizeof(*ctx));
        if(ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        rr = ngx_http_auth_radius_create_request(auth_radius_proxy,r);
        if(rr == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        ctx->proxy = auth_radius_proxy;
        ctx->rr = rr;
        ctx->r = r;
        ctx->rlcf = rlcf;

        ngx_http_set_ctx(r,ctx,ngx_http_auth_radius_module);
    }

    rc = ngx_http_auth_radius_authenticate(r);
    if(rc != NGX_AGAIN) {
        ngx_http_auth_radius_destroy_request(auth_radius_proxy,ctx->rr);
    }

    return rc;
}
