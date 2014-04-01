#include "ngx_http_auth_radius.h" 

#define MAX_RADIUS_SOCKETS       			32

typedef void (*ngx_queue_walk_handler)(ngx_queue_t* q,void* ctx); 

static void 
ngx_http_auth_radius_response_post_event(ngx_http_auth_radius_proxy_t* proxy,
        RADIUS_PACKET* reply); 
static ssize_t ngx_http_auth_radius_recv(ngx_connection_t *c);
static void 
ngx_http_auth_radius_process_finish(ngx_http_auth_radius_request_t* rr);

void
ngx_queue_walk(ngx_queue_t* queue,
        ngx_queue_walk_handler walk_handler,void* ctx) 
{
    ngx_queue_t* q = NULL;
    ngx_queue_t* next = NULL;
    ngx_queue_t* sentinel = NULL;
    
    sentinel = ngx_queue_sentinel(queue);

    for(q = ngx_queue_head(queue);q != sentinel;q = next) {
        next = ngx_queue_next(q);
        walk_handler(q,ctx);
    }
}


ngx_http_auth_radius_connection_t* 
ngx_http_auth_radius_connect(int sf,ngx_pool_t*pool,ngx_log_t* log)
{
    ngx_int_t          event;
    ngx_event_t       *rev, *wev;
    ngx_socket_t       s;
    ngx_connection_t  *c = NULL;
	ngx_http_auth_radius_connection_t* uc = NULL;

	assert(pool != NULL && log != NULL);

	uc = ngx_pcalloc(pool,sizeof(*uc));
	if(uc == NULL) {
		ngx_log_error(NGX_LOG_ERR,log,
                NGX_ENOMEM,"failed to create radius connection");
		return NULL;
	}
	
    s = ngx_socket(sf, SOCK_DGRAM, 0);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT,log, 0, "UDP socket %d", s);

    if (s == -1) {
        ngx_log_error(NGX_LOG_ALERT,log, ngx_socket_errno,
                      ngx_socket_n " failed");
		ngx_pfree(pool,uc);
        return NULL;
    }

    c = ngx_get_connection(s,log);

    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT,log, ngx_socket_errno,
                          ngx_close_socket_n "failed");
        }
		ngx_pfree(pool,uc);
        return NULL;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT,log, ngx_socket_errno,
                      ngx_nonblocking_n " failed");

        ngx_free_connection(c);

        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT,log, ngx_socket_errno,
                          ngx_close_socket_n " failed");
        }

		ngx_pfree(pool,uc);
        return NULL;
    }

    rev = c->read;
    wev = c->write;

    rev->log = log;
    wev->log = log;
	

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

#if (NGX_THREADS)

    /* TODO: lock event when call completion handler */

    rev->lock = &c->lock;
    wev->lock = &c->lock;
    rev->own_lock = &c->lock;
    wev->own_lock = &c->lock;

#endif

    /* UDP sockets are always ready to write */
    wev->ready = 1;

    if (ngx_add_event) {

        event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ?
                    /* kqueue, epoll */                 NGX_CLEAR_EVENT:
                    /* select, poll, /dev/poll */       NGX_LEVEL_EVENT;
                    /* eventport event type has no meaning: oneshot only */

        if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {

			ngx_pfree(pool,uc);
            return NULL;
        }

    } else {
        /* rtsig */

        if (ngx_add_conn(c) == NGX_ERROR) {
			ngx_pfree(pool,uc);
            return NULL;
        }
    }
	uc->c = c;
	uc->last_used = time(NULL);

    return uc;
}


void 
ngx_http_auth_radius_close_connection(ngx_http_auth_radius_connection_t* uc)
{
	ngx_pool_t* pool = NULL;
    ngx_http_auth_radius_proxy_t* proxy = uc->data;
	
	pool = proxy->pool;	
	if(fr_packet_list_socket_remove(proxy->request_packets,uc->c->fd)) {
		ngx_log_debug(NGX_LOG_INFO,proxy->log,0,
                "ngx_http_auth_radius: close udp connection: socket=%d",uc->c->fd);	

		fr_hash_table_delete(proxy->udp_connections,uc);
		ngx_close_connection(uc->c);
		ngx_pfree(pool,uc);
		proxy->conn_counter--;
	}
}


static ssize_t 
ngx_http_auth_radius_recv(ngx_connection_t *c)
{
    ssize_t       n;
    ngx_err_t     err;
    ngx_event_t  *rev;
	RADIUS_PACKET* reply = NULL;
	ngx_http_auth_radius_connection_t* uc = NULL;
	ngx_http_auth_radius_proxy_t* proxy = NULL;
	
	uc = c->data;
	proxy = uc->data;
    rev = c->read;

    do {
        reply = rad_recv(c->fd,0);

        if (reply) {
			ngx_http_auth_radius_response_post_event(proxy,reply);		
			return NGX_OK;
        }
		err = ngx_socket_errno; 

        if (err == NGX_EAGAIN || err == NGX_EINTR) {
            n = NGX_AGAIN;
        } else {
            n = ngx_connection_error(c, err, "ngx_http_auth_radius_recv() failed");
            break;
        }
    } while (err == NGX_EINTR);

    rev->ready = 0;

    if (n == NGX_ERROR) {
        rev->error = 1;
		ngx_http_auth_radius_close_connection(uc);
    }

    return n;
}


static void 
ngx_http_auth_radius_recv_response(ngx_event_t* rev) {
	ngx_connection_t* c = NULL;
	ssize_t n = 0;
	c = rev->data;

	do {
		n = ngx_http_auth_radius_recv(c);
		if(n == NGX_ERROR) {
			return;
		}
	}while(rev->ready);
}


ngx_http_auth_radius_connection_t* 
ngx_http_auth_radius_create_connection(ngx_http_auth_radius_proxy_t* proxy,int sf)
{
	fr_hash_table_t* ucs = NULL;
	ngx_http_auth_radius_connection_t* uc = NULL;

	ucs = proxy->udp_connections;
	uc = ngx_http_auth_radius_connect(sf,proxy->pool,proxy->log);
	if(uc == NULL) {
		return NULL;
	}	
	uc->data = proxy;

	if(fr_hash_table_insert(ucs,uc)) {
		proxy->conn_counter++;
	
		uc->c->data = uc;
		uc->c->read->handler = ngx_http_auth_radius_recv_response;
	} else {
		ngx_log_error(NGX_LOG_ERR,proxy->log,0,
		    "ngx_http_auth_radius: failed to insert the \
            connection socketfd=%d to hash-table of connections",
			uc->c->fd);

		ngx_close_connection(uc->c);	
		ngx_pfree(proxy->pool,uc);
		uc = NULL;
	}

	return uc;
}


ngx_int_t 
ngx_http_auth_radius_alloc_id(ngx_http_auth_radius_proxy_t* proxy,
        ngx_http_auth_radius_request_t* rr)
{
	assert(proxy != NULL && rr != NULL);
	
	fr_packet_list_t* pl = NULL;
	ngx_http_auth_radius_connection_t* uc = NULL;
	int rcode = 0;
	pl = proxy->request_packets;

retry:
	if(fr_hash_table_num_elements(proxy->udp_connections) == 0) {
		rcode = 0;
	} else {
		rcode = fr_packet_list_id_alloc(pl,rr->request);
	}

	if(rcode == 0)  {
		if(proxy->conn_counter < MAX_RADIUS_SOCKETS) { 
			//there is no udp connection,so we create new one.
			ngx_log_debug(NGX_LOG_INFO,proxy->log,0,
					"ngx_http_auth_radius: \
                    there is no udp connection,so we create a new one.");

			uc = ngx_http_auth_radius_create_connection(proxy,rr->request->dst_ipaddr.af);
			if(uc == NULL) {
				return NGX_ERROR;
			}
			if(fr_packet_list_socket_add(pl,uc->c->fd) == 0) {
				ngx_log_error(NGX_LOG_ERR,
                   proxy->log,0,
                   "ngx_http_auth_radius: add socket failed");
			}
			goto retry;
		} else {
			//beyond the limit of sockets
			ngx_log_error(NGX_LOG_ERR,proxy->log,0,
					"ngx_http_auth_radius: \
                    the opening sockets have been out of limits: %d",
					MAX_RADIUS_SOCKETS);

			return NGX_ERROR;
		}
	}

	if(rcode == 0) {
		ngx_log_error(NGX_LOG_ERR,proxy->log,0,
            "ngx_http_auth_radius: %s",fr_strerror());

		return NGX_ERROR;
	}

	assert(rr->request->id != -1);

	ngx_log_debug(NGX_LOG_INFO,proxy->log,0,
			"ngx_http_auth_radius: alloc request id successfully: %d,fd=%d",
			rr->request->id,rr->request->sockfd);

	return NGX_OK;
}


static void 
ngx_http_auth_radius_delete_request(ngx_http_auth_radius_request_t* rr)
{
    ngx_queue_remove(&rr->queue);
}


static void 
ngx_http_auth_radius_add_request(ngx_http_auth_radius_request_t* rr) {
    ngx_http_auth_radius_ctx_t* ctx = rr->data;
    ngx_http_auth_radius_proxy_t* proxy = ctx->proxy;

    ngx_queue_insert_tail(&proxy->requests,&rr->queue);           
}


void 
ngx_http_auth_radius_resend_handler(ngx_event_t* ev)
{
    ngx_http_auth_radius_proxy_t* proxy = NULL;
    ngx_http_auth_radius_request_t* rr = NULL;
    ngx_queue_t* next = NULL;
    ngx_queue_t* q = NULL;
    ngx_queue_t* sentinel = NULL;
    ngx_queue_t* requests = NULL;
    ngx_http_auth_radius_ctx_t* ctx = NULL;
    ngx_http_auth_radius_server_t* server = NULL;
    time_t timer;
    ngx_int_t temp_timer;
    time_t now; 
    
	if(ev) {
        timer = 0;
        
        now = time(NULL);
        proxy = ev->data;
        requests = &proxy->requests;
        sentinel = ngx_queue_sentinel(requests);
		
        for(q = ngx_queue_head(requests);q != sentinel;q = next) {
            next = ngx_queue_next(q);
            rr = ngx_queue_data(q,ngx_http_auth_radius_request_t,queue);
            ctx = rr->data;
            temp_timer = 0;
			server = ctx->rlcf->server;

            if(rr->done == 0)
            {
                if((rr->tries >= server->resend_limit) && (now >= rr->expire)) 
                {
                    rr->done = 1;
                    rr->error_code = NGX_HTTP_AUTH_RADIUS_TIMEDOUT;
                    ngx_http_auth_radius_process_finish(rr);
                } else if(now >= rr->expire) {
                    /*resend it*/
                   ngx_log_error(NGX_LOG_ALERT,proxy->log,0,
                       "resend the radius request id %d,code %d again",
					   rr->request->id,rr->request->code); 

                   rr->tries++;
                   rr->expire = now + server->auth_timeout;

                   rad_send_request(rr->request,(char*)server->share_secret.data,
                           rr->password);
                   temp_timer = server->auth_timeout;
                } else {
                    /*the request is not timed-out*/
                   temp_timer = rr->expire - now;
                }

                if((timer == 0) && temp_timer > 0) {
                    timer = temp_timer;
                } else if(temp_timer > 0) {
                   if(temp_timer < timer)
                       timer = temp_timer;
                }
            }
        }

        if(timer > 0) {
            ngx_add_timer(&proxy->resend_event,(ngx_msec_t)(timer * 1000));
		}
    }
}


static void 
ngx_http_auth_radius_process_response(ngx_http_auth_radius_request_t* rr)
{
	RADIUS_PACKET* pr = NULL;
	ngx_http_auth_radius_ctx_t* ctx = NULL;
	ngx_http_auth_radius_proxy_t* proxy = NULL;
    ngx_http_auth_radius_server_t* server = NULL;
    ngx_http_auth_radius_loc_conf_t* rlcf = NULL;
	RADIUS_PACKET* reply = NULL;
	ngx_log_t* log = NULL;
	char buf[256] = {0};

	ctx = rr->data;
	proxy = ctx->proxy;
    rlcf = ctx->rlcf;
    server = rlcf->server;
	log = proxy->log;
	reply = rr->reply;
	pr = rr->request;

	if(rad_verify(reply,pr,(char*)server->share_secret.data) < 0) //error
    {
     	ngx_memzero(buf,sizeof(buf)); 
        inet_ntop(reply->src_ipaddr.af,&reply->src_ipaddr.ipaddr,buf,sizeof(buf));
       	ngx_log_error(NGX_LOG_WARN,log,0,
            "unexpected reply from server: %s:%d,so discard it",
       	    buf,ntohs(reply->src_port));

		rr->reply = NULL;
		goto failed;
    }

	if(rad_decode(reply,pr,(char*)server->share_secret.data) < 0) {
		bzero(buf,sizeof(buf));
        inet_ntop(reply->src_ipaddr.af,&reply->src_ipaddr.ipaddr,buf,sizeof(buf));

		ngx_log_error(NGX_LOG_WARN,log,0,
                "ngx_http_auth_radius: \
                cann't decode the reply from server: %s:%d,so discard it",
                buf,ntohs(reply->src_port));
		rr->reply = NULL;

		goto failed;
	}
	
	if(rlcf->auth_type == EAPMD5) {
		rad_unmap_eap_types(reply);
	}
	/*just for debug*/
	if(fr_debug_flag)
		debug_reply_packet(reply);

	if(rlcf->auth_type == EAPMD5 && reply->code == PW_ACCESS_CHALLENGE) {
		if(rad_process_eap_request(pr,reply,
            (char*)server->share_secret.data,rr->password) < 0) 
        {
			rr->reply = NULL;
			goto failed;
	    } else { 
		    /*if we received a Challenge from radius-server,
            * we will send a access-request again
			*so we should reset the expired-time.
			*/
			rr->expire = time(NULL) + server->auth_timeout;
			/*
			* the reply is useless,so we free it.
			*/ 
			rr->reply = NULL;
			rad_free(&reply);
	    }
	} else {
		rr->reply = reply;
		rr->done = 1;
		rr->error_code = NGX_HTTP_AUTH_RADIUS_OK;
		ngx_http_auth_radius_process_finish(rr);
    }
    return;

failed:
	rad_free(&reply);
}


static void 
ngx_http_auth_radius_response_post_event_handler(ngx_event_t* ev)
{
	ngx_http_auth_radius_request_t* rr = NULL;
	rr = ev->data;
	ngx_pfree(rr->pool,ev);

	ngx_http_auth_radius_process_response(rr);
}


static void 
ngx_http_auth_radius_response_post_event(ngx_http_auth_radius_proxy_t* proxy,
        RADIUS_PACKET* reply)
{
	RADIUS_PACKET** pr = NULL;
	ngx_http_auth_radius_request_t* rr = NULL;
	fr_packet_list_t* pl = NULL;
	char addr[256] = {0};
	ngx_pool_t* pool = NULL;
	ngx_log_t* log = NULL;
	ngx_event_t* ev = NULL;

	pl = proxy->request_packets;
	log = proxy->log;

	pr = fr_packet_list_find_byreply(pl,reply);
	if(pr) {
		rr = fr_packet2myptr(ngx_http_auth_radius_request_t,request,pr);
		pool = rr->pool;
		ev = ngx_pcalloc(pool,sizeof(*ev));
		if(ev == NULL) {
			ngx_log_error(NGX_LOG_ERR,log,NGX_ENOMEM,"out of memory");
			rad_free(&reply);
			return;
		}

		rr->reply = reply;
		ev->data = rr;
		ev->log = log;
		ev->handler = ngx_http_auth_radius_response_post_event_handler;
		ngx_post_event(ev,&ngx_posted_events);
	} else {
        inet_ntop(reply->src_ipaddr.af,&reply->src_ipaddr.ipaddr,addr,sizeof(addr));
        ngx_log_error(NGX_LOG_WARN,log,0,
		    "ngx_http_auth_radius: \
            not find request correspond to the reply from server: \
            %s:%d,code=%d,id=%d,so discard it",
            addr,reply->src_port,reply->code,reply->id);
		rad_free(&reply);
	}
}


/*
 * we will call this function after radius authentication or authentication timeout
 */
static void 
ngx_http_auth_radius_process_finish(ngx_http_auth_radius_request_t* rr) {
	ngx_http_auth_radius_ctx_t* ctx = NULL;
    ngx_http_auth_radius_proxy_t* proxy = NULL; 

    ctx = rr->data;  
    proxy = ctx->proxy;

    if(rr->done) {
        fr_packet_list_delete(proxy->request_packets,rr->request);
        ngx_http_auth_radius_delete_request(rr);
		rr->handler(rr);
	}
}


void 
ngx_http_auth_radius_destroy_request(ngx_http_auth_radius_proxy_t* proxy,
        ngx_http_auth_radius_request_t* rr)
{
	ngx_pool_t* pool = NULL;

	if(rr == NULL) {
		return;
	}

	pool = rr->pool;

	if(rr->request->id >= 0) {
		ngx_log_debug(NGX_LOG_INFO,pool->log,0,
             "ngx_http_auth_radius: free radius packet id: %d",
             rr->request->id);
    	if(fr_packet_list_id_free(proxy->request_packets,rr->request) == 0) {
			ngx_log_error(NGX_LOG_WARN,pool->log,0,
                "ngx_http_auth_radius: free radius packet id %d failed",
                rr->request->id);
		}
		rr->request->id = -1;
    }

    /*free: RADIUS_PACKET to request*/
	if(rr->request) {
		rad_free(&rr->request);
	}	

    /*free: RADIUS_PACKET to reply*/
	if(rr->reply) {
		rad_free(&rr->reply);
	}

	ngx_pfree(pool,rr);	
}


/*
 * create radius request
 */
ngx_http_auth_radius_request_t* 
ngx_http_auth_radius_create_request(ngx_http_auth_radius_proxy_t* proxy,
        ngx_http_request_t* r)
{
	ngx_log_t* log = NULL;
	ngx_http_auth_radius_request_t* rr = NULL;
	RADIUS_PACKET* rp = NULL;
	ngx_addr_t* addr = NULL;
    int port = 0;
    ngx_http_auth_radius_loc_conf_t* rlcf = NULL;
    ngx_str_t user = ngx_null_string;
    ngx_str_t pwd = ngx_null_string;
    ngx_url_t* url = NULL;
    ngx_pool_t* pool = r->pool;
    ngx_http_auth_radius_server_t* server = NULL;

    log = proxy->log;
	rlcf = ngx_http_get_module_loc_conf(r,ngx_http_auth_radius_module);

	rr = ngx_pcalloc(pool,sizeof(ngx_http_auth_radius_request_t));
	if(rr == NULL) {
		goto failed;
	}
    rr->pool = pool;

    user = r->headers_in.user;
    pwd = r->headers_in.passwd;

	rp = rad_request_packet_create((char*)user.data,user.len,
		    (char*)pwd.data,pwd.len,rlcf->auth_type);
	if(rp == NULL) {
		goto failed;
	}
	
    /*Note:
     * we must use RADIUS_PACKET member dst_ipaddr as following
     */
    server = rlcf->server;
    url = &server->parsed_url;
	addr = url->addrs;
	bzero(&rp->dst_ipaddr,sizeof(rp->dst_ipaddr));
    fr_sockaddr2ipaddr((const struct sockaddr_storage*)addr->sockaddr,
            addr->socklen,&rp->dst_ipaddr,&port);
    rp->dst_port = port & 0xFFFF;
	rp->sockfd = -1; 
	rp->src_ipaddr.af = rp->dst_ipaddr.af;

	rr->request = rp;
	rr->reply = NULL;
	
	rr->tries = 0;
	ngx_memcpy(rr->password,(char*)pwd.data,pwd.len);
	rr->done = 0;
    
	if(ngx_http_auth_radius_alloc_id(proxy,rr) == NGX_ERROR) {
		goto failed;
	}
	/*
	 * Note:
	 * we must call rad_set_eap_id to set 
     * the eap-id attribute after ceating EAP-response packet
	 */
	if(rlcf->auth_type == EAPMD5) {
		if(rad_set_eap_id(rp) == -1) {
			goto failed;
		}
	}

	rr->timestamp = time(NULL);
    rr->expire = rr->timestamp + server->auth_timeout;
	rr->error_code = NGX_HTTP_AUTH_RADIUS_OK;	

	return rr;
failed:
	ngx_http_auth_radius_destroy_request(proxy,rr);
	return NULL;	
}


ngx_int_t 
ngx_http_auth_radius_send_request(ngx_http_request_t* r) {
	ngx_http_auth_radius_proxy_t* proxy = NULL;
    ngx_http_auth_radius_request_t* rr = NULL;
	ngx_http_auth_radius_ctx_t* ctx = NULL;
	ngx_http_auth_radius_server_t* server = NULL;
    ngx_http_auth_radius_loc_conf_t* rlcf = NULL;
    ngx_str_t share_secret = ngx_null_string;

    ctx = ngx_http_get_module_ctx(r,ngx_http_auth_radius_module);

	proxy = ctx->proxy;
    rr = ctx->rr;
    rlcf = ctx->rlcf;

    server = rlcf->server;
    share_secret = server->share_secret;

	if(rlcf->auth_type != EAPMD5) {
		if(rad_send_request(rr->request,(char*)share_secret.data,rr->password) < 0) {
			return NGX_ERROR;
		}
	} else {
		if(rad_send_eap_response(rr->request,(char*)share_secret.data,rr->password) < 0) {
			return NGX_ERROR;
		}
	}
	/*
	 * Note:
	 * the follow function fr_packet_list_insert is very different to others.
	 * On success,the function will return 1 
	 * On failed,it will return 0
	 */
	if(fr_packet_list_insert(proxy->request_packets,&rr->request) == 0) {
		ngx_log_error(NGX_LOG_ERR,proxy->log,0,
				"add radius packet failed: fd=%d,id=%d",
				rr->request->sockfd,rr->request->id);
		return NGX_ERROR;
	}	

    if(ngx_queue_empty(&proxy->requests)) {
        ngx_add_timer(&proxy->resend_event,(ngx_msec_t)(server->auth_timeout * 1000));
    }

    ngx_http_auth_radius_add_request(rr); 	
	
	return NGX_OK;	
}


ngx_int_t 
ngx_http_auth_radius_dict_init(const ngx_str_t* dict_dir,ngx_log_t* log)
{
	ngx_int_t rc = NGX_OK;
	u_char dict[1024] = {0};

	ngx_snprintf(dict,sizeof(dict) - 1,"%V",dict_dir);
	if(dict_init((char*)dict,"dictionary") == -1) {
		ngx_log_error(NGX_LOG_ERR,log,0,
              "ngx_http_auth_radius: failed to initial radius dictionry: %s",
              fr_strerror());
		rc = NGX_ERROR;
	}	
	return rc;
}


static int 
ngx_http_auth_radius_close_connection_walker(void* ctx,void* data)
{
	ngx_http_auth_radius_connection_t* uc = data;

	ngx_http_auth_radius_close_connection(uc);

	return 0;
}


static void 
ngx_http_auth_radius_destroy_connections(ngx_http_auth_radius_proxy_t* proxy)
{
	fr_hash_table_t* ucs = NULL;
	ucs = proxy->udp_connections;
	
	fr_hash_table_walk(ucs,ngx_http_auth_radius_close_connection_walker,proxy);
	fr_hash_table_free(ucs);
	proxy->udp_connections = NULL;
}


static void
ngx_http_auth_radius_clean_queue_request(ngx_queue_t* q,void* ctx)
{
    ngx_http_auth_radius_request_t* rr = NULL; 
    ngx_http_auth_radius_proxy_t* proxy = ctx;

	ngx_queue_remove(q);
	rr = ngx_queue_data(q,ngx_http_auth_radius_request_t,queue);
	ngx_http_auth_radius_destroy_request(proxy,rr);
}


static void 
ngx_http_auth_radius_cleanall_request(ngx_http_auth_radius_proxy_t* proxy)
{
   ngx_queue_walk(&proxy->requests,
		   ngx_http_auth_radius_clean_queue_request,proxy); 
}


static void 
ngx_http_auth_radius_proxy_cleanup(void* data)
{
	ngx_http_auth_radius_proxy_t* proxy = data;

	if(proxy) {
		ngx_log_debug(NGX_LOG_DEBUG,proxy->log,0,
			"cleanup radius authentication");

		ngx_http_auth_radius_cleanall_request(proxy);

		if(proxy->request_packets) {
       		fr_packet_list_free(proxy->request_packets);
		}

        if(proxy->resend_event.timer_set) {
           ngx_del_timer(&proxy->resend_event);
		}

		ngx_http_auth_radius_destroy_connections(proxy);

		dict_free();

        ngx_pfree(proxy->pool,proxy);
    }
}


static uint32_t 
ngx_http_auth_radius_hash_connection(const void* data)
{
	ngx_http_auth_radius_connection_t* uc = NULL;

    uc = (ngx_http_auth_radius_connection_t*)data;
	return fr_hash(&uc->c->fd,sizeof(uc->c->fd));
}


ngx_http_auth_radius_proxy_t* 
ngx_http_auth_radius_create_proxy(ngx_pool_t* pool)
{
	ngx_pool_cleanup_t* cln = NULL;
	ngx_http_auth_radius_proxy_t* proxy = NULL;
    ngx_log_t* log = NULL;

	if(pool == NULL) {
	    return NULL;
	}

    log = pool->log;
	
	cln = ngx_pool_cleanup_add(pool,0);
	if(cln == NULL) {
		goto failed;
	}

	cln->handler = ngx_http_auth_radius_proxy_cleanup;
	
	proxy = ngx_pcalloc(pool,sizeof(ngx_http_auth_radius_proxy_t));	
	if(proxy == NULL) {
		goto failed;
	}
	cln->data = proxy;

	proxy->request_packets = fr_packet_list_create(1);
	ngx_queue_init(&proxy->requests);

	proxy->resend_event.handler = ngx_http_auth_radius_resend_handler;
	proxy->resend_event.data = proxy;
	proxy->resend_event.log = log;
	proxy->pool = pool;

	proxy->log = log;
	proxy->log_level = NGX_LOG_ERR;
	proxy->udp_connections = fr_hash_table_create(ngx_http_auth_radius_hash_connection,
            NULL,NULL);
	if(proxy->udp_connections == NULL) {
		goto failed;
	}

	fr_debug_flag = 1;
	fr_log_fp = stdout;

    return proxy;
failed:
	ngx_http_auth_radius_proxy_cleanup(proxy);
	return NULL;
}


ngx_int_t
ngx_http_auth_radius_set_realm(ngx_http_request_t* r,const ngx_str_t* realm) {
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}


static void
ngx_http_auth_radius_authenticate_finish_handler(ngx_http_auth_radius_request_t* rr)
{
    ngx_http_auth_radius_ctx_t* ctx = rr->data;
    ngx_log_debug(NGX_LOG_INFO,ctx->proxy->log,0,
            "ngx_http_auth_radius: request finish: id=%d,code=%d",
            rr->request->id,rr->request->code);

    ngx_http_core_run_phases(ctx->r);
}


ngx_int_t 
ngx_http_auth_radius_authenticate(ngx_http_request_t* r)
{
	ngx_http_auth_radius_request_t* rr = NULL;
    ngx_http_auth_radius_ctx_t* ctx = NULL;
    ngx_int_t rc = NGX_AGAIN;
    ngx_http_auth_radius_loc_conf_t* rlcf = NULL;

    ctx = ngx_http_get_module_ctx(r,ngx_http_auth_radius_module);
    rr = ctx->rr;
    rlcf = ctx->rlcf;

    if(rr->done) {
        //radius authentication has finished
        if(rr->error_code != NGX_HTTP_AUTH_RADIUS_OK) {
            rc = ngx_http_auth_radius_set_realm(r,&rlcf->realm);; 
        } else {
            rc = NGX_OK;
        }

        return rc;
    }

	rr->handler = ngx_http_auth_radius_authenticate_finish_handler;
    rr->data = ctx;

	if(ngx_http_auth_radius_send_request(r) == NGX_ERROR) {
        return NGX_ERROR;
    }
    
    return NGX_AGAIN;
}
