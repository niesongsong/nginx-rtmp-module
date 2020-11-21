
/*
 * Copyright (C) nie950@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_rtmp.h"
#include "ngx_rtmp_streams.h"
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_relay_module.h"
#include "ngx_rtmp_netcall_module.h"


enum {
    NGX_RTMP_HTTP_FLV_PLAY      = 0,
    NGX_RTMP_HTTP_FLV_PUBLISH   = 1
};

enum {
    NGX_RTMP_HTTP_FLV_STAGE_NULL        = 0,
    NGX_RTMP_HTTP_FLV_STAGE_FLV         = 1,
    NGX_RTMP_HTTP_FLV_STAGE_TAG         = 2,
    NGX_RTMP_HTTP_FLV_STAGE_TAG_CONTENT = 3,
};

typedef struct {
    ngx_http_request_t  *r;
    ngx_rtmp_session_t  *s;

    ngx_str_t            host;
    ngx_str_t            app;
    ngx_str_t            port;
    ngx_str_t            stream;
    ngx_str_t            uri;
    ngx_chain_t         *args;

    ngx_chain_t         *in;
    ngx_chain_t         *free_chains;
    
    uint32_t             basetime;  /*first tag timestamp*/
    uint32_t             pts;

    uint32_t             audio : 1;
    uint32_t             video : 1;

    ngx_chain_t         *out;
    ngx_chain_t         *outlast;
    ngx_chain_t         *body;

    ngx_rtmp_header_t    h;

    uint32_t             nbody;
    ngx_uint_t           ncrs;
    ngx_uint_t           stage;
    ngx_uint_t           nheader;

    u_char              *last;
    u_char              *end;
    u_char               header[NGX_RTMP_MAX_CHUNK_HEADER];

} ngx_rtmp_flv_live_ctx_t;


static ngx_rtmp_connect_pt                      next_connect;
static ngx_rtmp_disconnect_pt                   next_disconnect;
static ngx_rtmp_play_pt                         next_play;
static ngx_rtmp_publish_pt                      next_publish;


static char * ngx_rtmp_flv_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_rtmp_flv_live_handler(ngx_http_request_t *r);

static ngx_rtmp_session_t *
    ngx_rtmp_flv_live_init_connection(ngx_http_request_t *r);
static void ngx_rtmp_flv_live_cleanup(void *data);

static void ngx_rtmp_flv_live_http_log_request(ngx_http_request_t *r);

static void ngx_rtmp_flv_live_send(ngx_event_t *wev);
static ngx_int_t ngx_rtmp_flv_live_send_cycle(ngx_rtmp_session_t *s);
static void ngx_rtmp_flv_live_recv(ngx_event_t *rev);

static void ngx_rtmp_flv_live_http_send(ngx_event_t *wev);
static void ngx_rtmp_flv_live_http_recv(ngx_event_t *rev);
static ngx_int_t ngx_rtmp_flv_live_http_recv_cycle(ngx_rtmp_session_t *s);

static ngx_int_t 
    ngx_rtmp_flv_live_http_recv_handle(ngx_rtmp_session_t *s, ngx_chain_t *in);
static ngx_int_t
    ngx_rtmp_flv_live_http_publish_local(ngx_rtmp_session_t *s);


static ngx_int_t 
    ngx_rtmp_flv_live_http_skip_header(ngx_rtmp_flv_live_ctx_t *s);
static size_t 
    ngx_rtmp_flv_live_copy_header(ngx_rtmp_flv_live_ctx_t *ctx, size_t n);

static ngx_int_t ngx_rtmp_flv_live_connect(ngx_rtmp_flv_live_ctx_t *ctx);
static ngx_int_t ngx_rtmp_flv_live_play(ngx_rtmp_flv_live_ctx_t *ctx);
static ngx_int_t ngx_rtmp_flv_live_send_headers(ngx_rtmp_flv_live_ctx_t *ctx);
static ngx_int_t ngx_rtmp_flv_live_index_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_rtmp_flv_live_index_connect(ngx_rtmp_session_t *s,
    ngx_rtmp_connect_t *v);

static ngx_chain_t *
    ngx_rtmp_flv_live_alloc_chain_buf(ngx_rtmp_flv_live_ctx_t *ctx);
static void ngx_rtmp_flv_live_free_chains(ngx_rtmp_flv_live_ctx_t *ctx,
    ngx_chain_t *start, ngx_chain_t *end);

static ngx_rtmp_flv_live_ctx_t *
    ngx_rtmp_flv_live_client_init(ngx_rtmp_session_t *s);

static ngx_int_t ngx_rtmp_flv_live_index_disconnect(ngx_rtmp_session_t *s);
static ngx_int_t ngx_rtmp_flv_live_index_play(ngx_rtmp_session_t *s,
    ngx_rtmp_play_t *v);
static ngx_int_t ngx_rtmp_flv_live_index_publish(ngx_rtmp_session_t *s,
    ngx_rtmp_publish_t *v);

static ngx_int_t ngx_rtmp_flv_live_prepare_message(ngx_rtmp_flv_live_ctx_t *ctx,
    ngx_chain_t *in);
static ssize_t ngx_rtmp_flv_live_send_buf(ngx_rtmp_session_t *s, u_char *buf,
    size_t size);

static ngx_http_module_t ngx_rtmp_flv_live_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


static ngx_command_t  ngx_rtmp_flv_live_commands[] = {

    { ngx_string("flv_live"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_rtmp_flv_live,
      0,
      0,
      NULL },

      ngx_null_command
};


/* HTTP module */
ngx_module_t ngx_rtmp_flv_live_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_flv_live_module_ctx,
    ngx_rtmp_flv_live_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


/* RTMP module */
static ngx_rtmp_module_t ngx_rtmp_flv_live_index_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_rtmp_flv_live_index_postconfiguration,  /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


static ngx_command_t ngx_rtmp_flv_live_index_commands[] = {
    ngx_null_command
};


/* default flashVer */
#define NGX_RTMP_FLV_LIVE_FLASHVER                 "FLV.11,1,102,55"
#define NGX_RTMP_FLV_MIME_TYPE                     "video/x-flv"
#define NGX_RTMP_FLV_SUFFIX                        ".flv"

static ngx_str_t ngx_rtmp_flv_live_urlencoded =
    ngx_string("application/x-www-form-urlencoded");

static u_char flv_header[] = {
        0x46, 0x4c, 0x56, /* 'F', 'L', 'V' */
        0x01, /* version = 1 */
        0x05, /* 00000 1 0 1 = has audio & video */
        0x00, 0x00,  0x00, 0x09, /* header size */
    };

ngx_module_t ngx_rtmp_flv_live_index_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_flv_live_index_module_ctx,
    ngx_rtmp_flv_live_index_commands,
    NGX_RTMP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static char *
ngx_rtmp_flv_live(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_rtmp_flv_live_handler;

    return NGX_CONF_OK;
}


static ngx_int_t ngx_rtmp_flv_live_index_postconfiguration(ngx_conf_t *cf)
{
    next_disconnect = ngx_rtmp_disconnect;
    ngx_rtmp_disconnect = ngx_rtmp_flv_live_index_disconnect;

    next_connect = ngx_rtmp_connect;
    ngx_rtmp_connect = ngx_rtmp_flv_live_index_connect;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_flv_live_index_play;

    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_flv_live_index_publish;

    return NGX_OK;
}

static ngx_int_t
ngx_rtmp_flv_live_index_connect(ngx_rtmp_session_t *s, ngx_rtmp_connect_t *v)
{
    ngx_rtmp_flv_live_ctx_t     *ctx;
    ngx_int_t                    rc;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_live_index_module);
    if (ctx == NULL || ctx->s != s || s->signature != NGX_HTTP_MODULE || 
       !ctx->r) 
    {
        goto next;
    }

    rc = next_connect(s, v);
    if (rc == NGX_OK) {
        rc = ngx_rtmp_flv_live_play(ctx);
    }

    return rc;

next:
    return next_connect(s, v);
}

static void
ngx_rtmp_flv_live_http_log_request(ngx_http_request_t *r)
{
    ngx_uint_t                  i, n;
    ngx_http_handler_pt        *log_handler;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    log_handler = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_HTTP_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](r);
    }
}


static ngx_int_t
ngx_rtmp_flv_live_index_disconnect(ngx_rtmp_session_t *s)
{
    ngx_rtmp_flv_live_ctx_t     *ctx;
    ngx_http_request_t          *r;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_live_index_module);
    if (ctx == NULL || ctx->s != s || s->signature != NGX_HTTP_MODULE) {
        goto next;
    }

    r = ctx->r;
    ctx->r = NULL;
    
    if (r) {
        if (!r->logged) {
            r->connection->log->action = "logging request";
            ngx_rtmp_flv_live_http_log_request(r);
        }

        r->request_line.len = 0;
    }

next:
    return next_disconnect(s);
}


static ngx_int_t
ngx_rtmp_flv_live_index_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_flv_live_ctx_t     *ctx;
    ngx_int_t                    rc;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_live_index_module);
    if (ctx == NULL || ctx->r == NULL || ctx->s == NULL ||  ctx->s != s
     || s->signature != NGX_HTTP_MODULE) 
     {
        goto next;
    }

    rc = ngx_rtmp_flv_live_send_headers(ctx);
    if (rc != NGX_OK) {
        ngx_rtmp_finalize_session(s);
        return rc;
    }

    ctx->end = ctx->last = ctx->header;
    ctx->stage = NGX_RTMP_HTTP_FLV_STAGE_FLV;

next:
    return next_play(s, v);
}

static ngx_int_t 
ngx_rtmp_flv_live_index_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    return next_publish(s, v);
}


static ngx_int_t 
ngx_rtmp_flv_live_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc;
    ngx_rtmp_flv_live_ctx_t         *ctx;
    size_t                           n;
    u_char                          *p;
    ngx_http_cleanup_t              *cln;

    if (ngx_rtmp_core_main_conf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_exiting || ngx_terminate) {
        return NGX_HTTP_CLOSE;
    }

    if (!(r->method & (NGX_HTTP_GET))) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "flv live: HTTP method was not \"GET\"");

        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->http_version == NGX_HTTP_VERSION_9
#if (NGX_HTTP_V2)
        || r->http_version == NGX_HTTP_VERSION_20
#endif
       )
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "flv live: HTTP version 0.9 or 2.0 not supported");

        return NGX_HTTP_NOT_ALLOWED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_flv_live_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_rtmp_flv_live_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_rtmp_flv_live_module);
    }
    ctx->r = r;

    /* discard body */

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /* uri format: .../app/stream.flv?args */

    ngx_str_null(&ctx->app);
    ngx_str_null(&ctx->stream);

    for (n = r->uri.len - 4; n; --n) {
        p = &r->uri.data[n - 1];

        if (*p != '/') {
            continue;
        }

        if (ctx->stream.data) {
            ctx->app.data = p + 1;
            ctx->app.len  = ctx->stream.data - ctx->app.data - 1;
            break;
        }

        ctx->stream.data = p + 1;
        ctx->stream.len  = r->uri.data + r->uri.len - ctx->stream.data - 4;
    }

    if (!ctx->app.data) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "flv live: HTTP invalid app or stream");

        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, 
        "flv-live: *%ui client connected app: '%V', name: '%V'", 
        r->connection->number, &ctx->stream, &ctx->app);

    ctx->s = ngx_rtmp_flv_live_init_connection(r);
    if (ctx->s == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->stage = NGX_RTMP_HTTP_FLV_STAGE_NULL;
    ngx_rtmp_set_ctx(ctx->s, ctx, ngx_rtmp_flv_live_index_module);

    /* live, ranges not allowed */
    r->allow_ranges = 0;
    r->read_event_handler = ngx_http_test_reading;

    /*connect stream*/
    rc = ngx_rtmp_flv_live_connect(ctx);
    if (rc != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_DECLINED;
    }

    cln->handler = ngx_rtmp_flv_live_cleanup;
    cln->data = ctx->s;

    r->main->count++;
    r->headers_out.status = 200;

    return NGX_DONE;
}


void ngx_rtmp_client_http_flv_live_handshake(ngx_rtmp_session_t *s)
{
    ngx_connection_t                *c;
    ngx_chain_t                     *out;
    ngx_rtmp_flv_live_ctx_t         *ctx;
    
    c = s->connection;
    s->signature = NGX_HTTP_MODULE;

    c->read->handler =  ngx_rtmp_flv_live_http_recv;
    c->write->handler = ngx_rtmp_flv_live_http_send;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "handshake: start http-flv handshake");

    ctx = ngx_rtmp_flv_live_client_init(s);
    if (ctx == NULL) {
        goto failed;
    }

    out = ngx_rtmp_netcall_http_format_request(NGX_RTMP_NETCALL_HTTP_GET,
        &ctx->host, &ctx->uri, ctx->args, NULL, c->pool, 
        &ngx_rtmp_flv_live_urlencoded);

    if (out == NULL) {
        goto failed;
    }

    ctx->out = out;
    ctx->outlast = ctx->out;

    ngx_rtmp_flv_live_http_send(c->write);
    return;

failed:

    ngx_rtmp_finalize_session(s);
    return;
}


static ngx_rtmp_session_t *
ngx_rtmp_flv_live_init_connection(ngx_http_request_t *r)
{
    ngx_uint_t                      n;
    ngx_rtmp_port_t                *port;
    ngx_rtmp_in_addr_t             *addr;
    ngx_rtmp_session_t             *s;
    ngx_rtmp_addr_conf_t           *addr_conf;
    ngx_listening_t                *ls;
    ngx_connection_t               *c;
    void                           *data;

#if (NGX_HAVE_INET6)
    ngx_rtmp_in6_addr_t            *addr6;
#endif

    ++ngx_rtmp_naccepted;

    /* AF_INET only */
    c = r->connection;
    addr_conf = NULL;
    port = NULL;

    /* find the server configuration rtmp */
    ls = ngx_cycle->listening.elts;
    for (n = 0; n < ngx_cycle->listening.nelts; ++n, ++ls) {
        if (ls->handler == ngx_rtmp_init_connection) {

            port = ls->servers;
            if (port == NULL || ls->sockaddr->sa_family == AF_UNIX) {
                continue;
            }

            switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                addr6 = port->addrs;
                addr_conf = & addr6[port->naddrs - 1].conf;
                break;
#endif

            default:
                addr = port->addrs;
                addr_conf = & addr[port->naddrs - 1].conf;

                break;
            }

            if (addr_conf != NULL) {
                break;
            }
        }
    }

    if (port == NULL || addr_conf == NULL) {
        return NULL;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "flv-live: *%ui client connected '%V'",
                  c->number, &c->addr_text);

    /*save data*/
    data = c->data;
    s = ngx_rtmp_init_session(c, addr_conf);
    if (s == NULL) {
        return NULL;
    }
    c->data = data;

    s->auto_pushed = 0;
    s->signature = NGX_HTTP_MODULE;

    c->write->handler = ngx_rtmp_flv_live_send;
    c->read->handler = ngx_rtmp_flv_live_recv;

    return s;
}


static void 
ngx_rtmp_flv_live_send(ngx_event_t *wev)
{
    ngx_connection_t           *c;
    ngx_rtmp_session_t         *s;
    ngx_http_request_t         *r;
    ngx_rtmp_flv_live_ctx_t    *ctx;
    ngx_chain_t                *cl;

    c = wev->data;
    r = c->data;

    if (c->destroyed) {
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_flv_live_module);
    if (ctx == NULL) {
        return ;
    }
    
    s = ctx->s;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_WARN, c->log, NGX_ETIMEDOUT,
                "client timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    /* 'F', 'L', 'V' */
    if (ctx->stage == NGX_RTMP_HTTP_FLV_STAGE_FLV) {
        if (ctx->outlast) {
            ctx->outlast = c->send_chain(c, ctx->outlast, 0);
            if (ctx->outlast == NGX_CHAIN_ERROR) {
                ngx_rtmp_finalize_session(s);
                return;
            }

            /* more data to send? */
            if (ctx->outlast) {
                ngx_add_timer(wev, 5000);
                if (ngx_handle_write_event(wev, 0) != NGX_OK) {
                    ngx_rtmp_finalize_session(s);
                }
                return;
            }

            for (cl = ctx->out; cl; cl = ctx->out) {
                ctx->out = ctx->out->next;
                ngx_free_chain(c->pool, cl);
            }

            ctx->stage = NGX_RTMP_HTTP_FLV_STAGE_TAG;
        }
    }

    if (ctx->stage != NGX_RTMP_HTTP_FLV_STAGE_TAG &&
        ctx->stage != NGX_RTMP_HTTP_FLV_STAGE_TAG_CONTENT) 
    {
        return;
    }

    ngx_rtmp_flv_live_send_cycle(s);

    if (wev->active) {
        ngx_del_event(wev, NGX_WRITE_EVENT, 0);
    }

    ngx_event_process_posted((ngx_cycle_t *) ngx_cycle, &s->posted_dry_events);
}


static ngx_int_t ngx_rtmp_flv_live_send_cycle(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t   *cscf;
    ngx_chain_t                *cl, *next;
    ngx_int_t                   n;
    ngx_rtmp_flv_live_ctx_t    *ctx;

    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_live_index_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    /* send message */
    for(;s->out_pos != s->out_last;) {

        cl = s->out[s->out_pos];
        if (cl == NULL) {
            ++s->out_pos;
            s->out_pos %= s->out_queue;
            continue;
        }

        /* send tag header */
        if (ctx->stage == NGX_RTMP_HTTP_FLV_STAGE_TAG) {
            if (s->out_chain == NULL) {
                n = ngx_rtmp_flv_live_prepare_message(ctx, cl);

                if (n != NGX_OK) {
                    /* skip unused message */
                    ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos]);

                    ++s->out_pos;
                    s->out_pos %= s->out_queue;
                    continue;
                }

                s->out_chain = cl;
                s->out_bpos = cl->buf->start + NGX_RTMP_MAX_CHUNK_HEADER;
            }

            /* send tag header*/
            while (ctx->last < ctx->end) {
                n = ngx_rtmp_flv_live_send_buf(s, ctx->last,
                        ctx->end - ctx->last);
                if (n < 0) {
                    return n;
                }

                ctx->last += n;
            }

            ctx->stage = NGX_RTMP_HTTP_FLV_STAGE_TAG_CONTENT;
        }

        /* send tag body */
        if (ctx->stage == NGX_RTMP_HTTP_FLV_STAGE_TAG_CONTENT) {
            while (s->out_chain) {
                n = ngx_rtmp_flv_live_send_buf(s, s->out_bpos,
                        s->out_chain->buf->last - s->out_bpos);
                if (n < 0) {
                    return n;
                }
                s->out_bpos += n;

                /* send chunk imcomplete */
                if (s->out_bpos != s->out_chain->buf->last) {
                    continue;
                }

                /* send message imcomplete : next chain */
                next = s->out_chain->next;
                if (next) {
                    s->out_chain = next;
                    s->out_bpos = next->buf->start + NGX_RTMP_MAX_CHUNK_HEADER;
                    continue;
                }

                /* ok send message complete */
                ngx_rtmp_free_shared_chain(cscf, s->out[s->out_pos]);
                ++s->out_pos;
                s->out_pos %= s->out_queue;

                ctx->stage = NGX_RTMP_HTTP_FLV_STAGE_TAG;
                s->out_chain = NULL;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_flv_live_prepare_message(ngx_rtmp_flv_live_ctx_t *ctx, ngx_chain_t *in)
{
    ngx_rtmp_header_t    *h;
    u_char               *p, *ph;
    uint32_t              pts, sz;

    if (in == NULL || in->buf->tag == NULL) {
        return NGX_ERROR;
    }

    h = (ngx_rtmp_header_t *)in->buf->tag;
    if (h->type != NGX_RTMP_MSG_AUDIO && h->type != NGX_RTMP_MSG_VIDEO 
     && h->type != NGX_RTMP_MSG_AMF_META)
    {
        return NGX_DECLINED;
    }

    /* skip dummy audio */
    if (h->mlen == 0) {
        return NGX_DECLINED;
    }

    /* first tag must be zero */
    if (ctx->basetime == 0) {
        ctx->basetime = h->timestamp;
        ctx->pts = h->timestamp;
    }

    pts = h->timestamp - ctx->basetime;

    ctx->last = ctx->header;
    ctx->end = ctx->last + 15;

    ph = ctx->last;

    /* pre-tag size */
    sz = ctx->h.mlen ? ctx->h.mlen + 11: 0;
    p = (u_char *)&sz;

    *ph++ = p[3];
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    *ph++ = h->type;

    p = (u_char*)&h->mlen;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];

    ctx->pts = h->timestamp;

    if ((int32_t)pts < 0) {
        ngx_log_error(NGX_LOG_INFO, ctx->s->connection->log, 0,
            "flv-live: prepare timestamp=%d, h->type=%uD, h->ts=%uD",
            (int32_t)pts, (uint32_t)h->type, h->timestamp);
        pts = 0;
    }

    p = (u_char*)&pts;
    *ph++ = p[2];
    *ph++ = p[1];
    *ph++ = p[0];
    *ph++ = p[3];

    *ph++ = 0;
    *ph++ = 0;
    *ph++ = 0;

    ctx->h = *h;

    return NGX_OK;
}


static ssize_t 
ngx_rtmp_flv_live_send_buf(ngx_rtmp_session_t *s, u_char *buf, size_t size)
{
    ngx_connection_t    *c;
    ssize_t              n;

    c = s->connection;
    n = c->send(c, buf, size);

    if (n == NGX_AGAIN || n == 0) {
        ngx_add_timer(c->write, s->timeout);
        if (ngx_handle_write_event(c->write, 0) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "rtmp send n=%d add write event failed", n);
            ngx_rtmp_finalize_session(s);
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    if (n < 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, ngx_errno,
                      "rtmp send n<0 n=%d", n);
        ngx_rtmp_finalize_session(s);
        return NGX_ERROR;
    }

    s->out_bytes += n;
    s->ping_reset = 1;

    ngx_rtmp_update_bandwidth(&ngx_rtmp_bw_out, n);

    return n;
}


static ngx_int_t
ngx_rtmp_flv_live_connect(ngx_rtmp_flv_live_ctx_t *ctx)
{
    ngx_connection_t                   *c;
    ngx_str_t                          *app;
    
    static ngx_rtmp_connect_t           v;

    c = ctx->s->connection;
    app = &ctx->app;

    ngx_memzero(&v, sizeof(ngx_rtmp_connect_t));
    ngx_memcpy(v.app, app->data, ngx_min(app->len, sizeof(v.app) - 1));

    if (ctx->r->args.len > 0) {
        ngx_memcpy(v.args, ctx->r->args.data,
            ngx_min(ctx->r->args.len, sizeof(v.args) - 1));
    }

    ngx_memcpy(v.flashver, NGX_RTMP_FLV_LIVE_FLASHVER, 
        sizeof(NGX_RTMP_FLV_LIVE_FLASHVER) - 1);

    *ngx_snprintf(v.tc_url, NGX_RTMP_MAX_URL, "%V://%V/%V", &ctx->r->schema,
            &ctx->r->headers_in.host->value, app) = 0;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
            "flv-live: connect: app='%s' args='%s' flashver='%s' swf_url='%s' "
            "tc_url='%s' page_url='%s' acodecs=%uD vcodecs=%uD "
            "object_encoding=%ui",
            v.app, v.args, v.flashver, v.swf_url, v.tc_url, v.page_url,
            (uint32_t)v.acodecs, (uint32_t)v.vcodecs,
            (ngx_int_t)v.object_encoding);

    return ngx_rtmp_connect(ctx->s, &v);
}


static ngx_int_t 
ngx_rtmp_flv_live_play(ngx_rtmp_flv_live_ctx_t *ctx)
{
    ngx_rtmp_session_t          *s;

    static ngx_rtmp_play_t       v;

    ngx_memzero(&v, sizeof(ngx_rtmp_play_t));

    s = ctx->s;
    ngx_memcpy(v.name, ctx->stream.data,
        ngx_min(ctx->stream.len, sizeof(v.name) - 1));

    ngx_memcpy(v.args, s->args.data,
        ngx_min(s->args.len, sizeof(v.args) - 1));

    v.silent = 1;
    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
           "flv-live: name='%s' args='%s' start=%i duration=%i "
           "reset=%i silent=%i",
           v.name, v.args, (ngx_int_t) v.start,
           (ngx_int_t) v.duration, (ngx_int_t) v.reset,
           (ngx_int_t) v.silent);

    return ngx_rtmp_play(s, &v);
}


static ngx_int_t 
ngx_rtmp_flv_live_send_headers(ngx_rtmp_flv_live_ctx_t *ctx)
{
    ngx_http_request_t          *r;
    ngx_int_t                    rc;
    unsigned                     delayed;
    ngx_chain_t                 *cl, *last;

    if (ctx->r == NULL) {
        return NGX_ERROR;
    }

    r = ctx->r;

    delayed = r->connection->write->delayed;
    r->connection->write->delayed = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->header_only = 1;

    ngx_str_set(&r->headers_out.content_type, NGX_RTMP_FLV_MIME_TYPE);

    rc = ngx_http_send_header(r);
    if (rc != NGX_AGAIN || r->out->buf == NULL) {
        return NGX_ERROR;
    }

    /*write buffered!*/
    r->connection->write->delayed = delayed;

    last = r->out;
    while (last->next) {
        last = last->next;
    }

    cl = ngx_alloc_chain_link(r->connection->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = ngx_create_temp_buf(r->connection->pool, sizeof(flv_header));
    if (cl->buf == NULL) {
        return NGX_ERROR;
    }
    cl->buf->last = ngx_cpymem(cl->buf->pos, flv_header, sizeof(flv_header));

    last->next = cl;
    cl->next = NULL;

    ctx->out = r->out;
    ctx->outlast = ctx->out;

    if (ctx->out == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_rtmp_flv_live_recv(ngx_event_t *rev)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;
    ngx_rtmp_session_t         *s;
    ngx_int_t                   n;
    ngx_rtmp_flv_live_ctx_t    *ctx;
    u_char                      buf[2048];

    c = rev->data;
    if (c->destroyed) {
        return;
    }

    r = c->data;
    ctx = ngx_http_get_module_ctx(r, ngx_rtmp_flv_live_module);
    s = ctx->s;

    for ( ;; ) {
        n = c->recv(c, buf, sizeof(buf));

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->read, s->timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
            }

            break;
        } else if (n == 0 || n == -1) {
            ngx_rtmp_finalize_session(s);
            break;
        }
    }
}


static void ngx_rtmp_flv_live_http_send(ngx_event_t *wev)
{
    ngx_connection_t                   *c;
    ngx_rtmp_session_t                 *s;
    ngx_rtmp_flv_live_ctx_t            *ctx;
    ngx_chain_t                        *cl;

    c = wev->data;
    s = c->data;

    if (c->destroyed) {
        return;
    }

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                "netcall: client send timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_live_index_module);
    if (ctx == NULL) {
        return ;
    }

    cl = c->send_chain(c, ctx->outlast, 0);
    if (cl == NGX_CHAIN_ERROR) {
        ngx_rtmp_finalize_session(s);
        return;
    }

    ctx->outlast = cl;

    ngx_event_process_posted((ngx_cycle_t *)ngx_cycle, &s->posted_dry_events);

    /* more data to send? */
    if (cl) {
        ngx_add_timer(wev, 5000);
        if (ngx_handle_write_event(wev, 0) != NGX_OK) {
            ngx_rtmp_finalize_session(s);
        }
        return;
    }

    /* we've sent everything we had.
     * now receive reply */
    ngx_del_event(wev, NGX_WRITE_EVENT, 0);

    for (cl = ctx->out; cl; cl = ctx->out) {
        ctx->out = ctx->out->next;
        ngx_free_chain(c->pool, cl);
    }

    ctx->out = ctx->outlast = NULL;

    ngx_rtmp_flv_live_http_recv(c->read);

    return;
}


static void ngx_rtmp_flv_live_http_recv(ngx_event_t *rev)
{
    ngx_rtmp_flv_live_ctx_t            *ctx;
    ngx_connection_t                   *c;
    ngx_rtmp_session_t                 *s;
    ngx_int_t                           n;
    ngx_buf_t                          *b;

    c = rev->data;
    s = c->data;

    if (c->destroyed) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_live_index_module);
    if (ctx == NULL) {
        ngx_rtmp_finalize_session(s);
        return ;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "http-flv: client recv http data timed out");
        c->timedout = 1;
        ngx_rtmp_finalize_session(s);
        return;
    }

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    for (;;) {
        if (ctx->in == NULL || ctx->in->buf->last == ctx->in->buf->end) {
            /* handle chain */
            if (ctx->in) {
                if (ngx_rtmp_flv_live_http_recv_handle(s, ctx->in) != NGX_OK) {
                    ngx_rtmp_finalize_session(s);
                    return;
                }
                ctx->in = NULL;
            }

            ctx->in = ngx_rtmp_flv_live_alloc_chain_buf(ctx);
            if (ctx->in == NULL) {
                ngx_rtmp_finalize_session(s);
                return;
            }
        }

        b = ctx->in->buf;
        n = c->recv(c, b->last, b->end - b->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_rtmp_finalize_session(s);
            return;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(rev, 50000);
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_rtmp_finalize_session(s);
            }
            return;
        }

        b->last += n;
    }
}

static ngx_int_t
ngx_rtmp_flv_live_http_skip_header(ngx_rtmp_flv_live_ctx_t *ctx)
{
    ngx_chain_t                        *in;
    ngx_buf_t                          *b;
    u_char                              ch;

    in = ctx->body;
    while (in && ctx->ncrs != 2) {
        b = in->buf;

        /* find \n[\r]\n */
        for (; b->pos != b->last && ctx->ncrs != 2; ++b->pos, --ctx->nbody) {
            ch = *b->pos;
            switch (ch) {
            case '\n':
                ++ctx->ncrs;
            case '\r':
                break;
            default:
                ctx->ncrs = 0;
            }
            /* 10th header byte is HTTP response header */
            if (++ctx->nheader == 10 && ch != (u_char)'2') {
                ngx_log_error(NGX_LOG_INFO, ctx->s->connection->log, 0,
                    "http-flv: remote HTTP response code: %cxx", ch);
                return NGX_ERROR;
            }
        }

        if (b->pos == b->last) {
            in = in->next;
        }
    }

    if (ctx->ncrs != 2) {
        return NGX_AGAIN;
    }

    /* free http headers */
    ngx_rtmp_flv_live_free_chains(ctx, ctx->body, in);

    ctx->body = in;
    ctx->stage = NGX_RTMP_HTTP_FLV_STAGE_FLV;

    return NGX_OK;
}

static ngx_int_t 
ngx_rtmp_flv_live_http_recv_handle(ngx_rtmp_session_t *s, ngx_chain_t *in)
{
    ngx_rtmp_flv_live_ctx_t            *ctx;
    ngx_chain_t                        *body;
    u_char                             *header;
    size_t                              n;
    ngx_int_t                           rc;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_live_index_module);
    if (in == NULL) {
        return NGX_OK;
    }

    /* detect body-size */
    n = 0;
    for (body = in; body; body = body->next) {
        n += body->buf->last - body->buf->pos;
    }

    if (ctx->body == NULL) {
        ctx->body = in;
        ctx->nbody = n;

    } else { /* append body */
        for (body = ctx->body; body->next; body = body->next) {
            /* no ops */
        }

        body->next = in;
        
        in = ctx->body;
        ctx->nbody += n;
    }

    /* skip HTTP header */
    if (ctx->ncrs != 2) {
        rc = ngx_rtmp_flv_live_http_skip_header(ctx);
        
        if (rc == NGX_AGAIN) {
            return NGX_OK;
        }

        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* parse 'F', 'L', 'V' header*/
    if (ctx->stage == NGX_RTMP_HTTP_FLV_STAGE_FLV && ctx->nbody >= 9) {

        /* copy flv header */
        if (ngx_rtmp_flv_live_copy_header(ctx, 9) != 9) {
            return NGX_ERROR;
        }

        header = ctx->header;

        /* signature */
        if (header[0] != 'F' || header[1] != 'L' || header[2] != 'V') {
            return NGX_ERROR;
        }

        /* version and headsize */
        if (header[3] != 0x01 || header[8] != 0x09) {
            return NGX_ERROR;
        }

        ctx->audio = (header[4] & 0x04) >> 2;
        ctx->video = header[4] & 0x01;

        ctx->stage = NGX_RTMP_HTTP_FLV_STAGE_TAG;

        /* publish local */
        if (ngx_rtmp_flv_live_http_publish_local(ctx->s) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ctx->stage == NGX_RTMP_HTTP_FLV_STAGE_TAG ||
        ctx->stage == NGX_RTMP_HTTP_FLV_STAGE_TAG_CONTENT) 
    {
        return ngx_rtmp_flv_live_http_recv_cycle(s);
    }

    return NGX_ERROR;
}

static size_t 
ngx_rtmp_flv_live_copy_header(ngx_rtmp_flv_live_ctx_t *ctx, size_t n)
{
    ngx_buf_t       *b;
    ngx_chain_t     *body, *in;
    size_t           m;

    /* copy flv header */
    ctx->last = ctx->header;
    ctx->end = ctx->last + n;

    in = ctx->body;
    for (body = in; body; body = body->next) {
        b = body->buf;

        n = ctx->end - ctx->last;
        m = b->last - b->pos;

        if (m >= n) {

            ctx->last = ngx_cpymem(ctx->last, b->pos, n);
            b->pos += n;
            ctx->nbody -= n;

            while (b->pos == b->last && body != NULL) {
                body = body->next;
            }
            ctx->body = body;

            /* free message chain */
            ngx_rtmp_flv_live_free_chains(ctx, in, ctx->body);
            break;
        }

        ctx->last = ngx_cpymem(ctx->last, b->pos, m);
        b->pos = b->last;

        ctx->nbody -= m;
    }

    return ctx->last - ctx->header;
}


static ngx_int_t ngx_rtmp_flv_live_http_recv_cycle(ngx_rtmp_session_t *s)
{
    ngx_rtmp_flv_live_ctx_t     *ctx;
    u_char                      *header;
    ngx_buf_t                   *b;
    ngx_chain_t                 *body, *in;
    ngx_int_t                    rc;
    size_t                       n, m;
    ngx_rtmp_header_t           *h;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_flv_live_index_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    for(;;) {
        /* tag header */
        if (ctx->stage == NGX_RTMP_HTTP_FLV_STAGE_TAG && ctx->nbody >= 15) {
            /* copy tag header */
            /* 4B: pre-tagsize */
            /* 1B: type */
            /* 3B: size */
            /* 3B: timestamp */
            /* 1B: ext-timestamp */
            /* 3B: streamId */
            if (ngx_rtmp_flv_live_copy_header(ctx, 15) != 15) {
                return NGX_ERROR;
            }

            header = ctx->header;

            /* 4B: pre-tagsize, ignore */
            ngx_memzero(&ctx->h, sizeof(ctx->h));

            h = &ctx->h;

            /* 1B: type */
            h->type = header[4];
            
            switch(h->type) {
            case NGX_RTMP_MSG_VIDEO:
                h->csid = NGX_RTMP_CSID_VIDEO;

                break;

            case NGX_RTMP_MSG_AUDIO:
                h->csid = NGX_RTMP_CSID_AUDIO;

                break;

            case NGX_RTMP_MSG_AMF_META:
                h->csid = NGX_RTMP_CSID_AMF;
                break;

            default:

                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                    "flv-live: tag-header, invalid type: type=%uD", 
                    (uint32_t)h->type);

                return NGX_ERROR;
            }

            /* 3B: size */
            h->mlen = (header[5] << 16) + (header[6] << 8) + header[7];

            /* > 1MB */
            if (h->mlen > 1024 * 1024) {

                ngx_log_error(NGX_LOG_WARN, s->connection->log, 0,
                    "flv-live: tag-header, invalid len: type=%uD, mlen=%uD", 
                    (uint32_t)h->type, (uint32_t)h->mlen);

                return NGX_ERROR;
            }

            /* 3B: timestamp */
            /* 1B: ext-timestamp */
            h->timestamp = (header[11] << 24) +
                (header[8] << 16) + (header[9] << 8) + header[10];

            /* 3B: streamId ignore */
            h->msid = NGX_RTMP_MSID;
            ctx->stage = NGX_RTMP_HTTP_FLV_STAGE_TAG_CONTENT;

            continue;
        }

        /* recieve a flv tag message */
        if (ctx->stage == NGX_RTMP_HTTP_FLV_STAGE_TAG_CONTENT &&
            ctx->nbody >= ctx->h.mlen)
        {

            /* detect message end */
            m = ctx->h.mlen;
            in = ctx->body;
            for (body = in; body; body = body->next) {
                b = body->buf;
                n = b->last - b->pos;

                if (n >= m) {
                    b->last = b->pos + m;

                    /* handle message */
                    rc = ngx_rtmp_receive_message(s, &ctx->h, in);
                    if (rc != NGX_OK) {
                        return rc;
                    }

                    b->pos = b->last;
                    b->last += (n - m);

                    while (b->pos == b->last && body != NULL) {
                        body = body->next;
                    }

                    ctx->body = body;
                    ctx->nbody -= ctx->h.mlen;

                    /* free message chain */
                    ngx_rtmp_flv_live_free_chains(ctx, in, ctx->body);
                    ctx->stage = NGX_RTMP_HTTP_FLV_STAGE_TAG;
                    break;
                }

                m -= n;
            }

            continue;
        }

        break;
    }

    return NGX_OK;
}

static void 
ngx_rtmp_flv_live_cleanup(void *data)
{
    ngx_rtmp_session_t *s;

    s = data;
    ngx_rtmp_finalize_session(s);

    return ;
}


static ngx_rtmp_flv_live_ctx_t * 
ngx_rtmp_flv_live_client_init(ngx_rtmp_session_t *s)
{
    ngx_chain_t                     *args;
    ngx_buf_t                       *b;
    
    ngx_rtmp_flv_live_ctx_t         *ctx;

    ngx_str_t                        sfx;
    size_t                           len;

    ngx_rtmp_relay_ctx_t            *rctx;
    ngx_rtmp_core_app_conf_t        *cacf;
    u_char                          *host_end, *p;

    cacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_core_module);
    rctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);

    if (cacf == NULL || rctx == NULL) {
        return NULL;
    }

    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_flv_live_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    args = ngx_rtmp_netcall_http_format_session(s, s->connection->pool);
    if (args == NULL) {
        return NULL;
    }

    ctx->args = args;
    ctx->s = s;

    /* host data */
    host_end = ngx_strlchr(rctx->url.data, rctx->url.data + rctx->url.len, '/');
    if (host_end) {
        ctx->host.data = rctx->url.data;
        ctx->host.len = host_end - rctx->url.data;
    } else {
        ctx->host.data = s->addr_text->data;
        ctx->host.len = s->addr_text->len;
    }

    ctx->app.data = cacf->name.data;
    ctx->app.len = cacf->name.len;

    /* app */
    if (rctx->app.len) {

        ctx->app.data = rctx->app.data;
        ctx->app.len = rctx->app.len;

        p = (u_char *)ngx_strchr(ctx->app.data, '?');
        if (p != NULL) {
            
            ctx->app.len = p - ctx->app.data;
            len = rctx->app.len - ctx->app.len - 1;

            /* split app, append to arglist */
            if (len > 0) {

                args = ngx_alloc_chain_link(s->connection->pool);
                if (args == NULL) {
                    return NULL;
                }

                b = ngx_create_temp_buf(s->connection->pool, len);
                if (b == NULL) {
                    return NULL;
                }

                b->last = ngx_cpymem(b->last, ++p, len);
                args->buf = b;
                args->next = ctx->args;
                
                ctx->args = args;
            }
        }
    }

    /* play_path */
    if (rctx->play_path.len) {
        ctx->stream.data = rctx->play_path.data;
        ctx->stream.len = rctx->play_path.len;

        sfx.len = 0;
    } else {
        ctx->stream.data = rctx->name.data;
        ctx->stream.len = rctx->name.len;

        sfx.data = (u_char *)NGX_RTMP_FLV_SUFFIX;
        sfx.len = sizeof(NGX_RTMP_FLV_SUFFIX) - 1;
    }

    ctx->uri.data = ngx_pcalloc(s->connection->pool, 
        ctx->app.len + ctx->stream.len + sfx.len);
    if (ctx->uri.data == NULL) {
        return NULL;
    }

    p = ngx_sprintf(ctx->uri.data, "/%V/%V%V", &ctx->app, &ctx->stream, &sfx);
    ctx->uri.len = p - ctx->uri.data;

    ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_flv_live_index_module);

    return ctx;
}


static ngx_chain_t *
ngx_rtmp_flv_live_alloc_chain_buf(ngx_rtmp_flv_live_ctx_t *ctx)
{
    ngx_pool_t      *pool;
    ngx_chain_t     *cl;

    cl = ctx->free_chains;

    if (cl) {
        ctx->free_chains = cl->next;
        cl->next = NULL;
        
        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        return cl;
    }

    pool = ctx->s->connection->pool;
    cl = ngx_pcalloc(pool, sizeof(ngx_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = ngx_create_temp_buf(pool, 4096);
    if (cl->buf == NULL) {
        return NULL;
    }

    return cl;
}

static void 
ngx_rtmp_flv_live_free_chains(ngx_rtmp_flv_live_ctx_t *ctx, ngx_chain_t *start,
    ngx_chain_t *end)
{
    ngx_chain_t     *cl;
    
    if (start == NULL || start == end) {
        return ;
    }

    for (cl = start; cl && cl->next != end; cl = cl->next) {
        /* no ops */
    }

    cl->next = ctx->free_chains;
    ctx->free_chains = start;
}


static ngx_int_t
ngx_rtmp_flv_live_http_publish_local(ngx_rtmp_session_t *s)
{
    ngx_rtmp_publish_t          v;
    ngx_rtmp_relay_ctx_t       *ctx;

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_relay_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&v, sizeof(ngx_rtmp_publish_t));
    v.silent = 1;
    *(ngx_cpymem(v.name, ctx->name.data,
            ngx_min(sizeof(v.name) - 1, ctx->name.len))) = 0;

    return ngx_rtmp_publish(s, &v);
}
