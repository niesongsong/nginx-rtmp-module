
/*
 * Copyright (C) nie950@gmail.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_rtmp_cmd_module.h"
#include "ngx_rtmp_codec_module.h"
#include "ngx_rtmp_gop_module.h"
#include "ngx_rtmp_live_module.h"


typedef struct {
    ngx_array_t             frames;
    uint8_t                 skip:1;

    uint8_t                 avc_header:1;
    uint8_t                 aac_header:1;
    ngx_rtmp_session_t     *session;
} ngx_rtmp_gop_ctx_t;


typedef struct {
    ngx_flag_t             gop_cache;
    ngx_uint_t             gop_cache_max_frame_cnt;
} ngx_rtmp_gop_app_conf_t;


/*gop frame struct*/
typedef struct {
    ngx_chain_t                   *in;
    ngx_uint_t                     priority;
    ngx_rtmp_header_t              h;
} ngx_rtmp_cache_frame_t;


static ngx_rtmp_publish_pt              next_publish;
static ngx_rtmp_play_pt                 next_play;
static ngx_rtmp_close_stream_pt         next_close_stream;


static ngx_int_t ngx_rtmp_gop_postconfiguration(ngx_conf_t *cf);
static void * ngx_rtmp_gop_create_app_conf(ngx_conf_t *cf);
static char * ngx_rtmp_gop_merge_app_conf(ngx_conf_t *cf,
       void *parent, void *child);

static ngx_int_t ngx_rtmp_gop_publish(ngx_rtmp_session_t *s,
    ngx_rtmp_publish_t *v);
static ngx_int_t ngx_rtmp_gop_play(ngx_rtmp_session_t *s,
    ngx_rtmp_play_t *v);
static ngx_int_t ngx_rtmp_gop_close_stream(ngx_rtmp_session_t *s,
    ngx_rtmp_close_stream_t *v);

static ngx_int_t ngx_rtmp_gop_append_frame(ngx_rtmp_gop_ctx_t *ctx,
    ngx_chain_t *in, ngx_rtmp_header_t *h, ngx_uint_t priority);

static ngx_int_t  ngx_rtmp_gop_append_abs_frame(ngx_rtmp_session_t *s, 
    ngx_rtmp_gop_ctx_t *ctx, ngx_chain_t *header, ngx_rtmp_header_t *h,
    ngx_uint_t priority);


static ngx_command_t  ngx_rtmp_gop_commands[] = {

    { ngx_string("gop_cache"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_app_conf_t, gop_cache),
      NULL },

    { ngx_string("gop_cache_max_frame_cnt"),
      NGX_RTMP_MAIN_CONF|NGX_RTMP_SRV_CONF|NGX_RTMP_APP_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_RTMP_APP_CONF_OFFSET,
      offsetof(ngx_rtmp_gop_app_conf_t, gop_cache_max_frame_cnt),
      NULL },

    ngx_null_command
};

static ngx_rtmp_module_t  ngx_rtmp_gop_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_rtmp_gop_postconfiguration,         /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_rtmp_gop_create_app_conf,           /* create app configuration */
    ngx_rtmp_gop_merge_app_conf             /* merge app configuration */
};

ngx_module_t  ngx_rtmp_gop_module = {
    NGX_MODULE_V1,
    &ngx_rtmp_gop_module_ctx,               /* module context */
    ngx_rtmp_gop_commands,                  /* module directives */
    NGX_RTMP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_rtmp_gop_create_app_conf(ngx_conf_t *cf)
{
    ngx_rtmp_gop_app_conf_t      *gacf;

    gacf = ngx_pcalloc(cf->pool, sizeof(ngx_rtmp_gop_app_conf_t));
    if (gacf == NULL) {
        return NULL;
    }
    gacf->gop_cache = NGX_CONF_UNSET;
    gacf->gop_cache_max_frame_cnt = NGX_CONF_UNSET_UINT;

    return gacf;
}


static char *
ngx_rtmp_gop_merge_app_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_rtmp_gop_app_conf_t *prev = parent;
    ngx_rtmp_gop_app_conf_t *conf = child;

    ngx_conf_merge_value(conf->gop_cache, prev->gop_cache, 0);
    ngx_conf_merge_uint_value(conf->gop_cache_max_frame_cnt, 
        prev->gop_cache_max_frame_cnt, 512);

    return NGX_CONF_OK;
}


void 
ngx_rtmp_gop_clean_frames(ngx_rtmp_session_t *s)
{
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_gop_ctx_t             *ctx;
    ngx_rtmp_cache_frame_t         *h;
    ngx_uint_t                      i;

    if (s == NULL) {
        return;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);

    if (ctx == NULL || cscf == NULL) {
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                  "gop: clean frames, skip='%u' frames='%u'",
                   (ngx_uint_t)ctx->skip, ctx->frames.nelts);

    h = (ngx_rtmp_cache_frame_t *)(ctx->frames.elts);
    for (i = 0; i < ctx->frames.nelts; i++) {
        ngx_rtmp_free_shared_chain(cscf, h[i].in);
    }

    ctx->frames.nelts  = 0;
    ctx->skip = 1;
    ctx->avc_header = 0;
    ctx->aac_header = 0;
}

static ngx_int_t
ngx_rtmp_gop_publish(ngx_rtmp_session_t *s, ngx_rtmp_publish_t *v)
{
    ngx_rtmp_gop_app_conf_t  *gacf;
    ngx_rtmp_live_app_conf_t *lacf;
    ngx_rtmp_gop_ctx_t       *ctx;
    ngx_int_t                 rc;

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_module);
    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live || gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                   "gop: publish: name='%s' type='%s'", v->name, v->type);

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    if (ctx == NULL) {
        
        ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_rtmp_gop_ctx_t));
        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "gop cache allocate ctx failed");
            goto next;
        }

        rc = ngx_array_init(&ctx->frames, s->connection->pool, 
            gacf->gop_cache_max_frame_cnt, sizeof(ngx_rtmp_cache_frame_t));

        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "gop cache allocate cache failed");
            goto next;
        }

        ctx->skip = 1;
        ctx->session = s;
        ngx_rtmp_set_ctx(s, ctx, ngx_rtmp_gop_module);
    }

next:
    return next_publish(s, v);
}

/*
   "NetStream.Play.Start" has been sent by ngx_rtmp_live_module
    dump a/v data (sps included)
*/
static ngx_int_t 
ngx_rtmp_gop_play(ngx_rtmp_session_t *s, ngx_rtmp_play_t *v)
{
    ngx_rtmp_gop_app_conf_t        *gacf;
    ngx_rtmp_gop_ctx_t             *ctx;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_live_ctx_t            *lctx, *pctx;
    ngx_rtmp_codec_ctx_t           *cctx;
    ngx_rtmp_session_t             *ss;
    ngx_rtmp_core_srv_conf_t       *cscf;
    ngx_rtmp_cache_frame_t         *header;
    ngx_uint_t                      i;
    ngx_uint_t                      csidx, ndropped;
    ngx_rtmp_live_chunk_stream_t   *cs;    
#ifdef NGX_DEBUG
    const char                     *type_s;
#endif

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_module);
    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (lacf == NULL || !lacf->live || gacf == NULL || !gacf->gop_cache) {
        goto next;
    }

    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);
    lctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_live_module);
    if (lctx == NULL || lctx->stream == NULL ||
        !(lctx->stream->active && lctx->stream->publishing)) 
    {
        goto next;
    }

    ctx = NULL;
    cctx = NULL;

    /* check stream status: find publish session gop ctx */
    for (pctx = lctx->stream->ctx; pctx; pctx = pctx->next) {
        if(pctx->publishing && pctx->session != NULL) {

            ss = pctx->session;

            ctx = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_gop_module);
            cctx = ngx_rtmp_get_module_ctx(ss, ngx_rtmp_codec_module);
 
            break;
        }
    }

    if (ctx == NULL) {
        goto next;
    }

    /* send meta data*/
    if (cctx && cctx->meta) {
        ngx_log_debug0(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
            "live: meta");

        /* send failed maybe resend in ngx_live_module, ignore*/
        if (ngx_rtmp_send_message(s, cctx->meta, 0) == NGX_OK) {
            lctx->meta_version = cctx->meta_version;
        }
    }

    /* dump a/v cached data (sps included) */
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    if (cscf == NULL) {
        goto next;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,  
        "gop: dump a/v frame, frames: %uD", ctx->frames.nelts);

    ndropped = 0;
    header = (ngx_rtmp_cache_frame_t *)(ctx->frames.elts);
    for (i = 0; i < ctx->frames.nelts; i++, header++) {

        if (header == NULL || header->in == NULL) {
            continue;
        }

        csidx = !(lacf->interleave || header->h.type == NGX_RTMP_MSG_VIDEO);
        cs = &lctx->cs[csidx];

#ifdef NGX_DEBUG

        type_s = (header->h.type == NGX_RTMP_MSG_VIDEO ? "video" : "audio");

        ngx_log_debug2(NGX_LOG_DEBUG_RTMP, s->connection->log, 0,
                       "gop: send %s packet time=%uD",
                       type_s, header->h.timestamp);
#endif

        if (ngx_rtmp_send_message(s, header->in, header->priority) != NGX_OK) {

            if (header->priority == NGX_RTMP_VIDEO_KEY_FRAME) {

                ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                    "gop: send key frame failed");

                return NGX_ERROR;
            }

            ++lctx->ndropped;
            ++ndropped;
        }

        cs->timestamp = header->h.timestamp;
        s->current_time = header->h.timestamp;

        cs->active = 1;
    }

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,  
        "gop: append frames finished, frames: %uD, droped: %uD", 
        ctx->frames.nelts, ndropped);

next:
    return next_play(s, v);
}


static ngx_int_t 
ngx_rtmp_gop_close_stream(ngx_rtmp_session_t *s,
    ngx_rtmp_close_stream_t *v)
{
    ngx_rtmp_gop_clean_frames(s);

    return next_close_stream(s, v);
}


static ngx_int_t
ngx_rtmp_gop_append_frame(ngx_rtmp_gop_ctx_t * ctx, ngx_chain_t * in,
    ngx_rtmp_header_t *h, ngx_uint_t priority)
{
    ngx_rtmp_cache_frame_t *frame;

    frame = (ngx_rtmp_cache_frame_t *)ngx_array_push(&ctx->frames);

    if (frame == NULL) {
        return NGX_ERROR;
    }

    frame->h.csid = h->csid;
    frame->h.mlen = h->mlen;
    frame->h.msid = h->msid;
    frame->h.type = h->type;
    frame->h.timestamp = h->timestamp;
    frame->in = in;
    frame->priority = priority;

    ngx_rtmp_ref_get(frame->in);

    return NGX_OK;
}

static ngx_int_t 
ngx_rtmp_gop_append_abs_frame(ngx_rtmp_session_t *s, ngx_rtmp_gop_ctx_t *ctx,
    ngx_chain_t *header, ngx_rtmp_header_t *h, ngx_uint_t priority)
{
    ngx_chain_t                    *apkt;
    ngx_int_t                       rc;
    ngx_rtmp_core_srv_conf_t       *cscf;
    
    cscf = ngx_rtmp_get_module_srv_conf(s, ngx_rtmp_core_module);
    apkt = ngx_rtmp_append_shared_bufs(cscf, NULL, header);
    rc = NGX_ERROR;

    if (apkt != NULL) {
        ngx_rtmp_prepare_message(s, h, NULL, apkt);
        rc = ngx_rtmp_gop_append_frame(ctx, apkt, h, priority);
        if (rc != NGX_OK) {
            ngx_rtmp_free_shared_chain(cscf, apkt);
        }
    }

    return rc;
}


ngx_int_t 
ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_rtmp_header_t *ch, 
    ngx_rtmp_header_t *lh, ngx_chain_t *in, ngx_chain_t *pkt)
{
    ngx_rtmp_gop_app_conf_t        *gacf;
    ngx_rtmp_gop_ctx_t             *ctx;
    ngx_rtmp_live_app_conf_t       *lacf;
    ngx_rtmp_codec_ctx_t           *cctx;
    ngx_uint_t                      prio;
    ngx_rtmp_header_t               clh;

    clh = *ch;
    clh.type = (ch->type == NGX_RTMP_MSG_AUDIO ? NGX_RTMP_MSG_VIDEO :
                                                NGX_RTMP_MSG_AUDIO);

    gacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_gop_module);
    lacf = ngx_rtmp_get_module_app_conf(s, ngx_rtmp_live_module);

    if (gacf == NULL || !gacf->gop_cache || lacf == NULL || !lacf->live) {
        return NGX_OK;
    }

    ctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_gop_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    prio = (ch->type == NGX_RTMP_MSG_VIDEO ?
            ngx_rtmp_get_video_frame_type(in) : 0);

    cctx = ngx_rtmp_get_module_ctx(s, ngx_rtmp_codec_module);
    
    /* video key frame*/
    if (prio == NGX_RTMP_VIDEO_KEY_FRAME) {

        /* h264 codec */
        if (cctx && cctx->video_codec_id == NGX_RTMP_VIDEO_H264 &&
            ngx_rtmp_is_codec_header(in) && !ctx->avc_header)
        {
            return NGX_OK;
        }

        ngx_rtmp_gop_clean_frames(s);
        ctx->skip = 0;

        /* append  h264 codec avc_header */
        if (cctx && cctx->avc_header &&
            cctx->video_codec_id == NGX_RTMP_VIDEO_H264)
        {
            ngx_rtmp_gop_append_abs_frame(s, ctx, cctx->avc_header, ch, 0);
            ctx->avc_header = 1;
        }

        /* interleave append aac codec header */
        if (lacf && lacf->interleave) {

            if (cctx && cctx->aac_header &&
                cctx->audio_codec_id == NGX_RTMP_AUDIO_AAC)
            {
                ngx_rtmp_gop_append_abs_frame(s, ctx, cctx->aac_header, &clh,0);
                ctx->aac_header = 1;
            }
        }

        /* video key frame */
        if (!ctx->avc_header) {

            ctx->avc_header = 1;
            ngx_rtmp_gop_append_abs_frame(s, ctx, in, ch, prio);

            return NGX_OK;
        }
    }

    /* do not start cache frame, until meet key frame */
    if (ctx->skip) {
        return NGX_OK;
    }

    /* audio header */
    if (ch->type == NGX_RTMP_MSG_AUDIO) {

        /* aac codec header */
        if (cctx && cctx->audio_codec_id == NGX_RTMP_AUDIO_AAC &&
            ngx_rtmp_is_codec_header(in) && !ctx->aac_header)
        {
            return NGX_OK;
        }

        /* noninterleave append aac codec header */
        if (!ctx->aac_header && (lacf == NULL || !lacf->interleave)) {

            if (cctx && cctx->aac_header &&
                cctx->audio_codec_id == NGX_RTMP_AUDIO_AAC)
            {
                ngx_rtmp_gop_append_abs_frame(s, ctx, cctx->aac_header, ch, 0);
                ctx->aac_header = 1;
            }

            /* noninterleave append abs packet */
            if (!ctx->aac_header) {
                ctx->aac_header = 1;
                ngx_rtmp_gop_append_abs_frame(s, ctx, in, ch, prio);

                return NGX_OK;
            }
        }
    }

    /* cache data */
    if (ctx->frames.nelts < gacf->gop_cache_max_frame_cnt) {

        ngx_rtmp_gop_append_frame(ctx, pkt, ch, prio);
        
    } else {    /* drop all cached frames */

        ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
            "gop: exceed max frame count, reset gop");

        ngx_rtmp_gop_clean_frames(s);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_rtmp_gop_postconfiguration(ngx_conf_t *cf)
{
    next_publish = ngx_rtmp_publish;
    ngx_rtmp_publish = ngx_rtmp_gop_publish;

    next_play = ngx_rtmp_play;
    ngx_rtmp_play = ngx_rtmp_gop_play;

    next_close_stream = ngx_rtmp_close_stream;
    ngx_rtmp_close_stream = ngx_rtmp_gop_close_stream;

    return NGX_OK;
}

