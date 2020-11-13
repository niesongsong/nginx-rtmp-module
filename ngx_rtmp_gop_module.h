
/*
 * Copyright (C) nie950@gmail.com
 */


#ifndef _NGX_RTMP_GOP_MODULE_H_INCLUDED_
#define _NGX_RTMP_GOP_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include "ngx_rtmp.h"

ngx_int_t ngx_rtmp_gop_cache_frame(ngx_rtmp_session_t *s, ngx_rtmp_header_t *ch,
    ngx_rtmp_header_t *lh, ngx_chain_t *in, ngx_chain_t *pkt);

extern ngx_module_t  ngx_rtmp_gop_module;


#endif /* _NGX_RTMP_GOP_MODULE_H_INCLUDED_ */
