
/*
 * Copyright (C)  liwq
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define ngx_strrchr(s1, c)   strrchr((const char *) s1, (int) c)

typedef struct {
    ngx_str_node_t     sn;             /* {node, str:ip} */
    ngx_queue_t        queue;
    time_t             expire;
    ngx_uint_t         times;          /*set rule times. if times==0:allow times==1:verify times>1:deny*/
    ngx_uint_t         shn;
    ngx_uint_t         ehn;
    u_char             ip;
} ngx_http_limit_ip_node_t;

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
} ngx_http_limit_ip_shctx_t;

typedef struct {
    ngx_http_limit_ip_shctx_t  *sh;
    ngx_slab_pool_t            *shpool;
} ngx_http_limit_ip_ctx_t;

typedef struct {
    time_t                    limit_continue_sec;
    ngx_shm_zone_t           *shm_zone;
    size_t                    size;
} ngx_http_limit_ip_srv_conf_t;


typedef struct {
    ngx_str_t   ip;
    ngx_str_t   nn;    /*net no.*/
    ngx_uint_t  shn;   /*start host no.*/
    ngx_uint_t  ehn;   /*end host no.*/
    time_t      expire;
    ngx_uint_t  times;
} ngx_http_limit_ip_args_t;


typedef struct {
    ngx_str_t   ip;
    ngx_str_t   nn;    /*net no.*/
    ngx_uint_t  hn;    /*host no.*/
    ngx_str_t   host;
} ngx_http_limit_ip_remote_t;


static ngx_str_t ngx_http_limit_ip_allow     = ngx_string("allow");
static ngx_str_t ngx_http_limit_ip_verify    = ngx_string("verify");
static ngx_str_t ngx_http_limit_ip_deny      = ngx_string("deny");

static ngx_str_t ngx_http_limit_ip_res_ok    = ngx_string("ok");
static ngx_str_t ngx_http_limit_ip_res_err   = ngx_string("error");
static ngx_str_t ngx_http_limit_ip_res_null  = ngx_string("null");


static ngx_int_t ngx_http_limit_ip_add_variables(ngx_conf_t *cf);
static void *ngx_http_limit_ip_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_limit_ip_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_limit_ip_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_limit_ip_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_limit_ip_ctx_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_limit_ip_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_limit_ip_args_parse(ngx_str_t *arg, ngx_http_limit_ip_args_t *args);
static ngx_int_t ngx_http_limit_ip_update_rule(ngx_http_limit_ip_ctx_t *ctx, ngx_http_limit_ip_args_t *args);
static ngx_int_t ngx_http_limit_ip_rule_dump(ngx_buf_t *b, ngx_uint_t *rl, ngx_http_limit_ip_ctx_t *ctx, 
    ngx_http_limit_ip_args_t *args);
static ngx_int_t ngx_http_limit_ip_handler(ngx_http_request_t *r);



static ngx_http_variable_t ngx_http_limit_ip_variable[] = {

  { ngx_string("limit_act"), NULL, ngx_http_limit_ip_get, 0, 0, 0 },

  { ngx_null_string, NULL, NULL, 0, 0, 0 }

};


static ngx_command_t ngx_http_limit_ip_commands[] = {

    { ngx_string("limit_ip"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_limit_ip_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("limit_continue"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_limit_ip_srv_conf_t, limit_continue_sec),
      NULL },

    { ngx_string("limit_cache_zone_size"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_limit_ip_zone,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_limit_ip_module_ctx = {
    ngx_http_limit_ip_add_variables,        /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_http_limit_ip_create_srv_conf,      /* create server configuration */
    ngx_http_limit_ip_merge_srv_conf,       /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_http_limit_ip_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_ip_module_ctx,          /* module context */
    ngx_http_limit_ip_commands,             /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t 
ngx_http_limit_ip_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t         *ite;
    ngx_http_variable_t         *v;

    for (ite = ngx_http_limit_ip_variable; ite->name.len; ite++) {
        v = ngx_http_add_variable(cf, &ite->name, ite->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }
        v->set_handler = ite->set_handler;
        v->get_handler = ite->get_handler;
        v->data = ite->data;
    }

    return NGX_OK;
}


static void *
ngx_http_limit_ip_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_limit_ip_srv_conf_t  *lscf;

    lscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_ip_srv_conf_t));
    if (NULL == lscf) {
        return NULL;
    }

    lscf->limit_continue_sec = NGX_CONF_UNSET;
    lscf->shm_zone = NULL;
    lscf->size     = NGX_CONF_UNSET_SIZE;

    return lscf;
}


static char *
ngx_http_limit_ip_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_limit_ip_srv_conf_t *prev = parent;
    ngx_http_limit_ip_srv_conf_t *conf = child;

    ngx_conf_merge_sec_value(conf->limit_continue_sec,
                              prev->limit_continue_sec, 300);

    if (NULL == conf->shm_zone) {
        if (NULL == prev->shm_zone) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 
                0, "limit_ip_cache_shm_zone null, please check nginx.conf \"limit_cache_zone_size\" ");
            return NGX_CONF_ERROR;
        }
        conf->shm_zone = prev->shm_zone;
        conf->size     = prev->size;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_limit_ip_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_str_t                            zone_name;
    ngx_shm_zone_t                      *shm_zone;
    ngx_http_limit_ip_ctx_t             *ctx;
    ngx_http_limit_ip_srv_conf_t        *lscf;
    ngx_str_t                           *value;
    size_t                               size;

    lscf = conf;
    value = cf->args->elts;
    size = ngx_parse_size(&value[1]);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_ip_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_set(&zone_name, "limit_ip_cache_shm_zone");

    shm_zone = ngx_shared_memory_add(cf, &zone_name, size, &ngx_http_limit_ip_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_limit_ip_ctx_init_zone;
    shm_zone->data = ctx;

    lscf->shm_zone = shm_zone;
    lscf->size     = size;
    return NGX_CONF_OK;
}



static ngx_int_t
ngx_http_limit_ip_ctx_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_ip_ctx_t  *octx = data;

    size_t                     len;
    ngx_http_limit_ip_ctx_t   *ctx;

    ctx = shm_zone->data;

    if (NULL != octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_ip_ctx_t));
    if (NULL == ctx->sh) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    // ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
    //                 ngx_http_limit_ip_rbtree_insert_value);
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_str_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    len = sizeof(" in limit_ip zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in limit_ip zone \"%V\"%Z",
                &shm_zone->shm.name);


    return NGX_OK;
}


static void 
ngx_limit_act_parse(ngx_http_limit_ip_node_t *lint, ngx_uint_t *hn, 
      ngx_time_t *nt, ngx_http_variable_value_t *v)
{

    if (NULL != lint && lint->times == 1 && lint->expire > nt->sec
        && *hn >= lint->shn && *hn <= lint->ehn) {
        // verify
        v->len = ngx_http_limit_ip_verify.len;
        v->data = ngx_http_limit_ip_verify.data;
    } else if (NULL != lint && lint->times > 1 && lint->expire > nt->sec
        && *hn >= lint->shn && *hn <= lint->ehn){
        // deny
        v->len = ngx_http_limit_ip_deny.len;
        v->data = ngx_http_limit_ip_deny.data;
    } else {
        // allow
        v->len = ngx_http_limit_ip_allow.len;
        v->data = ngx_http_limit_ip_allow.data;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return;
}

static void 
ngx_remote_ip_init(ngx_http_limit_ip_remote_t *lirt) {

    lirt->ip.len    = 0;
    lirt->ip.data   = NULL;
    lirt->nn.len    = 0;
    lirt->nn.data   = NULL;
    lirt->hn        = 0;
    lirt->host.len  = 0;
    lirt->host.data = NULL;

    return;
}

static ngx_int_t 
ngx_remote_ip_parse(ngx_http_limit_ip_remote_t *lirt)
{
    u_char    *e;
    ngx_str_t *ip;

    ip = &lirt->ip;

    e = (u_char*)ngx_strrchr(ip->data, '.');
    if (NULL != e) {
        lirt->nn.data = ip->data;
        lirt->nn.len  = e - ip->data;
        lirt->hn      = (ngx_uint_t)strtoull((const char*)e+1, NULL, 10);

        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_int_t 
ngx_http_limit_ip_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_limit_ip_srv_conf_t    *lscf;
    ngx_http_limit_ip_node_t        *lint;
    ngx_http_limit_ip_ctx_t         *ctx;
    ngx_http_limit_ip_remote_t       lirt;
    uint32_t                         hash;
    ngx_time_t                      *nt;

    lscf = ngx_http_get_module_srv_conf(r, ngx_http_limit_ip_module);
    if (NULL == lscf) {
        return NGX_ERROR;
    }

    ctx = (ngx_http_limit_ip_ctx_t*)lscf->shm_zone->data;
    if (NULL == ctx) {
        return NGX_ERROR;
    }

    ngx_remote_ip_init(&lirt);

    lirt.ip.data = r->connection->addr_text.data;
    lirt.ip.len  = r->connection->addr_text.len;

    // if not, strtoull maybe produce a bug. just maybe!
    lirt.ip.data = ngx_pcalloc(r->pool, lirt.ip.len+1);
    if (NULL != lirt.ip.data) {
        ngx_memset(lirt.ip.data, 0x00, lirt.ip.len+1);
        ngx_memcpy(lirt.ip.data, r->connection->addr_text.data, lirt.ip.len);
    }

    // ngx_remote_ip_parse(&lirt);

    hash = ngx_crc32_long(lirt.ip.data, lirt.ip.len);
    nt   = ngx_timeofday();

    // search ip
    lint = (ngx_http_limit_ip_node_t *)
           ngx_str_rbtree_lookup(&ctx->sh->rbtree, &lirt.ip, hash);

    // search subnet
    if (NULL == lint || lint->expire < nt->sec) {
        if (NGX_OK == ngx_remote_ip_parse(&lirt)) {
            hash = ngx_crc32_long(lirt.nn.data, lirt.nn.len);

            lint = (ngx_http_limit_ip_node_t *)
                   ngx_str_rbtree_lookup(&ctx->sh->rbtree, &lirt.nn, hash);
        }
    }

    // search host
    if (NULL == lint || lint->expire < nt->sec) {
        lirt.host.len  = r->headers_in.server.len;
        lirt.host.data = r->headers_in.server.data;

        hash = ngx_crc32_long(lirt.host.data, lirt.host.len);

        lint = (ngx_http_limit_ip_node_t *)
                   ngx_str_rbtree_lookup(&ctx->sh->rbtree, &lirt.host, hash);
    }

    ngx_limit_act_parse(lint, &lirt.hn, nt, v);

    return NGX_OK;
}


static ngx_http_limit_ip_node_t *
ngx_http_limit_ip_alloc_node_lru(ngx_http_limit_ip_ctx_t *ctx, size_t len)
{
    ngx_uint_t                 i;
    ngx_http_limit_ip_node_t  *lint;
    ngx_queue_t               *q;

    lint = ngx_slab_alloc_locked(ctx->shpool, len);
    if (NULL == lint) {
        for (i = 0; i < 10 && lint == NULL; i++) {
            if (ngx_queue_empty(&ctx->sh->queue)) {
                break;
            }

            q = ngx_queue_last(&ctx->sh->queue);
            // lint = (ngx_http_limit_ip_node_t *)
            //        (q - offsetof(ngx_http_limit_ip_node_t, queue));
            lint = ngx_queue_data(q, ngx_http_limit_ip_node_t, queue);

            ngx_queue_remove(q);
            ngx_rbtree_delete(&ctx->sh->rbtree, &lint->sn.node);
            ngx_slab_free_locked(ctx->shpool, lint);

            lint = ngx_slab_alloc_locked(ctx->shpool, len);
        }
    }
    return lint;
}


static ngx_int_t
ngx_http_limit_ip_update_rule(ngx_http_limit_ip_ctx_t *ctx, ngx_http_limit_ip_args_t *args)
{
    ngx_int_t                        times;
    uint32_t                         hash;
    ngx_time_t                      *nt;
    ngx_http_limit_ip_node_t        *lint;

    hash = ngx_crc32_long(args->ip.data, args->ip.len);
    nt   = ngx_timeofday();

    ngx_shmtx_lock(&ctx->shpool->mutex);
    lint = (ngx_http_limit_ip_node_t *)
           ngx_str_rbtree_lookup(&ctx->sh->rbtree, &args->ip, hash);

    if (NULL == lint) {
        lint = ngx_http_limit_ip_alloc_node_lru(ctx, sizeof(ngx_http_limit_ip_node_t)+args->ip.len);
        if (NULL == lint) {
            // ngx_log_error(NGX_LOG_EMERG, c->log, 0,
            //               "alloc lru node error");
            return NGX_ERROR;
        }
        lint->sn.node.key = hash;
        ngx_memcpy(&lint->ip, args->ip.data, args->ip.len);
        lint->sn.str.len = args->ip.len;
        lint->sn.str.data = &lint->ip;
        lint->expire = nt->sec + args->expire;
        lint->times = args->times? args->times: 1;
        lint->shn = args->shn;
        lint->ehn = args->ehn;
        ngx_rbtree_insert(&ctx->sh->rbtree, &lint->sn.node);
        ngx_queue_insert_head(&ctx->sh->queue, &lint->queue);
    } else {
        lint->times++;
        if (lint->times > 100) lint->times = 100;

        if (nt->sec - lint->expire > 2) {
            lint->times = args->times? args->times: 1;
        }

        times = 1;
        if (lint->times > 2) {
            times = lint->times;
        }
        lint->expire = nt->sec + args->expire * times;
        if (args->expire == 0) {
            lint->times = 0;
        }

        lint->shn = args->shn;
        lint->ehn = args->ehn;

        ngx_queue_remove(&lint->queue);
        ngx_queue_insert_head(&ctx->sh->queue, &lint->queue);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}

static ngx_int_t
ngx_http_limit_ip_del_rule(ngx_http_limit_ip_ctx_t *ctx, ngx_http_limit_ip_args_t *args) {
    uint32_t                         hash;
    ngx_http_limit_ip_node_t        *lint;

    hash = ngx_crc32_long(args->ip.data, args->ip.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);
    lint = (ngx_http_limit_ip_node_t *)
           ngx_str_rbtree_lookup(&ctx->sh->rbtree, &args->ip, hash);

    if (NULL != lint) {
        ngx_queue_remove(&lint->queue);
        ngx_rbtree_delete(&ctx->sh->rbtree, &lint->sn.node);
        ngx_slab_free_locked(ctx->shpool, lint);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_rbnode_2_buf(ngx_buf_t *b, ngx_uint_t *l, ngx_http_limit_ip_node_t *lint) {
    size_t         len;
    size_t         len2;
    size_t         ml;

    len2 =  b->end - b->last;
    if (len2 == 0) return NGX_ERROR;

    len  =  ngx_strlen("rule=") + lint->sn.str.len;
    len  += ngx_strlen(" extend=,") + 6;
    len  += ngx_strlen(" expire=") + 10;
    len  += ngx_strlen(" times=;") + 5;

    ml = len2 > len? len: len2;

    ngx_snprintf(b->pos + *l, ml, "rule=%V extend=%03i,%03i expire=%T times=%05ui;", 
                &lint->sn.str, lint->shn, lint->ehn, lint->expire, lint->times);
    *l += ml;
    b->last = b->pos + *l;
    return NGX_OK;
}


static ngx_int_t
ngx_http_limit_ip_rule_dump(ngx_buf_t *b, ngx_uint_t *rl, ngx_http_limit_ip_ctx_t *ctx, ngx_http_limit_ip_args_t *args)
{
    ngx_http_limit_ip_node_t    *lint;
    uint32_t                     hash;
    ngx_time_t                  *nt;
    ngx_queue_t                 *q;
    ngx_queue_t                 *cache;

    nt  = ngx_timeofday();
    *rl = 0;

    if (0 < args->ip.len) {
        hash = ngx_crc32_long(args->ip.data, args->ip.len);
        lint = (ngx_http_limit_ip_node_t *)
               ngx_str_rbtree_lookup(&ctx->sh->rbtree, &args->ip, hash);
        if (NULL != lint) {
            if (1 == args->expire && lint->expire > nt->sec) {
                return ngx_rbnode_2_buf(b, rl, lint);
            }

            if (1 != args->expire) {
                return ngx_rbnode_2_buf(b, rl, lint);
            }
        }
        return NGX_ERROR;
    }

    cache = &ctx->sh->queue;
    for(q = ngx_queue_head(cache); 
        q != ngx_queue_sentinel(cache);
        q = ngx_queue_next(q)) 
    {
        lint = ngx_queue_data(q, ngx_http_limit_ip_node_t, queue);

        if (lint->expire > nt->sec && lint->times != 0) {
            if (NGX_OK != ngx_rbnode_2_buf(b, rl, lint)) {
                break;
            }
        }
    }

    return *rl==0? NGX_ERROR: NGX_OK;
}

static void 
ngx_limit_args_init(ngx_http_limit_ip_args_t *lias)
{
    lias->ip.len     = 0;
    lias->ip.data    = NULL;
    lias->nn.len     = 0;
    lias->nn.data    = NULL;
    lias->expire     = 0;
    lias->times      = 0;
    lias->shn        = 0;
    lias->ehn        = 255;

    return;
}

static ngx_int_t
ngx_http_limit_ip_args_parse(ngx_str_t *arg, ngx_http_limit_ip_args_t *args)
{
    u_char    *p1, *p2, *p3;

    p1 = arg->data;

    //ip=192.168.19.1&expire=30&times=2
    //ip=192.168.19.1
    //ip=192.168.19.1,3
    while (NULL != p1 && *p1 != 0) {
        p2 = (u_char*)ngx_strchr(p1, '=');
        if (NULL == p2)  break;
        p3 = (u_char*)ngx_strchr(p2, '&');

        if (ngx_memcmp(p1, "ip=", 3) == 0) {
            args->ip.data = p2 + 1;
            args->ip.len = (p3==NULL? arg->data+arg->len-p2-2: p3-p2-1);
        }

        if (ngx_memcmp(p1, "expire=", 7) == 0) {
            args->expire = (time_t)strtoull((const char*)p2+1, NULL, 10);
        }

        if (ngx_memcmp(p1, "times=", 6) == 0) {
            args->times = (ngx_uint_t)strtoull((const char*)p2+1, NULL, 10);
        }

        if (NULL == p3) break;
        p1 = p3 + 1;
    }

    p1 = (u_char*)ngx_strchr(args->ip.data, ',');
    if (NULL != p1) {
        p2 = (u_char*)ngx_strrchr(args->ip.data, '.');
        if (NULL == p2) {
            return NGX_ERROR;
        }
        args->ip.len = p2 - args->ip.data;
        args->shn = (ngx_uint_t)strtoull((const char*)p2+1, NULL, 10);
        args->ehn = (ngx_uint_t)strtoull((const char*)p1+1, NULL, 10);
    }

    return NGX_OK;
}

/*
 *\ /xxxx/get[?ip=192.168.19.1]/
 *\ /xxxx/set?ip=192.168.19.1[&expire=30]/
 */
static ngx_int_t
ngx_http_limit_ip_handler(ngx_http_request_t *r)
{
    ngx_http_limit_ip_srv_conf_t  *lscf;
    ngx_http_limit_ip_args_t       lias;
    ngx_int_t                      rc;
    ngx_int_t                      i;
    u_char                        *u;
    ngx_str_t                      type;
    ngx_uint_t                     rl;
    ngx_str_t                      limit_args;
    ngx_buf_t                     *b;
    ngx_chain_t                    out;
    ngx_log_t                     *log;


    if (!(r->method & NGX_HTTP_GET)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    log = r->connection->log;
    lscf = ngx_http_get_module_srv_conf(r, ngx_http_limit_ip_module);

    ngx_log_error(NGX_LOG_NOTICE, log, 0, "SAE url: \"%V?%V\"", &r->uri, &r->args);


    rc = ngx_http_discard_request_body(r);
    if (NGX_OK != rc) {
        return rc;
    }

    if (r->uri.len == 0 || r->uri.data[0] != '/') {
        return NGX_DECLINED;
    }

    u = NULL;
    for(i=r->uri.len-2; i>=0; --i) {
        u = r->uri.data + i;
        if (*u == '/') {
            break;
        }
    }


    ngx_limit_args_init(&lias);
    lias.expire     = lscf->limit_continue_sec;

    limit_args.len  = r->args.len;
    limit_args.data = NULL;

    if (limit_args.len > 0) {
        if (r->args.data[r->args.len-1] != '/') {
            limit_args.len += 1;
        }

        limit_args.data = ngx_pcalloc(r->pool, limit_args.len);
        if (NULL == limit_args.data) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_memset(limit_args.data, 0x00, limit_args.len);
        ngx_memcpy(limit_args.data, r->args.data, limit_args.len-1);

        ngx_http_limit_ip_args_parse(&limit_args, &lias);
    }

    rl = 0;
    if (ngx_memcmp(u, "/set", 4) == 0) {

        if (lias.ip.len == 0) {
            return NGX_HTTP_BAD_REQUEST;
        }

        b = ngx_create_temp_buf(r->pool, 16);
        if (NULL == b) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = ngx_http_limit_ip_update_rule(lscf->shm_zone->data, &lias);
        ngx_memcpy(b->pos, ngx_http_limit_ip_res_ok.data, ngx_http_limit_ip_res_ok.len);
        rl = ngx_http_limit_ip_res_ok.len;
        b->last = b->pos + rl;

        if (NGX_ERROR == rc) {
            ngx_memcpy(b->pos, ngx_http_limit_ip_res_err.data, ngx_http_limit_ip_res_err.len);
            rl = ngx_http_limit_ip_res_err.len;
            b->last = b->pos + rl;
        }

    } else if(ngx_memcmp(u, "/get", 4) == 0) {

        b = ngx_create_temp_buf(r->pool, lscf->size);
        if (NULL == b) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = ngx_http_limit_ip_rule_dump(b, &rl, lscf->shm_zone->data, &lias);
        if (NGX_ERROR == rc) {
            ngx_memcpy(b->pos, ngx_http_limit_ip_res_null.data, ngx_http_limit_ip_res_null.len);
            rl = ngx_http_limit_ip_res_null.len;
            b->last = b->pos + rl;
        }

    } else if (ngx_memcmp(u, "/del", 4) == 0){

        if (lias.ip.len == 0) {
            return NGX_HTTP_BAD_REQUEST;
        }

        b = ngx_create_temp_buf(r->pool, 16);
        if (NULL == b) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = ngx_http_limit_ip_del_rule(lscf->shm_zone->data, &lias);

        ngx_memcpy(b->pos, ngx_http_limit_ip_res_ok.data, ngx_http_limit_ip_res_ok.len);
        rl = ngx_http_limit_ip_res_ok.len;
        b->last = b->pos + rl;

        if (NGX_ERROR == rc) {
            ngx_memcpy(b->pos, ngx_http_limit_ip_res_err.data, ngx_http_limit_ip_res_err.len);
            rl = ngx_http_limit_ip_res_err.len;
            b->last = b->pos + rl;
        }

    } else {
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_str_set(&type, "text/html");

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = rl;
    r->headers_out.content_type = type;

    rc = ngx_http_send_header(r);
    if (NGX_ERROR == rc || NGX_OK < rc || r->header_only) {
        return rc;
    }

    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_limit_ip_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_limit_ip_handler;

    return NGX_CONF_OK;
}
