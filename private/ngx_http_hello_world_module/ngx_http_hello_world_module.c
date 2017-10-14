#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pri_test.h>
#include "cJSON.h"

typedef struct {
    ngx_str_t output_words;
    ngx_uint_t flag;
} ngx_http_hello_world_loc_conf_t;

// To process HelloWorld command arguments
static char* ngx_http_hello_world(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

// Allocate memory for HelloWorld command
static void* ngx_http_hello_world_create_loc_conf(ngx_conf_t* cf);

// Copy HelloWorld argument to another place
static char* ngx_http_hello_world_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child);

// Structure for the HelloWorld command
static ngx_command_t ngx_http_hello_world_commands[] = {
    {
        ngx_string("hello_world"), // The command name
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_http_hello_world, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hello_world_loc_conf_t, output_words),
        NULL
    },

    {
        ngx_string("test_flag"), // The command name
        NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot, // The command handler
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hello_world_loc_conf_t, flag),
        NULL
    },
    ngx_null_command
};

// Structure for the HelloWorld context
static ngx_http_module_t ngx_http_hello_world_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_hello_world_create_loc_conf,
    ngx_http_hello_world_merge_loc_conf
};

// Structure for the HelloWorld module, the most important thing
ngx_module_t ngx_http_hello_world_module = {
    NGX_MODULE_V1,
    &ngx_http_hello_world_module_ctx,
    ngx_http_hello_world_commands,
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

static void ngx_http_hello_world_client_body_handler_pt(ngx_http_request_t *r)
{
    ngx_int_t rc = NGX_OK;
    ngx_buf_t* b;
    ngx_chain_t out[2];
    char log_buf[32] = {0};
    u_char body_buf[256] = {0};
    ngx_buf_t *p_body_buf = NULL;
    cJSON *root = NULL;
    cJSON *name = NULL;

    ngx_http_hello_world_loc_conf_t* hlcf = NULL;
    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hello_world_module);

    show_str(log_buf, 32);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", log_buf);

    p_body_buf = r->request_body->bufs->buf;
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "length:%d", ngx_buf_size(p_body_buf));
    
    ngx_snprintf(body_buf, sizeof(body_buf), "%*s",
            ngx_buf_size(p_body_buf), p_body_buf->pos);

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
            "receive body:%s", body_buf);

    root = cJSON_Parse((char *)body_buf);
    if (NULL == root)
    {

    }
    name = cJSON_GetObjectItemCaseSensitive(root, "name");

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "name: %s", name->valuestring);
#if 1
        r->headers_out.content_type.len = sizeof("text/plain") - 1;
        r->headers_out.content_type.data = (u_char*)"text/plain";
    
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    
        //
        show_str(log_buf, 32);
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "%s", log_buf);
    
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                              "uri:%V, args: %V", &r->uri,
                              &r->args);
    
        out[0].buf = b;
        out[0].next = &out[1];
    
        if (1 == hlcf->flag)
        {
            b->pos = (u_char*)"hello_world1, ";
            b->last = b->pos + sizeof("hello_world1, ") - 1;
        }
        else
        {
            b->pos = (u_char*)"hello_world2, ";
            b->last = b->pos + sizeof("hello_world2, ") - 1;
        }
    
        b->memory = 1;
    
        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    
        out[1].buf = b;
        out[1].next = NULL;
    
        b->pos = hlcf->output_words.data;
        b->last = hlcf->output_words.data + (hlcf->output_words.len);
        b->memory = 1;
        b->last_buf = 1;
    
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = hlcf->output_words.len + sizeof("hello_world1, ") - 1;
        rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return ;
        }
    
        rc = ngx_http_output_filter(r, &out[0]);
        ngx_http_finalize_request(r,rc);

        return;
#endif
}
#if 1
static ngx_int_t ngx_http_hello_world_handler(ngx_http_request_t* r) {
    ngx_int_t rc = NGX_OK;
    //ngx_buf_t* b;
    //ngx_chain_t out[2];
    //char log_buf[32] = {0};

    //ngx_http_hello_world_loc_conf_t* hlcf = NULL;
    //hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hello_world_module);

    if (ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len) <= 0)
    {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", "content length is 0");
        return rc;
    }

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "content length:%d", ngx_atoi(r->headers_in.content_length->value.data, r->headers_in.content_length->value.len));

    rc = ngx_http_read_client_request_body(r,
            ngx_http_hello_world_client_body_handler_pt);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
    {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", "unknown respone");
        return rc;
    }

    return NGX_DONE;

#if 0
    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char*)"text/plain";

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    //
    show_str(log_buf, 32);
    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "%s", log_buf);

    ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                          "uri:%V, args: %V", &r->uri,
                          &r->args);

    out[0].buf = b;
    out[0].next = &out[1];

    if (1 == hlcf->flag)
    {
        b->pos = (u_char*)"hello_world1, ";
        b->last = b->pos + sizeof("hello_world1, ") - 1;
    }
    else
    {
        b->pos = (u_char*)"hello_world2, ";
        b->last = b->pos + sizeof("hello_world2, ") - 1;
    }

    b->memory = 1;

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    out[1].buf = b;
    out[1].next = NULL;

    b->pos = hlcf->output_words.data;
    b->last = hlcf->output_words.data + (hlcf->output_words.len);
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = hlcf->output_words.len + sizeof("hello_world1, ") - 1;
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out[0]);
#endif
}

#else

static ngx_int_t ngx_http_hello_world_handler(ngx_http_request_t* r) {
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;

    b = ngx_palloc(r->pool, sizeof(ngx_buf_t));
    u_char *file_name = (u_char*)"/tmp/sgy.test";
    b->in_file = 1;
    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    b->file->fd = ngx_open_file(file_name, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK,
        NGX_FILE_OPEN, 0);
    b->file->log = r->connection->log;
    b->file->name.data = file_name;
    b->file->name.len = strlen((const char *)file_name);
    if (b->file->fd <= 0)
    {
        return NGX_HTTP_NOT_FOUND;
    }
    if (ngx_file_info(file_name, &b->file->info) == NGX_FILE_ERROR)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    r->headers_out.content_length_n = b->file->info.st_size;
    b->file_pos = 0;
    b->file_last = b->file->info.st_size;

    ngx_pool_cleanup_t* cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));  
    if (cln == NULL)  
        return NGX_ERROR;

    cln->handler = ngx_pool_cleanup_file;
    ngx_pool_cleanup_file_t *clnf = cln->data;
    clnf->fd = b->file->fd;
    clnf->name = b->file->name.data;
    clnf->log = r->pool->log;

    ngx_str_t type = ngx_string("text/plain");
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type = type;
    
#if 1
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
#endif
    out.buf = b;  
    out.next = NULL; 

    return ngx_http_output_filter(r, &out);
}
#endif

static void* ngx_http_hello_world_create_loc_conf(ngx_conf_t* cf) {
    ngx_http_hello_world_loc_conf_t* conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hello_world_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->output_words.len = 0;
    conf->output_words.data = NULL;

    conf->flag = NGX_CONF_UNSET;

    return conf;
}

static char* ngx_http_hello_world_merge_loc_conf(ngx_conf_t* cf, void* parent, void* child) {
    ngx_http_hello_world_loc_conf_t* prev = parent;
    ngx_http_hello_world_loc_conf_t* conf = child;
    ngx_conf_merge_str_value(conf->output_words, prev->output_words, "Nginx");
    ngx_conf_merge_uint_value(conf->flag, prev->flag,
            1);
    return NGX_CONF_OK;
}


static char* ngx_http_hello_world(ngx_conf_t* cf, ngx_command_t* cmd, void* conf) {
    ngx_http_core_loc_conf_t* clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hello_world_handler;
    ngx_conf_set_str_slot(cf, cmd, conf);
    return NGX_CONF_OK;
}

