
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define ngx_http_v3_is_v2_frame(type)                                         \
    ((type) == 0x02 || (type) == 0x06 || (type) == 0x08 || (type) == 0x09)


static ngx_int_t ngx_http_v3_parse_varlen_int(ngx_connection_t *c,
    ngx_http_v3_parse_varlen_int_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_prefix_int(ngx_connection_t *c,
    ngx_http_v3_parse_prefix_int_t *st, ngx_uint_t prefix, u_char ch);

static ngx_int_t ngx_http_v3_parse_field_section_prefix(ngx_connection_t *c,
    ngx_http_v3_parse_field_section_prefix_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_field_rep(ngx_connection_t *c,
    ngx_http_v3_parse_field_rep_t *st, ngx_uint_t base, u_char ch);
static ngx_int_t ngx_http_v3_parse_literal(ngx_connection_t *c,
    ngx_http_v3_parse_literal_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_field_ri(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_field_lri(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_field_l(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_field_pbi(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_field_lpbi(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch);

static ngx_int_t ngx_http_v3_parse_control(ngx_connection_t *c,
    ngx_http_v3_parse_control_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_settings(ngx_connection_t *c,
    ngx_http_v3_parse_settings_t *st, u_char ch);

static ngx_int_t ngx_http_v3_parse_encoder(ngx_connection_t *c,
    ngx_http_v3_parse_encoder_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_field_inr(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch);
static ngx_int_t ngx_http_v3_parse_field_iln(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch);

static ngx_int_t ngx_http_v3_parse_decoder(ngx_connection_t *c,
    ngx_http_v3_parse_decoder_t *st, u_char ch);

static ngx_int_t ngx_http_v3_parse_lookup(ngx_connection_t *c,
    ngx_uint_t dynamic, ngx_uint_t index, ngx_str_t *name, ngx_str_t *value);


static ngx_int_t
ngx_http_v3_parse_varlen_int(ngx_connection_t *c,
    ngx_http_v3_parse_varlen_int_t *st, u_char ch)
{
    enum {
        sw_start = 0,
        sw_length_2,
        sw_length_3,
        sw_length_4,
        sw_length_5,
        sw_length_6,
        sw_length_7,
        sw_length_8
    };

    switch (st->state) {

    case sw_start:

        st->value = ch;
        if (st->value & 0xc0) {
            st->state = sw_length_2;
            break;
        }

        goto done;

    case sw_length_2:

        st->value = (st->value << 8) + ch;
        if ((st->value & 0xc000) == 0x4000) {
            st->value &= 0x3fff;
            goto done;
        }

        st->state = sw_length_3;
        break;

    case sw_length_4:

        st->value = (st->value << 8) + ch;
        if ((st->value & 0xc0000000) == 0x80000000) {
            st->value &= 0x3fffffff;
            goto done;
        }

        st->state = sw_length_5;
        break;

    case sw_length_3:
    case sw_length_5:
    case sw_length_6:
    case sw_length_7:

        st->value = (st->value << 8) + ch;
        st->state++;
        break;

    case sw_length_8:

        st->value = (st->value << 8) + ch;
        st->value &= 0x3fffffffffffffff;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse varlen int %uL", st->value);

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_prefix_int(ngx_connection_t *c,
    ngx_http_v3_parse_prefix_int_t *st, ngx_uint_t prefix, u_char ch)
{
    ngx_uint_t  mask;
    enum {
        sw_start = 0,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        mask = (1 << prefix) - 1;
        st->value = ch & mask;

        if (st->value != mask) {
            goto done;
        }

        st->shift = 0;
        st->state = sw_value;
        break;

    case sw_value:

        st->value += (uint64_t) (ch & 0x7f) << st->shift;

        if (st->shift == 56
            && ((ch & 0x80) || (st->value & 0xc000000000000000)))
        {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client exceeded integer size limit");
            return NGX_HTTP_V3_ERR_EXCESSIVE_LOAD;
        }

        if (ch & 0x80) {
            st->shift += 7;
            break;
        }

        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse prefix int %uL", st->value);

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_headers(ngx_connection_t *c, ngx_http_v3_parse_headers_t *st,
    u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_type,
        sw_length,
        sw_skip,
        sw_prefix,
        sw_verify,
        sw_field_rep,
        sw_done
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse headers");

        st->state = sw_type;

        /* fall through */

    case sw_type:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->type = st->vlint.value;

        if (ngx_http_v3_is_v2_frame(st->type)
            || st->type == NGX_HTTP_V3_FRAME_DATA
            || st->type == NGX_HTTP_V3_FRAME_GOAWAY
            || st->type == NGX_HTTP_V3_FRAME_SETTINGS
            || st->type == NGX_HTTP_V3_FRAME_MAX_PUSH_ID
            || st->type == NGX_HTTP_V3_FRAME_CANCEL_PUSH
            || st->type == NGX_HTTP_V3_FRAME_PUSH_PROMISE)
        {
            return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED;
        }

        st->state = sw_length;
        break;

    case sw_length:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->length = st->vlint.value;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse headers type:%ui, len:%ui",
                       st->type, st->length);

        if (st->type != NGX_HTTP_V3_FRAME_HEADERS) {
            st->state = st->length > 0 ? sw_skip : sw_type;
            break;
        }

        if (st->length == 0) {
            return NGX_HTTP_V3_ERR_FRAME_ERROR;
        }

        st->state = sw_prefix;
        break;

    case sw_skip:

        if (--st->length == 0) {
            st->state = sw_type;
        }

        break;

    case sw_prefix:

        if (--st->length == 0) {
            return NGX_HTTP_V3_ERR_FRAME_ERROR;
        }

        rc = ngx_http_v3_parse_field_section_prefix(c, &st->prefix, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->state = sw_verify;
        break;

    case sw_verify:

        rc = ngx_http_v3_check_insert_count(c, st->prefix.insert_count);
        if (rc != NGX_OK) {
            return rc;
        }

        st->state = sw_field_rep;

        /* fall through */

    case sw_field_rep:

        rc = ngx_http_v3_parse_field_rep(c, &st->field_rep, st->prefix.base,
                                         ch);

        if (--st->length == 0 && rc == NGX_AGAIN) {
            return NGX_HTTP_V3_ERR_FRAME_ERROR;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        if (st->length == 0) {
            goto done;
        }

        return NGX_OK;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse headers done");

    if (st->prefix.insert_count > 0) {
        if (ngx_http_v3_send_ack_section(c, c->quic->id) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_field_section_prefix(ngx_connection_t *c,
    ngx_http_v3_parse_field_section_prefix_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_req_insert_count,
        sw_delta_base,
        sw_read_delta_base
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse field section prefix");

        st->state = sw_req_insert_count;

        /* fall through */

    case sw_req_insert_count:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 8, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->insert_count = st->pint.value;
        st->state = sw_delta_base;
        break;

    case sw_delta_base:

        st->sign = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_delta_base;

        /* fall through */

    case sw_read_delta_base:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->delta_base = st->pint.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    rc = ngx_http_v3_decode_insert_count(c, &st->insert_count);
    if (rc != NGX_OK) {
        return rc;
    }

    if (st->sign) {
        st->base = st->insert_count - st->delta_base - 1;
    } else {
        st->base = st->insert_count + st->delta_base;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, c->log, 0,
                  "http3 parse field section prefix done "
                  "insert_count:%ui, sign:%ui, delta_base:%ui, base:%ui",
                  st->insert_count, st->sign, st->delta_base, st->base);

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_field_rep(ngx_connection_t *c,
    ngx_http_v3_parse_field_rep_t *st, ngx_uint_t base, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_field_ri,
        sw_field_lri,
        sw_field_l,
        sw_field_pbi,
        sw_field_lpbi
    };

    if (st->state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse field representation");

        ngx_memzero(&st->field, sizeof(ngx_http_v3_parse_field_t));

        st->field.base = base;

        if (ch & 0x80) {
            /* Indexed Field Line */

            st->state = sw_field_ri;

        } else if (ch & 0x40) {
            /* Literal Field Line With Name Reference */

            st->state = sw_field_lri;

        } else if (ch & 0x20) {
            /* Literal Field Line With Literal Name */

            st->state = sw_field_l;

        } else if (ch & 0x10) {
            /* Indexed Field Line With Post-Base Index */

            st->state = sw_field_pbi;

        } else {
            /* Literal Field Line With Post-Base Name Reference */

            st->state = sw_field_lpbi;
        }
    }

    switch (st->state) {

    case sw_field_ri:
        rc = ngx_http_v3_parse_field_ri(c, &st->field, ch);
        break;

    case sw_field_lri:
        rc = ngx_http_v3_parse_field_lri(c, &st->field, ch);
        break;

    case sw_field_l:
        rc = ngx_http_v3_parse_field_l(c, &st->field, ch);
        break;

    case sw_field_pbi:
        rc = ngx_http_v3_parse_field_pbi(c, &st->field, ch);
        break;

    case sw_field_lpbi:
        rc = ngx_http_v3_parse_field_lpbi(c, &st->field, ch);
        break;

    default:
        rc = NGX_OK;
    }

    if (rc != NGX_DONE) {
        return rc;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field representation done");

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_literal(ngx_connection_t *c, ngx_http_v3_parse_literal_t *st,
    u_char ch)
{
    ngx_uint_t                 n;
    ngx_http_core_srv_conf_t  *cscf;
    enum {
        sw_start = 0,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse literal huff:%ui, len:%ui",
                       st->huffman, st->length);

        n = st->length;

        cscf = ngx_http_v3_get_module_srv_conf(c, ngx_http_core_module);

        if (n > cscf->large_client_header_buffers.size) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client sent too large field line");
            return NGX_HTTP_V3_ERR_EXCESSIVE_LOAD;
        }

        if (st->huffman) {
            n = n * 8 / 5;
            st->huffstate = 0;
        }

        st->last = ngx_pnalloc(c->pool, n + 1);
        if (st->last == NULL) {
            return NGX_ERROR;
        }

        st->value.data = st->last;
        st->state = sw_value;

        /* fall through */

    case sw_value:

        if (st->huffman) {
            if (ngx_http_v2_huff_decode(&st->huffstate, &ch, 1, &st->last,
                                        st->length == 1, c->log)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

        } else {
            *st->last++ = ch;
        }

        if (--st->length) {
            break;
        }

        st->value.len = st->last - st->value.data;
        *st->last = '\0';
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse literal done \"%V\"", &st->value);

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_field_ri(ngx_connection_t *c, ngx_http_v3_parse_field_t *st,
    u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_index
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse field ri");

        st->dynamic = (ch & 0x40) ? 0 : 1;
        st->state = sw_index;

        /* fall through */

    case sw_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 6, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field ri done %s%ui]",
                   st->dynamic ? "dynamic[-" : "static[", st->index);

    if (st->dynamic) {
        st->index = st->base - st->index - 1;
    }

    rc = ngx_http_v3_parse_lookup(c, st->dynamic, st->index, &st->name,
                                  &st->value);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_field_lri(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_index,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse field lri");

        st->dynamic = (ch & 0x10) ? 0 : 1;
        st->state = sw_index;

        /* fall through */

    case sw_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 4, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        st->state = sw_value_len;
        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->value = st->literal.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field lri done %s%ui] \"%V\"",
                   st->dynamic ? "dynamic[-" : "static[",
                   st->index, &st->value);

    if (st->dynamic) {
        st->index = st->base - st->index - 1;
    }

    rc = ngx_http_v3_parse_lookup(c, st->dynamic, st->index, &st->name, NULL);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_field_l(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_name_len,
        sw_name,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse field l");

        st->literal.huffman = (ch & 0x08) ? 1 : 0;
        st->state = sw_name_len;

        /* fall through */

    case sw_name_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 3, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            return NGX_ERROR;
        }

        st->state = sw_name;
        break;

    case sw_name:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->name = st->literal.value;
        st->state = sw_value_len;
        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->value = st->literal.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field l done \"%V\" \"%V\"",
                   &st->name, &st->value);

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_field_pbi(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_index
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse field pbi");

        st->state = sw_index;

        /* fall through */

    case sw_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 4, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field pbi done dynamic[+%ui]", st->index);

    rc = ngx_http_v3_parse_lookup(c, 1, st->base + st->index, &st->name,
                                  &st->value);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_field_lpbi(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_index,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse field lpbi");

        st->state = sw_index;

        /* fall through */

    case sw_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 3, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        st->state = sw_value_len;
        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->value = st->literal.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field lpbi done dynamic[+%ui] \"%V\"",
                   st->index, &st->value);

    rc = ngx_http_v3_parse_lookup(c, 1, st->base + st->index, &st->name, NULL);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_lookup(ngx_connection_t *c, ngx_uint_t dynamic,
    ngx_uint_t index, ngx_str_t *name, ngx_str_t *value)
{
    u_char  *p;

    if (!dynamic) {
        if (ngx_http_v3_lookup_static(c, index, name, value) != NGX_OK) {
            return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED;
        }

        return NGX_OK;
    }

    if (ngx_http_v3_lookup(c, index, name, value) != NGX_OK) {
        return NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED;
    }

    if (name) {
        p = ngx_pnalloc(c->pool, name->len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, name->data, name->len);
        p[name->len] = '\0';
        name->data = p;
    }

    if (value) {
        p = ngx_pnalloc(c->pool, value->len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, value->data, value->len);
        p[value->len] = '\0';
        value->data = p;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_parse_control(ngx_connection_t *c, ngx_http_v3_parse_control_t *st,
    u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_first_type,
        sw_type,
        sw_length,
        sw_cancel_push,
        sw_settings,
        sw_max_push_id,
        sw_goaway,
        sw_skip
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse control");

        st->state = sw_first_type;

        /* fall through */

    case sw_first_type:
    case sw_type:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->type = st->vlint.value;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse frame type:%ui", st->type);

        if (st->state == sw_first_type
            && st->type != NGX_HTTP_V3_FRAME_SETTINGS)
        {
            return NGX_HTTP_V3_ERR_MISSING_SETTINGS;
        }

        if (st->state != sw_first_type
            && st->type == NGX_HTTP_V3_FRAME_SETTINGS)
        {
            return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED;
        }

        if (ngx_http_v3_is_v2_frame(st->type)
            || st->type == NGX_HTTP_V3_FRAME_DATA
            || st->type == NGX_HTTP_V3_FRAME_HEADERS
            || st->type == NGX_HTTP_V3_FRAME_PUSH_PROMISE)
        {
            return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED;
        }

        st->state = sw_length;
        break;

    case sw_length:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse frame len:%uL", st->vlint.value);

        st->length = st->vlint.value;
        if (st->length == 0) {
            st->state = sw_type;
            break;
        }

        switch (st->type) {

        case NGX_HTTP_V3_FRAME_CANCEL_PUSH:
            st->state = sw_cancel_push;
            break;

        case NGX_HTTP_V3_FRAME_SETTINGS:
            st->state = sw_settings;
            break;

        case NGX_HTTP_V3_FRAME_MAX_PUSH_ID:
            st->state = sw_max_push_id;
            break;

        case NGX_HTTP_V3_FRAME_GOAWAY:
            st->state = sw_goaway;
            break;

        default:
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http3 parse skip unknown frame");
            st->state = sw_skip;
        }

        break;

    case sw_cancel_push:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);

        if (--st->length == 0 && rc == NGX_AGAIN) {
            return NGX_HTTP_V3_ERR_FRAME_ERROR;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_cancel_push(c, st->vlint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        st->state = sw_type;
        break;

    case sw_settings:

        rc = ngx_http_v3_parse_settings(c, &st->settings, ch);

        if (--st->length == 0 && rc == NGX_AGAIN) {
            return NGX_HTTP_V3_ERR_SETTINGS_ERROR;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        if (st->length == 0) {
            st->state = sw_type;
        }

        break;

    case sw_max_push_id:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);

        if (--st->length == 0 && rc == NGX_AGAIN) {
            return NGX_HTTP_V3_ERR_FRAME_ERROR;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_set_max_push_id(c, st->vlint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        st->state = sw_type;
        break;

    case sw_goaway:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);

        if (--st->length == 0 && rc == NGX_AGAIN) {
            return NGX_HTTP_V3_ERR_FRAME_ERROR;
        }

        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_goaway(c, st->vlint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        st->state = sw_type;
        break;

    case sw_skip:

        if (--st->length == 0) {
            st->state = sw_type;
        }

        break;
    }

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_v3_parse_settings(ngx_connection_t *c,
    ngx_http_v3_parse_settings_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_id,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse settings");

        st->state = sw_id;

        /* fall through */

    case sw_id:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->id = st->vlint.value;
        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        if (ngx_http_v3_set_param(c, st->id, st->vlint.value) != NGX_OK) {
            return NGX_HTTP_V3_ERR_SETTINGS_ERROR;
        }

        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse settings done");

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_encoder(ngx_connection_t *c, ngx_http_v3_parse_encoder_t *st,
    u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_inr,
        sw_iln,
        sw_capacity,
        sw_duplicate
    };

    if (st->state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse encoder instruction");

        if (ch & 0x80) {
            /* Insert With Name Reference */

            st->state = sw_inr;

        } else if (ch & 0x40) {
            /* Insert With Literal Name */

            st->state = sw_iln;

        } else if (ch & 0x20) {
            /* Set Dynamic Table Capacity */

            st->state = sw_capacity;

        } else {
            /* Duplicate */

            st->state = sw_duplicate;
        }
    }

    switch (st->state) {

    case sw_inr:

        rc = ngx_http_v3_parse_field_inr(c, &st->field, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        goto done;

    case sw_iln:

        rc = ngx_http_v3_parse_field_iln(c, &st->field, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        goto done;

    case sw_capacity:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 5, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_set_capacity(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;

    case sw_duplicate:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 5, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_duplicate(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse encoder instruction done");

    st->state = sw_start;
    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_v3_parse_field_inr(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_name_index,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse field inr");

        st->dynamic = (ch & 0x40) ? 0 : 1;
        st->state = sw_name_index;

        /* fall through */

    case sw_name_index:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 6, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->index = st->pint.value;
        st->state = sw_value_len;
        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            st->value.len = 0;
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->value = st->literal.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field inr done %s[%ui] \"%V\"",
                   st->dynamic ? "dynamic" : "static",
                   st->index, &st->value);

    rc = ngx_http_v3_ref_insert(c, st->dynamic, st->index, &st->value);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_field_iln(ngx_connection_t *c,
    ngx_http_v3_parse_field_t *st, u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_name_len,
        sw_name,
        sw_value_len,
        sw_read_value_len,
        sw_value
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse field iln");

        st->literal.huffman = (ch & 0x20) ? 1 : 0;
        st->state = sw_name_len;

        /* fall through */

    case sw_name_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 5, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            return NGX_ERROR;
        }

        st->state = sw_name;
        break;

    case sw_name:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->name = st->literal.value;
        st->state = sw_value_len;
        break;

    case sw_value_len:

        st->literal.huffman = (ch & 0x80) ? 1 : 0;
        st->state = sw_read_value_len;

        /* fall through */

    case sw_read_value_len:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->literal.length = st->pint.value;
        if (st->literal.length == 0) {
            st->value.len = 0;
            goto done;
        }

        st->state = sw_value;
        break;

    case sw_value:

        rc = ngx_http_v3_parse_literal(c, &st->literal, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->value = st->literal.value;
        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse field iln done \"%V\":\"%V\"",
                   &st->name, &st->value);

    rc = ngx_http_v3_insert(c, &st->name, &st->value);
    if (rc != NGX_OK) {
        return rc;
    }

    st->state = sw_start;
    return NGX_DONE;
}


static ngx_int_t
ngx_http_v3_parse_decoder(ngx_connection_t *c, ngx_http_v3_parse_decoder_t *st,
    u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_ack_section,
        sw_cancel_stream,
        sw_inc_insert_count
    };

    if (st->state == sw_start) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse decoder instruction");

        if (ch & 0x80) {
            /* Section Acknowledgment */

            st->state = sw_ack_section;

        } else if (ch & 0x40) {
            /*  Stream Cancellation */

            st->state = sw_cancel_stream;

        }  else {
            /*  Insert Count Increment */

            st->state = sw_inc_insert_count;
        }
    }

    switch (st->state) {

    case sw_ack_section:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 7, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_ack_section(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;

    case sw_cancel_stream:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 6, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_cancel_stream(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;

    case sw_inc_insert_count:

        rc = ngx_http_v3_parse_prefix_int(c, &st->pint, 6, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_inc_insert_count(c, st->pint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        goto done;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 parse decoder instruction done");

    st->state = sw_start;
    return NGX_AGAIN;
}


ngx_int_t
ngx_http_v3_parse_data(ngx_connection_t *c, ngx_http_v3_parse_data_t *st,
    u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_type,
        sw_length,
        sw_skip
    };

    switch (st->state) {

    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse data");

        st->state = sw_type;

        /* fall through */

    case sw_type:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->type = st->vlint.value;

        if (st->type == NGX_HTTP_V3_FRAME_HEADERS) {
            /* trailers */
            goto done;
        }

        if (ngx_http_v3_is_v2_frame(st->type)
            || st->type == NGX_HTTP_V3_FRAME_GOAWAY
            || st->type == NGX_HTTP_V3_FRAME_SETTINGS
            || st->type == NGX_HTTP_V3_FRAME_MAX_PUSH_ID
            || st->type == NGX_HTTP_V3_FRAME_CANCEL_PUSH
            || st->type == NGX_HTTP_V3_FRAME_PUSH_PROMISE)
        {
            return NGX_HTTP_V3_ERR_FRAME_UNEXPECTED;
        }

        st->state = sw_length;
        break;

    case sw_length:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        st->length = st->vlint.value;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http3 parse data type:%ui, len:%ui",
                       st->type, st->length);

        if (st->type != NGX_HTTP_V3_FRAME_DATA && st->length > 0) {
            st->state = sw_skip;
            break;
        }

        st->state = sw_type;
        return NGX_OK;

    case sw_skip:

        if (--st->length == 0) {
            st->state = sw_type;
        }

        break;
    }

    return NGX_AGAIN;

done:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse data done");

    st->state = sw_start;
    return NGX_DONE;
}


ngx_int_t
ngx_http_v3_parse_uni(ngx_connection_t *c, ngx_http_v3_parse_uni_t *st,
    u_char ch)
{
    ngx_int_t  rc;
    enum {
        sw_start = 0,
        sw_type,
        sw_control,
        sw_encoder,
        sw_decoder,
        sw_unknown
    };

    switch (st->state) {
    case sw_start:

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 parse uni");

        st->state = sw_type;

        /* fall through */

    case sw_type:

        rc = ngx_http_v3_parse_varlen_int(c, &st->vlint, ch);
        if (rc != NGX_DONE) {
            return rc;
        }

        rc = ngx_http_v3_register_uni_stream(c, st->vlint.value);
        if (rc != NGX_OK) {
            return rc;
        }

        switch (st->vlint.value) {
        case NGX_HTTP_V3_STREAM_CONTROL:
            st->state = sw_control;
            break;

        case NGX_HTTP_V3_STREAM_ENCODER:
            st->state = sw_encoder;
            break;

        case NGX_HTTP_V3_STREAM_DECODER:
            st->state = sw_decoder;
            break;

        default:
            st->state = sw_unknown;
        }

        break;

    case sw_control:

        rc = ngx_http_v3_parse_control(c, &st->u.control, ch);
        if (rc != NGX_OK) {
            return rc;
        }

        break;

    case sw_encoder:

        rc = ngx_http_v3_parse_encoder(c, &st->u.encoder, ch);
        if (rc != NGX_OK) {
            return rc;
        }

        break;

    case sw_decoder:

        rc = ngx_http_v3_parse_decoder(c, &st->u.decoder, ch);
        if (rc != NGX_OK) {
            return rc;
        }

        break;

    case sw_unknown:
        break;
    }

    return NGX_AGAIN;
}