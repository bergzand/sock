#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "nanocoap.h"

#if NANOCOAP_DEBUG
#define ENABLE_DEBUG (1)
#else
#define ENABLE_DEBUG (0)
#endif
#include "debug.h"

static int _decode_value(unsigned val, uint8_t **pkt_pos_ptr, uint8_t *pkt_end);
static uint32_t _decode_uint(uint8_t *pkt_pos, unsigned nbytes);

/* http://tools.ietf.org/html/rfc7252#section-3
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver| T |  TKL  |      Code     |          Message ID           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Token (if any, TKL bytes) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Options (if any) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |1 1 1 1 1 1 1 1|    Payload (if any) ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int coap_parse(coap_pkt_t *pkt, uint8_t *buf, size_t len)
{
    uint8_t *urlpos = pkt->url;
    coap_hdr_t *hdr = (coap_hdr_t *)buf;
    pkt->hdr = hdr;

    uint8_t *pkt_pos = hdr->data;
    uint8_t *pkt_end = buf + len;

    memset(pkt->url, '\0', NANOCOAP_URL_MAX);
    pkt->payload_len = 0;
    pkt->observe_value = UINT32_MAX;

    /* token value (tkl bytes) */
    if (coap_get_token_len(pkt)) {
        pkt->token = pkt_pos;
        pkt_pos += coap_get_token_len(pkt);
    } else {
        pkt->token = NULL;
    }

    /* parse options */
    pkt->options = (pkt_pos != pkt_end) ? pkt_pos : NULL;
    int option_nr = 0;
    while (pkt_pos != pkt_end) {
        uint8_t option_byte = *pkt_pos++;
        if (option_byte == 0xff) {
            pkt->payload = pkt_pos;
            pkt->payload_len = buf + len - pkt_pos;
            DEBUG("payload len = %u\n", pkt->payload_len);
            break;
        }
        else {
            int option_delta = _decode_value(option_byte >> 4, &pkt_pos, pkt_end);
            if (option_delta < 0) {
                DEBUG("bad op delta\n");
                return -EBADMSG;
            }
            int option_len = _decode_value(option_byte & 0xf, &pkt_pos, pkt_end);
            if (option_len < 0) {
                DEBUG("bad op len\n");
                return -EBADMSG;
            }
            option_nr += option_delta;
            DEBUG("option nr=%i len=%i\n", option_nr, option_len);

            switch (option_nr) {
                case COAP_OPT_URI_PATH:
                    *urlpos++ = '/';
                    memcpy(urlpos, pkt_pos, option_len);
                    urlpos += option_len;
                    break;
                case COAP_OPT_CONTENT_FORMAT:
                    if (option_len == 0) {
                        pkt->content_type = 0;
                    } else if (option_len == 1) {
                        pkt->content_type = *pkt_pos;
                    } else if (option_len == 2) {
                        memcpy(&pkt->content_type, pkt_pos, 2);
                        pkt->content_type = ntohs(pkt->content_type);
                    }
                    break;
                case COAP_OPT_OBSERVE:
                    if (option_len < 4) {
                        pkt->observe_value = _decode_uint(pkt_pos, option_len);
                    } else {
                        DEBUG("nanocoap: discarding packet with invalid option length.\n");
                        return -EBADMSG;
                    }
                    break;
                case COAP_OPT_BLOCK2:
                    if (option_len < 4) {
                        uint32_t blk2_opt = _decode_uint(pkt_pos, option_len);
                        uint8_t blk2_size = (blk2_opt & COAP_BLOCKWISE_SZX_MASK) + 4;
                        if (blk2_size > 10) {
                            DEBUG("nanocoap: discarding packet with invalid block szx.\n");
                            return -EBADMSG;
                        }
                    } else {
                        DEBUG("nanocoap: discarding packet with invalid option length.\n");
                        return -EBADMSG;
                    }
                    break;
                default:
                    DEBUG("nanocoap: unhandled option nr=%i len=%i critical=%u\n", option_nr, option_len, option_nr & 1);
                    if (option_nr & 1) {
                        DEBUG("nanocoap: discarding packet with unknown critical option.\n");
                        return -EBADMSG;
                    }
            }

            pkt_pos += option_len;
        }
    }

    /* set payload pointer to first byte after the options in case no payload
     * is present, so we can use it as reference to find the end of options
     * at a later point in time */
    if (pkt_pos == pkt_end) {
        pkt->payload = pkt_end;
    }

    DEBUG("coap pkt parsed. code=%u detail=%u payload_len=%u, 0x%02x\n",
            coap_get_code_class(pkt),
            coap_get_code_detail(pkt),
            pkt->payload_len, hdr->code);

    return 0;
}

ssize_t coap_handle_req(coap_pkt_t *pkt, uint8_t *resp_buf, unsigned resp_buf_len)
{
    if (coap_get_code_class(pkt) != COAP_REQ) {
        DEBUG("coap_handle_req(): not a request.\n");
        return -EBADMSG;
    }

    if (pkt->hdr->code == 0) {
        return coap_build_reply(pkt, COAP_CODE_EMPTY, resp_buf, resp_buf_len, 0);
    }

    unsigned method_flag = coap_method2flag(coap_get_code_detail(pkt));

    for (unsigned i = 0; i < coap_resources_numof; i++) {
        if (! (coap_resources[i].methods & method_flag)) {
            continue;
        }

        int res = strcmp((char*)pkt->url, coap_resources[i].path);
        if (res > 0) {
            continue;
        }
        else if (res < 0) {
            break;
        }
        else {
            return coap_resources[i].handler(pkt, resp_buf, resp_buf_len);
        }
    }

    return coap_build_reply(pkt, COAP_CODE_404, resp_buf, resp_buf_len, 0);
}

ssize_t coap_reply_simple(coap_pkt_t *pkt,
        unsigned code,
        uint8_t *buf, size_t len,
        unsigned ct,
        const uint8_t *payload, uint8_t payload_len)
{
    uint8_t *payload_start = buf + coap_get_total_hdr_len(pkt);
    uint8_t *bufpos = payload_start;

    if (payload_len) {
        bufpos += coap_put_option_ct(bufpos, 0, ct);
        *bufpos++ = 0xff;

        memcpy(bufpos, payload, payload_len);
        bufpos += payload_len;
    }

    return coap_build_reply(pkt, code, buf, len, bufpos - payload_start);
}

ssize_t coap_build_reply(coap_pkt_t *pkt, unsigned code,
        uint8_t *rbuf, unsigned rlen, unsigned payload_len)
{
    unsigned tkl = coap_get_token_len(pkt);
    unsigned len = sizeof(coap_hdr_t) + tkl;

    if ((len + payload_len + 1) > rlen) {
        return -ENOSPC;
    }

    /* if code is COAP_CODE_EMPTY (zero), use RST as type, else RESP */
    unsigned type = code ? COAP_RESP : COAP_RST;

    coap_build_hdr((coap_hdr_t*)rbuf, type, pkt->token, tkl, code, pkt->hdr->id);
    coap_hdr_set_type((coap_hdr_t*)rbuf, type);
    coap_hdr_set_code((coap_hdr_t*)rbuf, code);

    len += payload_len;

    return len;
}

ssize_t coap_build_hdr(coap_hdr_t *hdr, unsigned type, uint8_t *token, size_t token_len, unsigned code, uint16_t id)
{
    assert(!(type & ~0x3));
    assert(!(token_len & ~0x1f));

    memset(hdr, 0, sizeof(coap_hdr_t));
    hdr->ver_t_tkl = (0x1 << 6) | (type << 4) | token_len;
    hdr->code = code;
    hdr->id = id;

    if (token_len) {
        memcpy(hdr->data, token, token_len);
    }

    return sizeof(coap_hdr_t) + token_len;
}

static int _decode_value(unsigned val, uint8_t **pkt_pos_ptr, uint8_t *pkt_end)
{
    uint8_t *pkt_pos = *pkt_pos_ptr;
    size_t left = pkt_end - pkt_pos;
    int res;
    switch (val) {
        case 13:
            {
            /* An 8-bit unsigned integer follows the initial byte and
               indicates the Option Delta minus 13. */
            if (left < 1) {
                return -ENOSPC;
            }
            uint8_t delta = *pkt_pos++;
            res = delta + 13;
            break;
            }
        case 14:
            {
            /* A 16-bit unsigned integer in network byte order follows
             * the initial byte and indicates the Option Delta minus
             * 269. */
            if (left < 2) {
                return -ENOSPC;
            }
            uint16_t delta;
            uint8_t *_tmp = (uint8_t*)&delta;
            *_tmp++= *pkt_pos++;
            *_tmp++= *pkt_pos++;
            res = ntohs(delta) + 269;
            break;
            }
        case 15:
            /* Reserved for the Payload Marker.  If the field is set to
             * this value but the entire byte is not the payload
             * marker, this MUST be processed as a message format
             * error. */
            return -EBADMSG;
        default:
            res = val;
    }

    *pkt_pos_ptr = pkt_pos;
    return res;
}

static uint32_t _decode_uint(uint8_t *pkt_pos, unsigned nbytes)
{
    assert(nbytes <= 4);

    uint32_t res = 0;
    if (nbytes) {
        memcpy(((uint8_t*)&res) + (4 - nbytes), pkt_pos, nbytes);
    }
    return ntohl(res);
}

static unsigned _put_odelta(uint8_t *buf, unsigned lastonum, unsigned onum, unsigned olen)
{
    unsigned delta = onum - lastonum;
    if (delta < 13) {
        *buf = (uint8_t) ((delta << 4) | olen);
        return 1;
    } else if (delta == 13) {
        *buf++ = (uint8_t) ((13 << 4) | olen);
        *buf = delta - 13;
        return 2;
    } else {
        *buf++ = (uint8_t) ((14 << 4) | olen);
        uint16_t tmp = delta - 269;
        tmp = htons(tmp);
        memcpy(buf, &tmp, 2);
        return 3;
    }
}

size_t coap_put_option(uint8_t *buf, uint16_t lastonum, uint16_t onum, uint8_t *odata, size_t olen)
{
    assert(lastonum <= onum);
    int n = _put_odelta(buf, lastonum, onum, olen);
    if(olen) {
        memcpy(buf + n, odata, olen);
        n += olen;
    }
    return n;
}

size_t coap_put_option_ct(uint8_t *buf, uint16_t lastonum, uint16_t content_type)
{
    if (content_type == 0) {
        return coap_put_option(buf, lastonum, COAP_OPT_CONTENT_FORMAT, NULL, 0);
    }
    else if (content_type <= 255) {
        uint8_t tmp = content_type;
        return coap_put_option(buf, lastonum, COAP_OPT_CONTENT_FORMAT, &tmp, sizeof(tmp));
    }
    else {
        return coap_put_option(buf, lastonum, COAP_OPT_CONTENT_FORMAT, (uint8_t*)&content_type, sizeof(content_type));
    }
}

size_t coap_put_option_block2(uint8_t *buf, uint16_t lastonum, \
                              coap_blockwise_t *blk)
{
    size_t opt_len = 1;
    uint32_t tmp = 0;
    uint32_t opt_val;

    /* Calculate size exponent */
    uint8_t szx = coap_blockwise_size2szx(blk->end_pos - blk->start_pos);
    uint32_t num = blk->start_pos/(blk->end_pos - blk->start_pos);
    /* Determine option length */
    if (num > 0x0fff) {
        opt_len = 3;
    }
    else if (num > 0x0f) {
        opt_len = 2;
    }
    tmp = num << COAP_BLOCKWISE_NUM_OFF;
    tmp |= szx;
    tmp = htonl(tmp);
    tmp >>= 8 * (4 - opt_len);
    return coap_put_option(buf, lastonum, COAP_OPT_BLOCK2,
                           (uint8_t*)&tmp, opt_len);
}

size_t coap_put_option_uri(uint8_t *buf, uint16_t lastonum, const char *uri, uint16_t optnum)
{
    char separator = (optnum == COAP_OPT_URI_PATH) ? '/' : '&';
    size_t uri_len = strlen(uri);
    if (uri_len == 0) {
        return 0;
    }

    uint8_t *bufpos = buf;
    char *uripos = (char*)uri;

    while(uri_len) {
        size_t part_len;
        uripos++;
        uint8_t *part_start = (uint8_t*)uripos;

        while (uri_len--) {
            if ((*uripos == separator) || (*uripos == '\0')) {
                break;
            }
            uripos++;
        }

        part_len = (uint8_t*)uripos - part_start;

        if (part_len) {
            bufpos += coap_put_option(bufpos, lastonum, optnum, part_start, part_len);
            lastonum = optnum;
        }
    }

    return bufpos - buf;
}

void coap_blockwise_init(coap_pkt_t *pkt, coap_blockwise_t *blk)
{
    coap_opt_t opt;
    uint32_t blk2_num = 0;
    uint8_t blk2_size = COAP_BLOCKWISE_SZX_MAX;
    if(coap_find_option(pkt->payload, pkt->options, &opt, COAP_OPT_BLOCK2)) {
        uint32_t blk2_opt = _decode_uint(opt.val, opt.len);
        blk2_num = blk2_opt >> COAP_BLOCKWISE_NUM_OFF;
        blk2_size = (blk2_opt & COAP_BLOCKWISE_SZX_MASK) + 4;
    }
    /* Use the smallest block size */
    blk2_size = (COAP_BLOCKWISE_SZX_MAX > blk2_size) ?
        blk2_size :
        COAP_BLOCKWISE_SZX_MAX;
    blk->start_pos = blk2_num * 1 << blk2_size;
    blk->end_pos = blk->start_pos + (1 << blk2_size);
    blk->cur_pos = 0;
}

void coap_finish_option_block2(coap_blockwise_t *blk, uint8_t *options_pos, uint8_t *body_pos)
{
    coap_opt_t opt;
    uint8_t *hdr_pos = coap_find_option(body_pos, options_pos, &opt, COAP_OPT_BLOCK2);
    if (hdr_pos == NULL) {
        DEBUG("nanocoap: No block2 header found, unable to adjust more flag\n");
        return;
    }
    if (blk->cur_pos >= blk->end_pos) {
        opt.val[opt.len-1] |= 1 << COAP_BLOCKWISE_MORE_OFF;
    }
}


size_t coap_blockwise_put_char(coap_blockwise_t *blk, uint8_t *bufpos, char c)
{
    /* Only copy the char if it is within the window */
    if (blk->start_pos <=  blk->cur_pos && blk->cur_pos < blk->end_pos) {
        *bufpos = c;
        blk->cur_pos++;
        return 1;
    }
    blk->cur_pos++;
    return 0;
}

size_t coap_blockwise_put_string(coap_blockwise_t *blk, uint8_t *bufpos, \
                                 const char *c, size_t len)
{
    uint32_t str_offset = 0;
    uint32_t str_len = 0;
    /* Calculate offset inside the string that is in the window */
    if (blk->start_pos > blk->cur_pos) {
        str_offset = blk->start_pos - blk->cur_pos;
    }
    /* Calculate if the string is within the window */
    if (str_offset > len) {
        /* String is before the window */
        blk->cur_pos += len;
        return 0;
    }
    /* Check for string beyond window */
    if (blk->cur_pos >= blk->end_pos) {
        blk->cur_pos += len;
        return 0;
    }

    str_len = len - str_offset;
    /* Check if string is over the end of the window */
    if (blk->cur_pos + len >= blk->end_pos) {
        str_len = blk->end_pos - blk->cur_pos - str_offset;
    }
    memcpy(bufpos, c + str_offset, str_len);
    blk->cur_pos += len;
    return str_len;
}

ssize_t coap_well_known_core_default_handler(coap_pkt_t* pkt, uint8_t *buf, \
                                             size_t len)
{
    coap_blockwise_t blk;
    uint8_t *payload = buf + coap_get_total_hdr_len(pkt);
    uint8_t *bufpos = payload;

    coap_blockwise_init(pkt, &blk);
    bufpos += coap_put_option_ct(bufpos, 0, COAP_CT_LINK_FORMAT);
    bufpos += coap_put_option_block2(bufpos, COAP_OPT_CONTENT_FORMAT, &blk);
    *bufpos++ = 0xff;

    uint8_t *body_reply = bufpos;

    for (unsigned i = 0; i < coap_resources_numof; i++) {
        if (i) {
            bufpos += coap_blockwise_put_char(&blk, bufpos, ',');
        }
        unsigned url_len = strlen(coap_resources[i].path);
        bufpos += coap_blockwise_put_char(&blk, bufpos, '<');
        bufpos += coap_blockwise_put_string(&blk, bufpos, \
                                            coap_resources[i].path, url_len);
        bufpos += coap_blockwise_put_char(&blk, bufpos, '>');
    }

    unsigned payload_len = bufpos - payload;
    coap_finish_option_block2(&blk, payload, body_reply);

    return coap_build_reply(pkt, COAP_CODE_205, buf, len, payload_len);
}

static size_t _decode_optlen(uint8_t *buf, uint16_t *val)
{
    size_t len = 0;

    if (*val == 13) {
        *val += *buf;
        len = 1;
    }
    else if (*val == 14) {
        memcpy(val, buf, 2);
        *val = htons(*val) + 269;
        len = 2;
    }

    return len;
}

static int _parse_opt(uint8_t *optpos, coap_opt_t *opt)
{
    opt->val = optpos + 1;
    opt->delta = ((*optpos & 0xf0) >> 4);
    opt->len =  (*optpos & 0x0f);

    /* make sure delta and len raw values are valid */
    if ((opt->delta == 15) || (opt->len == 15)) {
        return -1;
    }

    opt->val += _decode_optlen(opt->val, &opt->delta);
    opt->val += _decode_optlen(opt->val, &opt->len);

    return (opt->val - optpos) + opt->len;
}

uint8_t *coap_find_option(uint8_t *payload_pos, uint8_t *bufpos,
                          coap_opt_t *opt, uint16_t optnum)
{
    assert(opt);

    /* check if we reached the end of options */
    if (!bufpos || (*bufpos == 0xff)) {
        return NULL;
    }

    uint16_t delta = 0;

    do {
        if (bufpos >= payload_pos) {
            return NULL;
        }
        int res = _parse_opt(bufpos, opt);
        if (res < 0) {
            return NULL;
        }
        bufpos += res;
        delta += opt->delta;
    } while (delta < optnum);

    if (delta != optnum) {
        bufpos = NULL;
    }

    return bufpos;
}
