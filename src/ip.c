#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

#define IP_HDR_LEN_PER_BYTE 4       // ip包头长度单位
#define IP_HDR_OFFSET_PER_BYTE 8    // ip分片偏移长度单位
#define IP_VERSION_4 4              // ipv4
#define IP_MORE_FRAGMENT (1 << 13)  // ip分片mf位*/

static int send_id = 0;

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // TO-DO
    ip_hdr_t* ip_hdr = (ip_hdr_t*)buf->data;
    if(buf->len < sizeof(ip_hdr_t)) return;
    if(ip_hdr->version != IP_VERSION_4) return;
    if(swap16(ip_hdr->total_len16) > buf->len) return;
    uint16_t sum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    uint16_t checksum = checksum16((uint16_t*)ip_hdr, sizeof(ip_hdr_t));
    if(checksum != sum) return;
    for(int i = 0; i < 4; ++i) {
        if(ip_hdr->dst_ip[i] != net_if_ip[i]) return;
    }
    buf_remove_padding(buf,buf->len - swap16(ip_hdr->total_len16));
    buf_remove_header(buf, sizeof(ip_hdr_t));
    if (net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) == -1)
    {
        printf("icmp_unreachable\n");
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
    return;
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = mf?swap16(IP_MAX_LEN):swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    ip_hdr->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | (offset / IP_HDR_OFFSET_PER_BYTE));
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = protocol;
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
    arp_out(buf, ip_hdr->dst_ip);
    return;
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    if(buf->len < IP_MAX_LEN - sizeof(ip_hdr_t)) {
        ip_fragment_out(buf, ip, protocol, send_id, 0, 0);
    } else {
        int offset = 0;
        while (buf->len > IP_MAX_LEN - sizeof(ip_hdr_t)) {
            uint32_t temp_len = buf->len;
            buf->len = IP_MAX_LEN - sizeof(ip_hdr_t);
            ip_fragment_out(buf, ip, protocol, send_id, offset, 1);
            offset += IP_MAX_LEN - sizeof(ip_hdr_t);
            buf->len = temp_len + sizeof(ip_hdr_t);
            buf_remove_header(buf, IP_MAX_LEN);
        }
        if (buf->len > 0) {
            ip_fragment_out(buf, ip, protocol, send_id, offset, 0);
        }
    }
    ++send_id;
    return;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}