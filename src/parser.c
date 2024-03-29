#include <tree_sitter/parser.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#define LANGUAGE_VERSION 14
#define STATE_COUNT 78
#define LARGE_STATE_COUNT 2
#define SYMBOL_COUNT 83
#define ALIAS_COUNT 0
#define TOKEN_COUNT 60
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 0
#define MAX_ALIAS_SEQUENCE_LENGTH 8
#define PRODUCTION_ID_COUNT 1

enum {
  anon_sym_DASH_GT = 1,
  anon_sym_LT_GT = 2,
  anon_sym_alert = 3,
  anon_sym_drop = 4,
  anon_sym_pass = 5,
  anon_sym_reject = 6,
  anon_sym_rejectboth = 7,
  anon_sym_rejectdst = 8,
  anon_sym_rejectsrc = 9,
  anon_sym_dcerpc = 10,
  anon_sym_dhcp = 11,
  anon_sym_dnp3 = 12,
  anon_sym_dns = 13,
  anon_sym_enip = 14,
  anon_sym_ftp = 15,
  anon_sym_http = 16,
  anon_sym_http2 = 17,
  anon_sym_icmp = 18,
  anon_sym_ikev2 = 19,
  anon_sym_imap = 20,
  anon_sym_ip = 21,
  anon_sym_ipv6 = 22,
  anon_sym_krb5 = 23,
  anon_sym_mqtt = 24,
  anon_sym_modbus = 25,
  anon_sym_nfs = 26,
  anon_sym_ntp = 27,
  anon_sym_pkthdr = 28,
  anon_sym_rdp = 29,
  anon_sym_rfb = 30,
  anon_sym_sip = 31,
  anon_sym_smb = 32,
  anon_sym_smtp = 33,
  anon_sym_snmp = 34,
  anon_sym_ssh = 35,
  anon_sym_tcp = 36,
  anon_sym_tftp = 37,
  anon_sym_tls = 38,
  anon_sym_udp = 39,
  anon_sym_any = 40,
  anon_sym_SLASH = 41,
  anon_sym_BANG = 42,
  anon_sym_DOT = 43,
  sym_network_octet = 44,
  sym_network_subnet_mask = 45,
  anon_sym_LBRACK = 46,
  anon_sym_RBRACK = 47,
  anon_sym_COMMA = 48,
  sym_port_single = 49,
  anon_sym_COLON = 50,
  anon_sym_DOLLAR = 51,
  aux_sym_variable_token1 = 52,
  anon_sym_LPAREN = 53,
  anon_sym_RPAREN = 54,
  anon_sym_SEMI = 55,
  sym_option_key = 56,
  sym_option_value = 57,
  anon_sym_POUND = 58,
  aux_sym_comment_token1 = 59,
  sym_file = 60,
  sym_rule = 61,
  sym_direction = 62,
  sym_action = 63,
  sym_protocol = 64,
  sym_network = 65,
  sym_network_ip = 66,
  sym_network_cidr = 67,
  sym_network_list = 68,
  sym_network_list_entry = 69,
  sym_port = 70,
  sym_port_list = 71,
  sym_port_spec = 72,
  sym_port_range = 73,
  sym_variable = 74,
  sym_options = 75,
  sym_option = 76,
  sym_option_key_value = 77,
  sym_comment = 78,
  aux_sym_file_repeat1 = 79,
  aux_sym_network_list_entry_repeat1 = 80,
  aux_sym_port_list_repeat1 = 81,
  aux_sym_option_repeat1 = 82,
};

static const char * const ts_symbol_names[] = {
  [ts_builtin_sym_end] = "end",
  [anon_sym_DASH_GT] = "->",
  [anon_sym_LT_GT] = "<>",
  [anon_sym_alert] = "alert",
  [anon_sym_drop] = "drop",
  [anon_sym_pass] = "pass",
  [anon_sym_reject] = "reject",
  [anon_sym_rejectboth] = "rejectboth",
  [anon_sym_rejectdst] = "rejectdst",
  [anon_sym_rejectsrc] = "rejectsrc",
  [anon_sym_dcerpc] = "dcerpc",
  [anon_sym_dhcp] = "dhcp",
  [anon_sym_dnp3] = "dnp3",
  [anon_sym_dns] = "dns",
  [anon_sym_enip] = "enip",
  [anon_sym_ftp] = "ftp",
  [anon_sym_http] = "http",
  [anon_sym_http2] = "http2",
  [anon_sym_icmp] = "icmp",
  [anon_sym_ikev2] = "ikev2",
  [anon_sym_imap] = "imap",
  [anon_sym_ip] = "ip",
  [anon_sym_ipv6] = "ipv6",
  [anon_sym_krb5] = "krb5",
  [anon_sym_mqtt] = "mqtt",
  [anon_sym_modbus] = "modbus",
  [anon_sym_nfs] = "nfs",
  [anon_sym_ntp] = "ntp",
  [anon_sym_pkthdr] = "pkthdr",
  [anon_sym_rdp] = "rdp",
  [anon_sym_rfb] = "rfb",
  [anon_sym_sip] = "sip",
  [anon_sym_smb] = "smb",
  [anon_sym_smtp] = "smtp",
  [anon_sym_snmp] = "snmp",
  [anon_sym_ssh] = "ssh",
  [anon_sym_tcp] = "tcp",
  [anon_sym_tftp] = "tftp",
  [anon_sym_tls] = "tls",
  [anon_sym_udp] = "udp",
  [anon_sym_any] = "any",
  [anon_sym_SLASH] = "/",
  [anon_sym_BANG] = "!",
  [anon_sym_DOT] = ".",
  [sym_network_octet] = "network_octet",
  [sym_network_subnet_mask] = "network_subnet_mask",
  [anon_sym_LBRACK] = "[",
  [anon_sym_RBRACK] = "]",
  [anon_sym_COMMA] = ",",
  [sym_port_single] = "port_single",
  [anon_sym_COLON] = ":",
  [anon_sym_DOLLAR] = "$",
  [aux_sym_variable_token1] = "variable_token1",
  [anon_sym_LPAREN] = "(",
  [anon_sym_RPAREN] = ")",
  [anon_sym_SEMI] = ";",
  [sym_option_key] = "option_key",
  [sym_option_value] = "option_value",
  [anon_sym_POUND] = "#",
  [aux_sym_comment_token1] = "comment_token1",
  [sym_file] = "file",
  [sym_rule] = "rule",
  [sym_direction] = "direction",
  [sym_action] = "action",
  [sym_protocol] = "protocol",
  [sym_network] = "network",
  [sym_network_ip] = "network_ip",
  [sym_network_cidr] = "network_cidr",
  [sym_network_list] = "network_list",
  [sym_network_list_entry] = "network_list_entry",
  [sym_port] = "port",
  [sym_port_list] = "port_list",
  [sym_port_spec] = "port_spec",
  [sym_port_range] = "port_range",
  [sym_variable] = "variable",
  [sym_options] = "options",
  [sym_option] = "option",
  [sym_option_key_value] = "option_key_value",
  [sym_comment] = "comment",
  [aux_sym_file_repeat1] = "file_repeat1",
  [aux_sym_network_list_entry_repeat1] = "network_list_entry_repeat1",
  [aux_sym_port_list_repeat1] = "port_list_repeat1",
  [aux_sym_option_repeat1] = "option_repeat1",
};

static const TSSymbol ts_symbol_map[] = {
  [ts_builtin_sym_end] = ts_builtin_sym_end,
  [anon_sym_DASH_GT] = anon_sym_DASH_GT,
  [anon_sym_LT_GT] = anon_sym_LT_GT,
  [anon_sym_alert] = anon_sym_alert,
  [anon_sym_drop] = anon_sym_drop,
  [anon_sym_pass] = anon_sym_pass,
  [anon_sym_reject] = anon_sym_reject,
  [anon_sym_rejectboth] = anon_sym_rejectboth,
  [anon_sym_rejectdst] = anon_sym_rejectdst,
  [anon_sym_rejectsrc] = anon_sym_rejectsrc,
  [anon_sym_dcerpc] = anon_sym_dcerpc,
  [anon_sym_dhcp] = anon_sym_dhcp,
  [anon_sym_dnp3] = anon_sym_dnp3,
  [anon_sym_dns] = anon_sym_dns,
  [anon_sym_enip] = anon_sym_enip,
  [anon_sym_ftp] = anon_sym_ftp,
  [anon_sym_http] = anon_sym_http,
  [anon_sym_http2] = anon_sym_http2,
  [anon_sym_icmp] = anon_sym_icmp,
  [anon_sym_ikev2] = anon_sym_ikev2,
  [anon_sym_imap] = anon_sym_imap,
  [anon_sym_ip] = anon_sym_ip,
  [anon_sym_ipv6] = anon_sym_ipv6,
  [anon_sym_krb5] = anon_sym_krb5,
  [anon_sym_mqtt] = anon_sym_mqtt,
  [anon_sym_modbus] = anon_sym_modbus,
  [anon_sym_nfs] = anon_sym_nfs,
  [anon_sym_ntp] = anon_sym_ntp,
  [anon_sym_pkthdr] = anon_sym_pkthdr,
  [anon_sym_rdp] = anon_sym_rdp,
  [anon_sym_rfb] = anon_sym_rfb,
  [anon_sym_sip] = anon_sym_sip,
  [anon_sym_smb] = anon_sym_smb,
  [anon_sym_smtp] = anon_sym_smtp,
  [anon_sym_snmp] = anon_sym_snmp,
  [anon_sym_ssh] = anon_sym_ssh,
  [anon_sym_tcp] = anon_sym_tcp,
  [anon_sym_tftp] = anon_sym_tftp,
  [anon_sym_tls] = anon_sym_tls,
  [anon_sym_udp] = anon_sym_udp,
  [anon_sym_any] = anon_sym_any,
  [anon_sym_SLASH] = anon_sym_SLASH,
  [anon_sym_BANG] = anon_sym_BANG,
  [anon_sym_DOT] = anon_sym_DOT,
  [sym_network_octet] = sym_network_octet,
  [sym_network_subnet_mask] = sym_network_subnet_mask,
  [anon_sym_LBRACK] = anon_sym_LBRACK,
  [anon_sym_RBRACK] = anon_sym_RBRACK,
  [anon_sym_COMMA] = anon_sym_COMMA,
  [sym_port_single] = sym_port_single,
  [anon_sym_COLON] = anon_sym_COLON,
  [anon_sym_DOLLAR] = anon_sym_DOLLAR,
  [aux_sym_variable_token1] = aux_sym_variable_token1,
  [anon_sym_LPAREN] = anon_sym_LPAREN,
  [anon_sym_RPAREN] = anon_sym_RPAREN,
  [anon_sym_SEMI] = anon_sym_SEMI,
  [sym_option_key] = sym_option_key,
  [sym_option_value] = sym_option_value,
  [anon_sym_POUND] = anon_sym_POUND,
  [aux_sym_comment_token1] = aux_sym_comment_token1,
  [sym_file] = sym_file,
  [sym_rule] = sym_rule,
  [sym_direction] = sym_direction,
  [sym_action] = sym_action,
  [sym_protocol] = sym_protocol,
  [sym_network] = sym_network,
  [sym_network_ip] = sym_network_ip,
  [sym_network_cidr] = sym_network_cidr,
  [sym_network_list] = sym_network_list,
  [sym_network_list_entry] = sym_network_list_entry,
  [sym_port] = sym_port,
  [sym_port_list] = sym_port_list,
  [sym_port_spec] = sym_port_spec,
  [sym_port_range] = sym_port_range,
  [sym_variable] = sym_variable,
  [sym_options] = sym_options,
  [sym_option] = sym_option,
  [sym_option_key_value] = sym_option_key_value,
  [sym_comment] = sym_comment,
  [aux_sym_file_repeat1] = aux_sym_file_repeat1,
  [aux_sym_network_list_entry_repeat1] = aux_sym_network_list_entry_repeat1,
  [aux_sym_port_list_repeat1] = aux_sym_port_list_repeat1,
  [aux_sym_option_repeat1] = aux_sym_option_repeat1,
};

static const TSSymbolMetadata ts_symbol_metadata[] = {
  [ts_builtin_sym_end] = {
    .visible = false,
    .named = true,
  },
  [anon_sym_DASH_GT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_LT_GT] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_alert] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_drop] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_pass] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reject] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rejectboth] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rejectdst] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rejectsrc] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dcerpc] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dhcp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dnp3] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dns] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_enip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ftp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http2] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_icmp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ikev2] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_imap] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ipv6] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_krb5] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_mqtt] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_modbus] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_nfs] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ntp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_pkthdr] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rdp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rfb] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_sip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_smb] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_smtp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_snmp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ssh] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tftp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tls] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_udp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_any] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_SLASH] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_BANG] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_DOT] = {
    .visible = true,
    .named = false,
  },
  [sym_network_octet] = {
    .visible = true,
    .named = true,
  },
  [sym_network_subnet_mask] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_LBRACK] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RBRACK] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_COMMA] = {
    .visible = true,
    .named = false,
  },
  [sym_port_single] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_COLON] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_DOLLAR] = {
    .visible = true,
    .named = false,
  },
  [aux_sym_variable_token1] = {
    .visible = false,
    .named = false,
  },
  [anon_sym_LPAREN] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_RPAREN] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_SEMI] = {
    .visible = true,
    .named = false,
  },
  [sym_option_key] = {
    .visible = true,
    .named = true,
  },
  [sym_option_value] = {
    .visible = true,
    .named = true,
  },
  [anon_sym_POUND] = {
    .visible = true,
    .named = false,
  },
  [aux_sym_comment_token1] = {
    .visible = false,
    .named = false,
  },
  [sym_file] = {
    .visible = true,
    .named = true,
  },
  [sym_rule] = {
    .visible = true,
    .named = true,
  },
  [sym_direction] = {
    .visible = true,
    .named = true,
  },
  [sym_action] = {
    .visible = true,
    .named = true,
  },
  [sym_protocol] = {
    .visible = true,
    .named = true,
  },
  [sym_network] = {
    .visible = true,
    .named = true,
  },
  [sym_network_ip] = {
    .visible = true,
    .named = true,
  },
  [sym_network_cidr] = {
    .visible = true,
    .named = true,
  },
  [sym_network_list] = {
    .visible = true,
    .named = true,
  },
  [sym_network_list_entry] = {
    .visible = true,
    .named = true,
  },
  [sym_port] = {
    .visible = true,
    .named = true,
  },
  [sym_port_list] = {
    .visible = true,
    .named = true,
  },
  [sym_port_spec] = {
    .visible = true,
    .named = true,
  },
  [sym_port_range] = {
    .visible = true,
    .named = true,
  },
  [sym_variable] = {
    .visible = true,
    .named = true,
  },
  [sym_options] = {
    .visible = true,
    .named = true,
  },
  [sym_option] = {
    .visible = true,
    .named = true,
  },
  [sym_option_key_value] = {
    .visible = true,
    .named = true,
  },
  [sym_comment] = {
    .visible = true,
    .named = true,
  },
  [aux_sym_file_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_network_list_entry_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_port_list_repeat1] = {
    .visible = false,
    .named = false,
  },
  [aux_sym_option_repeat1] = {
    .visible = false,
    .named = false,
  },
};

static const TSSymbol ts_alias_sequences[PRODUCTION_ID_COUNT][MAX_ALIAS_SEQUENCE_LENGTH] = {
  [0] = {0},
};

static const uint16_t ts_non_terminal_alias_map[] = {
  0,
};

static const TSStateId ts_primary_state_ids[STATE_COUNT] = {
  [0] = 0,
  [1] = 1,
  [2] = 2,
  [3] = 3,
  [4] = 4,
  [5] = 5,
  [6] = 6,
  [7] = 7,
  [8] = 8,
  [9] = 9,
  [10] = 10,
  [11] = 11,
  [12] = 12,
  [13] = 13,
  [14] = 14,
  [15] = 15,
  [16] = 16,
  [17] = 17,
  [18] = 18,
  [19] = 19,
  [20] = 20,
  [21] = 21,
  [22] = 22,
  [23] = 23,
  [24] = 24,
  [25] = 25,
  [26] = 26,
  [27] = 27,
  [28] = 28,
  [29] = 29,
  [30] = 30,
  [31] = 31,
  [32] = 32,
  [33] = 33,
  [34] = 34,
  [35] = 35,
  [36] = 36,
  [37] = 37,
  [38] = 38,
  [39] = 39,
  [40] = 40,
  [41] = 41,
  [42] = 42,
  [43] = 43,
  [44] = 44,
  [45] = 45,
  [46] = 46,
  [47] = 47,
  [48] = 48,
  [49] = 49,
  [50] = 50,
  [51] = 51,
  [52] = 52,
  [53] = 53,
  [54] = 54,
  [55] = 55,
  [56] = 56,
  [57] = 57,
  [58] = 58,
  [59] = 59,
  [60] = 60,
  [61] = 61,
  [62] = 62,
  [63] = 63,
  [64] = 64,
  [65] = 65,
  [66] = 66,
  [67] = 67,
  [68] = 68,
  [69] = 69,
  [70] = 70,
  [71] = 71,
  [72] = 72,
  [73] = 73,
  [74] = 74,
  [75] = 75,
  [76] = 76,
  [77] = 77,
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(91);
      if (lookahead == '!') ADVANCE(133);
      if (lookahead == '#') ADVANCE(157);
      if (lookahead == '$') ADVANCE(149);
      if (lookahead == '(') ADVANCE(151);
      if (lookahead == ')') ADVANCE(152);
      if (lookahead == ',') ADVANCE(142);
      if (lookahead == '-') ADVANCE(8);
      if (lookahead == '.') ADVANCE(134);
      if (lookahead == '/') ADVANCE(132);
      if (lookahead == ':') ADVANCE(148);
      if (lookahead == ';') ADVANCE(153);
      if (lookahead == '<') ADVANCE(9);
      if (lookahead == '[') ADVANCE(140);
      if (lookahead == ']') ADVANCE(141);
      if (lookahead == 'a') ADVANCE(38);
      if (lookahead == 'd') ADVANCE(22);
      if (lookahead == 'e') ADVANCE(42);
      if (lookahead == 'f') ADVANCE(74);
      if (lookahead == 'h') ADVANCE(84);
      if (lookahead == 'i') ADVANCE(16);
      if (lookahead == 'k') ADVANCE(63);
      if (lookahead == 'm') ADVANCE(43);
      if (lookahead == 'n') ADVANCE(31);
      if (lookahead == 'p') ADVANCE(10);
      if (lookahead == 'r') ADVANCE(23);
      if (lookahead == 's') ADVANCE(35);
      if (lookahead == 't') ADVANCE(19);
      if (lookahead == 'u') ADVANCE(26);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(137);
      END_STATE();
    case 1:
      if (lookahead == '!') ADVANCE(133);
      if (lookahead == '$') ADVANCE(149);
      if (lookahead == '(') ADVANCE(151);
      if (lookahead == ',') ADVANCE(142);
      if (lookahead == '-') ADVANCE(8);
      if (lookahead == '/') ADVANCE(132);
      if (lookahead == '<') ADVANCE(9);
      if (lookahead == '[') ADVANCE(140);
      if (lookahead == ']') ADVANCE(141);
      if (lookahead == 'a') ADVANCE(41);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(1)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(147);
      END_STATE();
    case 2:
      if (lookahead == '!') ADVANCE(133);
      if (lookahead == '$') ADVANCE(149);
      if (lookahead == '[') ADVANCE(140);
      if (lookahead == 'a') ADVANCE(41);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(2)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(137);
      END_STATE();
    case 3:
      if (lookahead == ')') ADVANCE(152);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      if (lookahead == '-' ||
          lookahead == '.' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(154);
      END_STATE();
    case 4:
      if (lookahead == '2') ADVANCE(110);
      END_STATE();
    case 5:
      if (lookahead == '3') ADVANCE(103);
      END_STATE();
    case 6:
      if (lookahead == '5') ADVANCE(114);
      END_STATE();
    case 7:
      if (lookahead == '6') ADVANCE(113);
      END_STATE();
    case 8:
      if (lookahead == '>') ADVANCE(92);
      END_STATE();
    case 9:
      if (lookahead == '>') ADVANCE(93);
      END_STATE();
    case 10:
      if (lookahead == 'a') ADVANCE(72);
      if (lookahead == 'k') ADVANCE(79);
      END_STATE();
    case 11:
      if (lookahead == 'a') ADVANCE(58);
      END_STATE();
    case 12:
      if (lookahead == 'b') ADVANCE(6);
      END_STATE();
    case 13:
      if (lookahead == 'b') ADVANCE(121);
      END_STATE();
    case 14:
      if (lookahead == 'b') ADVANCE(123);
      if (lookahead == 't') ADVANCE(59);
      END_STATE();
    case 15:
      if (lookahead == 'b') ADVANCE(85);
      END_STATE();
    case 16:
      if (lookahead == 'c') ADVANCE(39);
      if (lookahead == 'k') ADVANCE(27);
      if (lookahead == 'm') ADVANCE(11);
      if (lookahead == 'p') ADVANCE(112);
      END_STATE();
    case 17:
      if (lookahead == 'c') ADVANCE(101);
      END_STATE();
    case 18:
      if (lookahead == 'c') ADVANCE(100);
      END_STATE();
    case 19:
      if (lookahead == 'c') ADVANCE(51);
      if (lookahead == 'f') ADVANCE(83);
      if (lookahead == 'l') ADVANCE(69);
      END_STATE();
    case 20:
      if (lookahead == 'c') ADVANCE(77);
      END_STATE();
    case 21:
      if (lookahead == 'c') ADVANCE(53);
      END_STATE();
    case 22:
      if (lookahead == 'c') ADVANCE(30);
      if (lookahead == 'h') ADVANCE(21);
      if (lookahead == 'n') ADVANCE(46);
      if (lookahead == 'r') ADVANCE(45);
      END_STATE();
    case 23:
      if (lookahead == 'd') ADVANCE(49);
      if (lookahead == 'e') ADVANCE(37);
      if (lookahead == 'f') ADVANCE(13);
      END_STATE();
    case 24:
      if (lookahead == 'd') ADVANCE(15);
      END_STATE();
    case 25:
      if (lookahead == 'd') ADVANCE(64);
      END_STATE();
    case 26:
      if (lookahead == 'd') ADVANCE(52);
      END_STATE();
    case 27:
      if (lookahead == 'e') ADVANCE(86);
      END_STATE();
    case 28:
      if (lookahead == 'e') ADVANCE(66);
      END_STATE();
    case 29:
      if (lookahead == 'e') ADVANCE(20);
      END_STATE();
    case 30:
      if (lookahead == 'e') ADVANCE(67);
      END_STATE();
    case 31:
      if (lookahead == 'f') ADVANCE(68);
      if (lookahead == 't') ADVANCE(48);
      END_STATE();
    case 32:
      if (lookahead == 'h') ADVANCE(126);
      END_STATE();
    case 33:
      if (lookahead == 'h') ADVANCE(98);
      END_STATE();
    case 34:
      if (lookahead == 'h') ADVANCE(25);
      END_STATE();
    case 35:
      if (lookahead == 'i') ADVANCE(50);
      if (lookahead == 'm') ADVANCE(14);
      if (lookahead == 'n') ADVANCE(40);
      if (lookahead == 's') ADVANCE(32);
      END_STATE();
    case 36:
      if (lookahead == 'i') ADVANCE(55);
      END_STATE();
    case 37:
      if (lookahead == 'j') ADVANCE(29);
      END_STATE();
    case 38:
      if (lookahead == 'l') ADVANCE(28);
      if (lookahead == 'n') ADVANCE(87);
      END_STATE();
    case 39:
      if (lookahead == 'm') ADVANCE(57);
      END_STATE();
    case 40:
      if (lookahead == 'm') ADVANCE(60);
      END_STATE();
    case 41:
      if (lookahead == 'n') ADVANCE(87);
      END_STATE();
    case 42:
      if (lookahead == 'n') ADVANCE(36);
      END_STATE();
    case 43:
      if (lookahead == 'o') ADVANCE(24);
      if (lookahead == 'q') ADVANCE(81);
      END_STATE();
    case 44:
      if (lookahead == 'o') ADVANCE(80);
      END_STATE();
    case 45:
      if (lookahead == 'o') ADVANCE(54);
      END_STATE();
    case 46:
      if (lookahead == 'p') ADVANCE(5);
      if (lookahead == 's') ADVANCE(104);
      END_STATE();
    case 47:
      if (lookahead == 'p') ADVANCE(106);
      END_STATE();
    case 48:
      if (lookahead == 'p') ADVANCE(118);
      END_STATE();
    case 49:
      if (lookahead == 'p') ADVANCE(120);
      END_STATE();
    case 50:
      if (lookahead == 'p') ADVANCE(122);
      END_STATE();
    case 51:
      if (lookahead == 'p') ADVANCE(127);
      END_STATE();
    case 52:
      if (lookahead == 'p') ADVANCE(130);
      END_STATE();
    case 53:
      if (lookahead == 'p') ADVANCE(102);
      END_STATE();
    case 54:
      if (lookahead == 'p') ADVANCE(95);
      END_STATE();
    case 55:
      if (lookahead == 'p') ADVANCE(105);
      END_STATE();
    case 56:
      if (lookahead == 'p') ADVANCE(107);
      END_STATE();
    case 57:
      if (lookahead == 'p') ADVANCE(109);
      END_STATE();
    case 58:
      if (lookahead == 'p') ADVANCE(111);
      END_STATE();
    case 59:
      if (lookahead == 'p') ADVANCE(124);
      END_STATE();
    case 60:
      if (lookahead == 'p') ADVANCE(125);
      END_STATE();
    case 61:
      if (lookahead == 'p') ADVANCE(128);
      END_STATE();
    case 62:
      if (lookahead == 'p') ADVANCE(17);
      END_STATE();
    case 63:
      if (lookahead == 'r') ADVANCE(12);
      END_STATE();
    case 64:
      if (lookahead == 'r') ADVANCE(119);
      END_STATE();
    case 65:
      if (lookahead == 'r') ADVANCE(18);
      END_STATE();
    case 66:
      if (lookahead == 'r') ADVANCE(76);
      END_STATE();
    case 67:
      if (lookahead == 'r') ADVANCE(62);
      END_STATE();
    case 68:
      if (lookahead == 's') ADVANCE(117);
      END_STATE();
    case 69:
      if (lookahead == 's') ADVANCE(129);
      END_STATE();
    case 70:
      if (lookahead == 's') ADVANCE(96);
      END_STATE();
    case 71:
      if (lookahead == 's') ADVANCE(116);
      END_STATE();
    case 72:
      if (lookahead == 's') ADVANCE(70);
      END_STATE();
    case 73:
      if (lookahead == 's') ADVANCE(78);
      END_STATE();
    case 74:
      if (lookahead == 't') ADVANCE(47);
      END_STATE();
    case 75:
      if (lookahead == 't') ADVANCE(115);
      END_STATE();
    case 76:
      if (lookahead == 't') ADVANCE(94);
      END_STATE();
    case 77:
      if (lookahead == 't') ADVANCE(97);
      END_STATE();
    case 78:
      if (lookahead == 't') ADVANCE(99);
      END_STATE();
    case 79:
      if (lookahead == 't') ADVANCE(34);
      END_STATE();
    case 80:
      if (lookahead == 't') ADVANCE(33);
      END_STATE();
    case 81:
      if (lookahead == 't') ADVANCE(75);
      END_STATE();
    case 82:
      if (lookahead == 't') ADVANCE(56);
      END_STATE();
    case 83:
      if (lookahead == 't') ADVANCE(61);
      END_STATE();
    case 84:
      if (lookahead == 't') ADVANCE(82);
      END_STATE();
    case 85:
      if (lookahead == 'u') ADVANCE(71);
      END_STATE();
    case 86:
      if (lookahead == 'v') ADVANCE(4);
      END_STATE();
    case 87:
      if (lookahead == 'y') ADVANCE(131);
      END_STATE();
    case 88:
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(88)
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(150);
      END_STATE();
    case 89:
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') ADVANCE(155);
      if (lookahead != 0 &&
          lookahead != ';') ADVANCE(156);
      END_STATE();
    case 90:
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(90)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(139);
      END_STATE();
    case 91:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 92:
      ACCEPT_TOKEN(anon_sym_DASH_GT);
      END_STATE();
    case 93:
      ACCEPT_TOKEN(anon_sym_LT_GT);
      END_STATE();
    case 94:
      ACCEPT_TOKEN(anon_sym_alert);
      END_STATE();
    case 95:
      ACCEPT_TOKEN(anon_sym_drop);
      END_STATE();
    case 96:
      ACCEPT_TOKEN(anon_sym_pass);
      END_STATE();
    case 97:
      ACCEPT_TOKEN(anon_sym_reject);
      if (lookahead == 'b') ADVANCE(44);
      if (lookahead == 'd') ADVANCE(73);
      if (lookahead == 's') ADVANCE(65);
      END_STATE();
    case 98:
      ACCEPT_TOKEN(anon_sym_rejectboth);
      END_STATE();
    case 99:
      ACCEPT_TOKEN(anon_sym_rejectdst);
      END_STATE();
    case 100:
      ACCEPT_TOKEN(anon_sym_rejectsrc);
      END_STATE();
    case 101:
      ACCEPT_TOKEN(anon_sym_dcerpc);
      END_STATE();
    case 102:
      ACCEPT_TOKEN(anon_sym_dhcp);
      END_STATE();
    case 103:
      ACCEPT_TOKEN(anon_sym_dnp3);
      END_STATE();
    case 104:
      ACCEPT_TOKEN(anon_sym_dns);
      END_STATE();
    case 105:
      ACCEPT_TOKEN(anon_sym_enip);
      END_STATE();
    case 106:
      ACCEPT_TOKEN(anon_sym_ftp);
      END_STATE();
    case 107:
      ACCEPT_TOKEN(anon_sym_http);
      if (lookahead == '2') ADVANCE(108);
      END_STATE();
    case 108:
      ACCEPT_TOKEN(anon_sym_http2);
      END_STATE();
    case 109:
      ACCEPT_TOKEN(anon_sym_icmp);
      END_STATE();
    case 110:
      ACCEPT_TOKEN(anon_sym_ikev2);
      END_STATE();
    case 111:
      ACCEPT_TOKEN(anon_sym_imap);
      END_STATE();
    case 112:
      ACCEPT_TOKEN(anon_sym_ip);
      if (lookahead == 'v') ADVANCE(7);
      END_STATE();
    case 113:
      ACCEPT_TOKEN(anon_sym_ipv6);
      END_STATE();
    case 114:
      ACCEPT_TOKEN(anon_sym_krb5);
      END_STATE();
    case 115:
      ACCEPT_TOKEN(anon_sym_mqtt);
      END_STATE();
    case 116:
      ACCEPT_TOKEN(anon_sym_modbus);
      END_STATE();
    case 117:
      ACCEPT_TOKEN(anon_sym_nfs);
      END_STATE();
    case 118:
      ACCEPT_TOKEN(anon_sym_ntp);
      END_STATE();
    case 119:
      ACCEPT_TOKEN(anon_sym_pkthdr);
      END_STATE();
    case 120:
      ACCEPT_TOKEN(anon_sym_rdp);
      END_STATE();
    case 121:
      ACCEPT_TOKEN(anon_sym_rfb);
      END_STATE();
    case 122:
      ACCEPT_TOKEN(anon_sym_sip);
      END_STATE();
    case 123:
      ACCEPT_TOKEN(anon_sym_smb);
      END_STATE();
    case 124:
      ACCEPT_TOKEN(anon_sym_smtp);
      END_STATE();
    case 125:
      ACCEPT_TOKEN(anon_sym_snmp);
      END_STATE();
    case 126:
      ACCEPT_TOKEN(anon_sym_ssh);
      END_STATE();
    case 127:
      ACCEPT_TOKEN(anon_sym_tcp);
      END_STATE();
    case 128:
      ACCEPT_TOKEN(anon_sym_tftp);
      END_STATE();
    case 129:
      ACCEPT_TOKEN(anon_sym_tls);
      END_STATE();
    case 130:
      ACCEPT_TOKEN(anon_sym_udp);
      END_STATE();
    case 131:
      ACCEPT_TOKEN(anon_sym_any);
      END_STATE();
    case 132:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 133:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 134:
      ACCEPT_TOKEN(anon_sym_DOT);
      END_STATE();
    case 135:
      ACCEPT_TOKEN(sym_network_octet);
      END_STATE();
    case 136:
      ACCEPT_TOKEN(sym_network_octet);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(135);
      END_STATE();
    case 137:
      ACCEPT_TOKEN(sym_network_octet);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(136);
      END_STATE();
    case 138:
      ACCEPT_TOKEN(sym_network_subnet_mask);
      END_STATE();
    case 139:
      ACCEPT_TOKEN(sym_network_subnet_mask);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(138);
      END_STATE();
    case 140:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      END_STATE();
    case 141:
      ACCEPT_TOKEN(anon_sym_RBRACK);
      END_STATE();
    case 142:
      ACCEPT_TOKEN(anon_sym_COMMA);
      END_STATE();
    case 143:
      ACCEPT_TOKEN(sym_port_single);
      END_STATE();
    case 144:
      ACCEPT_TOKEN(sym_port_single);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(143);
      END_STATE();
    case 145:
      ACCEPT_TOKEN(sym_port_single);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(144);
      END_STATE();
    case 146:
      ACCEPT_TOKEN(sym_port_single);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(145);
      END_STATE();
    case 147:
      ACCEPT_TOKEN(sym_port_single);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(146);
      END_STATE();
    case 148:
      ACCEPT_TOKEN(anon_sym_COLON);
      END_STATE();
    case 149:
      ACCEPT_TOKEN(anon_sym_DOLLAR);
      END_STATE();
    case 150:
      ACCEPT_TOKEN(aux_sym_variable_token1);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(150);
      END_STATE();
    case 151:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 152:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 153:
      ACCEPT_TOKEN(anon_sym_SEMI);
      END_STATE();
    case 154:
      ACCEPT_TOKEN(sym_option_key);
      if (lookahead == '-' ||
          lookahead == '.' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(154);
      END_STATE();
    case 155:
      ACCEPT_TOKEN(sym_option_value);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') ADVANCE(155);
      if (lookahead != 0 &&
          lookahead != ';') ADVANCE(156);
      END_STATE();
    case 156:
      ACCEPT_TOKEN(sym_option_value);
      if (lookahead != 0 &&
          lookahead != ';') ADVANCE(156);
      END_STATE();
    case 157:
      ACCEPT_TOKEN(anon_sym_POUND);
      END_STATE();
    case 158:
      ACCEPT_TOKEN(aux_sym_comment_token1);
      if (lookahead == '\t' ||
          lookahead == '\r' ||
          lookahead == ' ') ADVANCE(158);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(159);
      END_STATE();
    case 159:
      ACCEPT_TOKEN(aux_sym_comment_token1);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(159);
      END_STATE();
    default:
      return false;
  }
}

static const TSLexMode ts_lex_modes[STATE_COUNT] = {
  [0] = {.lex_state = 0},
  [1] = {.lex_state = 0},
  [2] = {.lex_state = 0},
  [3] = {.lex_state = 0},
  [4] = {.lex_state = 0},
  [5] = {.lex_state = 0},
  [6] = {.lex_state = 1},
  [7] = {.lex_state = 2},
  [8] = {.lex_state = 1},
  [9] = {.lex_state = 1},
  [10] = {.lex_state = 2},
  [11] = {.lex_state = 0},
  [12] = {.lex_state = 0},
  [13] = {.lex_state = 0},
  [14] = {.lex_state = 2},
  [15] = {.lex_state = 1},
  [16] = {.lex_state = 1},
  [17] = {.lex_state = 2},
  [18] = {.lex_state = 1},
  [19] = {.lex_state = 1},
  [20] = {.lex_state = 1},
  [21] = {.lex_state = 2},
  [22] = {.lex_state = 1},
  [23] = {.lex_state = 0},
  [24] = {.lex_state = 0},
  [25] = {.lex_state = 0},
  [26] = {.lex_state = 1},
  [27] = {.lex_state = 0},
  [28] = {.lex_state = 1},
  [29] = {.lex_state = 1},
  [30] = {.lex_state = 1},
  [31] = {.lex_state = 2},
  [32] = {.lex_state = 0},
  [33] = {.lex_state = 2},
  [34] = {.lex_state = 1},
  [35] = {.lex_state = 3},
  [36] = {.lex_state = 3},
  [37] = {.lex_state = 3},
  [38] = {.lex_state = 0},
  [39] = {.lex_state = 0},
  [40] = {.lex_state = 1},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 0},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 0},
  [46] = {.lex_state = 0},
  [47] = {.lex_state = 0},
  [48] = {.lex_state = 0},
  [49] = {.lex_state = 3},
  [50] = {.lex_state = 0},
  [51] = {.lex_state = 0},
  [52] = {.lex_state = 0},
  [53] = {.lex_state = 2},
  [54] = {.lex_state = 0},
  [55] = {.lex_state = 158},
  [56] = {.lex_state = 2},
  [57] = {.lex_state = 0},
  [58] = {.lex_state = 88},
  [59] = {.lex_state = 0},
  [60] = {.lex_state = 2},
  [61] = {.lex_state = 0},
  [62] = {.lex_state = 0},
  [63] = {.lex_state = 2},
  [64] = {.lex_state = 0},
  [65] = {.lex_state = 0},
  [66] = {.lex_state = 2},
  [67] = {.lex_state = 2},
  [68] = {.lex_state = 2},
  [69] = {.lex_state = 0},
  [70] = {.lex_state = 0},
  [71] = {.lex_state = 0},
  [72] = {.lex_state = 0},
  [73] = {.lex_state = 89},
  [74] = {.lex_state = 0},
  [75] = {.lex_state = 2},
  [76] = {.lex_state = 90},
  [77] = {.lex_state = 0},
};

static const uint16_t ts_parse_table[LARGE_STATE_COUNT][SYMBOL_COUNT] = {
  [0] = {
    [ts_builtin_sym_end] = ACTIONS(1),
    [anon_sym_DASH_GT] = ACTIONS(1),
    [anon_sym_LT_GT] = ACTIONS(1),
    [anon_sym_alert] = ACTIONS(1),
    [anon_sym_drop] = ACTIONS(1),
    [anon_sym_pass] = ACTIONS(1),
    [anon_sym_reject] = ACTIONS(1),
    [anon_sym_rejectboth] = ACTIONS(1),
    [anon_sym_rejectdst] = ACTIONS(1),
    [anon_sym_rejectsrc] = ACTIONS(1),
    [anon_sym_dcerpc] = ACTIONS(1),
    [anon_sym_dhcp] = ACTIONS(1),
    [anon_sym_dnp3] = ACTIONS(1),
    [anon_sym_dns] = ACTIONS(1),
    [anon_sym_enip] = ACTIONS(1),
    [anon_sym_ftp] = ACTIONS(1),
    [anon_sym_http] = ACTIONS(1),
    [anon_sym_http2] = ACTIONS(1),
    [anon_sym_icmp] = ACTIONS(1),
    [anon_sym_ikev2] = ACTIONS(1),
    [anon_sym_imap] = ACTIONS(1),
    [anon_sym_ip] = ACTIONS(1),
    [anon_sym_ipv6] = ACTIONS(1),
    [anon_sym_krb5] = ACTIONS(1),
    [anon_sym_mqtt] = ACTIONS(1),
    [anon_sym_modbus] = ACTIONS(1),
    [anon_sym_nfs] = ACTIONS(1),
    [anon_sym_ntp] = ACTIONS(1),
    [anon_sym_pkthdr] = ACTIONS(1),
    [anon_sym_rdp] = ACTIONS(1),
    [anon_sym_rfb] = ACTIONS(1),
    [anon_sym_sip] = ACTIONS(1),
    [anon_sym_smb] = ACTIONS(1),
    [anon_sym_smtp] = ACTIONS(1),
    [anon_sym_snmp] = ACTIONS(1),
    [anon_sym_ssh] = ACTIONS(1),
    [anon_sym_tcp] = ACTIONS(1),
    [anon_sym_tftp] = ACTIONS(1),
    [anon_sym_tls] = ACTIONS(1),
    [anon_sym_udp] = ACTIONS(1),
    [anon_sym_any] = ACTIONS(1),
    [anon_sym_SLASH] = ACTIONS(1),
    [anon_sym_BANG] = ACTIONS(1),
    [anon_sym_DOT] = ACTIONS(1),
    [sym_network_octet] = ACTIONS(1),
    [sym_network_subnet_mask] = ACTIONS(1),
    [anon_sym_LBRACK] = ACTIONS(1),
    [anon_sym_RBRACK] = ACTIONS(1),
    [anon_sym_COMMA] = ACTIONS(1),
    [anon_sym_COLON] = ACTIONS(1),
    [anon_sym_DOLLAR] = ACTIONS(1),
    [anon_sym_LPAREN] = ACTIONS(1),
    [anon_sym_RPAREN] = ACTIONS(1),
    [anon_sym_SEMI] = ACTIONS(1),
    [anon_sym_POUND] = ACTIONS(1),
  },
  [1] = {
    [sym_file] = STATE(74),
    [sym_rule] = STATE(4),
    [sym_action] = STATE(2),
    [sym_comment] = STATE(4),
    [aux_sym_file_repeat1] = STATE(4),
    [ts_builtin_sym_end] = ACTIONS(3),
    [anon_sym_alert] = ACTIONS(5),
    [anon_sym_drop] = ACTIONS(5),
    [anon_sym_pass] = ACTIONS(5),
    [anon_sym_reject] = ACTIONS(7),
    [anon_sym_rejectboth] = ACTIONS(5),
    [anon_sym_rejectdst] = ACTIONS(5),
    [anon_sym_rejectsrc] = ACTIONS(5),
    [anon_sym_POUND] = ACTIONS(9),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 3,
    STATE(10), 1,
      sym_protocol,
    ACTIONS(13), 2,
      anon_sym_http,
      anon_sym_ip,
    ACTIONS(11), 28,
      anon_sym_dcerpc,
      anon_sym_dhcp,
      anon_sym_dnp3,
      anon_sym_dns,
      anon_sym_enip,
      anon_sym_ftp,
      anon_sym_http2,
      anon_sym_icmp,
      anon_sym_ikev2,
      anon_sym_imap,
      anon_sym_ipv6,
      anon_sym_krb5,
      anon_sym_mqtt,
      anon_sym_modbus,
      anon_sym_nfs,
      anon_sym_ntp,
      anon_sym_pkthdr,
      anon_sym_rdp,
      anon_sym_rfb,
      anon_sym_sip,
      anon_sym_smb,
      anon_sym_smtp,
      anon_sym_snmp,
      anon_sym_ssh,
      anon_sym_tcp,
      anon_sym_tftp,
      anon_sym_tls,
      anon_sym_udp,
  [38] = 2,
    ACTIONS(17), 2,
      anon_sym_http,
      anon_sym_ip,
    ACTIONS(15), 28,
      anon_sym_dcerpc,
      anon_sym_dhcp,
      anon_sym_dnp3,
      anon_sym_dns,
      anon_sym_enip,
      anon_sym_ftp,
      anon_sym_http2,
      anon_sym_icmp,
      anon_sym_ikev2,
      anon_sym_imap,
      anon_sym_ipv6,
      anon_sym_krb5,
      anon_sym_mqtt,
      anon_sym_modbus,
      anon_sym_nfs,
      anon_sym_ntp,
      anon_sym_pkthdr,
      anon_sym_rdp,
      anon_sym_rfb,
      anon_sym_sip,
      anon_sym_smb,
      anon_sym_smtp,
      anon_sym_snmp,
      anon_sym_ssh,
      anon_sym_tcp,
      anon_sym_tftp,
      anon_sym_tls,
      anon_sym_udp,
  [73] = 6,
    ACTIONS(7), 1,
      anon_sym_reject,
    ACTIONS(9), 1,
      anon_sym_POUND,
    ACTIONS(19), 1,
      ts_builtin_sym_end,
    STATE(2), 1,
      sym_action,
    STATE(5), 3,
      sym_rule,
      sym_comment,
      aux_sym_file_repeat1,
    ACTIONS(5), 6,
      anon_sym_alert,
      anon_sym_drop,
      anon_sym_pass,
      anon_sym_rejectboth,
      anon_sym_rejectdst,
      anon_sym_rejectsrc,
  [99] = 6,
    ACTIONS(21), 1,
      ts_builtin_sym_end,
    ACTIONS(26), 1,
      anon_sym_reject,
    ACTIONS(29), 1,
      anon_sym_POUND,
    STATE(2), 1,
      sym_action,
    STATE(5), 3,
      sym_rule,
      sym_comment,
      aux_sym_file_repeat1,
    ACTIONS(23), 6,
      anon_sym_alert,
      anon_sym_drop,
      anon_sym_pass,
      anon_sym_rejectboth,
      anon_sym_rejectdst,
      anon_sym_rejectsrc,
  [125] = 1,
    ACTIONS(32), 10,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
      anon_sym_LPAREN,
  [138] = 9,
    ACTIONS(34), 1,
      anon_sym_any,
    ACTIONS(36), 1,
      anon_sym_BANG,
    ACTIONS(38), 1,
      sym_network_octet,
    ACTIONS(40), 1,
      anon_sym_LBRACK,
    ACTIONS(42), 1,
      anon_sym_DOLLAR,
    STATE(9), 1,
      sym_network,
    STATE(16), 1,
      sym_network_cidr,
    STATE(19), 1,
      sym_variable,
    STATE(30), 2,
      sym_network_ip,
      sym_network_list,
  [167] = 8,
    ACTIONS(42), 1,
      anon_sym_DOLLAR,
    ACTIONS(44), 1,
      anon_sym_any,
    ACTIONS(46), 1,
      anon_sym_BANG,
    ACTIONS(48), 1,
      anon_sym_LBRACK,
    ACTIONS(50), 1,
      sym_port_single,
    STATE(27), 1,
      sym_port_range,
    STATE(46), 1,
      sym_port,
    STATE(44), 3,
      sym_port_list,
      sym_port_spec,
      sym_variable,
  [194] = 8,
    ACTIONS(42), 1,
      anon_sym_DOLLAR,
    ACTIONS(44), 1,
      anon_sym_any,
    ACTIONS(46), 1,
      anon_sym_BANG,
    ACTIONS(48), 1,
      anon_sym_LBRACK,
    ACTIONS(50), 1,
      sym_port_single,
    STATE(27), 1,
      sym_port_range,
    STATE(50), 1,
      sym_port,
    STATE(44), 3,
      sym_port_list,
      sym_port_spec,
      sym_variable,
  [221] = 9,
    ACTIONS(34), 1,
      anon_sym_any,
    ACTIONS(36), 1,
      anon_sym_BANG,
    ACTIONS(38), 1,
      sym_network_octet,
    ACTIONS(40), 1,
      anon_sym_LBRACK,
    ACTIONS(42), 1,
      anon_sym_DOLLAR,
    STATE(8), 1,
      sym_network,
    STATE(16), 1,
      sym_network_cidr,
    STATE(19), 1,
      sym_variable,
    STATE(30), 2,
      sym_network_ip,
      sym_network_list,
  [250] = 2,
    ACTIONS(54), 1,
      anon_sym_reject,
    ACTIONS(52), 8,
      ts_builtin_sym_end,
      anon_sym_alert,
      anon_sym_drop,
      anon_sym_pass,
      anon_sym_rejectboth,
      anon_sym_rejectdst,
      anon_sym_rejectsrc,
      anon_sym_POUND,
  [264] = 2,
    ACTIONS(58), 1,
      anon_sym_reject,
    ACTIONS(56), 8,
      ts_builtin_sym_end,
      anon_sym_alert,
      anon_sym_drop,
      anon_sym_pass,
      anon_sym_rejectboth,
      anon_sym_rejectdst,
      anon_sym_rejectsrc,
      anon_sym_POUND,
  [278] = 2,
    ACTIONS(62), 1,
      anon_sym_reject,
    ACTIONS(60), 8,
      ts_builtin_sym_end,
      anon_sym_alert,
      anon_sym_drop,
      anon_sym_pass,
      anon_sym_rejectboth,
      anon_sym_rejectdst,
      anon_sym_rejectsrc,
      anon_sym_POUND,
  [292] = 8,
    ACTIONS(34), 1,
      anon_sym_any,
    ACTIONS(38), 1,
      sym_network_octet,
    ACTIONS(42), 1,
      anon_sym_DOLLAR,
    ACTIONS(64), 1,
      anon_sym_BANG,
    STATE(16), 1,
      sym_network_cidr,
    STATE(19), 1,
      sym_variable,
    STATE(39), 1,
      sym_network_ip,
    STATE(59), 1,
      sym_network_list_entry,
  [317] = 1,
    ACTIONS(66), 8,
      anon_sym_any,
      anon_sym_SLASH,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [328] = 2,
    ACTIONS(70), 1,
      anon_sym_SLASH,
    ACTIONS(68), 7,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [341] = 8,
    ACTIONS(34), 1,
      anon_sym_any,
    ACTIONS(38), 1,
      sym_network_octet,
    ACTIONS(42), 1,
      anon_sym_DOLLAR,
    ACTIONS(64), 1,
      anon_sym_BANG,
    STATE(16), 1,
      sym_network_cidr,
    STATE(19), 1,
      sym_variable,
    STATE(39), 1,
      sym_network_ip,
    STATE(72), 1,
      sym_network_list_entry,
  [366] = 1,
    ACTIONS(72), 8,
      anon_sym_any,
      anon_sym_SLASH,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [377] = 1,
    ACTIONS(68), 7,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [387] = 1,
    ACTIONS(74), 7,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [397] = 7,
    ACTIONS(34), 1,
      anon_sym_any,
    ACTIONS(38), 1,
      sym_network_octet,
    ACTIONS(42), 1,
      anon_sym_DOLLAR,
    ACTIONS(64), 1,
      anon_sym_BANG,
    STATE(16), 1,
      sym_network_cidr,
    STATE(19), 1,
      sym_variable,
    STATE(51), 1,
      sym_network_ip,
  [419] = 2,
    ACTIONS(78), 1,
      sym_port_single,
    ACTIONS(76), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [430] = 2,
    ACTIONS(82), 1,
      anon_sym_COLON,
    ACTIONS(80), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [441] = 2,
    ACTIONS(82), 1,
      anon_sym_COLON,
    ACTIONS(84), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [452] = 1,
    ACTIONS(80), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [460] = 1,
    ACTIONS(86), 5,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      sym_port_single,
      anon_sym_DOLLAR,
  [468] = 1,
    ACTIONS(84), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [476] = 1,
    ACTIONS(88), 5,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      sym_port_single,
      anon_sym_DOLLAR,
  [484] = 5,
    ACTIONS(44), 1,
      anon_sym_any,
    ACTIONS(46), 1,
      anon_sym_BANG,
    ACTIONS(50), 1,
      sym_port_single,
    STATE(27), 1,
      sym_port_range,
    STATE(41), 1,
      sym_port_spec,
  [500] = 1,
    ACTIONS(90), 5,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      sym_port_single,
      anon_sym_DOLLAR,
  [508] = 1,
    ACTIONS(92), 5,
      anon_sym_any,
      anon_sym_BANG,
      sym_network_octet,
      anon_sym_LBRACK,
      anon_sym_DOLLAR,
  [516] = 1,
    ACTIONS(94), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [524] = 1,
    ACTIONS(96), 5,
      anon_sym_any,
      anon_sym_BANG,
      sym_network_octet,
      anon_sym_LBRACK,
      anon_sym_DOLLAR,
  [532] = 5,
    ACTIONS(44), 1,
      anon_sym_any,
    ACTIONS(46), 1,
      anon_sym_BANG,
    ACTIONS(50), 1,
      sym_port_single,
    STATE(27), 1,
      sym_port_range,
    STATE(52), 1,
      sym_port_spec,
  [548] = 4,
    ACTIONS(98), 1,
      anon_sym_RPAREN,
    ACTIONS(100), 1,
      sym_option_key,
    STATE(35), 1,
      aux_sym_option_repeat1,
    STATE(70), 1,
      sym_option_key_value,
  [561] = 4,
    ACTIONS(103), 1,
      anon_sym_RPAREN,
    ACTIONS(105), 1,
      sym_option_key,
    STATE(35), 1,
      aux_sym_option_repeat1,
    STATE(70), 1,
      sym_option_key_value,
  [574] = 4,
    ACTIONS(105), 1,
      sym_option_key,
    STATE(36), 1,
      aux_sym_option_repeat1,
    STATE(69), 1,
      sym_option,
    STATE(70), 1,
      sym_option_key_value,
  [587] = 3,
    ACTIONS(107), 1,
      anon_sym_RBRACK,
    ACTIONS(109), 1,
      anon_sym_COMMA,
    STATE(45), 1,
      aux_sym_port_list_repeat1,
  [597] = 3,
    ACTIONS(111), 1,
      anon_sym_RBRACK,
    ACTIONS(113), 1,
      anon_sym_COMMA,
    STATE(42), 1,
      aux_sym_network_list_entry_repeat1,
  [607] = 3,
    ACTIONS(115), 1,
      anon_sym_any,
    ACTIONS(117), 1,
      sym_port_single,
    STATE(25), 1,
      sym_port_range,
  [617] = 3,
    ACTIONS(109), 1,
      anon_sym_COMMA,
    ACTIONS(119), 1,
      anon_sym_RBRACK,
    STATE(38), 1,
      aux_sym_port_list_repeat1,
  [627] = 3,
    ACTIONS(113), 1,
      anon_sym_COMMA,
    ACTIONS(121), 1,
      anon_sym_RBRACK,
    STATE(48), 1,
      aux_sym_network_list_entry_repeat1,
  [637] = 1,
    ACTIONS(123), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [643] = 1,
    ACTIONS(125), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [649] = 3,
    ACTIONS(127), 1,
      anon_sym_RBRACK,
    ACTIONS(129), 1,
      anon_sym_COMMA,
    STATE(45), 1,
      aux_sym_port_list_repeat1,
  [659] = 2,
    STATE(7), 1,
      sym_direction,
    ACTIONS(132), 2,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
  [667] = 1,
    ACTIONS(134), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [673] = 3,
    ACTIONS(136), 1,
      anon_sym_RBRACK,
    ACTIONS(138), 1,
      anon_sym_COMMA,
    STATE(48), 1,
      aux_sym_network_list_entry_repeat1,
  [683] = 1,
    ACTIONS(98), 2,
      anon_sym_RPAREN,
      sym_option_key,
  [688] = 2,
    ACTIONS(141), 1,
      anon_sym_LPAREN,
    STATE(11), 1,
      sym_options,
  [695] = 1,
    ACTIONS(136), 2,
      anon_sym_RBRACK,
      anon_sym_COMMA,
  [700] = 1,
    ACTIONS(127), 2,
      anon_sym_RBRACK,
      anon_sym_COMMA,
  [705] = 2,
    ACTIONS(143), 1,
      sym_network_octet,
    ACTIONS(145), 1,
      anon_sym_LBRACK,
  [712] = 2,
    ACTIONS(147), 1,
      anon_sym_COLON,
    ACTIONS(149), 1,
      anon_sym_SEMI,
  [719] = 1,
    ACTIONS(151), 1,
      aux_sym_comment_token1,
  [723] = 1,
    ACTIONS(153), 1,
      sym_network_octet,
  [727] = 1,
    ACTIONS(155), 1,
      anon_sym_DOT,
  [731] = 1,
    ACTIONS(157), 1,
      aux_sym_variable_token1,
  [735] = 1,
    ACTIONS(159), 1,
      anon_sym_RBRACK,
  [739] = 1,
    ACTIONS(161), 1,
      sym_network_octet,
  [743] = 1,
    ACTIONS(163), 1,
      anon_sym_DOT,
  [747] = 1,
    ACTIONS(165), 1,
      anon_sym_DOT,
  [751] = 1,
    ACTIONS(167), 1,
      sym_network_octet,
  [755] = 1,
    ACTIONS(169), 1,
      anon_sym_DOT,
  [759] = 1,
    ACTIONS(171), 1,
      anon_sym_DOT,
  [763] = 1,
    ACTIONS(173), 1,
      sym_network_octet,
  [767] = 1,
    ACTIONS(175), 1,
      sym_network_octet,
  [771] = 1,
    ACTIONS(143), 1,
      sym_network_octet,
  [775] = 1,
    ACTIONS(177), 1,
      anon_sym_RPAREN,
  [779] = 1,
    ACTIONS(179), 1,
      anon_sym_SEMI,
  [783] = 1,
    ACTIONS(181), 1,
      anon_sym_DOT,
  [787] = 1,
    ACTIONS(183), 1,
      anon_sym_RBRACK,
  [791] = 1,
    ACTIONS(185), 1,
      sym_option_value,
  [795] = 1,
    ACTIONS(187), 1,
      ts_builtin_sym_end,
  [799] = 1,
    ACTIONS(189), 1,
      sym_network_octet,
  [803] = 1,
    ACTIONS(191), 1,
      sym_network_subnet_mask,
  [807] = 1,
    ACTIONS(193), 1,
      anon_sym_SEMI,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(2)] = 0,
  [SMALL_STATE(3)] = 38,
  [SMALL_STATE(4)] = 73,
  [SMALL_STATE(5)] = 99,
  [SMALL_STATE(6)] = 125,
  [SMALL_STATE(7)] = 138,
  [SMALL_STATE(8)] = 167,
  [SMALL_STATE(9)] = 194,
  [SMALL_STATE(10)] = 221,
  [SMALL_STATE(11)] = 250,
  [SMALL_STATE(12)] = 264,
  [SMALL_STATE(13)] = 278,
  [SMALL_STATE(14)] = 292,
  [SMALL_STATE(15)] = 317,
  [SMALL_STATE(16)] = 328,
  [SMALL_STATE(17)] = 341,
  [SMALL_STATE(18)] = 366,
  [SMALL_STATE(19)] = 377,
  [SMALL_STATE(20)] = 387,
  [SMALL_STATE(21)] = 397,
  [SMALL_STATE(22)] = 419,
  [SMALL_STATE(23)] = 430,
  [SMALL_STATE(24)] = 441,
  [SMALL_STATE(25)] = 452,
  [SMALL_STATE(26)] = 460,
  [SMALL_STATE(27)] = 468,
  [SMALL_STATE(28)] = 476,
  [SMALL_STATE(29)] = 484,
  [SMALL_STATE(30)] = 500,
  [SMALL_STATE(31)] = 508,
  [SMALL_STATE(32)] = 516,
  [SMALL_STATE(33)] = 524,
  [SMALL_STATE(34)] = 532,
  [SMALL_STATE(35)] = 548,
  [SMALL_STATE(36)] = 561,
  [SMALL_STATE(37)] = 574,
  [SMALL_STATE(38)] = 587,
  [SMALL_STATE(39)] = 597,
  [SMALL_STATE(40)] = 607,
  [SMALL_STATE(41)] = 617,
  [SMALL_STATE(42)] = 627,
  [SMALL_STATE(43)] = 637,
  [SMALL_STATE(44)] = 643,
  [SMALL_STATE(45)] = 649,
  [SMALL_STATE(46)] = 659,
  [SMALL_STATE(47)] = 667,
  [SMALL_STATE(48)] = 673,
  [SMALL_STATE(49)] = 683,
  [SMALL_STATE(50)] = 688,
  [SMALL_STATE(51)] = 695,
  [SMALL_STATE(52)] = 700,
  [SMALL_STATE(53)] = 705,
  [SMALL_STATE(54)] = 712,
  [SMALL_STATE(55)] = 719,
  [SMALL_STATE(56)] = 723,
  [SMALL_STATE(57)] = 727,
  [SMALL_STATE(58)] = 731,
  [SMALL_STATE(59)] = 735,
  [SMALL_STATE(60)] = 739,
  [SMALL_STATE(61)] = 743,
  [SMALL_STATE(62)] = 747,
  [SMALL_STATE(63)] = 751,
  [SMALL_STATE(64)] = 755,
  [SMALL_STATE(65)] = 759,
  [SMALL_STATE(66)] = 763,
  [SMALL_STATE(67)] = 767,
  [SMALL_STATE(68)] = 771,
  [SMALL_STATE(69)] = 775,
  [SMALL_STATE(70)] = 779,
  [SMALL_STATE(71)] = 783,
  [SMALL_STATE(72)] = 787,
  [SMALL_STATE(73)] = 791,
  [SMALL_STATE(74)] = 795,
  [SMALL_STATE(75)] = 799,
  [SMALL_STATE(76)] = 803,
  [SMALL_STATE(77)] = 807,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_file, 0),
  [5] = {.entry = {.count = 1, .reusable = true}}, SHIFT(3),
  [7] = {.entry = {.count = 1, .reusable = false}}, SHIFT(3),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [13] = {.entry = {.count = 1, .reusable = false}}, SHIFT(33),
  [15] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_action, 1),
  [17] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_action, 1),
  [19] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_file, 1),
  [21] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_file_repeat1, 2),
  [23] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_file_repeat1, 2), SHIFT_REPEAT(3),
  [26] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_file_repeat1, 2), SHIFT_REPEAT(3),
  [29] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_file_repeat1, 2), SHIFT_REPEAT(55),
  [32] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_variable, 2),
  [34] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [36] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [38] = {.entry = {.count = 1, .reusable = true}}, SHIFT(65),
  [40] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [42] = {.entry = {.count = 1, .reusable = true}}, SHIFT(58),
  [44] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [46] = {.entry = {.count = 1, .reusable = true}}, SHIFT(40),
  [48] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [50] = {.entry = {.count = 1, .reusable = true}}, SHIFT(24),
  [52] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_rule, 8),
  [54] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_rule, 8),
  [56] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_options, 3),
  [58] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_options, 3),
  [60] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_comment, 2),
  [62] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_comment, 2),
  [64] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [66] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_cidr, 7),
  [68] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_ip, 1),
  [70] = {.entry = {.count = 1, .reusable = true}}, SHIFT(76),
  [72] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_cidr, 8),
  [74] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_ip, 3),
  [76] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_range, 2),
  [78] = {.entry = {.count = 1, .reusable = true}}, SHIFT(32),
  [80] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_spec, 2),
  [82] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [84] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_spec, 1),
  [86] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list, 3),
  [88] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list, 4),
  [90] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network, 1),
  [92] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_direction, 1),
  [94] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_range, 3),
  [96] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_protocol, 1),
  [98] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_option_repeat1, 2),
  [100] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_option_repeat1, 2), SHIFT_REPEAT(54),
  [103] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_option, 1),
  [105] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [107] = {.entry = {.count = 1, .reusable = true}}, SHIFT(47),
  [109] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [111] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list_entry, 1),
  [113] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [115] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [117] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [119] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [121] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list_entry, 2),
  [123] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_list, 3),
  [125] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port, 1),
  [127] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_port_list_repeat1, 2),
  [129] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_port_list_repeat1, 2), SHIFT_REPEAT(34),
  [132] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [134] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_list, 4),
  [136] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_network_list_entry_repeat1, 2),
  [138] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_network_list_entry_repeat1, 2), SHIFT_REPEAT(21),
  [141] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [143] = {.entry = {.count = 1, .reusable = true}}, SHIFT(64),
  [145] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [147] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [149] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_option_key_value, 1),
  [151] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [153] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [155] = {.entry = {.count = 1, .reusable = true}}, SHIFT(63),
  [157] = {.entry = {.count = 1, .reusable = true}}, SHIFT(6),
  [159] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [161] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
  [163] = {.entry = {.count = 1, .reusable = true}}, SHIFT(56),
  [165] = {.entry = {.count = 1, .reusable = true}}, SHIFT(66),
  [167] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [169] = {.entry = {.count = 1, .reusable = true}}, SHIFT(75),
  [171] = {.entry = {.count = 1, .reusable = true}}, SHIFT(67),
  [173] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [175] = {.entry = {.count = 1, .reusable = true}}, SHIFT(71),
  [177] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [179] = {.entry = {.count = 1, .reusable = true}}, SHIFT(49),
  [181] = {.entry = {.count = 1, .reusable = true}}, SHIFT(60),
  [183] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [185] = {.entry = {.count = 1, .reusable = true}}, SHIFT(77),
  [187] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [189] = {.entry = {.count = 1, .reusable = true}}, SHIFT(61),
  [191] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [193] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_option_key_value, 3),
};

#ifdef __cplusplus
extern "C" {
#endif
#ifdef _WIN32
#define extern __declspec(dllexport)
#endif

extern const TSLanguage *tree_sitter_suricata(void) {
  static const TSLanguage language = {
    .version = LANGUAGE_VERSION,
    .symbol_count = SYMBOL_COUNT,
    .alias_count = ALIAS_COUNT,
    .token_count = TOKEN_COUNT,
    .external_token_count = EXTERNAL_TOKEN_COUNT,
    .state_count = STATE_COUNT,
    .large_state_count = LARGE_STATE_COUNT,
    .production_id_count = PRODUCTION_ID_COUNT,
    .field_count = FIELD_COUNT,
    .max_alias_sequence_length = MAX_ALIAS_SEQUENCE_LENGTH,
    .parse_table = &ts_parse_table[0][0],
    .small_parse_table = ts_small_parse_table,
    .small_parse_table_map = ts_small_parse_table_map,
    .parse_actions = ts_parse_actions,
    .symbol_names = ts_symbol_names,
    .symbol_metadata = ts_symbol_metadata,
    .public_symbol_map = ts_symbol_map,
    .alias_map = ts_non_terminal_alias_map,
    .alias_sequences = &ts_alias_sequences[0][0],
    .lex_modes = ts_lex_modes,
    .lex_fn = ts_lex,
    .primary_state_ids = ts_primary_state_ids,
  };
  return &language;
}
#ifdef __cplusplus
}
#endif
