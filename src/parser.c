#include <tree_sitter/parser.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#define LANGUAGE_VERSION 14
#define STATE_COUNT 74
#define LARGE_STATE_COUNT 2
#define SYMBOL_COUNT 80
#define ALIAS_COUNT 0
#define TOKEN_COUNT 57
#define EXTERNAL_TOKEN_COUNT 0
#define FIELD_COUNT 0
#define MAX_ALIAS_SEQUENCE_LENGTH 8
#define PRODUCTION_ID_COUNT 1

enum {
  anon_sym_DASH_GT = 1,
  anon_sym_LT_GT = 2,
  anon_sym_alert = 3,
  anon_sym_pass = 4,
  anon_sym_drop = 5,
  anon_sym_reject = 6,
  anon_sym_rejectsrc = 7,
  anon_sym_rejectdst = 8,
  anon_sym_rejectboth = 9,
  anon_sym_tcp = 10,
  anon_sym_udp = 11,
  anon_sym_icmp = 12,
  anon_sym_ip = 13,
  anon_sym_http = 14,
  anon_sym_ftp = 15,
  anon_sym_tls = 16,
  anon_sym_smb = 17,
  anon_sym_dns = 18,
  anon_sym_dcerpc = 19,
  anon_sym_ssh = 20,
  anon_sym_smtp = 21,
  anon_sym_imap = 22,
  anon_sym_modbus = 23,
  anon_sym_dnp3 = 24,
  anon_sym_enip = 25,
  anon_sym_nfs = 26,
  anon_sym_ikev2 = 27,
  anon_sym_krb5 = 28,
  anon_sym_ntp = 29,
  anon_sym_dhcp = 30,
  anon_sym_rfb = 31,
  anon_sym_rdp = 32,
  anon_sym_snmp = 33,
  anon_sym_tftp = 34,
  anon_sym_sip = 35,
  anon_sym_http2 = 36,
  anon_sym_any = 37,
  anon_sym_SLASH = 38,
  anon_sym_BANG = 39,
  anon_sym_DOT = 40,
  sym_network_octet = 41,
  sym_network_subnet_mask = 42,
  anon_sym_LBRACK = 43,
  anon_sym_RBRACK = 44,
  anon_sym_COMMA = 45,
  sym_port_single = 46,
  anon_sym_COLON = 47,
  anon_sym_DOLLAR = 48,
  aux_sym_variable_token1 = 49,
  anon_sym_LPAREN = 50,
  anon_sym_RPAREN = 51,
  anon_sym_SEMI = 52,
  sym_option_key = 53,
  sym_option_value = 54,
  anon_sym_POUND = 55,
  aux_sym_comment_token1 = 56,
  sym_file = 57,
  sym_rule = 58,
  sym_direction = 59,
  sym_action = 60,
  sym_protocol = 61,
  sym_network = 62,
  sym_network_ip = 63,
  sym_network_cidr = 64,
  sym_network_list = 65,
  sym_network_list_entry = 66,
  sym_port = 67,
  sym_port_list = 68,
  sym_port_spec = 69,
  sym_port_range = 70,
  sym_variable = 71,
  sym_options = 72,
  sym_option = 73,
  sym_option_key_value = 74,
  sym_comment = 75,
  aux_sym_file_repeat1 = 76,
  aux_sym_network_list_entry_repeat1 = 77,
  aux_sym_port_list_repeat1 = 78,
  aux_sym_option_repeat1 = 79,
};

static const char * const ts_symbol_names[] = {
  [ts_builtin_sym_end] = "end",
  [anon_sym_DASH_GT] = "->",
  [anon_sym_LT_GT] = "<>",
  [anon_sym_alert] = "alert",
  [anon_sym_pass] = "pass",
  [anon_sym_drop] = "drop",
  [anon_sym_reject] = "reject",
  [anon_sym_rejectsrc] = "rejectsrc",
  [anon_sym_rejectdst] = "rejectdst",
  [anon_sym_rejectboth] = "rejectboth",
  [anon_sym_tcp] = "tcp",
  [anon_sym_udp] = "udp",
  [anon_sym_icmp] = "icmp",
  [anon_sym_ip] = "ip",
  [anon_sym_http] = "http",
  [anon_sym_ftp] = "ftp",
  [anon_sym_tls] = "tls",
  [anon_sym_smb] = "smb",
  [anon_sym_dns] = "dns",
  [anon_sym_dcerpc] = "dcerpc",
  [anon_sym_ssh] = "ssh",
  [anon_sym_smtp] = "smtp",
  [anon_sym_imap] = "imap",
  [anon_sym_modbus] = "modbus",
  [anon_sym_dnp3] = "dnp3",
  [anon_sym_enip] = "enip",
  [anon_sym_nfs] = "nfs",
  [anon_sym_ikev2] = "ikev2",
  [anon_sym_krb5] = "krb5",
  [anon_sym_ntp] = "ntp",
  [anon_sym_dhcp] = "dhcp",
  [anon_sym_rfb] = "rfb",
  [anon_sym_rdp] = "rdp",
  [anon_sym_snmp] = "snmp",
  [anon_sym_tftp] = "tftp",
  [anon_sym_sip] = "sip",
  [anon_sym_http2] = "http2",
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
  [anon_sym_pass] = anon_sym_pass,
  [anon_sym_drop] = anon_sym_drop,
  [anon_sym_reject] = anon_sym_reject,
  [anon_sym_rejectsrc] = anon_sym_rejectsrc,
  [anon_sym_rejectdst] = anon_sym_rejectdst,
  [anon_sym_rejectboth] = anon_sym_rejectboth,
  [anon_sym_tcp] = anon_sym_tcp,
  [anon_sym_udp] = anon_sym_udp,
  [anon_sym_icmp] = anon_sym_icmp,
  [anon_sym_ip] = anon_sym_ip,
  [anon_sym_http] = anon_sym_http,
  [anon_sym_ftp] = anon_sym_ftp,
  [anon_sym_tls] = anon_sym_tls,
  [anon_sym_smb] = anon_sym_smb,
  [anon_sym_dns] = anon_sym_dns,
  [anon_sym_dcerpc] = anon_sym_dcerpc,
  [anon_sym_ssh] = anon_sym_ssh,
  [anon_sym_smtp] = anon_sym_smtp,
  [anon_sym_imap] = anon_sym_imap,
  [anon_sym_modbus] = anon_sym_modbus,
  [anon_sym_dnp3] = anon_sym_dnp3,
  [anon_sym_enip] = anon_sym_enip,
  [anon_sym_nfs] = anon_sym_nfs,
  [anon_sym_ikev2] = anon_sym_ikev2,
  [anon_sym_krb5] = anon_sym_krb5,
  [anon_sym_ntp] = anon_sym_ntp,
  [anon_sym_dhcp] = anon_sym_dhcp,
  [anon_sym_rfb] = anon_sym_rfb,
  [anon_sym_rdp] = anon_sym_rdp,
  [anon_sym_snmp] = anon_sym_snmp,
  [anon_sym_tftp] = anon_sym_tftp,
  [anon_sym_sip] = anon_sym_sip,
  [anon_sym_http2] = anon_sym_http2,
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
  [anon_sym_pass] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_drop] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_reject] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rejectsrc] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rejectdst] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rejectboth] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tcp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_udp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_icmp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ftp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tls] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_smb] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dns] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dcerpc] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ssh] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_smtp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_imap] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_modbus] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dnp3] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_enip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_nfs] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ikev2] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_krb5] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_ntp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_dhcp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rfb] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_rdp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_snmp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_tftp] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_sip] = {
    .visible = true,
    .named = false,
  },
  [anon_sym_http2] = {
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
};

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(82);
      if (lookahead == '!') ADVANCE(121);
      if (lookahead == '#') ADVANCE(143);
      if (lookahead == '$') ADVANCE(135);
      if (lookahead == '(') ADVANCE(137);
      if (lookahead == ')') ADVANCE(138);
      if (lookahead == ',') ADVANCE(128);
      if (lookahead == '-') ADVANCE(7);
      if (lookahead == '.') ADVANCE(122);
      if (lookahead == '/') ADVANCE(120);
      if (lookahead == ':') ADVANCE(134);
      if (lookahead == ';') ADVANCE(139);
      if (lookahead == '<') ADVANCE(8);
      if (lookahead == '[') ADVANCE(126);
      if (lookahead == ']') ADVANCE(127);
      if (lookahead == 'a') ADVANCE(35);
      if (lookahead == 'd') ADVANCE(21);
      if (lookahead == 'e') ADVANCE(39);
      if (lookahead == 'f') ADVANCE(70);
      if (lookahead == 'h') ADVANCE(77);
      if (lookahead == 'i') ADVANCE(15);
      if (lookahead == 'k') ADVANCE(60);
      if (lookahead == 'm') ADVANCE(40);
      if (lookahead == 'n') ADVANCE(29);
      if (lookahead == 'p') ADVANCE(9);
      if (lookahead == 'r') ADVANCE(22);
      if (lookahead == 's') ADVANCE(32);
      if (lookahead == 't') ADVANCE(19);
      if (lookahead == 'u') ADVANCE(24);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(0)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(123);
      END_STATE();
    case 1:
      if (lookahead == '\n') SKIP(1)
      if (lookahead == '\t' ||
          lookahead == '\r' ||
          lookahead == ' ') ADVANCE(141);
      if (lookahead != 0 &&
          lookahead != ')' &&
          lookahead != ';') ADVANCE(142);
      END_STATE();
    case 2:
      if (lookahead == '!') ADVANCE(121);
      if (lookahead == '$') ADVANCE(135);
      if (lookahead == '(') ADVANCE(137);
      if (lookahead == ',') ADVANCE(128);
      if (lookahead == '-') ADVANCE(7);
      if (lookahead == '/') ADVANCE(120);
      if (lookahead == '<') ADVANCE(8);
      if (lookahead == '[') ADVANCE(126);
      if (lookahead == ']') ADVANCE(127);
      if (lookahead == 'a') ADVANCE(38);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(2)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(133);
      END_STATE();
    case 3:
      if (lookahead == ')') ADVANCE(138);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(125);
      if (lookahead == '-' ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(140);
      END_STATE();
    case 4:
      if (lookahead == '2') ADVANCE(109);
      END_STATE();
    case 5:
      if (lookahead == '3') ADVANCE(106);
      END_STATE();
    case 6:
      if (lookahead == '5') ADVANCE(110);
      END_STATE();
    case 7:
      if (lookahead == '>') ADVANCE(83);
      END_STATE();
    case 8:
      if (lookahead == '>') ADVANCE(84);
      END_STATE();
    case 9:
      if (lookahead == 'a') ADVANCE(68);
      END_STATE();
    case 10:
      if (lookahead == 'a') ADVANCE(55);
      END_STATE();
    case 11:
      if (lookahead == 'b') ADVANCE(6);
      END_STATE();
    case 12:
      if (lookahead == 'b') ADVANCE(113);
      END_STATE();
    case 13:
      if (lookahead == 'b') ADVANCE(99);
      if (lookahead == 't') ADVANCE(56);
      END_STATE();
    case 14:
      if (lookahead == 'b') ADVANCE(78);
      END_STATE();
    case 15:
      if (lookahead == 'c') ADVANCE(36);
      if (lookahead == 'k') ADVANCE(25);
      if (lookahead == 'm') ADVANCE(10);
      if (lookahead == 'p') ADVANCE(95);
      END_STATE();
    case 16:
      if (lookahead == 'c') ADVANCE(101);
      END_STATE();
    case 17:
      if (lookahead == 'c') ADVANCE(89);
      END_STATE();
    case 18:
      if (lookahead == 'c') ADVANCE(72);
      END_STATE();
    case 19:
      if (lookahead == 'c') ADVANCE(48);
      if (lookahead == 'f') ADVANCE(76);
      if (lookahead == 'l') ADVANCE(65);
      END_STATE();
    case 20:
      if (lookahead == 'c') ADVANCE(50);
      END_STATE();
    case 21:
      if (lookahead == 'c') ADVANCE(28);
      if (lookahead == 'h') ADVANCE(20);
      if (lookahead == 'n') ADVANCE(43);
      if (lookahead == 'r') ADVANCE(42);
      END_STATE();
    case 22:
      if (lookahead == 'd') ADVANCE(46);
      if (lookahead == 'e') ADVANCE(34);
      if (lookahead == 'f') ADVANCE(12);
      END_STATE();
    case 23:
      if (lookahead == 'd') ADVANCE(14);
      END_STATE();
    case 24:
      if (lookahead == 'd') ADVANCE(49);
      END_STATE();
    case 25:
      if (lookahead == 'e') ADVANCE(79);
      END_STATE();
    case 26:
      if (lookahead == 'e') ADVANCE(61);
      END_STATE();
    case 27:
      if (lookahead == 'e') ADVANCE(18);
      END_STATE();
    case 28:
      if (lookahead == 'e') ADVANCE(63);
      END_STATE();
    case 29:
      if (lookahead == 'f') ADVANCE(64);
      if (lookahead == 't') ADVANCE(45);
      END_STATE();
    case 30:
      if (lookahead == 'h') ADVANCE(102);
      END_STATE();
    case 31:
      if (lookahead == 'h') ADVANCE(91);
      END_STATE();
    case 32:
      if (lookahead == 'i') ADVANCE(47);
      if (lookahead == 'm') ADVANCE(13);
      if (lookahead == 'n') ADVANCE(37);
      if (lookahead == 's') ADVANCE(30);
      END_STATE();
    case 33:
      if (lookahead == 'i') ADVANCE(52);
      END_STATE();
    case 34:
      if (lookahead == 'j') ADVANCE(27);
      END_STATE();
    case 35:
      if (lookahead == 'l') ADVANCE(26);
      if (lookahead == 'n') ADVANCE(80);
      END_STATE();
    case 36:
      if (lookahead == 'm') ADVANCE(54);
      END_STATE();
    case 37:
      if (lookahead == 'm') ADVANCE(57);
      END_STATE();
    case 38:
      if (lookahead == 'n') ADVANCE(80);
      END_STATE();
    case 39:
      if (lookahead == 'n') ADVANCE(33);
      END_STATE();
    case 40:
      if (lookahead == 'o') ADVANCE(23);
      END_STATE();
    case 41:
      if (lookahead == 'o') ADVANCE(74);
      END_STATE();
    case 42:
      if (lookahead == 'o') ADVANCE(51);
      END_STATE();
    case 43:
      if (lookahead == 'p') ADVANCE(5);
      if (lookahead == 's') ADVANCE(100);
      END_STATE();
    case 44:
      if (lookahead == 'p') ADVANCE(97);
      END_STATE();
    case 45:
      if (lookahead == 'p') ADVANCE(111);
      END_STATE();
    case 46:
      if (lookahead == 'p') ADVANCE(114);
      END_STATE();
    case 47:
      if (lookahead == 'p') ADVANCE(117);
      END_STATE();
    case 48:
      if (lookahead == 'p') ADVANCE(92);
      END_STATE();
    case 49:
      if (lookahead == 'p') ADVANCE(93);
      END_STATE();
    case 50:
      if (lookahead == 'p') ADVANCE(112);
      END_STATE();
    case 51:
      if (lookahead == 'p') ADVANCE(87);
      END_STATE();
    case 52:
      if (lookahead == 'p') ADVANCE(107);
      END_STATE();
    case 53:
      if (lookahead == 'p') ADVANCE(96);
      END_STATE();
    case 54:
      if (lookahead == 'p') ADVANCE(94);
      END_STATE();
    case 55:
      if (lookahead == 'p') ADVANCE(104);
      END_STATE();
    case 56:
      if (lookahead == 'p') ADVANCE(103);
      END_STATE();
    case 57:
      if (lookahead == 'p') ADVANCE(115);
      END_STATE();
    case 58:
      if (lookahead == 'p') ADVANCE(116);
      END_STATE();
    case 59:
      if (lookahead == 'p') ADVANCE(16);
      END_STATE();
    case 60:
      if (lookahead == 'r') ADVANCE(11);
      END_STATE();
    case 61:
      if (lookahead == 'r') ADVANCE(71);
      END_STATE();
    case 62:
      if (lookahead == 'r') ADVANCE(17);
      END_STATE();
    case 63:
      if (lookahead == 'r') ADVANCE(59);
      END_STATE();
    case 64:
      if (lookahead == 's') ADVANCE(108);
      END_STATE();
    case 65:
      if (lookahead == 's') ADVANCE(98);
      END_STATE();
    case 66:
      if (lookahead == 's') ADVANCE(86);
      END_STATE();
    case 67:
      if (lookahead == 's') ADVANCE(105);
      END_STATE();
    case 68:
      if (lookahead == 's') ADVANCE(66);
      END_STATE();
    case 69:
      if (lookahead == 's') ADVANCE(73);
      END_STATE();
    case 70:
      if (lookahead == 't') ADVANCE(44);
      END_STATE();
    case 71:
      if (lookahead == 't') ADVANCE(85);
      END_STATE();
    case 72:
      if (lookahead == 't') ADVANCE(88);
      END_STATE();
    case 73:
      if (lookahead == 't') ADVANCE(90);
      END_STATE();
    case 74:
      if (lookahead == 't') ADVANCE(31);
      END_STATE();
    case 75:
      if (lookahead == 't') ADVANCE(53);
      END_STATE();
    case 76:
      if (lookahead == 't') ADVANCE(58);
      END_STATE();
    case 77:
      if (lookahead == 't') ADVANCE(75);
      END_STATE();
    case 78:
      if (lookahead == 'u') ADVANCE(67);
      END_STATE();
    case 79:
      if (lookahead == 'v') ADVANCE(4);
      END_STATE();
    case 80:
      if (lookahead == 'y') ADVANCE(119);
      END_STATE();
    case 81:
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(81)
      if (lookahead != 0) ADVANCE(136);
      END_STATE();
    case 82:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 83:
      ACCEPT_TOKEN(anon_sym_DASH_GT);
      END_STATE();
    case 84:
      ACCEPT_TOKEN(anon_sym_LT_GT);
      END_STATE();
    case 85:
      ACCEPT_TOKEN(anon_sym_alert);
      END_STATE();
    case 86:
      ACCEPT_TOKEN(anon_sym_pass);
      END_STATE();
    case 87:
      ACCEPT_TOKEN(anon_sym_drop);
      END_STATE();
    case 88:
      ACCEPT_TOKEN(anon_sym_reject);
      if (lookahead == 'b') ADVANCE(41);
      if (lookahead == 'd') ADVANCE(69);
      if (lookahead == 's') ADVANCE(62);
      END_STATE();
    case 89:
      ACCEPT_TOKEN(anon_sym_rejectsrc);
      END_STATE();
    case 90:
      ACCEPT_TOKEN(anon_sym_rejectdst);
      END_STATE();
    case 91:
      ACCEPT_TOKEN(anon_sym_rejectboth);
      END_STATE();
    case 92:
      ACCEPT_TOKEN(anon_sym_tcp);
      END_STATE();
    case 93:
      ACCEPT_TOKEN(anon_sym_udp);
      END_STATE();
    case 94:
      ACCEPT_TOKEN(anon_sym_icmp);
      END_STATE();
    case 95:
      ACCEPT_TOKEN(anon_sym_ip);
      END_STATE();
    case 96:
      ACCEPT_TOKEN(anon_sym_http);
      if (lookahead == '2') ADVANCE(118);
      END_STATE();
    case 97:
      ACCEPT_TOKEN(anon_sym_ftp);
      END_STATE();
    case 98:
      ACCEPT_TOKEN(anon_sym_tls);
      END_STATE();
    case 99:
      ACCEPT_TOKEN(anon_sym_smb);
      END_STATE();
    case 100:
      ACCEPT_TOKEN(anon_sym_dns);
      END_STATE();
    case 101:
      ACCEPT_TOKEN(anon_sym_dcerpc);
      END_STATE();
    case 102:
      ACCEPT_TOKEN(anon_sym_ssh);
      END_STATE();
    case 103:
      ACCEPT_TOKEN(anon_sym_smtp);
      END_STATE();
    case 104:
      ACCEPT_TOKEN(anon_sym_imap);
      END_STATE();
    case 105:
      ACCEPT_TOKEN(anon_sym_modbus);
      END_STATE();
    case 106:
      ACCEPT_TOKEN(anon_sym_dnp3);
      END_STATE();
    case 107:
      ACCEPT_TOKEN(anon_sym_enip);
      END_STATE();
    case 108:
      ACCEPT_TOKEN(anon_sym_nfs);
      END_STATE();
    case 109:
      ACCEPT_TOKEN(anon_sym_ikev2);
      END_STATE();
    case 110:
      ACCEPT_TOKEN(anon_sym_krb5);
      END_STATE();
    case 111:
      ACCEPT_TOKEN(anon_sym_ntp);
      END_STATE();
    case 112:
      ACCEPT_TOKEN(anon_sym_dhcp);
      END_STATE();
    case 113:
      ACCEPT_TOKEN(anon_sym_rfb);
      END_STATE();
    case 114:
      ACCEPT_TOKEN(anon_sym_rdp);
      END_STATE();
    case 115:
      ACCEPT_TOKEN(anon_sym_snmp);
      END_STATE();
    case 116:
      ACCEPT_TOKEN(anon_sym_tftp);
      END_STATE();
    case 117:
      ACCEPT_TOKEN(anon_sym_sip);
      END_STATE();
    case 118:
      ACCEPT_TOKEN(anon_sym_http2);
      END_STATE();
    case 119:
      ACCEPT_TOKEN(anon_sym_any);
      END_STATE();
    case 120:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 121:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 122:
      ACCEPT_TOKEN(anon_sym_DOT);
      END_STATE();
    case 123:
      ACCEPT_TOKEN(sym_network_octet);
      END_STATE();
    case 124:
      ACCEPT_TOKEN(sym_network_subnet_mask);
      END_STATE();
    case 125:
      ACCEPT_TOKEN(sym_network_subnet_mask);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(124);
      END_STATE();
    case 126:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      END_STATE();
    case 127:
      ACCEPT_TOKEN(anon_sym_RBRACK);
      END_STATE();
    case 128:
      ACCEPT_TOKEN(anon_sym_COMMA);
      END_STATE();
    case 129:
      ACCEPT_TOKEN(sym_port_single);
      END_STATE();
    case 130:
      ACCEPT_TOKEN(sym_port_single);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(129);
      END_STATE();
    case 131:
      ACCEPT_TOKEN(sym_port_single);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(130);
      END_STATE();
    case 132:
      ACCEPT_TOKEN(sym_port_single);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(131);
      END_STATE();
    case 133:
      ACCEPT_TOKEN(sym_port_single);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(132);
      END_STATE();
    case 134:
      ACCEPT_TOKEN(anon_sym_COLON);
      END_STATE();
    case 135:
      ACCEPT_TOKEN(anon_sym_DOLLAR);
      END_STATE();
    case 136:
      ACCEPT_TOKEN(aux_sym_variable_token1);
      if (lookahead != 0 &&
          lookahead != '\t' &&
          lookahead != '\n' &&
          lookahead != '\r' &&
          lookahead != ' ') ADVANCE(136);
      END_STATE();
    case 137:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 138:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 139:
      ACCEPT_TOKEN(anon_sym_SEMI);
      END_STATE();
    case 140:
      ACCEPT_TOKEN(sym_option_key);
      if (lookahead == '-' ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(140);
      END_STATE();
    case 141:
      ACCEPT_TOKEN(sym_option_value);
      if (lookahead == '\t' ||
          lookahead == '\r' ||
          lookahead == ' ') ADVANCE(141);
      if (lookahead != 0 &&
          lookahead != '\n' &&
          lookahead != ')' &&
          lookahead != ';') ADVANCE(142);
      END_STATE();
    case 142:
      ACCEPT_TOKEN(sym_option_value);
      if (lookahead != 0 &&
          lookahead != '\n' &&
          lookahead != ')' &&
          lookahead != ';') ADVANCE(142);
      END_STATE();
    case 143:
      ACCEPT_TOKEN(anon_sym_POUND);
      END_STATE();
    case 144:
      ACCEPT_TOKEN(aux_sym_comment_token1);
      if (lookahead == '\t' ||
          lookahead == '\r' ||
          lookahead == ' ') ADVANCE(144);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(145);
      END_STATE();
    case 145:
      ACCEPT_TOKEN(aux_sym_comment_token1);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(145);
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
  [6] = {.lex_state = 2},
  [7] = {.lex_state = 2},
  [8] = {.lex_state = 0},
  [9] = {.lex_state = 0},
  [10] = {.lex_state = 0},
  [11] = {.lex_state = 0},
  [12] = {.lex_state = 0},
  [13] = {.lex_state = 2},
  [14] = {.lex_state = 2},
  [15] = {.lex_state = 2},
  [16] = {.lex_state = 2},
  [17] = {.lex_state = 2},
  [18] = {.lex_state = 0},
  [19] = {.lex_state = 2},
  [20] = {.lex_state = 0},
  [21] = {.lex_state = 0},
  [22] = {.lex_state = 0},
  [23] = {.lex_state = 0},
  [24] = {.lex_state = 2},
  [25] = {.lex_state = 2},
  [26] = {.lex_state = 2},
  [27] = {.lex_state = 0},
  [28] = {.lex_state = 2},
  [29] = {.lex_state = 0},
  [30] = {.lex_state = 3},
  [31] = {.lex_state = 3},
  [32] = {.lex_state = 3},
  [33] = {.lex_state = 0},
  [34] = {.lex_state = 0},
  [35] = {.lex_state = 0},
  [36] = {.lex_state = 0},
  [37] = {.lex_state = 0},
  [38] = {.lex_state = 0},
  [39] = {.lex_state = 0},
  [40] = {.lex_state = 0},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 2},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 0},
  [46] = {.lex_state = 0},
  [47] = {.lex_state = 0},
  [48] = {.lex_state = 0},
  [49] = {.lex_state = 3},
  [50] = {.lex_state = 0},
  [51] = {.lex_state = 0},
  [52] = {.lex_state = 81},
  [53] = {.lex_state = 0},
  [54] = {.lex_state = 0},
  [55] = {.lex_state = 0},
  [56] = {.lex_state = 0},
  [57] = {.lex_state = 3},
  [58] = {.lex_state = 0},
  [59] = {.lex_state = 0},
  [60] = {.lex_state = 0},
  [61] = {.lex_state = 0},
  [62] = {.lex_state = 0},
  [63] = {.lex_state = 0},
  [64] = {.lex_state = 144},
  [65] = {.lex_state = 0},
  [66] = {.lex_state = 0},
  [67] = {.lex_state = 0},
  [68] = {.lex_state = 0},
  [69] = {.lex_state = 1},
  [70] = {.lex_state = 0},
  [71] = {.lex_state = 0},
  [72] = {.lex_state = 0},
  [73] = {.lex_state = 0},
};

static const uint16_t ts_parse_table[LARGE_STATE_COUNT][SYMBOL_COUNT] = {
  [0] = {
    [ts_builtin_sym_end] = ACTIONS(1),
    [anon_sym_DASH_GT] = ACTIONS(1),
    [anon_sym_LT_GT] = ACTIONS(1),
    [anon_sym_alert] = ACTIONS(1),
    [anon_sym_pass] = ACTIONS(1),
    [anon_sym_drop] = ACTIONS(1),
    [anon_sym_reject] = ACTIONS(1),
    [anon_sym_rejectsrc] = ACTIONS(1),
    [anon_sym_rejectdst] = ACTIONS(1),
    [anon_sym_rejectboth] = ACTIONS(1),
    [anon_sym_tcp] = ACTIONS(1),
    [anon_sym_udp] = ACTIONS(1),
    [anon_sym_icmp] = ACTIONS(1),
    [anon_sym_ip] = ACTIONS(1),
    [anon_sym_http] = ACTIONS(1),
    [anon_sym_ftp] = ACTIONS(1),
    [anon_sym_tls] = ACTIONS(1),
    [anon_sym_smb] = ACTIONS(1),
    [anon_sym_dns] = ACTIONS(1),
    [anon_sym_dcerpc] = ACTIONS(1),
    [anon_sym_ssh] = ACTIONS(1),
    [anon_sym_smtp] = ACTIONS(1),
    [anon_sym_imap] = ACTIONS(1),
    [anon_sym_modbus] = ACTIONS(1),
    [anon_sym_dnp3] = ACTIONS(1),
    [anon_sym_enip] = ACTIONS(1),
    [anon_sym_nfs] = ACTIONS(1),
    [anon_sym_ikev2] = ACTIONS(1),
    [anon_sym_krb5] = ACTIONS(1),
    [anon_sym_ntp] = ACTIONS(1),
    [anon_sym_dhcp] = ACTIONS(1),
    [anon_sym_rfb] = ACTIONS(1),
    [anon_sym_rdp] = ACTIONS(1),
    [anon_sym_snmp] = ACTIONS(1),
    [anon_sym_tftp] = ACTIONS(1),
    [anon_sym_sip] = ACTIONS(1),
    [anon_sym_http2] = ACTIONS(1),
    [anon_sym_any] = ACTIONS(1),
    [anon_sym_SLASH] = ACTIONS(1),
    [anon_sym_BANG] = ACTIONS(1),
    [anon_sym_DOT] = ACTIONS(1),
    [sym_network_octet] = ACTIONS(1),
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
    [sym_file] = STATE(72),
    [sym_rule] = STATE(5),
    [sym_action] = STATE(2),
    [sym_comment] = STATE(5),
    [aux_sym_file_repeat1] = STATE(5),
    [ts_builtin_sym_end] = ACTIONS(3),
    [anon_sym_alert] = ACTIONS(5),
    [anon_sym_pass] = ACTIONS(5),
    [anon_sym_drop] = ACTIONS(5),
    [anon_sym_reject] = ACTIONS(7),
    [anon_sym_rejectsrc] = ACTIONS(5),
    [anon_sym_rejectdst] = ACTIONS(5),
    [anon_sym_rejectboth] = ACTIONS(5),
    [anon_sym_POUND] = ACTIONS(9),
  },
};

static const uint16_t ts_small_parse_table[] = {
  [0] = 3,
    ACTIONS(13), 1,
      anon_sym_http,
    STATE(12), 1,
      sym_protocol,
    ACTIONS(11), 26,
      anon_sym_tcp,
      anon_sym_udp,
      anon_sym_icmp,
      anon_sym_ip,
      anon_sym_ftp,
      anon_sym_tls,
      anon_sym_smb,
      anon_sym_dns,
      anon_sym_dcerpc,
      anon_sym_ssh,
      anon_sym_smtp,
      anon_sym_imap,
      anon_sym_modbus,
      anon_sym_dnp3,
      anon_sym_enip,
      anon_sym_nfs,
      anon_sym_ikev2,
      anon_sym_krb5,
      anon_sym_ntp,
      anon_sym_dhcp,
      anon_sym_rfb,
      anon_sym_rdp,
      anon_sym_snmp,
      anon_sym_tftp,
      anon_sym_sip,
      anon_sym_http2,
  [35] = 2,
    ACTIONS(17), 1,
      anon_sym_http,
    ACTIONS(15), 26,
      anon_sym_tcp,
      anon_sym_udp,
      anon_sym_icmp,
      anon_sym_ip,
      anon_sym_ftp,
      anon_sym_tls,
      anon_sym_smb,
      anon_sym_dns,
      anon_sym_dcerpc,
      anon_sym_ssh,
      anon_sym_smtp,
      anon_sym_imap,
      anon_sym_modbus,
      anon_sym_dnp3,
      anon_sym_enip,
      anon_sym_nfs,
      anon_sym_ikev2,
      anon_sym_krb5,
      anon_sym_ntp,
      anon_sym_dhcp,
      anon_sym_rfb,
      anon_sym_rdp,
      anon_sym_snmp,
      anon_sym_tftp,
      anon_sym_sip,
      anon_sym_http2,
  [67] = 6,
    ACTIONS(19), 1,
      ts_builtin_sym_end,
    ACTIONS(24), 1,
      anon_sym_reject,
    ACTIONS(27), 1,
      anon_sym_POUND,
    STATE(2), 1,
      sym_action,
    STATE(4), 3,
      sym_rule,
      sym_comment,
      aux_sym_file_repeat1,
    ACTIONS(21), 6,
      anon_sym_alert,
      anon_sym_pass,
      anon_sym_drop,
      anon_sym_rejectsrc,
      anon_sym_rejectdst,
      anon_sym_rejectboth,
  [93] = 6,
    ACTIONS(7), 1,
      anon_sym_reject,
    ACTIONS(9), 1,
      anon_sym_POUND,
    ACTIONS(30), 1,
      ts_builtin_sym_end,
    STATE(2), 1,
      sym_action,
    STATE(4), 3,
      sym_rule,
      sym_comment,
      aux_sym_file_repeat1,
    ACTIONS(5), 6,
      anon_sym_alert,
      anon_sym_pass,
      anon_sym_drop,
      anon_sym_rejectsrc,
      anon_sym_rejectdst,
      anon_sym_rejectboth,
  [119] = 8,
    ACTIONS(32), 1,
      anon_sym_any,
    ACTIONS(34), 1,
      anon_sym_BANG,
    ACTIONS(36), 1,
      anon_sym_LBRACK,
    ACTIONS(38), 1,
      sym_port_single,
    ACTIONS(40), 1,
      anon_sym_DOLLAR,
    STATE(22), 1,
      sym_port_range,
    STATE(40), 1,
      sym_port,
    STATE(35), 3,
      sym_port_list,
      sym_port_spec,
      sym_variable,
  [146] = 8,
    ACTIONS(32), 1,
      anon_sym_any,
    ACTIONS(34), 1,
      anon_sym_BANG,
    ACTIONS(36), 1,
      anon_sym_LBRACK,
    ACTIONS(38), 1,
      sym_port_single,
    ACTIONS(40), 1,
      anon_sym_DOLLAR,
    STATE(22), 1,
      sym_port_range,
    STATE(48), 1,
      sym_port,
    STATE(35), 3,
      sym_port_list,
      sym_port_spec,
      sym_variable,
  [173] = 2,
    ACTIONS(44), 1,
      anon_sym_reject,
    ACTIONS(42), 8,
      ts_builtin_sym_end,
      anon_sym_alert,
      anon_sym_pass,
      anon_sym_drop,
      anon_sym_rejectsrc,
      anon_sym_rejectdst,
      anon_sym_rejectboth,
      anon_sym_POUND,
  [187] = 2,
    ACTIONS(48), 1,
      anon_sym_reject,
    ACTIONS(46), 8,
      ts_builtin_sym_end,
      anon_sym_alert,
      anon_sym_pass,
      anon_sym_drop,
      anon_sym_rejectsrc,
      anon_sym_rejectdst,
      anon_sym_rejectboth,
      anon_sym_POUND,
  [201] = 2,
    ACTIONS(52), 1,
      anon_sym_reject,
    ACTIONS(50), 8,
      ts_builtin_sym_end,
      anon_sym_alert,
      anon_sym_pass,
      anon_sym_drop,
      anon_sym_rejectsrc,
      anon_sym_rejectdst,
      anon_sym_rejectboth,
      anon_sym_POUND,
  [215] = 7,
    ACTIONS(54), 1,
      anon_sym_any,
    ACTIONS(56), 1,
      anon_sym_BANG,
    ACTIONS(58), 1,
      sym_network_octet,
    ACTIONS(60), 1,
      anon_sym_LBRACK,
    STATE(7), 1,
      sym_network,
    STATE(14), 1,
      sym_network_cidr,
    STATE(26), 2,
      sym_network_ip,
      sym_network_list,
  [238] = 7,
    ACTIONS(54), 1,
      anon_sym_any,
    ACTIONS(56), 1,
      anon_sym_BANG,
    ACTIONS(58), 1,
      sym_network_octet,
    ACTIONS(60), 1,
      anon_sym_LBRACK,
    STATE(6), 1,
      sym_network,
    STATE(14), 1,
      sym_network_cidr,
    STATE(26), 2,
      sym_network_ip,
      sym_network_list,
  [261] = 1,
    ACTIONS(62), 8,
      anon_sym_any,
      anon_sym_SLASH,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [272] = 2,
    ACTIONS(66), 1,
      anon_sym_SLASH,
    ACTIONS(64), 7,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [285] = 1,
    ACTIONS(68), 8,
      anon_sym_any,
      anon_sym_SLASH,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [296] = 1,
    ACTIONS(64), 7,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [306] = 1,
    ACTIONS(70), 7,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [316] = 2,
    ACTIONS(74), 1,
      anon_sym_COLON,
    ACTIONS(72), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [327] = 2,
    ACTIONS(78), 1,
      sym_port_single,
    ACTIONS(76), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [338] = 6,
    ACTIONS(54), 1,
      anon_sym_any,
    ACTIONS(56), 1,
      anon_sym_BANG,
    ACTIONS(58), 1,
      sym_network_octet,
    STATE(14), 1,
      sym_network_cidr,
    STATE(38), 1,
      sym_network_ip,
    STATE(61), 1,
      sym_network_list_entry,
  [357] = 2,
    ACTIONS(74), 1,
      anon_sym_COLON,
    ACTIONS(80), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [368] = 1,
    ACTIONS(72), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [376] = 1,
    ACTIONS(82), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [384] = 5,
    ACTIONS(32), 1,
      anon_sym_any,
    ACTIONS(34), 1,
      anon_sym_BANG,
    ACTIONS(38), 1,
      sym_port_single,
    STATE(22), 1,
      sym_port_range,
    STATE(39), 1,
      sym_port_spec,
  [400] = 5,
    ACTIONS(32), 1,
      anon_sym_any,
    ACTIONS(34), 1,
      anon_sym_BANG,
    ACTIONS(38), 1,
      sym_port_single,
    STATE(22), 1,
      sym_port_range,
    STATE(47), 1,
      sym_port_spec,
  [416] = 1,
    ACTIONS(84), 5,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      sym_port_single,
      anon_sym_DOLLAR,
  [424] = 1,
    ACTIONS(80), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [432] = 1,
    ACTIONS(86), 5,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      sym_port_single,
      anon_sym_DOLLAR,
  [440] = 5,
    ACTIONS(54), 1,
      anon_sym_any,
    ACTIONS(56), 1,
      anon_sym_BANG,
    ACTIONS(58), 1,
      sym_network_octet,
    STATE(14), 1,
      sym_network_cidr,
    STATE(51), 1,
      sym_network_ip,
  [456] = 4,
    ACTIONS(88), 1,
      anon_sym_RPAREN,
    ACTIONS(90), 1,
      sym_option_key,
    STATE(32), 1,
      aux_sym_option_repeat1,
    STATE(66), 1,
      sym_option_key_value,
  [469] = 4,
    ACTIONS(90), 1,
      sym_option_key,
    STATE(30), 1,
      aux_sym_option_repeat1,
    STATE(65), 1,
      sym_option,
    STATE(66), 1,
      sym_option_key_value,
  [482] = 4,
    ACTIONS(92), 1,
      anon_sym_RPAREN,
    ACTIONS(94), 1,
      sym_option_key,
    STATE(32), 1,
      aux_sym_option_repeat1,
    STATE(66), 1,
      sym_option_key_value,
  [495] = 1,
    ACTIONS(97), 4,
      anon_sym_any,
      anon_sym_BANG,
      sym_network_octet,
      anon_sym_LBRACK,
  [502] = 1,
    ACTIONS(99), 4,
      anon_sym_any,
      anon_sym_BANG,
      sym_network_octet,
      anon_sym_LBRACK,
  [509] = 1,
    ACTIONS(101), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [515] = 1,
    ACTIONS(103), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [521] = 3,
    ACTIONS(105), 1,
      anon_sym_RBRACK,
    ACTIONS(107), 1,
      anon_sym_COMMA,
    STATE(43), 1,
      aux_sym_network_list_entry_repeat1,
  [531] = 3,
    ACTIONS(107), 1,
      anon_sym_COMMA,
    ACTIONS(109), 1,
      anon_sym_RBRACK,
    STATE(37), 1,
      aux_sym_network_list_entry_repeat1,
  [541] = 3,
    ACTIONS(111), 1,
      anon_sym_RBRACK,
    ACTIONS(113), 1,
      anon_sym_COMMA,
    STATE(46), 1,
      aux_sym_port_list_repeat1,
  [551] = 2,
    STATE(11), 1,
      sym_direction,
    ACTIONS(115), 2,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
  [559] = 1,
    ACTIONS(117), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [565] = 3,
    ACTIONS(119), 1,
      anon_sym_any,
    ACTIONS(121), 1,
      sym_port_single,
    STATE(27), 1,
      sym_port_range,
  [575] = 3,
    ACTIONS(123), 1,
      anon_sym_RBRACK,
    ACTIONS(125), 1,
      anon_sym_COMMA,
    STATE(43), 1,
      aux_sym_network_list_entry_repeat1,
  [585] = 1,
    ACTIONS(128), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [591] = 3,
    ACTIONS(130), 1,
      anon_sym_RBRACK,
    ACTIONS(132), 1,
      anon_sym_COMMA,
    STATE(45), 1,
      aux_sym_port_list_repeat1,
  [601] = 3,
    ACTIONS(113), 1,
      anon_sym_COMMA,
    ACTIONS(135), 1,
      anon_sym_RBRACK,
    STATE(45), 1,
      aux_sym_port_list_repeat1,
  [611] = 1,
    ACTIONS(130), 2,
      anon_sym_RBRACK,
      anon_sym_COMMA,
  [616] = 2,
    ACTIONS(137), 1,
      anon_sym_LPAREN,
    STATE(10), 1,
      sym_options,
  [623] = 1,
    ACTIONS(92), 2,
      anon_sym_RPAREN,
      sym_option_key,
  [628] = 2,
    ACTIONS(139), 1,
      anon_sym_COLON,
    ACTIONS(141), 1,
      anon_sym_SEMI,
  [635] = 1,
    ACTIONS(123), 2,
      anon_sym_RBRACK,
      anon_sym_COMMA,
  [640] = 1,
    ACTIONS(143), 1,
      aux_sym_variable_token1,
  [644] = 1,
    ACTIONS(145), 1,
      sym_network_octet,
  [648] = 1,
    ACTIONS(147), 1,
      anon_sym_DOT,
  [652] = 1,
    ACTIONS(149), 1,
      anon_sym_DOT,
  [656] = 1,
    ACTIONS(151), 1,
      sym_network_octet,
  [660] = 1,
    ACTIONS(153), 1,
      sym_network_subnet_mask,
  [664] = 1,
    ACTIONS(155), 1,
      anon_sym_DOT,
  [668] = 1,
    ACTIONS(157), 1,
      sym_network_octet,
  [672] = 1,
    ACTIONS(159), 1,
      anon_sym_DOT,
  [676] = 1,
    ACTIONS(161), 1,
      anon_sym_RBRACK,
  [680] = 1,
    ACTIONS(163), 1,
      sym_network_octet,
  [684] = 1,
    ACTIONS(165), 1,
      sym_network_octet,
  [688] = 1,
    ACTIONS(167), 1,
      aux_sym_comment_token1,
  [692] = 1,
    ACTIONS(169), 1,
      anon_sym_RPAREN,
  [696] = 1,
    ACTIONS(171), 1,
      anon_sym_SEMI,
  [700] = 1,
    ACTIONS(173), 1,
      anon_sym_DOT,
  [704] = 1,
    ACTIONS(175), 1,
      anon_sym_DOT,
  [708] = 1,
    ACTIONS(177), 1,
      sym_option_value,
  [712] = 1,
    ACTIONS(179), 1,
      sym_network_octet,
  [716] = 1,
    ACTIONS(181), 1,
      sym_network_octet,
  [720] = 1,
    ACTIONS(183), 1,
      ts_builtin_sym_end,
  [724] = 1,
    ACTIONS(185), 1,
      anon_sym_SEMI,
};

static const uint32_t ts_small_parse_table_map[] = {
  [SMALL_STATE(2)] = 0,
  [SMALL_STATE(3)] = 35,
  [SMALL_STATE(4)] = 67,
  [SMALL_STATE(5)] = 93,
  [SMALL_STATE(6)] = 119,
  [SMALL_STATE(7)] = 146,
  [SMALL_STATE(8)] = 173,
  [SMALL_STATE(9)] = 187,
  [SMALL_STATE(10)] = 201,
  [SMALL_STATE(11)] = 215,
  [SMALL_STATE(12)] = 238,
  [SMALL_STATE(13)] = 261,
  [SMALL_STATE(14)] = 272,
  [SMALL_STATE(15)] = 285,
  [SMALL_STATE(16)] = 296,
  [SMALL_STATE(17)] = 306,
  [SMALL_STATE(18)] = 316,
  [SMALL_STATE(19)] = 327,
  [SMALL_STATE(20)] = 338,
  [SMALL_STATE(21)] = 357,
  [SMALL_STATE(22)] = 368,
  [SMALL_STATE(23)] = 376,
  [SMALL_STATE(24)] = 384,
  [SMALL_STATE(25)] = 400,
  [SMALL_STATE(26)] = 416,
  [SMALL_STATE(27)] = 424,
  [SMALL_STATE(28)] = 432,
  [SMALL_STATE(29)] = 440,
  [SMALL_STATE(30)] = 456,
  [SMALL_STATE(31)] = 469,
  [SMALL_STATE(32)] = 482,
  [SMALL_STATE(33)] = 495,
  [SMALL_STATE(34)] = 502,
  [SMALL_STATE(35)] = 509,
  [SMALL_STATE(36)] = 515,
  [SMALL_STATE(37)] = 521,
  [SMALL_STATE(38)] = 531,
  [SMALL_STATE(39)] = 541,
  [SMALL_STATE(40)] = 551,
  [SMALL_STATE(41)] = 559,
  [SMALL_STATE(42)] = 565,
  [SMALL_STATE(43)] = 575,
  [SMALL_STATE(44)] = 585,
  [SMALL_STATE(45)] = 591,
  [SMALL_STATE(46)] = 601,
  [SMALL_STATE(47)] = 611,
  [SMALL_STATE(48)] = 616,
  [SMALL_STATE(49)] = 623,
  [SMALL_STATE(50)] = 628,
  [SMALL_STATE(51)] = 635,
  [SMALL_STATE(52)] = 640,
  [SMALL_STATE(53)] = 644,
  [SMALL_STATE(54)] = 648,
  [SMALL_STATE(55)] = 652,
  [SMALL_STATE(56)] = 656,
  [SMALL_STATE(57)] = 660,
  [SMALL_STATE(58)] = 664,
  [SMALL_STATE(59)] = 668,
  [SMALL_STATE(60)] = 672,
  [SMALL_STATE(61)] = 676,
  [SMALL_STATE(62)] = 680,
  [SMALL_STATE(63)] = 684,
  [SMALL_STATE(64)] = 688,
  [SMALL_STATE(65)] = 692,
  [SMALL_STATE(66)] = 696,
  [SMALL_STATE(67)] = 700,
  [SMALL_STATE(68)] = 704,
  [SMALL_STATE(69)] = 708,
  [SMALL_STATE(70)] = 712,
  [SMALL_STATE(71)] = 716,
  [SMALL_STATE(72)] = 720,
  [SMALL_STATE(73)] = 724,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_file, 0),
  [5] = {.entry = {.count = 1, .reusable = true}}, SHIFT(3),
  [7] = {.entry = {.count = 1, .reusable = false}}, SHIFT(3),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(64),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [13] = {.entry = {.count = 1, .reusable = false}}, SHIFT(34),
  [15] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_action, 1),
  [17] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_action, 1),
  [19] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_file_repeat1, 2),
  [21] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_file_repeat1, 2), SHIFT_REPEAT(3),
  [24] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_file_repeat1, 2), SHIFT_REPEAT(3),
  [27] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_file_repeat1, 2), SHIFT_REPEAT(64),
  [30] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_file, 1),
  [32] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [34] = {.entry = {.count = 1, .reusable = true}}, SHIFT(42),
  [36] = {.entry = {.count = 1, .reusable = true}}, SHIFT(24),
  [38] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
  [40] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [42] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_options, 3),
  [44] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_options, 3),
  [46] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_comment, 2),
  [48] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_comment, 2),
  [50] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_rule, 8),
  [52] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_rule, 8),
  [54] = {.entry = {.count = 1, .reusable = true}}, SHIFT(16),
  [56] = {.entry = {.count = 1, .reusable = true}}, SHIFT(70),
  [58] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [60] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [62] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_cidr, 8),
  [64] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_ip, 1),
  [66] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
  [68] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_cidr, 7),
  [70] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_ip, 3),
  [72] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_spec, 1),
  [74] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [76] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_range, 2),
  [78] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [80] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_spec, 2),
  [82] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_range, 3),
  [84] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network, 1),
  [86] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list, 3),
  [88] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_option, 1),
  [90] = {.entry = {.count = 1, .reusable = true}}, SHIFT(50),
  [92] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_option_repeat1, 2),
  [94] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_option_repeat1, 2), SHIFT_REPEAT(50),
  [97] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_direction, 1),
  [99] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_protocol, 1),
  [101] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port, 1),
  [103] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_list, 4),
  [105] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list_entry, 2),
  [107] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [109] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list_entry, 1),
  [111] = {.entry = {.count = 1, .reusable = true}}, SHIFT(44),
  [113] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [115] = {.entry = {.count = 1, .reusable = true}}, SHIFT(33),
  [117] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_variable, 2),
  [119] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [121] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [123] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_network_list_entry_repeat1, 2),
  [125] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_network_list_entry_repeat1, 2), SHIFT_REPEAT(29),
  [128] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_list, 3),
  [130] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_port_list_repeat1, 2),
  [132] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_port_list_repeat1, 2), SHIFT_REPEAT(25),
  [135] = {.entry = {.count = 1, .reusable = true}}, SHIFT(36),
  [137] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [139] = {.entry = {.count = 1, .reusable = true}}, SHIFT(69),
  [141] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_option_key_value, 1),
  [143] = {.entry = {.count = 1, .reusable = true}}, SHIFT(41),
  [145] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [147] = {.entry = {.count = 1, .reusable = true}}, SHIFT(59),
  [149] = {.entry = {.count = 1, .reusable = true}}, SHIFT(71),
  [151] = {.entry = {.count = 1, .reusable = true}}, SHIFT(60),
  [153] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [155] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [157] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [159] = {.entry = {.count = 1, .reusable = true}}, SHIFT(63),
  [161] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [163] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [165] = {.entry = {.count = 1, .reusable = true}}, SHIFT(58),
  [167] = {.entry = {.count = 1, .reusable = true}}, SHIFT(9),
  [169] = {.entry = {.count = 1, .reusable = true}}, SHIFT(8),
  [171] = {.entry = {.count = 1, .reusable = true}}, SHIFT(49),
  [173] = {.entry = {.count = 1, .reusable = true}}, SHIFT(56),
  [175] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [177] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [179] = {.entry = {.count = 1, .reusable = true}}, SHIFT(67),
  [181] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [183] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [185] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_option_key_value, 3),
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
