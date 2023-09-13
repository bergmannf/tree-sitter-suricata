#include <tree_sitter/parser.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif

#define LANGUAGE_VERSION 13
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

static bool ts_lex(TSLexer *lexer, TSStateId state) {
  START_LEXER();
  eof = lexer->eof(lexer);
  switch (state) {
    case 0:
      if (eof) ADVANCE(83);
      if (lookahead == '!') ADVANCE(122);
      if (lookahead == '#') ADVANCE(144);
      if (lookahead == '$') ADVANCE(136);
      if (lookahead == '(') ADVANCE(138);
      if (lookahead == ')') ADVANCE(139);
      if (lookahead == ',') ADVANCE(129);
      if (lookahead == '-') ADVANCE(7);
      if (lookahead == '.') ADVANCE(123);
      if (lookahead == '/') ADVANCE(121);
      if (lookahead == ':') ADVANCE(135);
      if (lookahead == ';') ADVANCE(140);
      if (lookahead == '<') ADVANCE(8);
      if (lookahead == '[') ADVANCE(127);
      if (lookahead == ']') ADVANCE(128);
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
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(124);
      END_STATE();
    case 1:
      if (lookahead == '\n') SKIP(1)
      if (lookahead == '\t' ||
          lookahead == '\r' ||
          lookahead == ' ') ADVANCE(142);
      if (lookahead != 0 &&
          lookahead != ')' &&
          lookahead != ';') ADVANCE(143);
      END_STATE();
    case 2:
      if (lookahead == '!') ADVANCE(122);
      if (lookahead == '$') ADVANCE(136);
      if (lookahead == '(') ADVANCE(138);
      if (lookahead == ',') ADVANCE(129);
      if (lookahead == '-') ADVANCE(7);
      if (lookahead == '/') ADVANCE(121);
      if (lookahead == '<') ADVANCE(8);
      if (lookahead == '[') ADVANCE(127);
      if (lookahead == ']') ADVANCE(128);
      if (lookahead == 'a') ADVANCE(38);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(2)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(134);
      END_STATE();
    case 3:
      if (lookahead == ')') ADVANCE(139);
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(3)
      if (lookahead == '-' ||
          lookahead == '.' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(141);
      END_STATE();
    case 4:
      if (lookahead == '2') ADVANCE(110);
      END_STATE();
    case 5:
      if (lookahead == '3') ADVANCE(107);
      END_STATE();
    case 6:
      if (lookahead == '5') ADVANCE(111);
      END_STATE();
    case 7:
      if (lookahead == '>') ADVANCE(84);
      END_STATE();
    case 8:
      if (lookahead == '>') ADVANCE(85);
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
      if (lookahead == 'b') ADVANCE(114);
      END_STATE();
    case 13:
      if (lookahead == 'b') ADVANCE(100);
      if (lookahead == 't') ADVANCE(56);
      END_STATE();
    case 14:
      if (lookahead == 'b') ADVANCE(78);
      END_STATE();
    case 15:
      if (lookahead == 'c') ADVANCE(36);
      if (lookahead == 'k') ADVANCE(25);
      if (lookahead == 'm') ADVANCE(10);
      if (lookahead == 'p') ADVANCE(96);
      END_STATE();
    case 16:
      if (lookahead == 'c') ADVANCE(102);
      END_STATE();
    case 17:
      if (lookahead == 'c') ADVANCE(90);
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
      if (lookahead == 'h') ADVANCE(103);
      END_STATE();
    case 31:
      if (lookahead == 'h') ADVANCE(92);
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
      if (lookahead == 's') ADVANCE(101);
      END_STATE();
    case 44:
      if (lookahead == 'p') ADVANCE(98);
      END_STATE();
    case 45:
      if (lookahead == 'p') ADVANCE(112);
      END_STATE();
    case 46:
      if (lookahead == 'p') ADVANCE(115);
      END_STATE();
    case 47:
      if (lookahead == 'p') ADVANCE(118);
      END_STATE();
    case 48:
      if (lookahead == 'p') ADVANCE(93);
      END_STATE();
    case 49:
      if (lookahead == 'p') ADVANCE(94);
      END_STATE();
    case 50:
      if (lookahead == 'p') ADVANCE(113);
      END_STATE();
    case 51:
      if (lookahead == 'p') ADVANCE(88);
      END_STATE();
    case 52:
      if (lookahead == 'p') ADVANCE(108);
      END_STATE();
    case 53:
      if (lookahead == 'p') ADVANCE(97);
      END_STATE();
    case 54:
      if (lookahead == 'p') ADVANCE(95);
      END_STATE();
    case 55:
      if (lookahead == 'p') ADVANCE(105);
      END_STATE();
    case 56:
      if (lookahead == 'p') ADVANCE(104);
      END_STATE();
    case 57:
      if (lookahead == 'p') ADVANCE(116);
      END_STATE();
    case 58:
      if (lookahead == 'p') ADVANCE(117);
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
      if (lookahead == 's') ADVANCE(109);
      END_STATE();
    case 65:
      if (lookahead == 's') ADVANCE(99);
      END_STATE();
    case 66:
      if (lookahead == 's') ADVANCE(87);
      END_STATE();
    case 67:
      if (lookahead == 's') ADVANCE(106);
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
      if (lookahead == 't') ADVANCE(86);
      END_STATE();
    case 72:
      if (lookahead == 't') ADVANCE(89);
      END_STATE();
    case 73:
      if (lookahead == 't') ADVANCE(91);
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
      if (lookahead == 'y') ADVANCE(120);
      END_STATE();
    case 81:
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(81)
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(137);
      END_STATE();
    case 82:
      if (lookahead == '\t' ||
          lookahead == '\n' ||
          lookahead == '\r' ||
          lookahead == ' ') SKIP(82)
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(126);
      END_STATE();
    case 83:
      ACCEPT_TOKEN(ts_builtin_sym_end);
      END_STATE();
    case 84:
      ACCEPT_TOKEN(anon_sym_DASH_GT);
      END_STATE();
    case 85:
      ACCEPT_TOKEN(anon_sym_LT_GT);
      END_STATE();
    case 86:
      ACCEPT_TOKEN(anon_sym_alert);
      END_STATE();
    case 87:
      ACCEPT_TOKEN(anon_sym_pass);
      END_STATE();
    case 88:
      ACCEPT_TOKEN(anon_sym_drop);
      END_STATE();
    case 89:
      ACCEPT_TOKEN(anon_sym_reject);
      if (lookahead == 'b') ADVANCE(41);
      if (lookahead == 'd') ADVANCE(69);
      if (lookahead == 's') ADVANCE(62);
      END_STATE();
    case 90:
      ACCEPT_TOKEN(anon_sym_rejectsrc);
      END_STATE();
    case 91:
      ACCEPT_TOKEN(anon_sym_rejectdst);
      END_STATE();
    case 92:
      ACCEPT_TOKEN(anon_sym_rejectboth);
      END_STATE();
    case 93:
      ACCEPT_TOKEN(anon_sym_tcp);
      END_STATE();
    case 94:
      ACCEPT_TOKEN(anon_sym_udp);
      END_STATE();
    case 95:
      ACCEPT_TOKEN(anon_sym_icmp);
      END_STATE();
    case 96:
      ACCEPT_TOKEN(anon_sym_ip);
      END_STATE();
    case 97:
      ACCEPT_TOKEN(anon_sym_http);
      if (lookahead == '2') ADVANCE(119);
      END_STATE();
    case 98:
      ACCEPT_TOKEN(anon_sym_ftp);
      END_STATE();
    case 99:
      ACCEPT_TOKEN(anon_sym_tls);
      END_STATE();
    case 100:
      ACCEPT_TOKEN(anon_sym_smb);
      END_STATE();
    case 101:
      ACCEPT_TOKEN(anon_sym_dns);
      END_STATE();
    case 102:
      ACCEPT_TOKEN(anon_sym_dcerpc);
      END_STATE();
    case 103:
      ACCEPT_TOKEN(anon_sym_ssh);
      END_STATE();
    case 104:
      ACCEPT_TOKEN(anon_sym_smtp);
      END_STATE();
    case 105:
      ACCEPT_TOKEN(anon_sym_imap);
      END_STATE();
    case 106:
      ACCEPT_TOKEN(anon_sym_modbus);
      END_STATE();
    case 107:
      ACCEPT_TOKEN(anon_sym_dnp3);
      END_STATE();
    case 108:
      ACCEPT_TOKEN(anon_sym_enip);
      END_STATE();
    case 109:
      ACCEPT_TOKEN(anon_sym_nfs);
      END_STATE();
    case 110:
      ACCEPT_TOKEN(anon_sym_ikev2);
      END_STATE();
    case 111:
      ACCEPT_TOKEN(anon_sym_krb5);
      END_STATE();
    case 112:
      ACCEPT_TOKEN(anon_sym_ntp);
      END_STATE();
    case 113:
      ACCEPT_TOKEN(anon_sym_dhcp);
      END_STATE();
    case 114:
      ACCEPT_TOKEN(anon_sym_rfb);
      END_STATE();
    case 115:
      ACCEPT_TOKEN(anon_sym_rdp);
      END_STATE();
    case 116:
      ACCEPT_TOKEN(anon_sym_snmp);
      END_STATE();
    case 117:
      ACCEPT_TOKEN(anon_sym_tftp);
      END_STATE();
    case 118:
      ACCEPT_TOKEN(anon_sym_sip);
      END_STATE();
    case 119:
      ACCEPT_TOKEN(anon_sym_http2);
      END_STATE();
    case 120:
      ACCEPT_TOKEN(anon_sym_any);
      END_STATE();
    case 121:
      ACCEPT_TOKEN(anon_sym_SLASH);
      END_STATE();
    case 122:
      ACCEPT_TOKEN(anon_sym_BANG);
      END_STATE();
    case 123:
      ACCEPT_TOKEN(anon_sym_DOT);
      END_STATE();
    case 124:
      ACCEPT_TOKEN(sym_network_octet);
      END_STATE();
    case 125:
      ACCEPT_TOKEN(sym_network_subnet_mask);
      END_STATE();
    case 126:
      ACCEPT_TOKEN(sym_network_subnet_mask);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(125);
      END_STATE();
    case 127:
      ACCEPT_TOKEN(anon_sym_LBRACK);
      END_STATE();
    case 128:
      ACCEPT_TOKEN(anon_sym_RBRACK);
      END_STATE();
    case 129:
      ACCEPT_TOKEN(anon_sym_COMMA);
      END_STATE();
    case 130:
      ACCEPT_TOKEN(sym_port_single);
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
      ACCEPT_TOKEN(sym_port_single);
      if (('0' <= lookahead && lookahead <= '9')) ADVANCE(133);
      END_STATE();
    case 135:
      ACCEPT_TOKEN(anon_sym_COLON);
      END_STATE();
    case 136:
      ACCEPT_TOKEN(anon_sym_DOLLAR);
      END_STATE();
    case 137:
      ACCEPT_TOKEN(aux_sym_variable_token1);
      if (('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(137);
      END_STATE();
    case 138:
      ACCEPT_TOKEN(anon_sym_LPAREN);
      END_STATE();
    case 139:
      ACCEPT_TOKEN(anon_sym_RPAREN);
      END_STATE();
    case 140:
      ACCEPT_TOKEN(anon_sym_SEMI);
      END_STATE();
    case 141:
      ACCEPT_TOKEN(sym_option_key);
      if (lookahead == '-' ||
          lookahead == '.' ||
          ('0' <= lookahead && lookahead <= '9') ||
          ('A' <= lookahead && lookahead <= 'Z') ||
          lookahead == '_' ||
          ('a' <= lookahead && lookahead <= 'z')) ADVANCE(141);
      END_STATE();
    case 142:
      ACCEPT_TOKEN(sym_option_value);
      if (lookahead == '\t' ||
          lookahead == '\r' ||
          lookahead == ' ') ADVANCE(142);
      if (lookahead != 0 &&
          lookahead != '\n' &&
          lookahead != ')' &&
          lookahead != ';') ADVANCE(143);
      END_STATE();
    case 143:
      ACCEPT_TOKEN(sym_option_value);
      if (lookahead != 0 &&
          lookahead != '\n' &&
          lookahead != ')' &&
          lookahead != ';') ADVANCE(143);
      END_STATE();
    case 144:
      ACCEPT_TOKEN(anon_sym_POUND);
      END_STATE();
    case 145:
      ACCEPT_TOKEN(aux_sym_comment_token1);
      if (lookahead == '\t' ||
          lookahead == '\r' ||
          lookahead == ' ') ADVANCE(145);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(146);
      END_STATE();
    case 146:
      ACCEPT_TOKEN(aux_sym_comment_token1);
      if (lookahead != 0 &&
          lookahead != '\n') ADVANCE(146);
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
  [9] = {.lex_state = 2},
  [10] = {.lex_state = 0},
  [11] = {.lex_state = 0},
  [12] = {.lex_state = 0},
  [13] = {.lex_state = 0},
  [14] = {.lex_state = 0},
  [15] = {.lex_state = 2},
  [16] = {.lex_state = 2},
  [17] = {.lex_state = 2},
  [18] = {.lex_state = 2},
  [19] = {.lex_state = 2},
  [20] = {.lex_state = 0},
  [21] = {.lex_state = 0},
  [22] = {.lex_state = 2},
  [23] = {.lex_state = 0},
  [24] = {.lex_state = 2},
  [25] = {.lex_state = 0},
  [26] = {.lex_state = 0},
  [27] = {.lex_state = 0},
  [28] = {.lex_state = 2},
  [29] = {.lex_state = 2},
  [30] = {.lex_state = 2},
  [31] = {.lex_state = 0},
  [32] = {.lex_state = 0},
  [33] = {.lex_state = 3},
  [34] = {.lex_state = 3},
  [35] = {.lex_state = 3},
  [36] = {.lex_state = 0},
  [37] = {.lex_state = 0},
  [38] = {.lex_state = 0},
  [39] = {.lex_state = 2},
  [40] = {.lex_state = 0},
  [41] = {.lex_state = 0},
  [42] = {.lex_state = 0},
  [43] = {.lex_state = 0},
  [44] = {.lex_state = 0},
  [45] = {.lex_state = 0},
  [46] = {.lex_state = 0},
  [47] = {.lex_state = 0},
  [48] = {.lex_state = 3},
  [49] = {.lex_state = 0},
  [50] = {.lex_state = 0},
  [51] = {.lex_state = 0},
  [52] = {.lex_state = 145},
  [53] = {.lex_state = 0},
  [54] = {.lex_state = 81},
  [55] = {.lex_state = 0},
  [56] = {.lex_state = 0},
  [57] = {.lex_state = 0},
  [58] = {.lex_state = 0},
  [59] = {.lex_state = 0},
  [60] = {.lex_state = 0},
  [61] = {.lex_state = 0},
  [62] = {.lex_state = 0},
  [63] = {.lex_state = 0},
  [64] = {.lex_state = 0},
  [65] = {.lex_state = 0},
  [66] = {.lex_state = 0},
  [67] = {.lex_state = 0},
  [68] = {.lex_state = 0},
  [69] = {.lex_state = 1},
  [70] = {.lex_state = 0},
  [71] = {.lex_state = 0},
  [72] = {.lex_state = 82},
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
    [sym_file] = STATE(70),
    [sym_rule] = STATE(4),
    [sym_action] = STATE(2),
    [sym_comment] = STATE(4),
    [aux_sym_file_repeat1] = STATE(4),
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
    STATE(10), 1,
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
      anon_sym_pass,
      anon_sym_drop,
      anon_sym_rejectsrc,
      anon_sym_rejectdst,
      anon_sym_rejectboth,
  [93] = 6,
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
    STATE(26), 1,
      sym_port_range,
    STATE(49), 1,
      sym_port,
    STATE(44), 3,
      sym_port_list,
      sym_port_spec,
      sym_variable,
  [146] = 1,
    ACTIONS(42), 10,
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
  [159] = 9,
    ACTIONS(40), 1,
      anon_sym_DOLLAR,
    ACTIONS(44), 1,
      anon_sym_any,
    ACTIONS(46), 1,
      anon_sym_BANG,
    ACTIONS(48), 1,
      sym_network_octet,
    ACTIONS(50), 1,
      anon_sym_LBRACK,
    STATE(6), 1,
      sym_network,
    STATE(16), 1,
      sym_network_cidr,
    STATE(19), 1,
      sym_variable,
    STATE(30), 2,
      sym_network_ip,
      sym_network_list,
  [188] = 8,
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
    STATE(26), 1,
      sym_port_range,
    STATE(46), 1,
      sym_port,
    STATE(44), 3,
      sym_port_list,
      sym_port_spec,
      sym_variable,
  [215] = 9,
    ACTIONS(40), 1,
      anon_sym_DOLLAR,
    ACTIONS(44), 1,
      anon_sym_any,
    ACTIONS(46), 1,
      anon_sym_BANG,
    ACTIONS(48), 1,
      sym_network_octet,
    ACTIONS(50), 1,
      anon_sym_LBRACK,
    STATE(9), 1,
      sym_network,
    STATE(16), 1,
      sym_network_cidr,
    STATE(19), 1,
      sym_variable,
    STATE(30), 2,
      sym_network_ip,
      sym_network_list,
  [244] = 2,
    ACTIONS(54), 1,
      anon_sym_reject,
    ACTIONS(52), 8,
      ts_builtin_sym_end,
      anon_sym_alert,
      anon_sym_pass,
      anon_sym_drop,
      anon_sym_rejectsrc,
      anon_sym_rejectdst,
      anon_sym_rejectboth,
      anon_sym_POUND,
  [258] = 2,
    ACTIONS(58), 1,
      anon_sym_reject,
    ACTIONS(56), 8,
      ts_builtin_sym_end,
      anon_sym_alert,
      anon_sym_pass,
      anon_sym_drop,
      anon_sym_rejectsrc,
      anon_sym_rejectdst,
      anon_sym_rejectboth,
      anon_sym_POUND,
  [272] = 2,
    ACTIONS(62), 1,
      anon_sym_reject,
    ACTIONS(60), 8,
      ts_builtin_sym_end,
      anon_sym_alert,
      anon_sym_pass,
      anon_sym_drop,
      anon_sym_rejectsrc,
      anon_sym_rejectdst,
      anon_sym_rejectboth,
      anon_sym_POUND,
  [286] = 8,
    ACTIONS(40), 1,
      anon_sym_DOLLAR,
    ACTIONS(44), 1,
      anon_sym_any,
    ACTIONS(46), 1,
      anon_sym_BANG,
    ACTIONS(48), 1,
      sym_network_octet,
    STATE(16), 1,
      sym_network_cidr,
    STATE(19), 1,
      sym_variable,
    STATE(36), 1,
      sym_network_ip,
    STATE(56), 1,
      sym_network_list_entry,
  [311] = 1,
    ACTIONS(64), 8,
      anon_sym_any,
      anon_sym_SLASH,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [322] = 2,
    ACTIONS(68), 1,
      anon_sym_SLASH,
    ACTIONS(66), 7,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [335] = 1,
    ACTIONS(70), 8,
      anon_sym_any,
      anon_sym_SLASH,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [346] = 1,
    ACTIONS(72), 7,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [356] = 1,
    ACTIONS(66), 7,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      sym_port_single,
      anon_sym_DOLLAR,
  [366] = 7,
    ACTIONS(40), 1,
      anon_sym_DOLLAR,
    ACTIONS(44), 1,
      anon_sym_any,
    ACTIONS(46), 1,
      anon_sym_BANG,
    ACTIONS(48), 1,
      sym_network_octet,
    STATE(16), 1,
      sym_network_cidr,
    STATE(19), 1,
      sym_variable,
    STATE(50), 1,
      sym_network_ip,
  [388] = 2,
    ACTIONS(76), 1,
      anon_sym_COLON,
    ACTIONS(74), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [399] = 2,
    ACTIONS(80), 1,
      sym_port_single,
    ACTIONS(78), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [410] = 2,
    ACTIONS(76), 1,
      anon_sym_COLON,
    ACTIONS(82), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [421] = 1,
    ACTIONS(84), 5,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      sym_port_single,
      anon_sym_DOLLAR,
  [429] = 1,
    ACTIONS(82), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [437] = 1,
    ACTIONS(74), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [445] = 1,
    ACTIONS(86), 5,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_RBRACK,
      anon_sym_COMMA,
      anon_sym_LPAREN,
  [453] = 5,
    ACTIONS(32), 1,
      anon_sym_any,
    ACTIONS(34), 1,
      anon_sym_BANG,
    ACTIONS(38), 1,
      sym_port_single,
    STATE(26), 1,
      sym_port_range,
    STATE(38), 1,
      sym_port_spec,
  [469] = 5,
    ACTIONS(32), 1,
      anon_sym_any,
    ACTIONS(34), 1,
      anon_sym_BANG,
    ACTIONS(38), 1,
      sym_port_single,
    STATE(26), 1,
      sym_port_range,
    STATE(51), 1,
      sym_port_spec,
  [485] = 1,
    ACTIONS(88), 5,
      anon_sym_any,
      anon_sym_BANG,
      anon_sym_LBRACK,
      sym_port_single,
      anon_sym_DOLLAR,
  [493] = 1,
    ACTIONS(90), 5,
      anon_sym_any,
      anon_sym_BANG,
      sym_network_octet,
      anon_sym_LBRACK,
      anon_sym_DOLLAR,
  [501] = 1,
    ACTIONS(92), 5,
      anon_sym_any,
      anon_sym_BANG,
      sym_network_octet,
      anon_sym_LBRACK,
      anon_sym_DOLLAR,
  [509] = 4,
    ACTIONS(94), 1,
      anon_sym_RPAREN,
    ACTIONS(96), 1,
      sym_option_key,
    STATE(33), 1,
      aux_sym_option_repeat1,
    STATE(66), 1,
      sym_option_key_value,
  [522] = 4,
    ACTIONS(99), 1,
      sym_option_key,
    STATE(35), 1,
      aux_sym_option_repeat1,
    STATE(65), 1,
      sym_option,
    STATE(66), 1,
      sym_option_key_value,
  [535] = 4,
    ACTIONS(99), 1,
      sym_option_key,
    ACTIONS(101), 1,
      anon_sym_RPAREN,
    STATE(33), 1,
      aux_sym_option_repeat1,
    STATE(66), 1,
      sym_option_key_value,
  [548] = 3,
    ACTIONS(103), 1,
      anon_sym_RBRACK,
    ACTIONS(105), 1,
      anon_sym_COMMA,
    STATE(40), 1,
      aux_sym_network_list_entry_repeat1,
  [558] = 1,
    ACTIONS(107), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [564] = 3,
    ACTIONS(109), 1,
      anon_sym_RBRACK,
    ACTIONS(111), 1,
      anon_sym_COMMA,
    STATE(45), 1,
      aux_sym_port_list_repeat1,
  [574] = 3,
    ACTIONS(113), 1,
      anon_sym_any,
    ACTIONS(115), 1,
      sym_port_single,
    STATE(25), 1,
      sym_port_range,
  [584] = 3,
    ACTIONS(105), 1,
      anon_sym_COMMA,
    ACTIONS(117), 1,
      anon_sym_RBRACK,
    STATE(42), 1,
      aux_sym_network_list_entry_repeat1,
  [594] = 3,
    ACTIONS(119), 1,
      anon_sym_RBRACK,
    ACTIONS(121), 1,
      anon_sym_COMMA,
    STATE(41), 1,
      aux_sym_port_list_repeat1,
  [604] = 3,
    ACTIONS(124), 1,
      anon_sym_RBRACK,
    ACTIONS(126), 1,
      anon_sym_COMMA,
    STATE(42), 1,
      aux_sym_network_list_entry_repeat1,
  [614] = 1,
    ACTIONS(129), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [620] = 1,
    ACTIONS(131), 3,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
      anon_sym_LPAREN,
  [626] = 3,
    ACTIONS(111), 1,
      anon_sym_COMMA,
    ACTIONS(133), 1,
      anon_sym_RBRACK,
    STATE(41), 1,
      aux_sym_port_list_repeat1,
  [636] = 2,
    STATE(8), 1,
      sym_direction,
    ACTIONS(135), 2,
      anon_sym_DASH_GT,
      anon_sym_LT_GT,
  [644] = 2,
    ACTIONS(137), 1,
      anon_sym_COLON,
    ACTIONS(139), 1,
      anon_sym_SEMI,
  [651] = 1,
    ACTIONS(94), 2,
      anon_sym_RPAREN,
      sym_option_key,
  [656] = 2,
    ACTIONS(141), 1,
      anon_sym_LPAREN,
    STATE(11), 1,
      sym_options,
  [663] = 1,
    ACTIONS(124), 2,
      anon_sym_RBRACK,
      anon_sym_COMMA,
  [668] = 1,
    ACTIONS(119), 2,
      anon_sym_RBRACK,
      anon_sym_COMMA,
  [673] = 1,
    ACTIONS(143), 1,
      aux_sym_comment_token1,
  [677] = 1,
    ACTIONS(145), 1,
      anon_sym_DOT,
  [681] = 1,
    ACTIONS(147), 1,
      aux_sym_variable_token1,
  [685] = 1,
    ACTIONS(149), 1,
      sym_network_octet,
  [689] = 1,
    ACTIONS(151), 1,
      anon_sym_RBRACK,
  [693] = 1,
    ACTIONS(153), 1,
      sym_network_octet,
  [697] = 1,
    ACTIONS(155), 1,
      anon_sym_DOT,
  [701] = 1,
    ACTIONS(157), 1,
      sym_network_octet,
  [705] = 1,
    ACTIONS(159), 1,
      anon_sym_DOT,
  [709] = 1,
    ACTIONS(161), 1,
      anon_sym_DOT,
  [713] = 1,
    ACTIONS(163), 1,
      sym_network_octet,
  [717] = 1,
    ACTIONS(165), 1,
      sym_network_octet,
  [721] = 1,
    ACTIONS(167), 1,
      anon_sym_DOT,
  [725] = 1,
    ACTIONS(169), 1,
      anon_sym_RPAREN,
  [729] = 1,
    ACTIONS(171), 1,
      anon_sym_SEMI,
  [733] = 1,
    ACTIONS(173), 1,
      sym_network_octet,
  [737] = 1,
    ACTIONS(175), 1,
      anon_sym_DOT,
  [741] = 1,
    ACTIONS(177), 1,
      sym_option_value,
  [745] = 1,
    ACTIONS(179), 1,
      ts_builtin_sym_end,
  [749] = 1,
    ACTIONS(181), 1,
      sym_network_octet,
  [753] = 1,
    ACTIONS(183), 1,
      sym_network_subnet_mask,
  [757] = 1,
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
  [SMALL_STATE(8)] = 159,
  [SMALL_STATE(9)] = 188,
  [SMALL_STATE(10)] = 215,
  [SMALL_STATE(11)] = 244,
  [SMALL_STATE(12)] = 258,
  [SMALL_STATE(13)] = 272,
  [SMALL_STATE(14)] = 286,
  [SMALL_STATE(15)] = 311,
  [SMALL_STATE(16)] = 322,
  [SMALL_STATE(17)] = 335,
  [SMALL_STATE(18)] = 346,
  [SMALL_STATE(19)] = 356,
  [SMALL_STATE(20)] = 366,
  [SMALL_STATE(21)] = 388,
  [SMALL_STATE(22)] = 399,
  [SMALL_STATE(23)] = 410,
  [SMALL_STATE(24)] = 421,
  [SMALL_STATE(25)] = 429,
  [SMALL_STATE(26)] = 437,
  [SMALL_STATE(27)] = 445,
  [SMALL_STATE(28)] = 453,
  [SMALL_STATE(29)] = 469,
  [SMALL_STATE(30)] = 485,
  [SMALL_STATE(31)] = 493,
  [SMALL_STATE(32)] = 501,
  [SMALL_STATE(33)] = 509,
  [SMALL_STATE(34)] = 522,
  [SMALL_STATE(35)] = 535,
  [SMALL_STATE(36)] = 548,
  [SMALL_STATE(37)] = 558,
  [SMALL_STATE(38)] = 564,
  [SMALL_STATE(39)] = 574,
  [SMALL_STATE(40)] = 584,
  [SMALL_STATE(41)] = 594,
  [SMALL_STATE(42)] = 604,
  [SMALL_STATE(43)] = 614,
  [SMALL_STATE(44)] = 620,
  [SMALL_STATE(45)] = 626,
  [SMALL_STATE(46)] = 636,
  [SMALL_STATE(47)] = 644,
  [SMALL_STATE(48)] = 651,
  [SMALL_STATE(49)] = 656,
  [SMALL_STATE(50)] = 663,
  [SMALL_STATE(51)] = 668,
  [SMALL_STATE(52)] = 673,
  [SMALL_STATE(53)] = 677,
  [SMALL_STATE(54)] = 681,
  [SMALL_STATE(55)] = 685,
  [SMALL_STATE(56)] = 689,
  [SMALL_STATE(57)] = 693,
  [SMALL_STATE(58)] = 697,
  [SMALL_STATE(59)] = 701,
  [SMALL_STATE(60)] = 705,
  [SMALL_STATE(61)] = 709,
  [SMALL_STATE(62)] = 713,
  [SMALL_STATE(63)] = 717,
  [SMALL_STATE(64)] = 721,
  [SMALL_STATE(65)] = 725,
  [SMALL_STATE(66)] = 729,
  [SMALL_STATE(67)] = 733,
  [SMALL_STATE(68)] = 737,
  [SMALL_STATE(69)] = 741,
  [SMALL_STATE(70)] = 745,
  [SMALL_STATE(71)] = 749,
  [SMALL_STATE(72)] = 753,
  [SMALL_STATE(73)] = 757,
};

static const TSParseActionEntry ts_parse_actions[] = {
  [0] = {.entry = {.count = 0, .reusable = false}},
  [1] = {.entry = {.count = 1, .reusable = false}}, RECOVER(),
  [3] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_file, 0),
  [5] = {.entry = {.count = 1, .reusable = true}}, SHIFT(3),
  [7] = {.entry = {.count = 1, .reusable = false}}, SHIFT(3),
  [9] = {.entry = {.count = 1, .reusable = true}}, SHIFT(52),
  [11] = {.entry = {.count = 1, .reusable = true}}, SHIFT(31),
  [13] = {.entry = {.count = 1, .reusable = false}}, SHIFT(31),
  [15] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_action, 1),
  [17] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_action, 1),
  [19] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_file, 1),
  [21] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_file_repeat1, 2),
  [23] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_file_repeat1, 2), SHIFT_REPEAT(3),
  [26] = {.entry = {.count = 2, .reusable = false}}, REDUCE(aux_sym_file_repeat1, 2), SHIFT_REPEAT(3),
  [29] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_file_repeat1, 2), SHIFT_REPEAT(52),
  [32] = {.entry = {.count = 1, .reusable = true}}, SHIFT(26),
  [34] = {.entry = {.count = 1, .reusable = true}}, SHIFT(39),
  [36] = {.entry = {.count = 1, .reusable = true}}, SHIFT(28),
  [38] = {.entry = {.count = 1, .reusable = true}}, SHIFT(21),
  [40] = {.entry = {.count = 1, .reusable = true}}, SHIFT(54),
  [42] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_variable, 2),
  [44] = {.entry = {.count = 1, .reusable = true}}, SHIFT(19),
  [46] = {.entry = {.count = 1, .reusable = true}}, SHIFT(63),
  [48] = {.entry = {.count = 1, .reusable = true}}, SHIFT(61),
  [50] = {.entry = {.count = 1, .reusable = true}}, SHIFT(14),
  [52] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_rule, 8),
  [54] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_rule, 8),
  [56] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_options, 3),
  [58] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_options, 3),
  [60] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_comment, 2),
  [62] = {.entry = {.count = 1, .reusable = false}}, REDUCE(sym_comment, 2),
  [64] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_cidr, 7),
  [66] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_ip, 1),
  [68] = {.entry = {.count = 1, .reusable = true}}, SHIFT(72),
  [70] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_cidr, 8),
  [72] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_ip, 3),
  [74] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_spec, 1),
  [76] = {.entry = {.count = 1, .reusable = true}}, SHIFT(22),
  [78] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_range, 2),
  [80] = {.entry = {.count = 1, .reusable = true}}, SHIFT(27),
  [82] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_spec, 2),
  [84] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list, 3),
  [86] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_range, 3),
  [88] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network, 1),
  [90] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_protocol, 1),
  [92] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_direction, 1),
  [94] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_option_repeat1, 2),
  [96] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_option_repeat1, 2), SHIFT_REPEAT(47),
  [99] = {.entry = {.count = 1, .reusable = true}}, SHIFT(47),
  [101] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_option, 1),
  [103] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list_entry, 1),
  [105] = {.entry = {.count = 1, .reusable = true}}, SHIFT(20),
  [107] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_list, 4),
  [109] = {.entry = {.count = 1, .reusable = true}}, SHIFT(43),
  [111] = {.entry = {.count = 1, .reusable = true}}, SHIFT(29),
  [113] = {.entry = {.count = 1, .reusable = true}}, SHIFT(25),
  [115] = {.entry = {.count = 1, .reusable = true}}, SHIFT(23),
  [117] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_network_list_entry, 2),
  [119] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_port_list_repeat1, 2),
  [121] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_port_list_repeat1, 2), SHIFT_REPEAT(29),
  [124] = {.entry = {.count = 1, .reusable = true}}, REDUCE(aux_sym_network_list_entry_repeat1, 2),
  [126] = {.entry = {.count = 2, .reusable = true}}, REDUCE(aux_sym_network_list_entry_repeat1, 2), SHIFT_REPEAT(20),
  [129] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port_list, 3),
  [131] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_port, 1),
  [133] = {.entry = {.count = 1, .reusable = true}}, SHIFT(37),
  [135] = {.entry = {.count = 1, .reusable = true}}, SHIFT(32),
  [137] = {.entry = {.count = 1, .reusable = true}}, SHIFT(69),
  [139] = {.entry = {.count = 1, .reusable = true}}, REDUCE(sym_option_key_value, 1),
  [141] = {.entry = {.count = 1, .reusable = true}}, SHIFT(34),
  [143] = {.entry = {.count = 1, .reusable = true}}, SHIFT(13),
  [145] = {.entry = {.count = 1, .reusable = true}}, SHIFT(59),
  [147] = {.entry = {.count = 1, .reusable = true}}, SHIFT(7),
  [149] = {.entry = {.count = 1, .reusable = true}}, SHIFT(58),
  [151] = {.entry = {.count = 1, .reusable = true}}, SHIFT(24),
  [153] = {.entry = {.count = 1, .reusable = true}}, SHIFT(53),
  [155] = {.entry = {.count = 1, .reusable = true}}, SHIFT(62),
  [157] = {.entry = {.count = 1, .reusable = true}}, SHIFT(15),
  [159] = {.entry = {.count = 1, .reusable = true}}, SHIFT(55),
  [161] = {.entry = {.count = 1, .reusable = true}}, SHIFT(67),
  [163] = {.entry = {.count = 1, .reusable = true}}, SHIFT(17),
  [165] = {.entry = {.count = 1, .reusable = true}}, SHIFT(64),
  [167] = {.entry = {.count = 1, .reusable = true}}, SHIFT(71),
  [169] = {.entry = {.count = 1, .reusable = true}}, SHIFT(12),
  [171] = {.entry = {.count = 1, .reusable = true}}, SHIFT(48),
  [173] = {.entry = {.count = 1, .reusable = true}}, SHIFT(68),
  [175] = {.entry = {.count = 1, .reusable = true}}, SHIFT(57),
  [177] = {.entry = {.count = 1, .reusable = true}}, SHIFT(73),
  [179] = {.entry = {.count = 1, .reusable = true}},  ACCEPT_INPUT(),
  [181] = {.entry = {.count = 1, .reusable = true}}, SHIFT(60),
  [183] = {.entry = {.count = 1, .reusable = true}}, SHIFT(18),
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
  };
  return &language;
}
#ifdef __cplusplus
}
#endif
