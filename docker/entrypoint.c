#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef FRP_MODE
#define FRP_MODE "frps"
#endif

static const char *env_or(const char *name, const char *fallback) {
  const char *v = getenv(name);
  return (v && v[0]) ? v : fallback;
}

static int is_help_or_version(const char *arg) {
  return !strcmp(arg, "-h") || !strcmp(arg, "--help") ||
         !strcmp(arg, "--version") || !strcmp(arg, "-v");
}

static int has_config_or_dir_arg(int argc, char **argv) {
  for (int i = 0; i < argc; i++) {
    if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) return 1;
    if (!strncmp(argv[i], "--config=", 9)) return 1;
    if (!strcmp(argv[i], "--config-dir")) return 1;
    if (!strncmp(argv[i], "--config-dir=", 13)) return 1;
  }
  return 0;
}

static int mkdir_p(const char *path) {
  char buf[4096], *p;
  struct stat st;
  size_t len;

  len = strlen(path);
  if (len >= sizeof(buf)) return -1;
  memcpy(buf, path, len + 1);

  for (p = buf + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      if (stat(buf, &st) != 0) {
        if (mkdir(buf, 0755) != 0 && errno != EEXIST) return -1;
      }
      *p = '/';
    }
  }
  if (stat(buf, &st) != 0) {
    if (mkdir(buf, 0755) != 0 && errno != EEXIST) return -1;
  }
  return 0;
}

/* Write a TOML string value, escaping \, ", and control characters. */
static void write_toml_str(FILE *f, const char *s) {
  fputc('"', f);
  for (; *s; s++) {
    switch (*s) {
      case '\\': fputs("\\\\", f); break;
      case '"':  fputs("\\\"", f); break;
      case '\n': fputs("\\n", f);  break;
      case '\r': fputs("\\r", f);  break;
      case '\t': fputs("\\t", f);  break;
      default:   fputc(*s, f);    break;
    }
  }
  fputc('"', f);
}

static void write_kv(FILE *f, const char *key, const char *val) {
  fprintf(f, "%s = ", key);
  write_toml_str(f, val);
  fputc('\n', f);
}

static void write_opt(FILE *f, const char *key, const char *env) {
  const char *v = getenv(env);
  if (v && v[0]) {
    fprintf(f, "%s = ", key);
    write_toml_str(f, v);
    fputc('\n', f);
  }
}

static int generate_frps_config(const char *path) {
  FILE *f = fopen(path, "w");
  if (!f) { perror("fopen"); return -1; }

  write_kv(f, "bind_addr", env_or("FRP_BIND_ADDR", "0.0.0.0"));
  fprintf(f, "bind_port = %s\n", env_or("FRP_BIND_PORT", "7000"));

  const char *token = getenv("FRP_AUTH_TOKEN");
  if (token && token[0]) {
    fprintf(f, "\n[auth]\n");
    fprintf(f, "method = \"token\"\n");
    write_kv(f, "token", token);
  }

  const char *dash_port = getenv("FRP_DASHBOARD_PORT");
  if (dash_port && dash_port[0]) {
    fprintf(f, "\n[web_server]\n");
    write_kv(f, "addr", env_or("FRP_DASHBOARD_ADDR", "0.0.0.0"));
    fprintf(f, "port = %s\n", dash_port);
    write_opt(f, "user", "FRP_DASHBOARD_USER");
    write_opt(f, "password", "FRP_DASHBOARD_PWD");
  }

  write_opt(f, "sub_domain_host", "FRP_SUBDOMAIN_HOST");
  write_opt(f, "tls_cert_file", "FRP_TLS_CERT_FILE");
  write_opt(f, "tls_key_file", "FRP_TLS_KEY_FILE");

  fclose(f);
  return 0;
}

static int generate_frpc_config(const char *path) {
  FILE *f = fopen(path, "w");
  if (!f) { perror("fopen"); return -1; }

  write_kv(f, "server_addr", env_or("FRP_SERVER_ADDR", "127.0.0.1"));
  fprintf(f, "server_port = %s\n", env_or("FRP_SERVER_PORT", "7000"));
  write_opt(f, "token", "FRP_AUTH_TOKEN");

  const char *name = getenv("FRP_TUNNEL_NAME");
  const char *lport = getenv("FRP_TUNNEL_LOCAL_PORT");
  const char *rport = getenv("FRP_TUNNEL_REMOTE_PORT");
  if (name && name[0] && lport && lport[0] && rport && rport[0]) {
    fprintf(f, "\n[[proxies]]\n");
    write_kv(f, "name", name);
    write_kv(f, "type", env_or("FRP_TUNNEL_TYPE", "tcp"));
    write_kv(f, "local_ip", env_or("FRP_TUNNEL_LOCAL_IP", "127.0.0.1"));
    fprintf(f, "local_port = %s\n", lport);
    fprintf(f, "remote_port = %s\n", rport);
  }

  fclose(f);
  return 0;
}

int main(int argc, char **argv) {
  const char *conf_path = env_or("FRP_CONF", "/app/frp.toml");
  const char *bin = "/usr/bin/frp";
  struct stat st;

  if (argc > 1 && is_help_or_version(argv[1])) {
    execv(bin, argv);
    perror("execv");
    return 1;
  }

  if (stat(conf_path, &st) != 0 || st.st_size == 0) {
    if (stat(conf_path, &st) == 0 && S_ISDIR(st.st_mode)) {
      fprintf(stderr, "[frp-rs] config path is a directory: %s\n", conf_path);
      return 1;
    }

    const char *slash = strrchr(conf_path, '/');
    if (slash && slash != conf_path) {
      char parent[4096];
      size_t plen = slash - conf_path;
      if (plen >= sizeof(parent)) return 1;
      memcpy(parent, conf_path, plen);
      parent[plen] = '\0';
      if (mkdir_p(parent) != 0) {
        fprintf(stderr, "[frp-rs] mkdir_p(%s): %s\n", parent, strerror(errno));
        return 1;
      }
    }

    fprintf(stderr, "[frp-rs] generating config (%s mode): %s\n", FRP_MODE, conf_path);

    int ret;
    if (!strcmp(FRP_MODE, "frpc")) ret = generate_frpc_config(conf_path);
    else                            ret = generate_frps_config(conf_path);
    if (ret != 0) return ret;

    fprintf(stderr, "[frp-rs] config generated\n");
  }

  int inject_c = !has_config_or_dir_arg(argc - 1, argv + 1);

  char **new_argv = calloc(argc + 3, sizeof(char *));
  if (!new_argv) { perror("calloc"); return 1; }
  int i = 0;
  new_argv[i++] = (char *)bin;
  if (inject_c) {
    new_argv[i++] = "-c";
    new_argv[i++] = (char *)conf_path;
  }
  for (int j = 1; j < argc; j++) new_argv[i++] = argv[j];
  new_argv[i] = NULL;

  execv(bin, new_argv);
  perror("execv");
  return 1;
}
