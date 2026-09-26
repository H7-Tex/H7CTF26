#define _LGPL_SOURCE
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <atomic>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <urcu/urcu-memb.h>
#include <urcu/urcu.h>
#include <urcu/rculfhash.h>
#include <urcu/call-rcu.h>
#include <urcu/compiler.h>
#include <urcu/uatomic.h>

#include <sodium.h>

static const int PORT = 9006;
static const int MAX_WORKERS = 16;
static const int STRIKE_LIMIT = 3;

enum Role { ROLE_ANON = 0, ROLE_USER = 1, ROLE_ADMIN = 2, ROLE_PROMOTING = 3 };

struct Conn;

struct Principal {
    struct cds_lfht_node node;
    struct rcu_head rcu;
    uint64_t key;
    int role;
    uint32_t scopes;
    void (*render)(Principal *, Conn *);
    char label[40];
};

struct Conn {
    int fd;
    Principal *cached;
    uint64_t resolved_key;
    void *blob;
    size_t blob_len;
    int strikes;
    bool authed_user;
};

static struct cds_lfht *g_table = nullptr;
static char g_flag[128];
static unsigned char g_sign_pk[crypto_sign_PUBLICKEYBYTES];
static unsigned char g_sign_sk[crypto_sign_SECRETKEYBYTES];

static std::mutex g_slab_mtx;
static std::vector<void *> g_slab_free;
static const size_t SLOT_SIZE = sizeof(Principal);

static std::mutex g_lock_mtx;
static std::set<uint64_t> g_locked_keys;

static std::atomic<int> g_active_workers{0};

static void *slab_alloc()
{
    std::lock_guard<std::mutex> lk(g_slab_mtx);
    if (!g_slab_free.empty()) {
        void *p = g_slab_free.back();
        g_slab_free.pop_back();
        return p;
    }
    void *p = nullptr;
    if (posix_memalign(&p, 16, SLOT_SIZE) != 0)
        return nullptr;
    return p;
}

static void slab_release(void *p)
{
    std::lock_guard<std::mutex> lk(g_slab_mtx);
    g_slab_free.push_back(p);
}

static unsigned long hash_key(uint64_t key)
{
    uint64_t h = key;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return (unsigned long)h;
}

static int key_match(struct cds_lfht_node *node, const void *k)
{
    Principal *p = caa_container_of(node, Principal, node);
    return p->key == *(const uint64_t *)k;
}

static void send_line(Conn *c, const char *s)
{
    send(c->fd, s, strlen(s), MSG_NOSIGNAL);
}

__attribute__((used, noinline)) static void anon_render(Principal *p, Conn *c)
{
    (void)p;
    send_line(c, "view: principal is anonymous, no privileged surface exposed\n");
}

__attribute__((used, noinline)) static void user_render(Principal *p, Conn *c)
{
    (void)p;
    send_line(c, "view: user principal, scopes=read:self no privileged surface\n");
}

__attribute__((used, noinline)) static void admin_render(Principal *p, Conn *c)
{
    (void)p;
    char out[256];
    int n = snprintf(out, sizeof(out), "view: admin principal\n%s\n", g_flag);
    send(c->fd, out, n, MSG_NOSIGNAL);
}

static Principal *make_principal(uint64_t key, int role)
{
    Principal *p = (Principal *)slab_alloc();
    if (!p)
        return nullptr;
    memset(p, 0, SLOT_SIZE);
    cds_lfht_node_init(&p->node);
    p->key = key;
    p->role = role;
    if (role == ROLE_USER) {
        p->scopes = 0x1;
        p->render = user_render;
        snprintf(p->label, sizeof(p->label), "user-%08llx", (unsigned long long)key);
    } else {
        p->scopes = 0x0;
        p->render = anon_render;
        snprintf(p->label, sizeof(p->label), "anon-%08llx", (unsigned long long)key);
    }
    return p;
}

static bool key_is_locked(uint64_t key)
{
    std::lock_guard<std::mutex> lk(g_lock_mtx);
    return g_locked_keys.count(key) != 0;
}

static void lock_key(uint64_t key)
{
    std::lock_guard<std::mutex> lk(g_lock_mtx);
    g_locked_keys.insert(key);
}

static Principal *resolve_key(uint64_t key)
{
    struct cds_lfht_iter iter;
    unsigned long h = hash_key(key);

    urcu_memb_read_lock();
    cds_lfht_lookup(g_table, h, key_match, &key, &iter);
    struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);
    Principal *p = nullptr;
    if (node) {
        p = caa_container_of(node, Principal, node);
    }
    urcu_memb_read_unlock();

    if (p)
        return p;

    Principal *fresh = make_principal(key, ROLE_ANON);
    if (!fresh)
        return nullptr;

    urcu_memb_read_lock();
    struct cds_lfht_node *ex = cds_lfht_add_unique(g_table, h, key_match, &key, &fresh->node);
    urcu_memb_read_unlock();

    if (ex != &fresh->node) {
        slab_release(fresh);
        return caa_container_of(ex, Principal, node);
    }
    return fresh;
}

static Principal *pin_lookup(Conn *c, uint64_t key)
{
    Principal *p = resolve_key(key);
    if (!p)
        return nullptr;
    c->cached = p;
    c->resolved_key = key;
    return p;
}

static Principal *resolve_pinned(Conn *c)
{
    urcu_memb_read_lock();
    Principal *p = c->cached;
    urcu_memb_read_unlock();
    return p;
}

static bool promote_key(uint64_t key)
{
    struct cds_lfht_iter iter;
    unsigned long h = hash_key(key);

    urcu_memb_read_lock();
    cds_lfht_lookup(g_table, h, key_match, &key, &iter);
    struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);
    if (!node) {
        urcu_memb_read_unlock();
        return false;
    }
    Principal *old = caa_container_of(node, Principal, node);
    int prev = uatomic_cmpxchg(&old->role, ROLE_ANON, ROLE_PROMOTING);
    if (prev != ROLE_ANON) {
        urcu_memb_read_unlock();
        return false;
    }

    Principal *fresh = make_principal(key, ROLE_USER);
    if (!fresh) {
        uatomic_set(&old->role, ROLE_ANON);
        urcu_memb_read_unlock();
        return false;
    }

    cds_lfht_del(g_table, &old->node);
    cds_lfht_add(g_table, h, &fresh->node);
    urcu_memb_read_unlock();

    urcu_memb_synchronize_rcu();
    slab_release(old);
    return true;
}

static std::string b64_encode(const unsigned char *data, size_t len)
{
    size_t cap = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(cap, '\0');
    sodium_bin2base64(&out[0], cap, data, len, sodium_base64_VARIANT_ORIGINAL);
    out.resize(strlen(out.c_str()));
    return out;
}

static bool b64_decode(const std::string &in, std::vector<unsigned char> &out)
{
    out.resize(in.size());
    size_t real = 0;
    if (sodium_base642bin(out.data(), out.size(), in.c_str(), in.size(), nullptr, &real, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return false;
    out.resize(real);
    return true;
}

static std::string issue_voucher(uint64_t key)
{
    unsigned char payload[9];
    payload[0] = (unsigned char)ROLE_USER;
    memcpy(payload + 1, &key, 8);
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr, payload, sizeof(payload), g_sign_sk);
    unsigned char blob[9 + crypto_sign_BYTES];
    memcpy(blob, payload, 9);
    memcpy(blob + 9, sig, crypto_sign_BYTES);
    return b64_encode(blob, sizeof(blob));
}

static int verify_voucher(const std::string &token, uint64_t *out_key, int *out_role)
{
    std::vector<unsigned char> blob;
    if (!b64_decode(token, blob))
        return -1;
    if (blob.size() != 9 + crypto_sign_BYTES)
        return -1;
    unsigned char *payload = blob.data();
    unsigned char *sig = blob.data() + 9;
    if (crypto_sign_verify_detached(sig, payload, 9, g_sign_pk) != 0)
        return -1;
    *out_role = payload[0];
    memcpy(out_key, payload + 1, 8);
    return 0;
}

static bool read_line(Conn *c, std::string &line)
{
    line.clear();
    char ch;
    while (true) {
        ssize_t r = recv(c->fd, &ch, 1, 0);
        if (r <= 0)
            return false;
        if (ch == '\n')
            return true;
        if (ch == '\r')
            continue;
        line.push_back(ch);
        if (line.size() > 4096)
            return false;
    }
}

static bool parse_hex(const std::string &s, std::vector<unsigned char> &out)
{
    if (s.size() % 2 != 0)
        return false;
    out.clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        auto nyb = [](char x) -> int {
            if (x >= '0' && x <= '9') return x - '0';
            if (x >= 'a' && x <= 'f') return x - 'a' + 10;
            if (x >= 'A' && x <= 'F') return x - 'A' + 10;
            return -1;
        };
        int hi = nyb(s[i]);
        int lo = nyb(s[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back((unsigned char)((hi << 4) | lo));
    }
    return true;
}

static void handle_conn(int fd)
{
    urcu_memb_register_thread();

    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    Conn conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = fd;

    send_line(&conn, "gatecache edge authorization cache\n");
    send_line(&conn, "commands: RESOLVE ENROLL UPGRADE WHOAMI STORE RENDER PING QUIT\n");

    std::string line;
    while (read_line(&conn, line)) {
        std::string cmd, arg;
        size_t sp = line.find(' ');
        if (sp == std::string::npos) {
            cmd = line;
        } else {
            cmd = line.substr(0, sp);
            arg = line.substr(sp + 1);
        }

        if (cmd == "RESOLVE") {
            uint64_t key = strtoull(arg.c_str(), nullptr, 16);
            if (key_is_locked(key)) {
                send_line(&conn, "ERR key soft-locked\n");
                continue;
            }
            Principal *p = pin_lookup(&conn, key);
            if (!p) {
                send_line(&conn, "ERR resolve failed\n");
                continue;
            }
            char msg[64];
            snprintf(msg, sizeof(msg), "OK resolved role=%d\n", uatomic_read(&p->role));
            send_line(&conn, msg);
        } else if (cmd == "ENROLL") {
            uint64_t key = strtoull(arg.c_str(), nullptr, 16);
            if (key_is_locked(key)) {
                send_line(&conn, "ERR key soft-locked\n");
                continue;
            }
            std::string v = issue_voucher(key);
            std::string out = "VOUCHER " + v + "\n";
            send_line(&conn, out.c_str());
        } else if (cmd == "UPGRADE") {
            uint64_t vkey = 0;
            int vrole = -1;
            if (verify_voucher(arg, &vkey, &vrole) != 0) {
                conn.strikes++;
                usleep(150000);
                if (conn.strikes >= STRIKE_LIMIT) {
                    if (conn.resolved_key)
                        lock_key(conn.resolved_key);
                    send_line(&conn, "ERR tamper limit, connection dropped\n");
                    break;
                }
                send_line(&conn, "ERR voucher rejected\n");
                continue;
            }
            if (vrole != ROLE_USER) {
                send_line(&conn, "ERR privilege tier not issuable\n");
                continue;
            }
            if (key_is_locked(vkey)) {
                send_line(&conn, "ERR key soft-locked\n");
                continue;
            }
            resolve_key(vkey);
            if (promote_key(vkey)) {
                conn.authed_user = true;
                send_line(&conn, "OK upgraded role=1\n");
            } else {
                send_line(&conn, "ERR promotion busy\n");
            }
        } else if (cmd == "WHOAMI") {
            Principal *p = resolve_pinned(&conn);
            if (!p) {
                send_line(&conn, "ERR resolve first\n");
                continue;
            }
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "role=%d handler=0x%lx session=0x%lx label=%s\n",
                     p->role, (unsigned long)p->render, (unsigned long)p, p->label);
            send(conn.fd, msg, strlen(msg), MSG_NOSIGNAL);
        } else if (cmd == "STORE") {
            std::vector<unsigned char> bytes;
            if (!parse_hex(arg, bytes) || bytes.size() > SLOT_SIZE) {
                send_line(&conn, "ERR bad payload\n");
                continue;
            }
            void *buf = slab_alloc();
            if (!buf) {
                send_line(&conn, "ERR alloc failed\n");
                continue;
            }
            memset(buf, 0, SLOT_SIZE);
            memcpy(buf, bytes.data(), bytes.size());
            if (conn.blob)
                slab_release(conn.blob);
            conn.blob = buf;
            conn.blob_len = bytes.size();
            char msg[48];
            snprintf(msg, sizeof(msg), "OK stored %zu\n", bytes.size());
            send_line(&conn, msg);
        } else if (cmd == "RENDER") {
            Principal *p = resolve_pinned(&conn);
            if (!p) {
                send_line(&conn, "ERR resolve first\n");
                continue;
            }
            p->render(p, &conn);
        } else if (cmd == "PING") {
            urcu_memb_read_lock();
            urcu_memb_read_unlock();
            urcu_memb_quiescent_state();
            send_line(&conn, "PONG\n");
        } else if (cmd == "QUIT") {
            break;
        } else if (cmd.empty()) {
            continue;
        } else {
            send_line(&conn, "ERR unknown command\n");
        }
    }

    if (conn.blob)
        slab_release(conn.blob);
    close(fd);
    urcu_memb_unregister_thread();
    g_active_workers.fetch_sub(1);
}

static void load_flag()
{
    const char *f = getenv("FLAG");
    if (f && strlen(f) > 0 && strlen(f) < sizeof(g_flag)) {
        strncpy(g_flag, f, sizeof(g_flag) - 1);
    } else {
        strncpy(g_flag, "flag unavailable", sizeof(g_flag) - 1);
    }
    unsetenv("FLAG");
}

int main()
{
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, nullptr, _IONBF, 0);

    if (sodium_init() < 0) {
        fprintf(stderr, "sodium init failed\n");
        return 1;
    }
    crypto_sign_keypair(g_sign_pk, g_sign_sk);
    load_flag();

    urcu_memb_init();
    g_table = cds_lfht_new_flavor(16, 16, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, &urcu_memb_flavor, nullptr);
    if (!g_table) {
        fprintf(stderr, "table alloc failed\n");
        return 1;
    }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    listen(srv, 32);

    while (true) {
        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        int fd = accept(srv, (struct sockaddr *)&cli, &clilen);
        if (fd < 0)
            continue;
        if (g_active_workers.load() >= MAX_WORKERS) {
            const char *busy = "ERR server at capacity\n";
            send(fd, busy, strlen(busy), MSG_NOSIGNAL);
            close(fd);
            continue;
        }
        g_active_workers.fetch_add(1);
        std::thread(handle_conn, fd).detach();
    }
    return 0;
}
