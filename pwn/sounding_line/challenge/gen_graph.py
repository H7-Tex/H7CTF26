import sys
import collections

N = 48
SINKS = [6, 19, 31, 43]
S_STAR = 31
ROV0 = 0
REG0 = 23
CHORDS = 2


def build_graph(seed):
    state = (seed * 2654435761 + 1) & 0xFFFFFFFF
    def rnd():
        nonlocal state
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        return state
    adj = [set() for _ in range(N)]
    for u in range(N):
        adj[u].add((u + 1) % N)
        adj[u].add((u - 1) % N)
    for u in range(N):
        for _ in range(CHORDS):
            v = rnd() % N
            if v != u:
                adj[u].add(v)
    return [sorted(s) for s in adj]


def moves(adj, u):
    return adj[u] + [u]


def attractor(adj, targets, movesets):
    tset = set(targets)
    W = [[False] * N for _ in range(N)]
    changed = True
    while changed:
        changed = False
        for r in range(N):
            mr = movesets[r]
            Wr = W
            for c in range(N):
                if r == c or W[r][c]:
                    continue
                regm = movesets[c]
                regset = set(regm)
                won = False
                for rp in mr:
                    if rp == c or rp in regset:
                        continue
                    if rp in tset:
                        won = True
                        break
                    allok = True
                    Wrp = W[rp]
                    for cp in regm:
                        if not Wrp[cp]:
                            allok = False
                            break
                    if allok:
                        won = True
                        break
                if won:
                    W[r][c] = True
                    changed = True
    return W


def win_depth(adj, targets, movesets):
    tset = set(targets)
    depth = [[None] * N for _ in range(N)]
    changed = True
    while changed:
        changed = False
        for r in range(N):
            mr = movesets[r]
            for c in range(N):
                if r == c or depth[r][c] is not None:
                    continue
                regm = movesets[c]
                regset = set(regm)
                best = None
                for rp in mr:
                    if rp == c or rp in regset:
                        continue
                    if rp in tset:
                        best = 1
                        break
                    worst = 0
                    ok = True
                    for cp in regm:
                        dv = depth[rp][cp]
                        if dv is None:
                            ok = False
                            break
                        if dv > worst:
                            worst = dv
                    if ok and (best is None or worst + 1 < best):
                        best = worst + 1
                if best is not None:
                    depth[r][c] = best
                    changed = True
    return depth


def greedy_reaches(adj, target, movesets):
    dist = {target: 0}
    q = collections.deque([target])
    while q:
        x = q.popleft()
        for u in range(N):
            if x in movesets[u] and u not in dist:
                dist[u] = dist[x] + 1
                q.append(u)
    r, c = ROV0, REG0
    for _ in range(80):
        best, bd = None, 1 << 30
        for rp in movesets[r]:
            if rp == c:
                continue
            d = dist.get(rp, 1 << 30)
            if d < bd:
                bd, best = d, rp
        if best is None:
            return False
        r = best
        regm = movesets[c]
        if r in SINKS and r not in regm:
            return True
        if r in regm:
            return False
        cbest, cd = None, 1 << 30
        for cp in regm:
            dd = dist.get(cp, 1 << 30)
            if dd < cd:
                cd, cbest = dd, cp
        c = cbest
        if c == r:
            return False
    return False


def evaluate(seed):
    adj = build_graph(seed)
    ms = [moves(adj, u) for u in range(N)]
    w = attractor(adj, [S_STAR], ms)
    if not w[ROV0][REG0]:
        return None
    dep = win_depth(adj, [S_STAR], ms)
    d = dep[ROV0][REG0]
    if d is None or d < 6:
        return None
    if greedy_reaches(adj, S_STAR, ms):
        return None
    return adj, d


def find_seed():
    for seed in range(1, 60000):
        r = evaluate(seed)
        if r is not None:
            return seed, r[0], r[1]
    return None, None, None


SEED = 45

if __name__ == "__main__":
    seed = SEED
    adj = build_graph(seed)
    ms = [moves(adj, u) for u in range(N)]
    w = attractor(adj, [S_STAR], ms)
    if not w[ROV0][REG0]:
        print("locked seed is not a forced win", file=sys.stderr)
        sys.exit(1)
    depth = win_depth(adj, [S_STAR], ms)[ROV0][REG0]
    sys.stderr.write("seed=%d depth=%d\n" % (seed, depth))
    maxdeg = max(len(a) for a in adj)
    out = []
    out.append("#ifndef MANIFOLD_H")
    out.append("#define MANIFOLD_H")
    out.append("#define MANIFOLD_NODES %d" % N)
    out.append("#define ROV_START %d" % ROV0)
    out.append("#define REG_START %d" % REG0)
    out.append("#define MANIFOLD_MAXDEG %d" % maxdeg)
    rows = []
    for u in range(N):
        padded = adj[u] + [-1] * (maxdeg - len(adj[u]))
        rows.append("{" + ",".join(str(x) for x in padded) + "}")
    out.append("static const int manifold_adj[MANIFOLD_NODES][MANIFOLD_MAXDEG] = {")
    out.append(",\n".join(rows))
    out.append("};")
    out.append("static const int manifold_deg[MANIFOLD_NODES] = {%s};" % ",".join(str(len(a)) for a in adj))
    out.append("#define MANIFOLD_NSINKS %d" % len(SINKS))
    out.append("static const int manifold_sinks[MANIFOLD_NSINKS] = {%s};" % ",".join(str(x) for x in SINKS))
    out.append("#endif")
    sys.stdout.write("\n".join(out) + "\n")
