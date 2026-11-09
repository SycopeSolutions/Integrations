#!/usr/bin/env python3
"""
ixflow_replay.py - loop an IPFIX export (Keysight/Ixia IxFlow, PEN 3054) from a pcap file.

Demo/lab tool: turns a static IxFlow pcap into a continuous live flow stream with
timestamps rewritten to "now". No pcap is shipped - use your own IxFlow capture.
Requires only the Python 3.8+ standard library.

Usage:
  python3 ixflow_replay.py prep capture.pcap -o ixflow.cache
  python3 ixflow_replay.py run -c ixflow.cache --dst <sycope-ip> \\
      --remap-ie 3054:176=232 --remap-ie 3054:177=299

Two modes:
  prep  - one-off: pcap -> .cache (IP defragmentation, index of timestamp fields)
  run   - loop: send IPFIX datagrams to the collector, rewriting timestamps to
          "now" while keeping the original pacing and a continuous sequenceNumber.

Rewritten fields:
  - IPFIX header: exportTime (offset 4), sequenceNumber (offset 8)
  - data records: IE 152 flowStartMilliseconds, IE 153 flowEndMilliseconds

Templates (Template Set 2 / Options Template Set 3) are sent at the start of every
loop and then every --template-interval seconds.

Why --remap-ie 3054:176=232 --remap-ie 3054:177=299: IxFlow sends server->client
bytes/packets as 3054:176/177. Sycope ignores the PEN, and IE 176-179 collide with
the built-in ICMP type/code fields, so those counters would be lost. Remapping them
in the templates to IANA responderOctets (232) / responderPackets (299) lets Sycope
store them. Record data is not changed.
"""

import argparse, collections, os, pickle, socket, struct, sys, time

IPFIX_VER = 10
TS_IES = {(0, 152), (0, 153)}          # 8-byte absolute timestamps in ms


# --------------------------------------------------------------------------- prep

def iter_pcap(path):
    with open(path, 'rb') as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise SystemExit('pcap file too short')
        magic = gh[:4]
        if magic == b'\xd4\xc3\xb2\xa1':
            endian, nano = '<', False
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian, nano = '>', False
        elif magic == b'\x4d\x3c\xb2\xa1':
            endian, nano = '<', True
        elif magic == b'\xa1\xb2\x3c\x4d':
            endian, nano = '>', True
        else:
            raise SystemExit('unsupported format (pcapng? use: editcap -F pcap in.pcapng out.pcap)')
        linktype = struct.unpack(endian + 'I', gh[20:24])[0]
        if linktype != 1:
            raise SystemExit('expected Ethernet (linktype 1), got %d' % linktype)
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            ts, sub, incl, orig = struct.unpack(endian + 'IIII', ph)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield ts + (sub / 1e9 if nano else sub / 1e6), data


def udp_datagrams(path, want_port):
    """Yield (t, src, dst, sport, dport, payload), with IPv4 defragmentation."""
    frags = collections.defaultdict(dict)
    for t, d in iter_pcap(path):
        if len(d) < 14:
            continue
        et = struct.unpack('>H', d[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8) and len(d) >= off + 4:
            et = struct.unpack('>H', d[off + 2:off + 4])[0]
            off += 4
        if et != 0x0800:
            continue
        ip = d[off:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ihl = (ip[0] & 0xF) * 4
        tot = struct.unpack('>H', ip[2:4])[0]
        ipid = struct.unpack('>H', ip[4:6])[0]
        ff = struct.unpack('>H', ip[6:8])[0]
        mf, fo = (ff >> 13) & 1, (ff & 0x1FFF) * 8
        if ip[9] != 17:
            continue
        src = '.'.join(map(str, ip[12:16]))
        dst = '.'.join(map(str, ip[16:20]))
        body = ip[ihl:tot]
        if mf == 0 and fo == 0:
            buf = body
        else:
            key = (src, dst, ipid)
            frags[key][fo] = body
            if mf:
                continue
            parts = frags.pop(key)
            buf = b''.join(parts[o] for o in sorted(parts))
        if len(buf) < 8:
            continue
        sp, dp, ul, _ = struct.unpack('>HHHH', buf[:8])
        if want_port and dp != want_port:
            continue
        yield t, src, dst, sp, dp, buf[8:ul]


def _vlen(buf, declared):
    """Return (prefix length, value length) for a field with the given declared length."""
    if declared != 0xFFFF:
        return 0, declared
    n = buf[0]
    if n == 255:
        return 3, struct.unpack('>H', buf[1:3])[0]
    return 1, n


def scan(args, templates, tmpl_raw, build):
    """One pass over the pcap. First pass (build=False) collects templates, second indexes data."""
    records = []
    t0 = e0 = None
    stats = collections.Counter()

    for t, src, dst, sp, dp, p in udp_datagrams(args.pcap, args.port):
        if len(p) < 16 or struct.unpack('>H', p[:2])[0] != IPFIX_VER:
            stats['not-ipfix'] += 1
            continue
        _, mlen, etime, seq, dom = struct.unpack('>HHIII', p[:16])
        if mlen > len(p):
            stats['truncated'] += 1
            continue
        if t0 is None:
            t0, e0 = t, etime
        ts_offsets, nrec, has_tmpl = [], 0, False
        o = 16
        while o + 4 <= mlen:
            sid, slen = struct.unpack('>HH', p[o:o + 4])
            if slen < 4:
                break
            body, bbase = p[o + 4:o + slen], o + 4
            if sid in (2, 3):
                has_tmpl = True
                b = 0
                while b + 4 <= len(body):
                    start = b
                    tid, cnt = struct.unpack('>HH', body[b:b + 4]); b += 4
                    if sid == 3:
                        b += 2            # scope field count
                    fields = []
                    for _ in range(cnt):
                        if b + 4 > len(body):
                            break
                        ie, fl = struct.unpack('>HH', body[b:b + 4]); b += 4
                        pen = 0
                        if ie & 0x8000:
                            pen = struct.unpack('>I', body[b:b + 4])[0]; b += 4
                            ie &= 0x7FFF
                        fields.append((pen, ie, fl))
                    templates[(dom, tid)] = fields
                    tmpl_raw[(dom, tid)] = (sid, body[start:b])
            elif sid >= 256:
                fields = templates.get((dom, sid))
                if fields is None:
                    stats['data-no-template'] += 1
                else:
                    b = 0
                    while b + 4 <= len(body):
                        rstart = b
                        for pen, ie, fl in fields:
                            pre, ln = _vlen(body[b:], fl)
                            if (pen, ie) in TS_IES and ln == 8:
                                ts_offsets.append(bbase + b + pre)
                            b += pre + ln
                        if b > len(body):
                            b = rstart
                            break
                        nrec += 1
            o += slen
        if build:
            records.append({'t': t - t0, 'export': etime, 'data': bytes(p[:mlen]),
                            'ts': ts_offsets, 'n': nrec})
        stats['datagrams'] += 1
        stats['records'] += nrec

    return records, e0, stats


def prep(args):
    templates, tmpl_raw = {}, {}
    scan(args, templates, tmpl_raw, build=False)          # pass 1: templates only
    records, e0, stats = scan(args, templates, tmpl_raw, build=True)   # pass 2: data index

    if not records:
        raise SystemExit('no IPFIX datagrams found on port %d' % args.port)

    # synthetic template-only messages: one set per message (no IP fragmentation)
    tmpl_msgs = []
    for (dom, tid), (sid, raw) in sorted(tmpl_raw.items()):
        setbytes = struct.pack('>HH', sid, 4 + len(raw)) + raw
        msg = bytearray(struct.pack('>HHIII', IPFIX_VER, 16 + len(setbytes), 0, 0, dom) + setbytes)
        tmpl_msgs.append({'dom': dom, 'tid': tid, 'data': msg})

    cache = {'records': records, 'templates': tmpl_msgs, 'e0': e0,
             'span': records[-1]['t'], 'nrec': stats['records'],
             'ies': sorted({(p_, i) for f in templates.values() for p_, i, _ in f})}
    with open(args.cache, 'wb') as f:
        pickle.dump(cache, f, protocol=4)

    print('pcap            : %s' % args.pcap)
    print('IPFIX datagrams : %d' % stats['datagrams'])
    print('flow records    : %d  (%.1f flows/s)' % (stats['records'], stats['records'] / cache['span']))
    print('loop length     : %.1f s' % cache['span'])
    print('templates       : %s' % ', '.join(str(m['tid']) for m in tmpl_msgs))
    print('PEN fields      : %s' % sorted({p_ for p_, _ in cache['ies'] if p_}))
    print('with timestamps : %d datagrams contain IE 152/153' % sum(1 for r in records if r['ts']))
    for k, v in stats.items():
        if k.startswith(('not-', 'trunc', 'data-')):
            print('warning: %s = %d' % (k, v))
    print('\ncache: %s (%.1f MB)' % (args.cache, os.path.getsize(args.cache) / 1e6))


# --------------------------------------------------------------------------- run

class RawSender:
    """Send with a spoofed source address (requires root, Linux only)."""
    def __init__(self, src, sport, dst, dport):
        self.src, self.sport, self.dst, self.dport = src, sport, dst, dport
        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sa, self.da = socket.inet_aton(src), socket.inet_aton(dst)
        self.ipid = 0

    def send(self, payload):
        udp = struct.pack('>HHHH', self.sport, self.dport, 8 + len(payload), 0) + payload
        self.ipid = (self.ipid + 1) & 0xFFFF
        tot = 20 + len(udp)
        hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, tot, self.ipid, 0x4000, 64, 17, 0,
                          self.sa, self.da)
        c = 0
        for i in range(0, 20, 2):
            c += struct.unpack('>H', hdr[i:i + 2])[0]
        c = (c & 0xFFFF) + (c >> 16)
        hdr = hdr[:10] + struct.pack('>H', ~c & 0xFFFF) + hdr[12:]
        self.s.sendto(hdr + udp, (self.dst, 0))


class UdpSender:
    def __init__(self, src, sport, dst, dport):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 21)
        if src or sport:
            self.s.bind((src or '0.0.0.0', sport or 0))
        self.dst = (dst, dport)

    def send(self, payload):
        self.s.sendto(payload, self.dst)


def parse_remap(specs):
    """'3054:176=232' -> {(3054, 176): (0, 232)}; the target may also carry a PEN: '3054:176=29305:1'."""
    out = {}
    for s in specs or []:
        src, dst = s.split('=')
        sp, si = src.split(':') if ':' in src else ('0', src)
        dp, di = dst.split(':') if ':' in dst else ('0', dst)
        out[(int(sp), int(si))] = (int(dp), int(di))
    return out


def remap_template_msg(msg, remap):
    """Rewrite field IDs in a message holding a single template set (2 or 3).
    Field lengths do not change, so the byte layout of data records stays the same;
    only the template itself changes length (a PEN field spec is 8 B, a non-PEN one 4 B)."""
    dom = struct.unpack('>I', msg[12:16])[0]
    sid = struct.unpack('>H', msg[16:18])[0]
    body = bytes(msg[20:])
    out, b, hits = bytearray(), 0, 0
    while b + 4 <= len(body):
        tid, cnt = struct.unpack('>HH', body[b:b + 4])
        out += body[b:b + 4]; b += 4
        if sid == 3:
            out += body[b:b + 2]; b += 2
        for _ in range(cnt):
            ie, fl = struct.unpack('>HH', body[b:b + 4]); b += 4
            pen = 0
            if ie & 0x8000:
                pen = struct.unpack('>I', body[b:b + 4])[0]; b += 4
                ie &= 0x7FFF
            if (pen, ie) in remap:
                pen, ie = remap[(pen, ie)]; hits += 1
            if pen:
                out += struct.pack('>HHI', ie | 0x8000, fl, pen)
            else:
                out += struct.pack('>HH', ie, fl)
    setbytes = struct.pack('>HH', sid, 4 + len(out)) + out
    new = bytearray(struct.pack('>HHIII', IPFIX_VER, 16 + len(setbytes), 0, 0, dom) + setbytes)
    return new, hits


# --------------------------------------------------------------------------- mirror (virtual router)
#
# A second exporter ("edge router") sends the same sessions as IxFlow, but using IANA fields only
# and adding information the probe does not have: ingress/egress interfaces, access VLAN, next hop.
# The collector (Sycope) merges both exporters' records of the same session into one
# (exporterIps = [router, probe]).

MIRROR_TID = 256
# (IE, length) - order = record byte layout
MIRROR_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 2), (1, 8), (2, 8), (232, 8), (299, 8),
                 (152, 8), (153, 8), (10, 4), (14, 4), (58, 2), (15, 4), (16, 4), (17, 4), (136, 1)]
MIRROR_REC_LEN = sum(l for _, l in MIRROR_FIELDS)
# access side chosen by client country (3054:120), uplink by server country (3054:140)
ACCESS_IF = {b'TH': (11, 111), b'JP': (12, 112)}            # ifIndex, VLAN
ACCESS_DEFAULT = (13, 113)
UPLINK_IF = {b'TH': (1, '203.0.113.1'), b'CN': (2, '198.51.100.1')}
UPLINK_DEFAULT = (3, '192.0.2.1')
CLIENT_NET = ('1.1.0.0', 16)                                 # IxFlow client range in the sample


def _parse_templates(tmsgs):
    defs = {}
    for m in tmsgs:
        b = bytes(m['data'])
        sid = struct.unpack('>H', b[16:18])[0]
        body, x = b[20:], 0
        tid, cnt = struct.unpack('>HH', body[:4]); x = 4
        if sid == 3:
            x += 2
        f = []
        for _ in range(cnt):
            ie, fl = struct.unpack('>HH', body[x:x + 4]); x += 4
            pen = 0
            if ie & 0x8000:
                pen = struct.unpack('>I', body[x:x + 4])[0]; x += 4
                ie &= 0x7FFF
            f.append((pen, ie, fl))
        defs[tid] = (sid, f)
    return defs


def mirror_template():
    body = struct.pack('>HH', MIRROR_TID, len(MIRROR_FIELDS)) + b''.join(
        struct.pack('>HH', ie, l) for ie, l in MIRROR_FIELDS)
    s = struct.pack('>HH', 2, 4 + len(body)) + body
    return bytearray(struct.pack('>HHIII', IPFIX_VER, 16 + len(s), 0, 0, 0) + s)


def build_mirror(recs, tmsgs, max_per_msg=15):
    """For each cached datagram: list of (message, ts offsets, record count) for the router."""
    defs = _parse_templates(tmsgs)
    net = struct.unpack('>I', socket.inet_aton(CLIENT_NET[0]))[0]
    mask = (0xFFFFFFFF << (32 - CLIENT_NET[1])) & 0xFFFFFFFF
    out, nrec = [], 0
    for r in recs:
        p = r['data']; ml = struct.unpack('>H', p[2:4])[0]; o = 16
        rows = []
        while o + 4 <= ml:
            sid, sl = struct.unpack('>HH', p[o:o + 4]); body = p[o + 4:o + sl]; o += sl
            if sid < 256 or sid not in defs or defs[sid][0] != 2:
                continue
            fields = defs[sid][1]
            if (0, 8) not in {(pe, ie) for pe, ie, _ in fields}:
                continue                        # IPv4 templates with addresses only
            b = 0
            while b < len(body):
                st, v = b, {}
                for pen, ie, fl in fields:
                    pre, ln = _vlen(body[b:], fl)
                    v[(pen, ie)] = body[b + pre:b + pre + ln]; b += pre + ln
                if b > len(body) or b == st:
                    break
                rows.append(v)
        msgs = []
        for i in range(0, len(rows), max_per_msg):
            chunk, recb, ts = rows[i:i + max_per_msg], bytearray(), []
            for v in chunk:
                g = lambda k, n: (v.get(k, b'') or b'').rjust(n, b'\0')[-n:]
                src = g((0, 8), 4)
                client_is_src = (struct.unpack('>I', src)[0] & mask) == net
                ccc = (v.get((3054, 120)) or b'')[:2]
                scc = (v.get((3054, 140)) or b'')[:2]
                acc_if, vlan = ACCESS_IF.get(ccc, ACCESS_DEFAULT)
                up_if, nh = UPLINK_IF.get(scc, UPLINK_DEFAULT)
                i_if, o_if = (acc_if, up_if) if client_is_src else (up_if, acc_if)
                base = 16 + 4 + len(recb)
                vals = {8: src, 12: g((0, 12), 4), 7: g((0, 7), 2), 11: g((0, 11), 2), 4: g((0, 4), 1),
                        6: g((0, 6), 2), 1: g((0, 1), 8), 2: g((0, 2), 8),
                        232: g((3054, 176), 8), 299: g((3054, 177), 8),
                        152: g((0, 152), 8), 153: g((0, 153), 8),
                        10: struct.pack('>I', i_if), 14: struct.pack('>I', o_if), 58: struct.pack('>H', vlan),
                        15: socket.inet_aton(nh), 16: g((0, 16), 4), 17: g((0, 17), 4), 136: g((0, 136), 1)}
                off = 0
                for ie, l in MIRROR_FIELDS:
                    if ie in (152, 153):
                        ts.append(base + off)
                    off += l
                recb += b''.join(vals[ie] for ie, _ in MIRROR_FIELDS)
            s = struct.pack('>HH', MIRROR_TID, 4 + len(recb)) + recb
            msgs.append((bytearray(struct.pack('>HHIII', IPFIX_VER, 16 + len(s), 0, 0, 0) + s), ts, len(chunk)))
            nrec += len(chunk)
        out.append(msgs)
    return out, nrec


def run(args):
    with open(args.cache, 'rb') as f:
        c = pickle.load(f)
    recs, tmsgs, e0, span = c['records'], c['templates'], c['e0'], c['span']

    mirror = msender = None
    if args.mirror_src:
        mirror, mn = build_mirror(recs, tmsgs)       # from the original templates (before --remap-ie)
        mtmpl = mirror_template()
        msender = UdpSender(args.mirror_src, 0, args.dst, args.dport)
        mseq = 0
        print('mirror: router %s -> %s:%d, %d records/loop (template %d, %d B/record)'
              % (args.mirror_src, args.dst, args.dport, mn, MIRROR_TID, MIRROR_REC_LEN), flush=True)

    remap = parse_remap(args.remap_ie)
    if remap:
        total = 0
        for m in tmsgs:
            m['data'], h = remap_template_msg(m['data'], remap)
            total += h
        print('remap-ie: %s -> replaced %d template fields'
              % (', '.join('%d:%d=%d:%d' % (k + v) for k, v in remap.items()), total), flush=True)

    S = RawSender if args.spoof else UdpSender
    sender = S(args.spoof or args.bind, args.sport, args.dst, args.dport)

    seq = 0                       # sequenceNumber: number of data records sent, continuous across loops
    loop = 0
    sent_dg = sent_rec = 0
    t_report = time.time()
    print('-> %s:%d   source=%s   loop=%.1fs   %d datagrams / %d records'
          % (args.dst, args.dport, args.spoof or args.bind or 'auto', span,
             len(recs), c['nrec']), flush=True)

    try:
        while args.loops == 0 or loop < args.loops:
            loop += 1
            wall0 = time.time()
            # The original time axis is mapped affinely onto the current time:
            #   new_ms = base_ms + (original_ms - e0*1000) * speed
            # so with --speed != 1 record timestamps compress exactly like the
            # sending pace and never get ahead of the clock.
            base_ms = (wall0 - args.lag) * 1000.0
            org0_ms = e0 * 1000.0
            sp = args.speed
            remap = lambda ms: int(base_ms + (ms - org0_ms) * sp)
            next_tmpl = 0.0

            for ri, r in enumerate(recs):
                due = wall0 + r['t'] * sp
                d = due - time.time()
                if d > 0:
                    time.sleep(d)

                # periodic template refresh
                if r['t'] >= next_tmpl:
                    now_s = remap(r['export'] * 1000.0) // 1000
                    for m in tmsgs:
                        b = m['data']
                        struct.pack_into('>II', b, 4, now_s & 0xFFFFFFFF, seq & 0xFFFFFFFF)
                        sender.send(bytes(b))
                        sent_dg += 1
                    if msender:
                        struct.pack_into('>II', mtmpl, 4, now_s & 0xFFFFFFFF, mseq & 0xFFFFFFFF)
                        msender.send(bytes(mtmpl))
                    next_tmpl = r['t'] + args.template_interval

                b = bytearray(r['data'])          # copy: the cache stays untouched
                struct.pack_into('>II', b, 4,
                                 (remap(r['export'] * 1000.0) // 1000) & 0xFFFFFFFF,
                                 seq & 0xFFFFFFFF)
                for off in r['ts']:
                    v = remap(int.from_bytes(b[off:off + 8], 'big'))
                    b[off:off + 8] = v.to_bytes(8, 'big')
                sender.send(bytes(b))
                if msender:
                    exp = (remap(r['export'] * 1000.0) // 1000) & 0xFFFFFFFF
                    for mm, mts, mn in mirror[ri]:
                        mb = bytearray(mm)
                        struct.pack_into('>II', mb, 4, exp, mseq & 0xFFFFFFFF)
                        for off in mts:
                            mb[off:off + 8] = remap(int.from_bytes(mb[off:off + 8], 'big')).to_bytes(8, 'big')
                        msender.send(bytes(mb))
                        mseq = (mseq + mn) & 0xFFFFFFFF
                seq = (seq + r['n']) & 0xFFFFFFFF
                sent_dg += 1
                sent_rec += r['n']

                if time.time() - t_report >= args.report:
                    print('[loop %d] %6.1fs/%.0fs  datagrams=%d  records=%d  seq=%d'
                          % (loop, r['t'], span, sent_dg, sent_rec, seq), flush=True)
                    t_report = time.time()

            if args.gap:
                time.sleep(args.gap)
    except KeyboardInterrupt:
        print('\nstopped: loops=%d datagrams=%d records=%d' % (loop, sent_dg, sent_rec))


# --------------------------------------------------------------------------- cli

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('prep', help='pcap -> cache')
    p.add_argument('pcap')
    p.add_argument('-o', '--cache', default='ixflow.cache')
    p.add_argument('--port', type=int, default=2055, help='export destination port in the pcap (0 = any)')
    p.set_defaults(func=prep)

    r = sub.add_parser('run', help='replay to the collector in a loop')
    r.add_argument('-c', '--cache', default='ixflow.cache')
    r.add_argument('--dst', required=True, help='Sycope collector IP')
    r.add_argument('--dport', type=int, default=2055)
    r.add_argument('--bind', default='', help='local source address')
    r.add_argument('--sport', type=int, default=0, help='local source port (0 = random)')
    r.add_argument('--spoof', default='', help='spoof the source IP (raw socket, requires root)')
    r.add_argument('--speed', type=float, default=1.0, help='time multiplier; <1 = faster')
    r.add_argument('--lag', type=float, default=2.0,
                   help='shift back in seconds so that no timestamp lands in the future')
    r.add_argument('--loops', type=int, default=0, help='0 = forever')
    r.add_argument('--gap', type=float, default=0.0, help='pause between loops in seconds')
    r.add_argument('--template-interval', type=float, default=30.0)
    r.add_argument('--report', type=float, default=30.0)
    r.add_argument('--remap-ie', action='append', metavar='PEN:IE=IE',
                   help='replace a field ID in the templates, e.g. 3054:176=232 '
                        '(repeatable); record data unchanged')
    r.add_argument('--mirror-src', default='',
                   help='IP of a virtual edge router that sends the same sessions using IANA fields '
                        '(interfaces, VLAN, next hop); the address must be assigned to this host')
    r.set_defaults(func=run)

    a = ap.parse_args()
    a.func(a)


if __name__ == '__main__':
    main()
