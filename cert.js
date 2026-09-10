'use strict';
// Goa Scan — lecture d'un certificat X.509 encodé en DER (base64).
// Décodeur ASN.1 minimal : uniquement les champs utiles à l'audit.
(function (root) {
  const NAME_OID = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST' };
  const SIG_OID = {
    '1.2.840.113549.1.1.4': 'md5WithRSA', '1.2.840.113549.1.1.5': 'sha1WithRSA',
    '1.2.840.113549.1.1.11': 'sha256WithRSA', '1.2.840.113549.1.1.12': 'sha384WithRSA',
    '1.2.840.113549.1.1.13': 'sha512WithRSA', '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.10045.4.1': 'ecdsaWithSHA1', '1.2.840.10045.4.3.2': 'ecdsaWithSHA256',
    '1.2.840.10045.4.3.3': 'ecdsaWithSHA384', '1.2.840.10045.4.3.4': 'ecdsaWithSHA512',
    '1.3.101.112': 'Ed25519',
  };
  const CURVES = { '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521' };
  const CURVE_BITS = { 'P-256': 256, 'P-384': 384, 'P-521': 521 };
  // Politiques du CA/Browser Forum : niveau de validation du titulaire.
  const POLICY = { '2.23.140.1.1': 'EV', '2.23.140.1.2.1': 'DV', '2.23.140.1.2.2': 'OV', '2.23.140.1.2.3': 'IV' };

  function bytes(b64) {
    const s = atob(b64);
    const u = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
    return u;
  }

  function tlv(b, pos) {
    const tag = b[pos];
    let len = b[pos + 1];
    let start = pos + 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) throw new Error('longueur DER invalide');
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + b[start + i];
      start += n;
    }
    if (start + len > b.length) throw new Error('DER tronqué');
    return { tag, start, end: start + len };
  }

  function children(b, node) {
    const out = [];
    for (let p = node.start; p < node.end;) {
      const c = tlv(b, p);
      out.push(c);
      p = c.end;
    }
    return out;
  }

  function oid(b, n) {
    const v = b.subarray(n.start, n.end);
    const parts = v[0] >= 80 ? [2, v[0] - 80] : [Math.floor(v[0] / 40), v[0] % 40];
    let acc = 0;
    for (let i = 1; i < v.length; i++) {
      acc = acc * 128 + (v[i] & 0x7f);
      if (!(v[i] & 0x80)) { parts.push(acc); acc = 0; }
    }
    return parts.join('.');
  }

  function text(b, n) {
    const v = b.subarray(n.start, n.end);
    if (n.tag === 0x1e) { // BMPString
      let s = '';
      for (let i = 0; i + 1 < v.length; i += 2) s += String.fromCharCode((v[i] << 8) | v[i + 1]);
      return s;
    }
    return new TextDecoder(n.tag === 0x0c ? 'utf-8' : 'latin1').decode(v);
  }

  function dname(b, n) {
    const parts = {};
    const dn = [];
    for (const set of children(b, n)) {
      for (const atv of children(b, set)) {
        const [type, value] = children(b, atv);
        const key = NAME_OID[oid(b, type)];
        if (!key || key in parts) continue;
        parts[key] = text(b, value);
        dn.push(`${key}=${parts[key]}`);
      }
    }
    return { cn: parts.CN || '', o: parts.O || '', dn: dn.join(', ') };
  }

  function time(b, n) {
    let s = new TextDecoder().decode(b.subarray(n.start, n.end));
    if (n.tag === 0x17) s = (Number(s.slice(0, 2)) >= 50 ? '19' : '20') + s; // UTCTime
    return Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12), +(s.slice(12, 14) || 0));
  }

  function intBits(b, n) {
    let i = n.start;
    while (i < n.end && b[i] === 0) i++;
    return i >= n.end ? 0 : (n.end - i - 1) * 8 + (32 - Math.clz32(b[i]));
  }

  const hex = (v) => Array.from(v, (x) => x.toString(16).padStart(2, '0')).join(':').toUpperCase();

  function publicKey(b, spki) {
    const [alg, bits] = children(b, spki);
    const [algOid, params] = children(b, alg);
    const o = oid(b, algOid);
    if (o === '1.2.840.113549.1.1.1') {
      const [modulus] = children(b, tlv(b, bits.start + 1)); // +1 : octet des bits inutilisés
      return { type: 'RSA', bits: intBits(b, modulus) };
    }
    if (o === '1.2.840.10045.2.1') {
      const curve = params?.tag === 0x06 ? (CURVES[oid(b, params)] || oid(b, params)) : '?';
      return { type: 'EC', curve, bits: CURVE_BITS[curve] || 0 };
    }
    if (o === '1.3.101.112') return { type: 'Ed25519', bits: 256 };
    return { type: o, bits: 0 };
  }

  function ipv6(v) {
    const g = [];
    for (let i = 0; i + 1 < v.length; i += 2) g.push(((v[i] << 8) | v[i + 1]).toString(16));
    return g.join(':');
  }

  function extensions(b, seq, out) {
    for (const ext of children(b, seq)) {
      const parts = children(b, ext);
      const id = oid(b, parts[0]);
      const value = () => tlv(b, parts[parts.length - 1].start); // contenu de l'OCTET STRING
      if (id === '2.5.29.17') {
        for (const gn of children(b, value())) {
          const v = b.subarray(gn.start, gn.end);
          if (gn.tag === 0x82) out.san.push(new TextDecoder().decode(v));
          else if (gn.tag === 0x87) out.san.push(v.length === 4 ? v.join('.') : ipv6(v));
        }
      } else if (id === '2.5.29.19') {
        const c = children(b, value());
        out.isCA = c.length > 0 && c[0].tag === 0x01 && b[c[0].start] !== 0;
      } else if (id === '2.5.29.32') {
        for (const info of children(b, value())) {
          const level = POLICY[oid(b, children(b, info)[0])];
          if (level) out.validation = level;
        }
      } else if (id === '1.3.6.1.4.1.11129.2.4.2') {
        out.sct = true; // Certificate Transparency : SCT intégrés
      }
    }
  }

  function parseCertificate(b64) {
    const b = bytes(b64);
    const [tbs, sigAlg] = children(b, tlv(b, 0));
    const f = children(b, tbs);
    let i = f[0].tag === 0xa0 ? 1 : 0; // version explicite
    const serial = f[i++];
    i++; // algorithme de signature, répété dans le TBS
    const issuer = dname(b, f[i++]);
    const [notBefore, notAfter] = children(b, f[i++]);
    const subject = dname(b, f[i++]);
    const spki = f[i++];

    const out = {
      subject, issuer,
      serial: hex(b.subarray(serial.start, serial.end)).replace(/^00:/, ''),
      notBefore: time(b, notBefore), notAfter: time(b, notAfter),
      sigAlg: (() => { const o = oid(b, children(b, sigAlg)[0]); return SIG_OID[o] || o; })(),
      key: publicKey(b, spki),
      san: [], isCA: false, validation: null, sct: false,
    };
    for (; i < f.length; i++) if (f[i].tag === 0xa3) extensions(b, children(b, f[i])[0], out);
    out.selfSigned = out.subject.dn === out.issuer.dn;
    return out;
  }

  async function fingerprint(b64) {
    return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(b64))));
  }

  const api = { parseCertificate, fingerprint };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GoaCert = api;
})(globalThis);
