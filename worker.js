/**
 * KBL Push Notification Worker
 *
 * 【事前準備】
 * 1. Cloudflareダッシュボードで新規Workerを作成し、このコードを貼り付ける
 * 2. KV Namespace を1つ作成し（例: KBL_PUSH_SUBSCRIPTIONS）、Workerの
 *    「設定 > 変数とシークレット」からバインディング名 KBL_PUSH_SUBSCRIPTIONS として紐付ける
 * 3. 環境変数（シークレット推奨）を設定する
 *      NOTIFY_SECRET       … GAS からの通知リクエストを認証する合言葉（自分で決めてよい）
 *      VAPID_PUBLIC_KEY    … 別途生成したVAPID公開鍵
 *      VAPID_PRIVATE_KEY   … 別途生成したVAPID秘密鍵
 *      VAPID_SUBJECT       … "mailto:自分のメールアドレス"
 * 4. デプロイ後、発行されたWorkerのURL（例: https://kbl-push.xxxx.workers.dev）を
 *    index.html の PUSH_WORKER_URL に設定する
 *
 * 【エンドポイント】
 *   POST /subscribe   { worker, subscription }        … 職人の端末をプッシュ購読登録
 *   POST /notify       { worker: "山田" or "all", title, body }
 *                       ヘッダー x-notify-secret が必須（GAS側から呼ぶ）
 */

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === "/subscribe" && request.method === "POST") {
        const { worker, subscription } = await request.json();
        if (!worker || !subscription) {
          return withCors(jsonResponse({ result: "error", message: "missing fields" }, 400));
        }
        await env.KBL_PUSH_SUBSCRIPTIONS.put("sub:" + worker, JSON.stringify(subscription));
        return withCors(jsonResponse({ result: "ok" }));
      }

      if (url.pathname === "/notify" && request.method === "POST") {
        const secret = request.headers.get("x-notify-secret");
        if (secret !== env.NOTIFY_SECRET) {
          return withCors(jsonResponse({ result: "error", message: "unauthorized" }, 401));
        }
        const { worker, title, body } = await request.json();

        const subs = [];
        if (worker === "all") {
          const list = await env.KBL_PUSH_SUBSCRIPTIONS.list({ prefix: "sub:" });
          for (const k of list.keys) {
            const v = await env.KBL_PUSH_SUBSCRIPTIONS.get(k.name);
            if (v) subs.push(JSON.parse(v));
          }
        } else {
          const v = await env.KBL_PUSH_SUBSCRIPTIONS.get("sub:" + worker);
          if (v) subs.push(JSON.parse(v));
        }

        let sent = 0;
        const errors = [];
        for (const sub of subs) {
          try {
            await sendWebPush(sub, JSON.stringify({ title, body }), env);
            sent++;
          } catch (e) {
            errors.push(e.message);
          }
        }
        return withCors(jsonResponse({ result: "ok", sent, total: subs.length, errors }));
      }

      return withCors(jsonResponse({ result: "error", message: "not found" }, 404));
    } catch (e) {
      return withCors(jsonResponse({ result: "error", message: e.message }, 500));
    }
  }
};

function withCors(res) {
  res.headers.set("Access-Control-Allow-Origin", "*");
  res.headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.headers.set("Access-Control-Allow-Headers", "Content-Type,x-notify-secret");
  return res;
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

// ===== 以下、Web Push（VAPID + aes128gcm）の実装 =====

async function sendWebPush(subscription, payloadText, env) {
  const endpoint = subscription.endpoint;
  const audience = new URL(endpoint).origin;

  const jwt = await createVapidJwt(audience, env.VAPID_SUBJECT, env.VAPID_PRIVATE_KEY, env.VAPID_PUBLIC_KEY);
  const encrypted = await encryptPayload(subscription, payloadText);

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "Content-Encoding": "aes128gcm",
      "TTL": "60",
      "Authorization": `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`
    },
    body: encrypted
  });

  if (!res.ok && res.status !== 201) {
    throw new Error("push failed: " + res.status + " " + (await res.text()));
  }
}

function base64UrlToUint8Array(base64Url) {
  const padding = "=".repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const arr = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
  return arr;
}

function uint8ArrayToBase64Url(bytes) {
  let str = "";
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

async function createVapidJwt(audience, subject, privateKeyB64, publicKeyB64) {
  const pub = base64UrlToUint8Array(publicKeyB64); // 65 bytes, 0x04||X||Y
  const x = pub.slice(1, 33);
  const y = pub.slice(33, 65);
  const d = privateKeyB64; // 既にbase64url

  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: uint8ArrayToBase64Url(x),
    y: uint8ArrayToBase64Url(y),
    d: d,
    ext: true
  };

  const privateKey = await crypto.subtle.importKey(
    "jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );

  const header = { typ: "JWT", alg: "ES256" };
  const now = Math.floor(Date.now() / 1000);
  const claims = { aud: audience, exp: now + 12 * 3600, sub: subject };

  const encHeader = uint8ArrayToBase64Url(new TextEncoder().encode(JSON.stringify(header)));
  const encClaims = uint8ArrayToBase64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const signingInput = encHeader + "." + encClaims;

  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(signingInput)
  );

  return signingInput + "." + uint8ArrayToBase64Url(new Uint8Array(signature));
}

async function encryptPayload(subscription, payloadText) {
  const uaPublicBytes = base64UrlToUint8Array(subscription.keys.p256dh); // 65 bytes
  const authSecret = base64UrlToUint8Array(subscription.keys.auth);      // 16 bytes

  // 1. サーバー側の使い捨てECDH鍵ペアを生成
  const asKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]
  );
  const asPublicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", asKeyPair.publicKey));

  // 2. 共有鍵を導出
  const uaPublicKey = await crypto.subtle.importKey(
    "raw", uaPublicBytes, { name: "ECDH", namedCurve: "P-256" }, false, []
  );
  const sharedSecretBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: uaPublicKey }, asKeyPair.privateKey, 256
  );

  // 3. HKDF段階1: 共有鍵 + auth_secret から IKM を導出
  const ecdhKeyMaterial = await crypto.subtle.importKey(
    "raw", sharedSecretBits, "HKDF", false, ["deriveBits"]
  );
  const info1 = concatBytes(
    new TextEncoder().encode("WebPush: info\0"),
    uaPublicBytes,
    asPublicBytes
  );
  const ikm = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: authSecret, info: info1 },
    ecdhKeyMaterial, 256
  );

  // 4. HKDF段階2: salt(ランダム16byte) + IKM から CEK / NONCE を導出
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const ikmKeyMaterial = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);

  const cekBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("Content-Encoding: aes128gcm\0") },
    ikmKeyMaterial, 128
  );
  const nonceBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("Content-Encoding: nonce\0") },
    ikmKeyMaterial, 96
  );

  const cek = await crypto.subtle.importKey("raw", cekBits, "AES-GCM", false, ["encrypt"]);

  // 5. 平文に区切りバイト(0x02)を付けて暗号化
  const plaintext = concatBytes(new TextEncoder().encode(payloadText), new Uint8Array([0x02]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(nonceBits) }, cek, plaintext
  ));

  // 6. aes128gcmヘッダー: salt(16) + レコードサイズ(4, BE) + keyid長(1) + keyid(asPublicBytes 65)
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096, false);
  const header = concatBytes(salt, rs, new Uint8Array([asPublicBytes.length]), asPublicBytes);

  return concatBytes(header, ciphertext);
}
