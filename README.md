# LD_PRELOAD CRC (memcached / lighttpd)

LD_PRELOAD で `send/recv` をフックし、**CRC 付与・検証**を行うライブラリです。  
proxy を挟まずに E2E CRC を成立させます。

---

## ビルド

```bash
make -C /home/ubuntu/ld_preload
```

生成物:
- `/home/ubuntu/ld_preload/libsei_preload.so`

---

## 使い方

### memcached (memtier)

```bash
LD_PRELOAD=/home/ubuntu/ld_preload/libsei_preload.so \
SEI_PRELOAD_MODE=memcached \
memtier_benchmark -s localhost -p 11211 -P memcache_text \
  --test-time=30 --threads=8 --key-maximum=1000000 --data-size=16 \
  --ratio=1:19 --key-pattern=R:R --hide-histogram --clients=4
```

### lighttpd (wrk)

```bash
LD_PRELOAD=/home/ubuntu/ld_preload/libsei_preload.so \
SEI_PRELOAD_MODE=http \
wrk -t2 -c10 -d10s -s /home/ubuntu/wrk_mix_95_5.lua http://127.0.0.1:8080
```

### auto モード

```bash
LD_PRELOAD=/home/ubuntu/ld_preload/libsei_preload.so \
SEI_PRELOAD_MODE=auto \
<command>
```

- 接続先ポートが `11211` なら memcached
- `8080` なら HTTP

---

## 機能

### memcached

- クライアント送信時に `CRC(4B)` を **コマンド行** と **value ブロック** それぞれに付与
- サーバー応答の **末尾 CRC トレーラ** を検証
- CRC が一致した場合のみレスポンスをアプリに返す

### HTTP

- リクエストに `X-SEI-CRC` を付与（`METHOD + " " + target`）
- レスポンスの `X-SEI-CRC` を検証（body の CRC）
- chunked 応答は **デコードして検証**（レスポンス自体は元の bytes を返す）

---

## テストフック

```bash
SEI_PRELOAD_CORRUPT=1
```

次の 1 回だけ CRC を壊してミスマッチを発生させます。

---

## 制限事項 / 注意点

- **ASCII text protocol のみ対応**（memcached binary protocol は非対応）
- **TLS/SSL は非対応**（暗号化されたデータは見えない）
- レスポンスを **全体バッファして検証**するため、
  大きなレスポンスではメモリ/レイテンシが増える
- `sendfile/splice` などのゼロコピー API は未対応

