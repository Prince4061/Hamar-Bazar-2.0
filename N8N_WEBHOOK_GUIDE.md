# 🚀 Hamar Bazar 2.0 - n8n & Webhook Automation Guide

This guide explains how the **Webhook Automation Engine** works in Hamar Bazar 2.0, why webhook connection issues occur and how they were resolved, how to connect n8n step-by-step for future workflows, and the complete webhook payload schema.

---

## 📌 1. Root Cause Analysis: Why Webhook Requests Failed & How They Were Fixed

During initial testing, webhook requests failed to reach n8n due to three key technical factors. Understanding these prevents future setup issues:

### ❌ Problem 1: Invalid `0.0.0.0` Destination IP on Windows
- **What happened**: n8n UI displayed `https://0.0.0.0:5678/webhook-test/...` by default because `WEBHOOK_URL` environment variable was not configured in n8n's Docker container.
- **Root Cause**: `0.0.0.0` is an internal server listening address. On Windows OS, socket connections to `0.0.0.0` throw `[WinError 10049: The requested address is not valid in its context]`.
- **Solution**: Replaced `0.0.0.0` with the actual public Cloudflare domain where n8n is deployed: **`https://n8n.hamarai.in/...`**. Added automatic IP translation (`0.0.0.0` -> `127.0.0.1`) in [`app.py`](file:///G:/Hamar%20Bazar/Hamar-Bazar-2.0/app.py) as a fallback for local testing.

### ❌ Problem 2: Cached Database Settings
- **What happened**: Updating code in `app.py` alone did not change the active webhook URL because SQLite database `marketplace.db` cached the old setting inside the `system_settings` table.
- **Solution**: Force-updated `system_settings` table in `marketplace.db` and updated `database.py` initialization code to persist `https://n8n.hamarai.in/webhook-test/167078e4-ccf5-4507-b605-fe218217f4b0`.

### ❌ Problem 3: Cloudflare WAF Bot Protection (HTTP 403)
- **What happened**: Python's default `urllib` user agent (`Python-urllib/3.x`) was blocked by Cloudflare WAF with `HTTP 403 Forbidden`.
- **Solution**: Configured standard browser `User-Agent` headers (`Mozilla/5.0 (Windows NT 10.0... Chrome/120.0...)`) in `send_webhook_http` function.

### ❌ Problem 4: n8n Test URL vs Production URL Behavior
- **What happened**: `webhook-test/...` URLs in n8n only listen for **120 seconds** when the user clicks *"Listen for test event"*. If no request arrives in 120s, n8n returns `HTTP 404 Not Found`.
- **Solution**: For 24/7 automated production triggers, use n8n **Production URL** (`/webhook/...` instead of `/webhook-test/...`) and toggle the workflow **Active** in n8n.

---

## 🛠️ 2. Step-by-Step Guide: Connecting n8n to Hamar Bazar 2.0

Follow these simple steps whenever you want to connect a new n8n workflow or update existing ones:

### Step 1: Create a Webhook Trigger Node in n8n
1. Open your n8n dashboard (e.g. `https://n8n.hamarai.in`).
2. Create a new workflow and add a **Webhook** trigger node.
3. Set **HTTP Method** to `POST`.
4. Copy your Webhook URL:
   - For temporary testing: Use **Test URL** (`https://n8n.hamarai.in/webhook-test/<your-path>`)
   - For 24/7 live system: Use **Production URL** (`https://n8n.hamarai.in/webhook/<your-path>`)

### Step 2: Configure Webhook URL in Hamar Bazar 2.0
You can configure the URL in two ways:

#### Option A: Via Super Admin Panel (Recommended)
1. Open Hamar Bazar in browser: **`http://127.0.0.1:5001/admin`**
2. Login with Admin credentials (Username: `admin`).
3. Click on **Automation & Webhooks** tab.
4. Paste your Webhook URL and click **Save Settings**.
5. Click **Send Test Payload** to test connectivity instantly.

#### Option B: Via Command Line / Python Script
Run the following script inside project directory:
```bash
python -c "import sqlite3; conn = sqlite3.connect('marketplace.db'); conn.execute('UPDATE system_settings SET value = ? WHERE key = ?', ('YOUR_N8N_URL_HERE', 'webhook_url')); conn.commit(); print('Updated Database Settings!');"
```

### Step 3: Activate Workflow in n8n
- For Production use, toggle the **Active** switch at the top-right corner of your n8n workflow.

---

## 📩 3. Complete Webhook Payload Schema Reference

Whenever a customer places an order, Hamar Bazar sends a `POST` request with `Content-Type: application/json` containing the following structure:

```json
{
  "event": "order_created",
  "timestamp": "2026-08-02T09:39:52.123456",
  "source": "HamarBazar-Hyperlocal",
  "data": {
    "order_id": 87,
    "customer_id": 1,
    "customer_name": "Alice Sharma",
    "customer_phone": "9876543210",
    "customer_address": "Flat 302, Green Glen Layout, Bellandur, Bengaluru",
    "shop_id": 1,
    "subtotal": 120.0,
    "delivery_fee": 15.0,
    "grand_total": 135.0,
    "priority_type": "NORMAL",
    "status": "PENDING",
    "payment_mode": "COD",
    "pickup_otp": "4821",
    "delivery_otp": "9102",
    "items": [
      {
        "product_id": 1,
        "name": "Amul Taaza Milk 1L",
        "quantity": 2,
        "price": 60.0,
        "item_total": 120.0,
        "custom_text": null,
        "custom_instructions": null,
        "custom_image_path": null
      }
    ]
  }
}
```

---

## ⚡ 4. Quick Debugging & Verification Checklist

If webhooks are not triggering, verify the following:

1. **Check Server Logs**:
   In Flask console output, look for:
   - `[WEBHOOK SUCCESS] Event 'order_created' delivered to https://n8n.hamarai.in/... - Status: 200`
2. **HTTP 404 Error in n8n**: Means you are using a Test URL without clicking *"Listen for test event"* in n8n. Either click the button before ordering or switch to Production URL and activate the workflow.
3. **HTTP 403 Error**: Cloudflare WAF block. Verify `User-Agent` header is set in `app.py`.
4. **WinError 10061 / 10049**: Destination IP issue. Do NOT use `0.0.0.0`. Always use public domain `n8n.hamarai.in` or `127.0.0.1` for local listeners.
