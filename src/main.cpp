#include <Arduino.h>
#include <esp_random.h>
#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <WiFiClientSecure.h>
#include "SSD1306Wire.h"
#include "hw_config.h"

static const char* mqtt_server = "broker.hivemq.com";

// WiFi credentials (hardcoded for ESP32-S3)
const char* WIFI_SSID = "YOUR_WIFI_SSID";  // BURAYA WiFi ADINI YAZIN
const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";  // BURAYA WiFi ŞİFRESİNİ YAZIN

// WordPress API config
const char* WP_BASE_URL = "https://your-wordpress-site.com";  // Site root (no /wp-json)
const char* DEVICE_KEY = "YOUR_DEVICE_KEY";  // Same key set in WP Admin > Cyber-Aegis

#define I2C_SDA 8
#define I2C_SCL 9

SSD1306Wire display(0x3c, I2C_SDA, I2C_SCL);
WiFiClient   espClient;
PubSubClient mqttClient(espClient);

extern void setup_cyber_ui();
extern void draw_screen();
extern void switch_tab(int index);
void update_status_icons(bool wifi, bool mqtt);
void add_threat_to_list(const char* identifier, const char* type);
void add_traffic_log(const char* ip, const char* page, const char* country);
void update_system_info(const char* wp, const char* db, const char* php, int plugins, int updates);
void toggle_log_detail(bool active);
bool is_log_detail_active();
void scroll_logs();
void show_auth_request(const char* user, const char* ip);
void hide_auth_request();
void update_radar_status(const char* msg, bool alarm);
void draw_splash_screen();
const char* get_selected_ip();
void update_wp_lockdown(bool on);
void update_last_bridge_action(const char* line);

extern bool auth_request_active;

void fetch_system_status();
void bridge_command(const char* cmd, const char* ip = nullptr);

static const int BTN_PINS[4] = { BTN_K1, BTN_K2, BTN_K3, BTN_K4 };
static bool btn_prev_raw[4];
static unsigned long btn_down_ms[4];
static bool btn_fired[4];
static int pending_button = -1;

static inline bool btn_raw_level(int idx) {
#if BTN_ACTIVE_LOW
    return digitalRead(BTN_PINS[idx]) == LOW;
#else
    return digitalRead(BTN_PINS[idx]) == HIGH;
#endif
}

void init_buttons() {
    for (int i = 0; i < 4; i++) {
#if BTN_ACTIVE_LOW
        pinMode(BTN_PINS[i], INPUT_PULLUP);
#else
        pinMode(BTN_PINS[i], INPUT);
#endif
        btn_prev_raw[i] = false;
        btn_down_ms[i]  = 0;
        btn_fired[i]    = false;
    }
}

void update_button_fsm() {
    unsigned long now = millis();
    for (int i = 0; i < 4; i++) {
        bool raw = btn_raw_level(i);
        if (raw) {
            if (!btn_prev_raw[i]) btn_down_ms[i] = now;
            btn_prev_raw[i] = true;
            if (!btn_fired[i] && (now - btn_down_ms[i] >= (unsigned long)BTN_HOLD_MS)) {
                btn_fired[i] = true;
                if (pending_button < 0) pending_button = i;
            }
        } else {
            btn_prev_raw[i] = false;
            btn_fired[i]    = false;
        }
    }
}

static String wp_api_base() {
    String b = WP_BASE_URL;
    b.trim();
    while (b.endsWith("/")) b.remove(b.length() - 1);
    return b;
}

static String wp_status_url() {
    return wp_api_base() + "/wp-json/cyber-aegis/v1/status";
}

static bool post_hardware_command(const char* cmd, const char* ip) {
    String base = wp_api_base();
    if (!base.length()) {
        Serial.println("[HTTP] NO WP_BASE_URL set in firmware");
        update_last_bridge_action("NO URL");
        return false;
    }
    String key = DEVICE_KEY;
    if (!key.length()) {
        Serial.println("[HTTP] NO DEVICE_KEY set in firmware");
        update_last_bridge_action("NO KEY");
        return false;
    }

    String url = base + "/wp-json/cyber-aegis/v1/hardware";
    bool is_https = url.startsWith("https://");
    Serial.printf("[HTTP] POST %s cmd=%s\n", url.c_str(), cmd);

    HTTPClient http;
    bool began = false;
    WiFiClientSecure secureClient;
    WiFiClient plainClient;
    if (is_https) {
        secureClient.setInsecure();
        began = http.begin(secureClient, url);
    } else {
        began = http.begin(plainClient, url);
    }
    if (!began) {
        Serial.println("[HTTP] begin() failed");
        update_last_bridge_action("HTTP?");
        return false;
    }
    http.setTimeout(15000);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Cyber-Aegis-Device-Key", key);

    StaticJsonDocument<256> doc;
    doc["cmd"] = cmd;
    if (ip && ip[0]) doc["ip"] = ip;
    char body[256];
    serializeJson(doc, body, sizeof(body));

    int code = http.POST(body);
    bool ok  = (code >= 200 && code < 300);
    Serial.printf("[HTTP] response code=%d ok=%d\n", code, ok);
    if (ok) {
        String payload = http.getString();
        Serial.printf("[HTTP] response: %s\n", payload.c_str());
        StaticJsonDocument<256> rd;
        if (!deserializeJson(rd, payload)) {
            if (rd["lockdown"].is<bool>()) update_wp_lockdown(rd["lockdown"].as<bool>());
        }
        update_last_bridge_action(cmd);
    } else {
        String err = http.getString();
        if (err.length()) Serial.printf("[HTTP] body: %s\n", err.c_str());
        char buf[24];
        snprintf(buf, sizeof(buf), "E%d", code);
        update_last_bridge_action(buf);
    }
    http.end();
    return ok;
}

static void mqtt_mirror_command(const char* cmd, const char* ip) {
    if (!mqttClient.connected()) {
        Serial.printf("[MQTT] NOT CONNECTED - cmd '%s' dropped\n", cmd);
        update_last_bridge_action("NO MQTT");
        return;
    }
    StaticJsonDocument<256> doc;
    doc["cmd"]    = cmd;
    doc["client"] = "Cyber-Aegis";
    if (ip && ip[0]) doc["ip"] = ip;
    char buffer[256];
    serializeJson(doc, buffer);
    bool ok = mqttClient.publish("cyber_aegis/hardware/command", buffer);
    Serial.printf("[MQTT] PUB cyber_aegis/hardware/command -> %s | ok=%d\n", buffer, ok);
}

void bridge_command(const char* cmd, const char* ip) {
    // Send via HTTP POST to WordPress REST API (works without admin panel open)
    (void)post_hardware_command(cmd, ip);
    // Also mirror via MQTT for live UI updates when admin panel is open
    mqtt_mirror_command(cmd, ip);
}

unsigned long last_btn_check   = 0;
unsigned long last_ui_update   = 0;
unsigned long last_mqtt_retry  = 0;
unsigned long last_heartbeat   = 0;
int current_page = 0;

void mqtt_callback(char* topic, byte* payload, unsigned int length) {
    StaticJsonDocument<512> doc;
    if (deserializeJson(doc, payload, length)) return;

    if (strcmp(topic, "cyber_aegis/alerts/traffic") == 0) {
        add_traffic_log(doc["ip"] | "0.0.0.0", doc["page"] | "/", doc["country"] | "?");
    } else if (strcmp(topic, "cyber_aegis/status/system") == 0) {
        update_system_info(doc["wp"] | "?", doc["db"] | "?", doc["php"] | "?",
                           doc["active_plugins"] | 0, doc["updates"] | 0);
        if (doc["lockdown"].is<bool>()) update_wp_lockdown(doc["lockdown"].as<bool>());
    } else if (strcmp(topic, "cyber_aegis/alerts/auth") == 0) {
        show_auth_request(doc["user"] | "user", doc["ip"] | "?");
    } else if (strcmp(topic, "cyber_aegis/remote_control") == 0) {
        const char* cmd = doc["cmd"] | "";
        if (!strcmp(cmd, "ui_flash")) update_radar_status("PING", true);
        else if (!strcmp(cmd, "lockdown")) update_radar_status("LOCKDOWN", true);
        else if (!strcmp(cmd, "admin_unlock")) update_radar_status("UNLOCK", false);
    } else if (strcmp(topic, "cyber_aegis/alerts/security") == 0) {
        const char* type = doc["type"] | "";
        if (!strcmp(type, "SQLi")) update_radar_status("SQLi", true);
        else if (!strcmp(type, "BAN_CONFIRMED")) update_radar_status("BANNED", false);
    } else {
        const char* type = doc["type"];
        if (!type) return;
        if (!strcmp(type, "BRUTE_FORCE")) {
            update_radar_status("ATTACK", true);
            add_threat_to_list(doc["ip"] | "?", "BF");
        } else if (!strcmp(type, "FIM_ALERT")) {
            update_radar_status("FILE", true);
            add_threat_to_list(doc["file"] | "?", "FIM");
        } else if (!strcmp(type, "STATUS_OK")) {
            update_radar_status("SECURE", false);
        }
    }
}

void check_buttons() {
    if (millis() - last_btn_check < BTN_COOLDOWN_MS) return;
    if (pending_button < 0) return;

    const int ev = pending_button;
    pending_button = -1;
    last_btn_check = millis();

    if (is_log_detail_active()) {
        if (ev == 2) {
            toggle_log_detail(false);
            return;
        }
        if (ev == 3) {
            const char* target_ip = get_selected_ip();
            if (target_ip && target_ip[0]) bridge_command("ban_ip", target_ip);
            toggle_log_detail(false);
            return;
        }
        return;
    }

    if (auth_request_active) {
        if (ev == 2) {
            bridge_command("auth_approve", nullptr);
            hide_auth_request();
            update_radar_status("APPROVED", false);
            return;
        }
        if (ev == 3) {
            bridge_command("auth_deny", nullptr);
            hide_auth_request();
            update_radar_status("DENIED", true);
            return;
        }
        return;
    }

    switch (ev) {
        case 0:
            current_page = (current_page > 0) ? current_page - 1 : 3;
            switch_tab(current_page);
            break;
        case 1:
            current_page = (current_page < 3) ? current_page + 1 : 0;
            switch_tab(current_page);
            break;
        case 2:
            if (current_page == 1) scroll_logs();
            else if (current_page == 3) {
                fetch_system_status();
                update_last_bridge_action("SYNC");
            } else {
                bridge_command("admin_unlock", nullptr);
                update_radar_status("UNLOCK", false);
            }
            break;
        case 3:
            if (current_page == 1) toggle_log_detail(true);
            else if (current_page == 3) {
                bridge_command("ping", nullptr);
                update_last_bridge_action("PING");
            } else {
                bridge_command("lockdown", nullptr);
                update_radar_status("LOCKDOWN", true);
            }
            break;
        default:
            break;
    }
}

void mqtt_reconnect() {
    if (mqttClient.connected()) return;
    if (WiFi.status() != WL_CONNECTED) return;
    if (millis() - last_mqtt_retry < 5000) return;
    last_mqtt_retry = millis();

    String clientId = "ca_s3_" + String((uint32_t)esp_random(), HEX);
    mqttClient.setKeepAlive(60);
    Serial.printf("[MQTT] Connecting to %s as %s... ", mqtt_server, clientId.c_str());
    if (mqttClient.connect(clientId.c_str())) {
        Serial.println("OK");
        mqttClient.subscribe("cyber_aegis/#");
        Serial.println("[MQTT] Subscribed to cyber_aegis/#");
    } else {
        Serial.printf("FAIL (state=%d)\n", mqttClient.state());
    }
}

void fetch_system_status() {
    if (WiFi.status() != WL_CONNECTED) return;
    String base = wp_api_base();
    if (!base.length()) return;

    WiFiClientSecure client;
    client.setInsecure();
    HTTPClient http;
    if (!http.begin(client, wp_status_url())) {
        update_last_bridge_action("HTTP?");
        return;
    }
    http.setTimeout(15000);
    int code = http.GET();
    if (code > 0 && code < 400) {
        String payload = http.getString();
        StaticJsonDocument<512> doc;
        if (!deserializeJson(doc, payload)) {
            update_system_info(doc["wp"] | "?", doc["db"] | "?", doc["php"] | "?",
                               doc["active_plugins"] | 0, doc["updates"] | 0);
            if (doc["lockdown"].is<bool>()) update_wp_lockdown(doc["lockdown"].as<bool>());
        }
    } else {
        char b[16];
        snprintf(b, sizeof(b), "E%d", code);
        update_last_bridge_action(b);
    }
    http.end();
}

// Track last polled server timestamp (unix seconds, from server's `now`).
static uint32_t last_event_ts = 0;

void fetch_events() {
    if (WiFi.status() != WL_CONNECTED) return;
    String base = wp_api_base();
    if (!base.length()) return;
    String key = DEVICE_KEY;
    if (!key.length()) return;

    String url = base + "/wp-json/cyber-aegis/v1/events?since=" + String(last_event_ts);

    bool is_https = url.startsWith("https://");
    HTTPClient http;
    bool began = false;
    WiFiClientSecure secureClient;
    WiFiClient plainClient;
    if (is_https) {
        secureClient.setInsecure();
        began = http.begin(secureClient, url);
    } else {
        began = http.begin(plainClient, url);
    }
    if (!began) {
        Serial.println("[EVT] http.begin failed");
        return;
    }
    http.setTimeout(10000);
    http.addHeader("X-Cyber-Aegis-Device-Key", key);

    int code = http.GET();
    Serial.printf("[EVT] GET %s -> %d\n", url.c_str(), code);
    if (code >= 200 && code < 300) {
        DynamicJsonDocument doc(2048);
        DeserializationError err = deserializeJson(doc, http.getStream());
        if (err) {
            Serial.printf("[EVT] JSON err: %s\n", err.c_str());
        }
        if (!err) {
            if (doc["now"].is<uint32_t>()) last_event_ts = doc["now"].as<uint32_t>();
            if (doc["lockdown"].is<bool>()) update_wp_lockdown(doc["lockdown"].as<bool>());

            JsonArray events = doc["events"].as<JsonArray>();
            for (JsonObject e : events) {
                const char* kind = e["kind"] | "";
                const char* ip   = e["ip"] | "?";
                const char* user = e["user"] | "?";
                const char* page = e["page"] | "/";
                const char* country = e["country"] | "??";
                const char* file = e["file"] | "?";

                if (!strcmp(kind, "traffic")) {
                    add_traffic_log(ip, page, country);
                } else if (!strcmp(kind, "login_failed")) {
                    add_threat_to_list(ip, "LF");
                    update_radar_status("LOGIN FAIL", true);
                } else if (!strcmp(kind, "brute_force")) {
                    add_threat_to_list(ip, "BF");
                    update_radar_status("BRUTE FORCE", true);
                } else if (!strcmp(kind, "login_ok")) {
                    add_threat_to_list(user, "OK");
                    update_radar_status("LOGIN OK", false);
                } else if (!strcmp(kind, "upgrade")) {
                    update_radar_status("UPGRADE", false);
                } else if (!strcmp(kind, "auth_request")) {
                    show_auth_request(user, ip);
                    update_radar_status("AUTH REQ", true);
                } else if (!strcmp(kind, "auth_approved")) {
                    hide_auth_request();
                    update_radar_status("APPROVED", false);
                } else if (!strcmp(kind, "auth_denied")) {
                    hide_auth_request();
                    update_radar_status("DENIED", true);
                } else if (!strcmp(kind, "fim_alert")) {
                    add_threat_to_list(file, "FIM");
                    update_radar_status("FIM ALERT", true);
                } else if (!strcmp(kind, "sqli")) {
                    add_threat_to_list(ip, "SQLI");
                    update_radar_status("SQLi", true);
                } else if (!strcmp(kind, "user_enum")) {
                    add_threat_to_list(ip, "ENUM");
                    update_radar_status("USER ENUM", true);
                } else if (!strcmp(kind, "ip_banned")) {
                    char msg[24];
                    snprintf(msg, sizeof(msg), "BAN %.16s", ip);
                    update_radar_status(msg, false);
                }
            }
        }
    }
    http.end();
}

void setup() {
    Serial.begin(115200);
    delay(500);  // USB CDC stabilizasyon
    Serial.println("\n[SETUP] 1/10 Serial OK");

    int psram_size = ESP.getPsramSize();
    if (psram_size > 0) {
        psramInit();
        Serial.printf("[SETUP] 2/10 PSRAM=%d free=%d\n", psram_size, ESP.getFreePsram());
    } else {
        Serial.println("[SETUP] 2/10 PSRAM not found");
    }

    randomSeed((uint32_t)esp_random());
    Serial.println("[SETUP] 3/10 Random seed OK");

    init_buttons();
    Serial.println("[SETUP] 4/10 Buttons OK");

    Wire.begin(I2C_SDA, I2C_SCL);
    Serial.println("[SETUP] 5/10 Wire OK");

    display.init();
    display.flipScreenVertically();
    display.setContrast(255);
    Serial.println("[SETUP] 6/10 Display OK");

    draw_splash_screen();
    setup_cyber_ui();
    Serial.println("[SETUP] 7/10 UI OK");

    Serial.printf("[SETUP] 8/10 WiFi connecting to %s\n", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.setSleep(false);
    WiFi.setTxPower(WIFI_POWER_15dBm);
    WiFi.begin(WIFI_SSID, WIFI_PASS);

    int dots = 0;
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
        dots++;
        if (dots > 40) {
            Serial.println("\n[SETUP] WiFi FAILED");
            return;
        }
    }
    Serial.printf("\n[SETUP] 9/10 WiFi OK IP=%s\n", WiFi.localIP().toString().c_str());

    mqttClient.setServer(mqtt_server, 1883);
    mqttClient.setCallback(mqtt_callback);
    Serial.println("[SETUP] 10/10 MQTT OK");
}

static unsigned long last_events_poll = 0;
static unsigned long last_status_poll = 0;

void loop() {
    update_button_fsm();

    bool wifi_ok = (WiFi.status() == WL_CONNECTED);
    bool mqtt_ok = mqttClient.connected();
    mqtt_reconnect();

    if (mqtt_ok) {
        mqttClient.loop();
        if (millis() - last_heartbeat > 3000) {
            last_heartbeat = millis();
            StaticJsonDocument<64> doc;
            doc["status"] = "online";
            doc["device"] = "ESP32-S3";
            char hb[64];
            serializeJson(doc, hb);
            mqttClient.publish("cyber_aegis/heartbeat", hb);
        }
    }

    // Poll events every 5s
    if (wifi_ok && millis() - last_events_poll > 5000) {
        last_events_poll = millis();
        fetch_events();
    }

    // Poll system status every 30s
    if (wifi_ok && millis() - last_status_poll > 30000) {
        last_status_poll = millis();
        fetch_system_status();
    }

    update_status_icons(wifi_ok, mqtt_ok);
    check_buttons();

    if (millis() - last_ui_update > 100) {
        draw_screen();
        last_ui_update = millis();
    }
}
