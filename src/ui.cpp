#include <Arduino.h>
#include <Wire.h>
#include "SSD1306Wire.h"
#include "hw_config.h"

extern SSD1306Wire display;

void draw_splash_screen() {
    display.clear();
    display.setColor(WHITE);
    display.setTextAlignment(TEXT_ALIGN_CENTER);
    display.setFont(ArialMT_Plain_10);
    display.drawString(64, 18, "Cyber-Aegis");
    display.drawString(64, 34, "Security Terminal");
    display.drawString(64, 50, "v" CYBER_AEGIS_FW_VERSION);
    display.display();
    delay(1200);
}

int  current_tab   = 0;
bool wifi_ok       = false;
bool mqtt_ok       = false;
static char radar_msg[32] = "SECURE";

struct LogEntry {
    char type[10];
    char ip[20];
    char page[32];
    char country[5];
    char time[10];
    bool active;
};

#define MAX_LOGS 5
static LogEntry logs[MAX_LOGS];
static int log_count = 0;
static int selected_log_idx = 0;

static char wp_ver[10]  = "?.?";
static char db_stat[10] = "-";
static char php_ver[10] = "?.?";
static int active_plugs = 0;
static int updates_pending = 0;
static bool wp_lockdown = false;
static char bridge_action[24] = "—";

bool auth_request_active = false;
char auth_user[32] = "";
char auth_ip[32] = "";

static bool log_detail_active = false;

static void draw_status_bar() {
    display.setFont(ArialMT_Plain_10);
    display.setTextAlignment(TEXT_ALIGN_LEFT);
    display.drawString(0, 0, "AEGIS");
    display.setTextAlignment(TEXT_ALIGN_RIGHT);
    display.drawString(127, 0, String(wifi_ok ? "W" : "-") + " " + String(mqtt_ok ? "M" : "-"));
    display.drawHorizontalLine(0, 11, 128);
}

static void draw_tab_bar() {
    display.drawHorizontalLine(0, 52, 128);
    const char* labels[] = {"DASH", "LOGS", "SYS", "WP"};
    const int tab_w = 32;
    display.setFont(ArialMT_Plain_10);
    display.setTextAlignment(TEXT_ALIGN_CENTER);
    for (int i = 0; i < 4; i++) {
        int x = i * tab_w;
        int cx = x + tab_w / 2;
        if (i == current_tab) {
            display.fillRect(x, 53, tab_w, 11);
            display.setColor(BLACK);
            display.drawString(cx, 53, labels[i]);
            display.setColor(WHITE);
        } else {
            display.drawString(cx, 53, labels[i]);
        }
    }
}

static void draw_tab_status() {
    display.setFont(ArialMT_Plain_10);
    display.setTextAlignment(TEXT_ALIGN_CENTER);
    int cx = 64, cy = 29;
    display.drawRect(cx - 11, cy - 10, 22, 17);
    display.drawLine(cx - 4, cy - 1, cx - 1, cy + 4);
    display.drawLine(cx - 1, cy + 4, cx + 6, cy - 5);
    display.drawString(64, 42, radar_msg);
}

static void draw_tab_threats() {
    display.setFont(ArialMT_Plain_10);
    if (log_count == 0) {
        display.setTextAlignment(TEXT_ALIGN_CENTER);
        display.drawString(64, 28, "No events");
        return;
    }
    display.setTextAlignment(TEXT_ALIGN_LEFT);
    int y = 13;
    for (int i = 0; i < log_count; i++) {
        if (i == selected_log_idx) display.drawString(1, y, ">");
        char line[45];
        if (strcmp(logs[i].type, "TRAF") == 0)
            snprintf(line, sizeof(line), " [%s] %s", logs[i].country, logs[i].ip);
        else
            snprintf(line, sizeof(line), " !%s %s", logs[i].type, logs[i].ip);
        display.drawString(8, y, line);
        y += 10;
        if (y > 50) break;
    }
}

static void draw_tab_fim() {
    display.setFont(ArialMT_Plain_10);
    display.setTextAlignment(TEXT_ALIGN_LEFT);
    display.drawString(2, 13, "WP " + String(wp_ver));
    display.drawString(2, 22, "DB " + String(db_stat));
    display.drawString(2, 31, "PHP " + String(php_ver));
    display.drawString(2, 40, updates_pending ? ("UPD " + String(updates_pending)) : String("OK"));
    display.drawString(2, 49, String("LD ") + (wp_lockdown ? "ON" : "OFF"));
}

static void draw_tab_wp_bridge() {
    display.setFont(ArialMT_Plain_10);
    display.setTextAlignment(TEXT_ALIGN_LEFT);
    display.drawString(2, 14, "K3 sync  K4 ping");
    display.drawString(2, 28, "K3 unlock / K4 lock");
    display.drawString(2, 42, String(bridge_action).substring(0, 21));
}

void setup_cyber_ui() {
    display.clear();
    display.display();
}

void draw_screen() {
    display.clear();
    display.setColor(WHITE);

    if (auth_request_active) {
        display.setFont(ArialMT_Plain_10);
        display.setTextAlignment(TEXT_ALIGN_CENTER);
        display.drawString(64, 0, "LOGIN APPROVAL");
        display.drawHorizontalLine(10, 12, 108);
        display.drawString(64, 20, "User: " + String(auth_user));
        display.drawString(64, 34, String(auth_ip).substring(0, 18));
        display.drawString(64, 52, "K3 OK  K4 deny");
        display.display();
        return;
    }

    if (log_detail_active && log_count > 0) {
        LogEntry& l = logs[selected_log_idx];
        display.setFont(ArialMT_Plain_10);
        display.setTextAlignment(TEXT_ALIGN_CENTER);
        display.drawString(64, 0, "LOG");
        display.drawHorizontalLine(0, 12, 128);
        display.setTextAlignment(TEXT_ALIGN_LEFT);
        display.drawString(2, 16, "IP " + String(l.ip));
        display.drawString(2, 28, String(l.country) + " " + String(l.page).substring(0, 18));
        display.setTextAlignment(TEXT_ALIGN_CENTER);
        display.drawString(32, 52, "K3 back");
        display.drawString(96, 52, "K4 ban");
        display.display();
        return;
    }

    draw_status_bar();
    switch (current_tab) {
        case 0: draw_tab_status(); break;
        case 1: draw_tab_threats(); break;
        case 2: draw_tab_fim(); break;
        case 3: draw_tab_wp_bridge(); break;
    }
    draw_tab_bar();
    display.display();
}

void switch_tab(int index) {
    current_tab = index;
}

void update_radar_status(const char* msg, bool alarm) {
    (void)alarm;
    strncpy(radar_msg, msg, sizeof(radar_msg) - 1);
    radar_msg[sizeof(radar_msg) - 1] = '\0';
    if (alarm) current_tab = 0;
}

void update_status_icons(bool wifi, bool mqtt) {
    wifi_ok = wifi;
    mqtt_ok = mqtt;
}

void add_threat_to_list(const char* identifier, const char* type) {
    for (int i = MAX_LOGS - 1; i > 0; i--) logs[i] = logs[i - 1];
    strncpy(logs[0].type, type, sizeof(logs[0].type) - 1);
    logs[0].type[sizeof(logs[0].type) - 1] = '\0';
    strncpy(logs[0].ip, identifier, sizeof(logs[0].ip) - 1);
    logs[0].ip[sizeof(logs[0].ip) - 1] = '\0';
    strncpy(logs[0].country, "!!", sizeof(logs[0].country) - 1);
    logs[0].country[sizeof(logs[0].country) - 1] = '\0';
    strncpy(logs[0].page, "-", sizeof(logs[0].page) - 1);
    logs[0].page[sizeof(logs[0].page) - 1] = '\0';
    logs[0].active = true;
    if (log_count < MAX_LOGS) log_count++;
    current_tab = 1;
}

void add_traffic_log(const char* ip, const char* page, const char* country) {
    for (int i = MAX_LOGS - 1; i > 0; i--) logs[i] = logs[i - 1];
    strncpy(logs[0].type, "TRAF", sizeof(logs[0].type) - 1);
    logs[0].type[sizeof(logs[0].type) - 1] = '\0';
    strncpy(logs[0].ip, ip, sizeof(logs[0].ip) - 1);
    logs[0].ip[sizeof(logs[0].ip) - 1] = '\0';
    strncpy(logs[0].page, page, sizeof(logs[0].page) - 1);
    logs[0].page[sizeof(logs[0].page) - 1] = '\0';
    strncpy(logs[0].country, country, sizeof(logs[0].country) - 1);
    logs[0].country[sizeof(logs[0].country) - 1] = '\0';
    logs[0].active = true;
    if (log_count < MAX_LOGS) log_count++;
}

void scroll_logs() {
    if (log_count == 0) return;
    selected_log_idx = (selected_log_idx + 1) % log_count;
}

void show_auth_request(const char* user, const char* ip) {
    auth_request_active = true;
    strncpy(auth_user, user, sizeof(auth_user) - 1);
    auth_user[sizeof(auth_user) - 1] = '\0';
    strncpy(auth_ip, ip, sizeof(auth_ip) - 1);
    auth_ip[sizeof(auth_ip) - 1] = '\0';
}

void hide_auth_request() {
    auth_request_active = false;
}

void update_system_info(const char* wp, const char* db, const char* php, int plugins, int updates) {
    strncpy(wp_ver, wp, sizeof(wp_ver) - 1);
    wp_ver[sizeof(wp_ver) - 1] = '\0';
    strncpy(db_stat, db, sizeof(db_stat) - 1);
    db_stat[sizeof(db_stat) - 1] = '\0';
    strncpy(php_ver, php, sizeof(php_ver) - 1);
    php_ver[sizeof(php_ver) - 1] = '\0';
    active_plugs  = plugins;
    updates_pending = updates;
}

void update_wp_lockdown(bool on) {
    wp_lockdown = on;
}

void update_last_bridge_action(const char* line) {
    if (!line) return;
    strncpy(bridge_action, line, sizeof(bridge_action) - 1);
    bridge_action[sizeof(bridge_action) - 1] = '\0';
}

void toggle_log_detail(bool active) {
    log_detail_active = active;
}

bool is_log_detail_active() {
    return log_detail_active;
}

const char* get_selected_ip() {
    if (log_detail_active && selected_log_idx < log_count) return logs[selected_log_idx].ip;
    return "";
}
