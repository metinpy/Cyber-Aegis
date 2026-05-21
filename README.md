# Cyber-Aegis

Cyber-Aegis is an open-source **ESP32-S3 based hardware security monitor** for WordPress sites. It acts as a physical command center that connects directly to your WordPress installation, providing real-time security alerts, threat monitoring, and instant response capabilities through a compact OLED display and physical button interface.

Developed by **metin.py**.

---

## Features

- **Real-Time Security Radar:** Monitors your WordPress site for brute-force attacks, SQL injections, unauthorized login attempts, and file integrity changes (FIM).
- **Physical Action Center:** Use physical buttons to instantly lock down the site, ban suspicious IPs, or approve/deny two-factor administrative login requests — no browser needed.
- **MQTT Live Streaming:** Events are streamed in real time from the WordPress plugin to the device via an MQTT broker.
- **WordPress REST API Bridge:** The device can send commands back to WordPress (ban IP, lockdown, approve auth) via a secure REST API.
- **OLED Display Interface:** Clean, always-on dashboard with multiple tabs (Radar, Threat Log, Traffic, System Status).

---

## Hardware Requirements

| Component | Details |
|-----------|---------|
| Microcontroller | ESP32-S3 (with PSRAM) |
| Display | SSD1306 0.96" I2C OLED |
| Buttons | 4x Push Buttons (Active Low, wired to GND) |

---

## Wiring & Connections

### SSD1306 OLED Display (I2C)
| OLED Pin | ESP32-S3 Pin |
|----------|--------------|
| VCC      | 3.3V         |
| GND      | GND          |
| SDA      | GPIO 8       |
| SCL      | GPIO 9       |

### Physical Buttons
| Button   | ESP32-S3 GPIO | Function                          |
|----------|---------------|-----------------------------------|
| Button 1 | GPIO 1        | Navigate Left / Previous Tab      |
| Button 2 | GPIO 2        | Navigate Right / Next Tab         |
| Button 3 | GPIO 3        | Approve / Scroll Logs / Sync      |
| Button 4 | GPIO 4        | Deny / Lockdown / Ban IP / Ping   |

> **Note:** Buttons should be wired to connect to GND when pressed. Internal pull-ups are used by default. You can override GPIO assignments in `src/hw_config.h`.

---

## Setup & Installation

### 1. Prerequisites
- [PlatformIO](https://platformio.org/) installed in VS Code (or standalone CLI).
- A WordPress site with the **Cyber-Aegis WordPress Plugin** installed and activated.
- An MQTT broker (default: `broker.hivemq.com` — free, no account needed).

### 2. Clone the Repository
```bash
git clone https://github.com/metin-py/cyber-aegis.git
cd cyber-aegis/firmware
```

### 3. Configure Your Credentials

Open `src/main.cpp` and fill in your details:
```cpp
// Wi-Fi credentials
const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// WordPress API
const char* WP_BASE_URL = "https://your-wordpress-site.com"; // No trailing slash
const char* DEVICE_KEY  = "YOUR_DEVICE_KEY"; // Must match the key in WP Admin > Cyber-Aegis
```

> **DEVICE_KEY** is a secret token you define in your WordPress admin panel under the Cyber-Aegis plugin settings. It authenticates hardware commands.

### 4. Flash to Device
- Connect your ESP32-S3 via USB.
- In PlatformIO, click **Upload** or run:
  ```bash
  pio run --target upload
  ```
- Open the Serial Monitor at **115200 baud** to verify startup logs:
  ```
  [SETUP] 9/10 WiFi OK IP=192.168.x.x
  [SETUP] 10/10 MQTT OK
  ```

---

## Usage

Once powered on, the device connects to Wi-Fi and subscribes to MQTT events from your WordPress plugin.

| Screen Tab   | Description                                        |
|--------------|----------------------------------------------------|
| **Radar**    | Live threat status, lockdown toggle, ping          |
| **Logs**     | Scrollable list of recent threats and events       |
| **Traffic**  | Real-time visitor traffic log with country codes   |
| **System**   | WordPress/DB/PHP version, plugin count, updates    |

### Button Actions (Context-Sensitive)

- **Normal Mode:** Navigate tabs with Button 1 / 2. Button 4 triggers lockdown on Radar tab.
- **Auth Request Popup:** Button 3 = Approve login, Button 4 = Deny login.
- **Log Detail View:** Button 3 = Back, Button 4 = Ban the selected IP.

---

## License

This project is released as open-source software. Keep your `WIFI_PASS`, `DEVICE_KEY`, and any API tokens out of version control.

---

*Created and maintained by **metin.py**.*
