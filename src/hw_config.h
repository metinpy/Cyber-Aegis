#pragma once
/** Product firmware version (shown on splash). */
#ifndef CYBER_AEGIS_FW_VERSION
#define CYBER_AEGIS_FW_VERSION "1.0.0"
#endif

/** Buttons: active LOW (to GND). Override in platformio.ini if needed. */
#ifndef BTN_K1
#define BTN_K1 1
#endif
#ifndef BTN_K2
#define BTN_K2 2
#endif
#ifndef BTN_K3
#define BTN_K3 3
#endif
#ifndef BTN_K4
#define BTN_K4 4
#endif

#ifndef BTN_ACTIVE_LOW
#define BTN_ACTIVE_LOW 1
#endif

#ifndef BTN_HOLD_MS
#define BTN_HOLD_MS 45
#endif

#ifndef BTN_COOLDOWN_MS
#define BTN_COOLDOWN_MS 200
#endif

/** WPA2 password for setup AP (>=8 chars). Change this before flashing — override in platformio.ini via -D CYBER_AEGIS_AP_PASSWORD=\"yourpassword\" */
#ifndef CYBER_AEGIS_AP_PASSWORD
#define CYBER_AEGIS_AP_PASSWORD "ChangeMe1"
#endif
