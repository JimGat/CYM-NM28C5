# CYM-NM28C5 — Screen stop-hook requirement (v2.10.23+)

## Background

v2.10.23 applied @birolt29's navigation consolidation patch. It replaced all per-screen
bottom Back/Exit buttons with a single top-bar `‹ Back` driven by a runtime navigation
stack. `rfhat_add_back_btn()` is now a **no-op stub** — its callback is never called.

`run_screen_stop_fn()` fires the registered hook on ANY exit (both top-bar Back and Home)
before the parent screen is rebuilt. Without a registered hook, LVGL timers and
`lv_async_call` callbacks keep running against freed LVGL objects → `Load access fault`
(MTVAL = field offset inside freed lv_obj_t).

## Mandatory pattern for every new screen

Every screen that starts an LVGL timer, a background task, or queues an `lv_async_call`
source MUST register a stop hook.

```c
// 1. Define BEFORE the show_xxx function.
static void my_screen_stop(void)
{
    if (s_my_tmr) { lv_timer_del(s_my_tmr); s_my_tmr = NULL; }
    my_task_cancel();           // task sets ctx->task = NULL, then vTaskDelete
    s_my_status_lbl = NULL;    // NULL every lv_obj_t* reachable by async callbacks
    s_my_canvas     = NULL;
}

// 2. Register IMMEDIATELY after create_function_page_base() — before building UI.
static void show_my_screen(void)
{
    create_function_page_base("My Screen");
    g_screen_stop_fn = my_screen_stop;   // ← MANDATORY — never omit
    apply_menu_bg();
    // ... build UI ...
}
```

## Rules

- Register `g_screen_stop_fn` **after** `create_function_page_base()` returns, never before.
  (The call runs `reset_function_page_children` internally which could clear a prematurely set hook.)
- The stop fn must NULL every `lv_obj_t *` global that any `lv_async_call` callback writes.
- All `lv_async_call` callbacks must NULL-guard every LVGL pointer they touch.
- The stop fn must NOT navigate — navigation is handled by the nav stack after the hook returns.
- For RF-HAT context-struct screens: assign `s_X = ctx` AFTER `create_function_page_base()`,
  then register `g_screen_stop_fn`.

## Screens with registered stop hooks

### Original RF-HAT screens (v2.10.24–v2.10.25)

| Screen | Stop fn | Key cleanup |
|--------|---------|-------------|
| CC1101 Capture | `cc1101_cap_screen_stop` | timer + `cc1101_capture_cancel()` |
| CC1101 Replay | `cc1101_rep_screen_stop` | timer + `cc1101_replay_cancel()` |
| CC1101 Jammer | `cc1101_jam_screen_stop` | timer + `cc1101_idle()` |
| CC1101 Band Scope | `cc1101_bs_screen_stop` | timer + cancel flag |
| CC1101 Z-Wave Scout | `cc1101_zwave_screen_stop` | timer + cancel flag |
| nRF24 Ch Scan | `nrf24_chscan_screen_stop` | timer + cancel flag |
| nRF24 Sniffer | `nrf24_sniffer_screen_stop` | timer + cancel flag |
| nRF24 Jammer | `nrf24_jam_screen_stop` | timer |
| nRF24 Futaba | `nrf24_futaba_screen_stop` | timer + cancel flag |
| nRF24 Fox Hunt | `nrf24_foxhunt_screen_stop` | timer + vibrator restore |
| RF433 Fox Hunt | `rf433_foxhunt_screen_stop` | timer + GPIO ISR remove + vibrator |
| RFID Scan & Read | `rfid_scan_screen_stop` | 2 timers + `stop_poll()` + `stop_emulate()` |
| RFID Key Test | `rfid_key_test_screen_stop` | `stop_poll()` |
| RFID Clone | `rfid_clone_screen_stop` | `stop_poll()` |
| RFID Card Emulate | `rfid_emulate_screen_stop` | `stop_poll()` + `stop_emulate()` |

### Additional screens audited and fixed (v2.11.2)

| Screen | Stop fn | Key cleanup |
|--------|---------|-------------|
| CC1101 Fox Hunt | `cc1101_foxhunt_screen_stop` | timer + `cc1101_idle()` + vibrator restore |
| MITM | `mitm_scan_stop` | timer |
| CCCD Probe | `gw_probe_running_stop` | probe active flag + timer + NULL status lbl |
| BLE Scan | `ble_scan_screen_stop` | `bt_scan_stop()` + ui_active flag + NULL list/status |
| CC1101 Weather Station | `cc1101_weather_screen_stop` | stop flag + NULL status/list |
| CC1101 Alarm Sensors | `cc1101_alarm_screen_stop` | stop flag + NULL status/list/freq btns |
| RF433 OOK Scan | `rf433_ook_scan_stop` | stop flag + NULL status/list |
| Zigbee Scout | `zgwd_scout_stop` | cancel flag + timer + NULL UI ptrs |
| ZB Pan Detail | `zgwd_pan_detail_stop` | NULL result label |
| ZB Locator | `zgwd_locator_stop` | vibrator off + running flag + timer + NULL bars |
| ZB Assoc Flood | `zgwd_flood_stop` | cancel flag + timer |

### v2.11.3

| Screen | Stop fn | Key cleanup |
|--------|---------|-------------|
| Drone Detector | `drone_detector_stop` | `drone_scan_active=false` + task poll (≤3.5s) + free stack + NULL UI ptrs |
