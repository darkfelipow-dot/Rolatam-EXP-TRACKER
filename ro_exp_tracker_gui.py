"""
ro_exp_tracker_gui.py
=====================
State-of-the-art Real-Time EXP per Second / EXP per Hour Tracker for Ragnarok Online.
Uses scapy for local TCP map-server packet sniffing to safely measure EXP gains in real-time.

Features:
  - Beautiful neon dark theme with custom HSL-tailored colors.
  - Custom canvas-based progress bars for Base/Job EXP with perfect percentages.
  - Real-time sliding window calculations (1 min, 5 min, 15 min, Session Average).
  - Floating Transparent Overlay Mode (stay-on-top, borderless, drag-and-drop).
  - Colorful live log highlighting Base EXP (Green), Job EXP (Cyan) and Level Ups (Gold).
  - Level-up flash animation to WOW the user.
  - Automatic map-server port detection via psutil / Scapy signatures.

Usage: Run as Administrator.
"""

import sys
import os
import time
import struct
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, TCP, Raw, IP
import psutil
from ro_port_detector import RoPortDetector

# ─────────────────────────────────────────────────────────────
#  ESTADO GLOBAL
# ─────────────────────────────────────────────────────────────
state = {
    # Absolute EXP & Levels
    'base_exp': 0,
    'job_exp': 0,
    'base_level': 0,
    'job_level': 0,
    'next_base_exp': 0,
    'next_job_exp': 0,
    
    # Tracking Baselines & Totals
    'start_time': None,
    'tracking_active': False,
    'total_base_gained': 0,
    'total_job_gained': 0,
    
    'prev_base_exp': None,
    'prev_job_exp': None,
    'prev_base_level': None,
    'prev_job_level': None,
    
    # Sliding Window Configurations
    'window_size': 9999999,  # default: Promedio Sesión for stable measurements
    
    # Event Log
    'gains_log': [],  # list of dicts: {'timestamp': float, 'type': str, 'amount': int, 'level': int}
    'buffered_base_exp': 0,
    'buffered_job_exp': 0,
    'last_buffer_flush': 0,
    'target_pid': None,
    'target_local_port': None,
}

current_port = None
current_ip = None
ui_instance = None
state_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────
#  TABLA DE EXP DE RANGO DINÁMICO (NIVELES 1-200)
# ─────────────────────────────────────────────────────────────
# Transcendent, Third Classes and Expanded Classes unreduced EXP requirements
import math

def _generate_expanded_table():
    # ─────────────────────────────────────────────────────────────
    #  TABLA 1: SUMMONER / EXPANDED (UNREDUCED BASELINE)
    # ─────────────────────────────────────────────────────────────
    # Levels 1-99: Transcendent progression
    # Levels 100-200: Unreduced Renewal Baseline
    table = {
        1: 420, 2: 660, 3: 1080, 4: 1800, 5: 2640, 6: 3840, 7: 4560, 8: 5040, 9: 5460, 10: 6000,
        11: 6600, 12: 7200, 13: 7320, 14: 7620, 15: 8040, 16: 8820, 17: 9600, 18: 10080, 19: 10560, 20: 11040,
        21: 12610, 22: 13390, 23: 14300, 24: 15340, 25: 16900, 26: 18460, 27: 19500, 28: 20800, 29: 22100, 30: 23400,
        31: 24700, 32: 26000, 33: 27300, 34: 28600, 35: 30160, 36: 31200, 37: 33800, 38: 35750, 39: 37700, 40: 39000,
        41: 44100, 42: 46200, 43: 47600, 44: 50400, 45: 52500, 46: 53200, 47: 56000, 48: 58800, 49: 62300, 50: 65800,
        51: 68600, 52: 71400, 53: 74200, 54: 77000, 55: 79800, 56: 82600, 57: 86100, 58: 88200, 59: 91000, 60: 93800,
        61: 103500, 62: 105000, 63: 109500, 64: 115500, 65: 120000, 66: 126000, 67: 132000, 68: 136500, 69: 142500, 70: 165000,
        71: 192000, 72: 210000, 73: 232500, 74: 244500, 75: 255000, 76: 270000, 77: 282000, 78: 292500, 79: 300000, 80: 345000,
        81: 416000, 82: 480000, 83: 560000, 84: 640000, 85: 768000, 86: 880000, 87: 960000, 88: 1088000, 89: 1200000, 90: 1440000,
        91: 1700000, 92: 2040000, 93: 2550000, 94: 3060000, 95: 3570000, 96: 4080000, 97: 4760000, 98: 5610000, 99: 6800000,
        100: 4032062, 101: 4048190, 102: 4064382, 103: 4080639, 104: 4096961, 105: 4113348, 106: 4129801, 107: 4146319, 108: 4162904, 109: 4179555,
        110: 4196273, 111: 4213057, 112: 4229909, 113: 4246828, 114: 4263815, 115: 4280870, 116: 4297993, 117: 4315184, 118: 4332444, 119: 4349773,
        120: 4367171, 121: 4384639, 122: 4402177, 123: 4419785, 124: 4437463, 125: 4455212, 126: 4473032, 127: 4490923, 128: 4508886, 129: 4526921,
        130: 4545028, 131: 4563207, 132: 4581459, 133: 4599784, 134: 4618182, 135: 4636654, 136: 4655200, 137: 4673820, 138: 4692515, 139: 4711284,
        140: 4730128, 141: 4749048, 142: 4768043, 143: 4787114, 144: 4806262, 145: 4825486, 146: 4844787, 147: 4864165, 148: 4883621, 149: 4903155,
        150: 4922767, 151: 4942457, 152: 4962226, 153: 4982074, 154: 5002002, 155: 5022009, 156: 5042096, 157: 5062264, 158: 5082512, 159: 5102841,
        160: 5123252, 161: 5143744, 162: 5164318, 163: 5184975, 164: 5205714, 165: 5226536, 166: 5247441, 167: 5268430, 168: 5289503, 169: 5310660,
        170: 5331902, 171: 5353229, 172: 5374641, 173: 5396139, 174: 5417723, 175: 5439393, 176: 5461150, 177: 5482994, 178: 5504925, 179: 5526944,
        180: 5549051, 181: 5571246, 182: 5593530, 183: 5615903, 184: 5638366, 185: 5660919, 186: 5683562, 187: 5706295, 188: 5729119, 189: 5752035,
        190: 5775042, 191: 5798141, 192: 5821333, 193: 5844618, 194: 5867996, 195: 5891467, 196: 5915032, 197: 5938691, 198: 5962445, 199: 5986294,
        200: 6010238
    }
    return table

def _generate_adjusted_table():
    # ─────────────────────────────────────────────────────────────
    #  TABLA 2: ADJUSTED (REDUCED EXP FROM USER IMAGE)
    # ─────────────────────────────────────────────────────────────
    # Sourced directly from the image user provided (Official 2020 kRO Reduction).
    # Levels 1-99 share standard baseline logic.
    table = _generate_expanded_table() # Seed with baseline 1-99
    
    # Overwrite Levels 100-200 with precise RED ADJUSTED values from provided image data
    adjusted_data = {
        100: 1273747, 101: 1364282, 102: 1448928, 103: 1533085, 104: 1631202,
        105: 1735688, 106: 1846675, 107: 1964693, 108: 2090014, 109: 2224413,
        110: 2366775, 111: 2518240, 112: 2679415, 113: 2850897, 114: 3033354,
        115: 3227488, 116: 3434047, 117: 3653828, 118: 3887670, 119: 4136480,
        120: 4401314, 121: 4755467, 122: 5138334, 123: 5551810, 124: 5998075,
        125: 6481388, 126: 7003204, 127: 7566891, 128: 8175950, 129: 8834632,
        130: 9545683, 131: 10313388, 132: 11143488, 133: 12040437, 134: 13009560,
        135: 14056888, 136: 15188172, 137: 16410873, 138: 17731503, 139: 19158711,
        140: 20701195, 141: 22367981, 142: 24168320, 143: 26112547, 144: 28214245,
        145: 30485317, 146: 32939008, 147: 35590395, 148: 38455077, 149: 41550755,
        150: 44894635, 151: 48508165, 152: 52412834, 153: 56631331, 154: 61188536,
        155: 66114175, 156: 71436299, 157: 77186395, 158: 83399977, 159: 90111184,
        160: 97364184, 161: 105201603, 162: 113668386, 163: 122818973, 164: 132704203,
        165: 143386860, 166: 154930180, 167: 167398014, 168: 180873483, 169: 195436696,
        170: 211166924, 171: 228166105, 172: 246528388, 173: 266361640, 174: 287801897,
        175: 310968267, 176: 382913746, 177: 399479680, 178: 447978881, 179: 503931270,
        180: 579923277, 181: 684332340, 182: 740962898, 183: 839484361, 184: 949141086,
        185: 1074428384, 186: 1215202696, 187: 1374780273, 188: 1548535690, 189: 1744262356,
        190: 1967144895, 191: 2219799123, 192: 2509169015, 193: 2837962030, 194: 3219468683,
        195: 3712289668, 196: 4282319658, 197: 4717911684, 198: 6394941731, 199: 8065764639,
        200: 8968313072
    }
    for lvl, val in adjusted_data.items():
        table[lvl] = val
    return table

EXP_TABLE_SUMMONER = _generate_expanded_table()
EXP_TABLE_ADJUSTED = _generate_adjusted_table()

# Reference variable that is swapped dynamically via UI dropdown
BASE_EXP_TABLE = EXP_TABLE_SUMMONER


# ─────────────────────────────────────────────────────────────
#  HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────
def format_seconds(seconds):
    if seconds is None or seconds < 0:
        return "--"
    seconds = int(seconds)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    if hours > 0:
        return f"{hours:02d}h {minutes:02d}m {secs:02d}s"
    elif minutes > 0:
        return f"{minutes:02d}m {secs:02d}s"
    else:
        return f"{secs:02d}s"


def format_exp(val):
    if val >= 1_000_000_000:
        return f"{val / 1_000_000_000:.2f}B"
    elif val >= 1_000_000:
        return f"{val / 1_000_000:.2f}M"
    elif val >= 1_000:
        return f"{val / 1_000:.1f}K"
    return str(val)


# ─────────────────────────────────────────────────────────────
#  METRIC CALCULATOR
# ─────────────────────────────────────────────────────────────
def calculate_metrics():
    with state_lock:
        now = time.time()
        
        # Calculate active tracking elapsed time
        if state['tracking_active'] and state['start_time']:
            elapsed = now - state['start_time']
        else:
            elapsed = 0
            
        # Filter sliding window logs
        window_limit = now - state['window_size']
        recent_base = [g for g in state['gains_log'] if g['timestamp'] >= window_limit and g['type'] == 'base']
        recent_job  = [g for g in state['gains_log'] if g['timestamp'] >= window_limit and g['type'] == 'job']
        
        base_window_gained = sum(g['amount'] for g in recent_base)
        job_window_gained  = sum(g['amount'] for g in recent_job)
        
        # DAMPING STABILIZER: clamp divisor to at least 60s to prevent massive random spikes on first kill
        min_smooth_divisor = 60.0 
        
        # Determine actual active window duration
        actual_window = min(state['window_size'], elapsed) if elapsed > 0 else 0
        smooth_window = max(min_smooth_divisor, actual_window)
        
        base_exp_sec = base_window_gained / smooth_window
        job_exp_sec  = job_window_gained / smooth_window
            
        # Session Averages
        session_divisor = max(min_smooth_divisor, elapsed)
        session_base_sec = state['total_base_gained'] / session_divisor
        session_job_sec  = state['total_job_gained'] / session_divisor
            
        return {
            'elapsed': elapsed,
            'base_exp_sec': base_exp_sec,
            'job_exp_sec': job_exp_sec,
            'base_exp_hr': base_exp_sec * 3600,
            'job_exp_hr': job_exp_sec * 3600,
            'session_base_sec': session_base_sec,
            'session_job_sec': session_job_sec,
            'session_base_hr': session_base_sec * 3600,
            'session_job_hr': session_job_sec * 3600,
        }


# ─────────────────────────────────────────────────────────────
#  PACKET PROCESSORS (ZC_PAR_CHANGE / ZC_LONGPAR_CHANGE)
# ─────────────────────────────────────────────────────────────
def handle_status_update(var_type, var_value):
    global ui_instance
    print(f"[DEBUG] Status Update - Param ID: {var_type}, Value: {var_value}", flush=True)
    now = time.time()
    trigger_alert_level = None
    log_msg_data = None
    
    with state_lock:
        # SP_BASEEXP (1)
        if var_type == 1:
            # Debug Log
            try:
                with open("ro_packet_log.txt", "a", encoding="utf-8") as fl:
                    fl.write(f"[{time.strftime('%H:%M:%S')}] BASE EXP Captured -> Value: {var_value:,} (Prev: {state['prev_base_exp'] or 0:,})\n")
            except: pass
            
            # ANTI-EXPONENTIAL BUG SHIELD
            # Equipment buffs occasionally place \xb0\x00 sequences inside their binary description buffers,
            # which triggers false-positive jumps. legitimate server packets rarely jump over 50M instantaneously without an actual kill.
            if state['tracking_active'] and state['prev_base_exp'] is not None:
                abs_diff = abs(var_value - state['prev_base_exp'])
                if abs_diff > 150000000: # Extremely generous ceiling of 150M to account for quests, but blocks billions
                     print(f"[REJECTED] Potential Packet Bug Blocked. Jump of {abs_diff:,} detected.")
                     try:
                        with open("ro_packet_log.txt", "a", encoding="utf-8") as fl:
                            fl.write(f"  >>> REJECTED AS FALSE POSITIVE (Delta {abs_diff:,} > limit)\n")
                     except: pass
                     return # Discard corrupted interpretation

            if state['prev_base_exp'] is None:
                state['prev_base_exp'] = var_value
            state['base_exp'] = var_value
            
            if state['tracking_active'] and var_value > state['prev_base_exp']:
                gained = var_value - state['prev_base_exp']
                state['total_base_gained'] += gained
                state['gains_log'].append({
                    'timestamp': now,
                    'type': 'base',
                    'amount': gained,
                    'level': state['base_level']
                })
                log_msg_data = ('base', f"+{gained:,} Base EXP")
                
            state['prev_base_exp'] = var_value
            
        # SP_JOBEXP (2)
        elif var_type == 2:
            # Anti-bug Shield for Job Exp
            if state['tracking_active'] and state['prev_job_exp'] is not None:
                if abs(var_value - state['prev_job_exp']) > 100000000:
                     print(f"[REJECTED] Potential Job Packet Bug Blocked.")
                     return
            
            if state['prev_job_exp'] is None:
                state['prev_job_exp'] = var_value
            state['job_exp'] = var_value
            
            if state['tracking_active'] and var_value > state['prev_job_exp']:
                gained = var_value - state['prev_job_exp']
                state['total_job_gained'] += gained
                state['gains_log'].append({
                    'timestamp': now,
                    'type': 'job',
                    'amount': gained,
                    'level': state['job_level']
                })
                log_msg_data = ('job', f"+{gained:,} Job EXP")
                
            state['prev_job_exp'] = var_value

            
        # SP_BASELEVEL (11)
        elif var_type == 11:
            if state['prev_base_level'] is None:
                state['prev_base_level'] = var_value
            state['base_level'] = var_value
            
            if state['tracking_active'] and var_value > state['prev_base_level']:
                trigger_alert_level = ('Base', var_value)
                log_msg_data = ('level_up', f"★ BASE LEVEL UP! reached level {var_value} ★")
                
            state['prev_base_level'] = var_value
            
        # SP_JOBLEVEL (12)
        elif var_type == 12:
            if state['prev_job_level'] is None:
                state['prev_job_level'] = var_value
            state['job_level'] = var_value
            
            if state['tracking_active'] and var_value > state['prev_job_level']:
                trigger_alert_level = ('Job', var_value)
                log_msg_data = ('level_up', f"★ JOB LEVEL UP! reached level {var_value} ★")
                
            state['prev_job_level'] = var_value
            
        # SP_NEXTBASEEXP (23)
        elif var_type == 23:
            state['next_base_exp'] = var_value
            
        # SP_NEXTJOBEXP (24)
        elif var_type == 24:
            state['next_job_exp'] = var_value

    # UI updates out of state_lock to avoid deadlocks
    if ui_instance:
        if log_msg_data:
            ui_instance.log_message(log_msg_data[1], log_msg_data[0])
        if trigger_alert_level:
            ui_instance.trigger_level_up(trigger_alert_level[0], trigger_alert_level[1])


def handle_notify_exp(exp_type, exp_val):
    # RESTRICT CEILING: A single monster kill / notify on unreduced tables almost never exceeds 10-12M.
    # Setting this ceiling safely filters out the false-positive binary echoes (like the 19.6M fake read).
    if exp_val <= 0 or exp_val > 12000000:
        if exp_val > 0:
            print(f"[FILTERED] Ignored suspected false notify exp: {exp_val:,}")
        return
        
    with state_lock:
        now = time.time()
        if exp_type == 0:
            state['total_base_gained'] += exp_val
            state['base_exp'] += exp_val
            state['buffered_base_exp'] += exp_val
            state['gains_log'].append({
                'timestamp': now,
                'type': 'base',
                'amount': exp_val,
                'level': state['base_level']
            })
        elif exp_type == 1:
            state['total_job_gained'] += exp_val
            state['job_exp'] += exp_val
            state['buffered_job_exp'] += exp_val
            state['gains_log'].append({
                'timestamp': now,
                'type': 'job',
                'amount': exp_val,
                'level': state['job_level']
            })


def process_packet(packet):
    global current_port
    try:
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return
        if current_port is None:
            return
            
        with state_lock:
            target_port = state['target_local_port']
            
        # If target local port is configured, filter strictly by that client's port!
        if target_port is not None:
            if packet[TCP].sport != target_port and packet[TCP].dport != target_port:
                return
        else:
            # Fall back to any traffic on the Map Server port
            if packet[TCP].sport != current_port and packet[TCP].dport != current_port:
                return

        payload = bytes(packet[Raw].load)
        
        # 1. ZC_PAR_CHANGE (0x00B0)
        start_search = 0
        while True:
            pos = payload.find(b'\xb0\x00', start_search)
            if pos == -1:
                break
            if len(payload) >= pos + 8:
                try:
                    v_type = struct.unpack_from('<H', payload, pos + 2)[0]
                    v_val  = struct.unpack_from('<i', payload, pos + 4)[0]
                    handle_status_update(v_type, v_val)
                except Exception:
                    pass
            start_search = pos + 2
            
        # 2. ZC_LONGPAR_CHANGE (0x022D y 0x00B1)
        for op in [b'\x2d\x02', b'\xb1\x00']:
            start_search = 0
            while True:
                pos = payload.find(op, start_search)
                if pos == -1:
                    break
                # Try 8-byte value parsing for modern high-limit Renewal EXP
                parsed = False
                if len(payload) >= pos + 12:
                    try:
                        v_type = struct.unpack_from('<H', payload, pos + 2)[0]
                        v_val  = struct.unpack_from('<q', payload, pos + 4)[0]
                        handle_status_update(v_type, v_val)
                        parsed = True
                    except Exception:
                        pass
                # Fallback to 4-byte parsing
                if not parsed and len(payload) >= pos + 8:
                    try:
                        v_type = struct.unpack_from('<H', payload, pos + 2)[0]
                        v_val  = struct.unpack_from('<i', payload, pos + 4)[0]
                        handle_status_update(v_type, v_val)
                    except Exception:
                        pass
                start_search = pos + 2

        # 3. ZC_NOTIFY_EXP (0x07F6: Legacy 4-byte amount, 0x0AC9 / 0x0ACC: Modern 8-byte amount)
        for op in [b'\xf6\x07', b'\xc9\x0a', b'\xcc\x0a']:
            start_search = 0
            while True:
                pos = payload.find(op, start_search)
                if pos == -1:
                    break
                try:
                    if op == b'\xf6\x07': # Legacy 14-byte packet structure
                        if len(payload) >= pos + 14:
                            exp_val  = struct.unpack_from('<I', payload, pos + 6)[0]
                            exp_type = struct.unpack_from('<H', payload, pos + 10)[0] # Var ID at offset 10
                            print(f"[DEBUG] ZC_NOTIFY_EXP (Legacy) Parsed - Opcode: {op.hex()}, Type: {exp_type}, Amount: {exp_val}", flush=True)
                            handle_notify_exp(exp_type, exp_val)
                    else: # Modern 18-byte packet structure (0x0AC9, 0x0ACC)
                        if len(payload) >= pos + 18:
                            exp_val  = struct.unpack_from('<Q', payload, pos + 6)[0] # 64-bit Quad amount
                            exp_type = struct.unpack_from('<H', payload, pos + 14)[0] # Actual Var ID at offset 14
                            
                            # RE-MAP MODERN IDs to match internal tracking (0 for Base, 1 for Job)
                            # User confirmed on this modern server: Type 1 is Base, Type 2 is Job.
                            mapped_type = 0 if exp_type == 1 else (1 if exp_type == 2 else exp_type)
                            
                            print(f"[DEBUG] ZC_NOTIFY_EXP (Modern) Parsed - Opcode: {op.hex()}, OrigType: {exp_type}, InternalType: {mapped_type}, Amount: {exp_val}", flush=True)
                            handle_notify_exp(mapped_type, exp_val)
                except Exception:
                    pass
                start_search = pos + 2
            
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
#  PREMIUM CANVAS PROGRESS BAR
# ─────────────────────────────────────────────────────────────
class PremiumProgressBar(tk.Canvas):
    def __init__(self, parent, width=380, height=24, bg_color="#1F1F1F", fill_color="#00E676", text_color="#FFFFFF", **kwargs):
        super().__init__(parent, width=width, height=height, bg="#121212", bd=0, highlightthickness=0, **kwargs)
        self.width = width
        self.height = height
        self.bg_color = bg_color
        self.fill_color = fill_color
        self.text_color = text_color
        self.percentage = 0.0
        self.label_text = ""
        self.draw()

    def set_progress(self, percentage, label_text=""):
        self.percentage = max(0.0, min(100.0, percentage))
        self.label_text = label_text
        self.draw()

    def draw(self):
        self.delete("all")
        # Background arc/rounded rectangle representation
        r = 8  # corner radius
        # Draw background
        self.create_rounded_rect(0, 0, self.width, self.height, r, fill=self.bg_color)
        
        # Draw progress fill
        fill_width = int((self.percentage / 100.0) * self.width)
        if fill_width > r:
            self.create_rounded_rect(0, 0, fill_width, self.height, r, fill=self.fill_color)
        elif fill_width > 0:
            # minimal sliver
            self.create_rectangle(0, 0, fill_width, self.height, fill=self.fill_color, width=0)
            
        # Center Label Text
        self.create_text(self.width / 2, self.height / 2, text=self.label_text, fill=self.text_color, font=("Segoe UI", 9, "bold"))

    def create_rounded_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1,
            x1 + r, y1,
            x2 - r, y1,
            x2 - r, y1,
            x2, y1,
            x2, y1 + r,
            x2, y1 + r,
            x2, y2 - r,
            x2, y2 - r,
            x2, y2,
            x2 - r, y2,
            x2 - r, y2,
            x1 + r, y2,
            x1 + r, y2,
            x1, y2,
            x1, y2 - r,
            x1, y2 - r,
            x1, y1 + r,
            x1, y1 + r,
            x1, y1
        ]
        return self.create_polygon(points, smooth=True, **kwargs)


# ─────────────────────────────────────────────────────────────
#  FLOATING TRANSPARENT OVERLAY
# ─────────────────────────────────────────────────────────────
class FloatingOverlay(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.attributes("-alpha", 0.85)
        self.configure(bg="#2D2D2D")
        
        # Initial sizing and position
        self.geometry("340x110+120+120")
        
        # Mouse dragging bindings
        self.bind("<ButtonPress-1>", self.start_drag)
        self.bind("<B1-Motion>", self.drag)
        
        # Outer Border
        self.border_frame = tk.Frame(self, bg="#444444", bd=1)
        self.border_frame.pack(fill="both", expand=True, padx=1, pady=1)
        
        self.inner_frame = tk.Frame(self.border_frame, bg="#121212")
        self.inner_frame.pack(fill="both", expand=True)
        
        # Top title row (Draggable handle area)
        self.title_bar = tk.Frame(self.inner_frame, bg="#1A1A1A", height=22)
        self.title_bar.pack(fill="x", side="top")
        
        self.title_lbl = tk.Label(self.title_bar, text="★ RO EXP OVERLAY (Click & Drag) ★", bg="#1A1A1A", fg="#888888", font=("Segoe UI", 8, "bold"))
        self.title_lbl.pack(side="left", padx=8)
        
        self.close_btn = tk.Label(self.title_bar, text="✕", bg="#1A1A1A", fg="#FF3D00", font=("Segoe UI", 9, "bold"), cursor="hand2")
        self.close_btn.pack(side="right", padx=8)
        self.close_btn.bind("<Button-1>", lambda e: self.destroy())
        
        # Grid content
        self.content_frame = tk.Frame(self.inner_frame, bg="#121212")
        self.content_frame.pack(fill="both", expand=True, padx=12, pady=6)
        
        # Row 1: Base EXP info
        self.base_hr_lbl = tk.Label(self.content_frame, text="BASE: +0 XP/hr", bg="#121212", fg="#00E676", font=("Segoe UI", 11, "bold"))
        self.base_hr_lbl.grid(row=0, column=0, sticky="w", pady=2)
        
        self.base_ttl_lbl = tk.Label(self.content_frame, text="TTL: --", bg="#121212", fg="#FFD600", font=("Segoe UI", 10, "bold"))
        self.base_ttl_lbl.grid(row=0, column=1, sticky="e", padx=5, pady=2)
        
        # Row 2: Job EXP info
        self.job_hr_lbl = tk.Label(self.content_frame, text="JOB:  +0 XP/hr", bg="#121212", fg="#00B0FF", font=("Segoe UI", 11, "bold"))
        self.job_hr_lbl.grid(row=1, column=0, sticky="w", pady=2)
        
        self.job_ttl_lbl = tk.Label(self.content_frame, text="TTL: --", bg="#121212", fg="#FFD600", font=("Segoe UI", 10, "bold"))
        self.job_ttl_lbl.grid(row=1, column=1, sticky="e", padx=5, pady=2)
        
        # Row 3: Session info
        self.session_lbl = tk.Label(self.content_frame, text="Lvl: Base -- / Job -- | Session: 00:00:00", bg="#121212", fg="#888888", font=("Segoe UI", 8))
        self.session_lbl.grid(row=2, column=0, columnspan=2, sticky="w", pady=2)
        
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(1, weight=1)
        
        # Resize Grip
        self.grip = tk.Label(self.inner_frame, text="◢", bg="#121212", fg="#444444", cursor="size_nw_se", font=("Segoe UI", 8))
        self.grip.place(relx=1.0, rely=1.0, anchor="se")
        self.grip.bind("<ButtonPress-1>", self.start_resize)
        self.grip.bind("<B1-Motion>", self.resize_window)
        
        self.update_overlay()
        
    def start_drag(self, event):
        self.x = event.x
        self.y = event.y

    def drag(self, event):
        deltax = event.x - self.x
        deltay = event.y - self.y
        x = self.winfo_x() + deltax
        y = self.winfo_y() + deltay
        self.geometry(f"+{x}+{y}")

    def start_resize(self, event):
        self.resize_start_x = event.x_root
        self.resize_start_y = event.y_root
        self.resize_start_w = self.winfo_width()
        self.resize_start_h = self.winfo_height()

    def resize_window(self, event):
        dx = event.x_root - self.resize_start_x
        dy = event.y_root - self.resize_start_y
        new_w = max(240, self.resize_start_w + dx)
        new_h = max(90, self.resize_start_h + dy)
        self.geometry(f"{new_w}x{new_h}")
        
    def update_overlay(self):
        try:
            if not self.winfo_exists():
                return
            
            metrics = calculate_metrics()
            
            # Base Exp metrics
            base_rate = metrics['base_exp_hr']
            self.base_hr_lbl.config(text=f"BASE: +{base_rate:,.0f} XP/hr")
            
            ttl_base = "TTL: --"
            with state_lock:
                if state['next_base_exp'] > 0 and state['base_exp'] > 0:
                    needed = max(0, state['next_base_exp'] - state['base_exp'])
                    rate = metrics['base_exp_sec']
                    if rate > 0:
                        ttl_base = f"TTL: {format_seconds(needed / rate)}"
            self.base_ttl_lbl.config(text=ttl_base)
            
            # Job Exp metrics
            job_rate = metrics['job_exp_hr']
            self.job_hr_lbl.config(text=f"JOB:  +{job_rate:,.0f} XP/hr")
            
            ttl_job = "TTL: --"
            with state_lock:
                if state['next_job_exp'] > 0 and state['job_exp'] > 0:
                    needed = max(0, state['next_job_exp'] - state['job_exp'])
                    rate = metrics['job_exp_sec']
                    if rate > 0:
                        ttl_job = f"TTL: {format_seconds(needed / rate)}"
            self.job_ttl_lbl.config(text=ttl_job)
            
            # Info string
            with state_lock:
                b_lvl = state['base_level']
                j_lvl = state['job_level']
            self.session_lbl.config(text=f"Lvl: Base {b_lvl} / Job {j_lvl} | Session: {format_seconds(metrics['elapsed'])}")
            
        except Exception:
            pass
        self.after(500, self.update_overlay)


# ─────────────────────────────────────────────────────────────
#  MAIN APP INTERFACE (TKINTER DESIGN)
# ─────────────────────────────────────────────────────────────
class App:
    def __init__(self, root):
        global ui_instance
        ui_instance = self
        self.root = root
        self.root.title("ROEXP TRACKER v1.0")
        self.root.geometry("460x760")
        self.root.attributes("-topmost", False)
        self.root.configure(bg="#121212")
        
        # Styling Setup
        self.setup_custom_styles()
        
        # ── Header Frame ─────────────────────────────────────
        self.header_frame = tk.Frame(root, bg="#121212")
        self.header_frame.pack(fill="x", padx=20, pady=15)
        
        self.title_lbl = tk.Label(self.header_frame, text="ROEXP", bg="#121212", fg="#00E676", font=("Segoe UI", 16, "bold"))
        self.title_lbl.pack(anchor="w")
        
        self.status_lbl = tk.Label(self.header_frame, text="Map Server Status: BUSCANDO SERVICIO RO...", bg="#121212", fg="#FF9100", font=("Segoe UI", 9, "bold"))
        # self.status_lbl.pack(anchor="w", pady=2)
        
        # ── Control Panel (Card Layout) ──────────────────────
        self.control_card = tk.Frame(root, bg="#1E1E1E", bd=1, relief="flat")
        self.control_card.pack(fill="x", padx=20, pady=5)
        
        self.control_inner = tk.Frame(self.control_card, bg="#1E1E1E", padx=15, pady=12)
        self.control_inner.pack(fill="both")
        
        # Buttons row
        self.start_btn = tk.Button(self.control_inner, text="INICIAR SESIÓN", bg="#00E676", fg="#121212", activebackground="#00B0FF", activeforeground="#FFFFFF", bd=0, font=("Segoe UI", 10, "bold"), cursor="hand2", height=1, width=15, command=self.toggle_tracking)
        self.start_btn.grid(row=0, column=0, padx=5, pady=5)
        self.bind_hover_effect(self.start_btn, "#00E676", "#00B254")
        
        self.reset_btn = tk.Button(self.control_inner, text="RESET", bg="#424242", fg="#FFFFFF", activebackground="#D50000", activeforeground="#FFFFFF", bd=0, font=("Segoe UI", 10, "bold"), cursor="hand2", height=1, width=8, command=self.reset_tracking)
        self.reset_btn.grid(row=0, column=1, padx=5, pady=5)
        self.bind_hover_effect(self.reset_btn, "#424242", "#2E2E2E")
        
        self.overlay_btn = tk.Button(self.control_inner, text="OVERLAY TRANSPARENTE", bg="#00B0FF", fg="#FFFFFF", activebackground="#0091EA", bd=0, font=("Segoe UI", 10, "bold"), cursor="hand2", height=1, width=20, command=self.open_overlay)
        self.overlay_btn.grid(row=0, column=2, padx=5, pady=5)
        self.bind_hover_effect(self.overlay_btn, "#00B0FF", "#008CD4")
        
        # Config options row (Sliding window)
        self.win_lbl = tk.Label(self.control_inner, text="Ventana de cálculo:", bg="#1E1E1E", fg="#888888", font=("Segoe UI", 9))
        self.win_lbl.grid(row=1, column=0, sticky="w", padx=5, pady=8)
        
        self.win_combo = ttk.Combobox(self.control_inner, values=["1 Minuto", "5 Minutos", "15 Minutos", "Promedio Sesión"], state="readonly", width=16)
        self.win_combo.current(3)
        self.win_combo.grid(row=1, column=1, columnspan=2, sticky="w", padx=5, pady=8)
        self.win_combo.bind("<<ComboboxSelected>>", self.change_window_size)
        
        # New Row 2: Table Selection (Summoner vs Adjusted)
        self.table_lbl = tk.Label(self.control_inner, text="Tabla EXP:", bg="#1E1E1E", fg="#888888", font=("Segoe UI", 9))
        self.table_lbl.grid(row=2, column=0, sticky="w", padx=5, pady=8)
        
        self.table_combo = ttk.Combobox(self.control_inner, values=["Standard (Normal)", "Adjusted (Reducida)"], state="readonly", width=16)
        self.table_combo.current(0)
        self.table_combo.grid(row=2, column=1, columnspan=2, sticky="w", padx=5, pady=8)
        self.table_combo.bind("<<ComboboxSelected>>", self.change_exp_table)
        
        # Row 3 (was 2): Level / EXP Manual Sync
        self.sync_lbl = tk.Label(self.control_inner, text="Base Lvl:", bg="#1E1E1E", fg="#888888", font=("Segoe UI", 9))
        self.sync_lbl.grid(row=3, column=0, sticky="w", padx=5, pady=4)
        
        self.lvl_entry = tk.Entry(self.control_inner, bg="#121212", fg="#FFFFFF", bd=0, insertbackground="#FFFFFF", width=8, font=("Segoe UI", 9, "bold"), justify="center")
        self.lvl_entry.grid(row=3, column=1, sticky="w", padx=5, pady=4)
        self.lvl_entry.insert(0, "187")
        
        self.pct_frame = tk.Frame(self.control_inner, bg="#1E1E1E")
        self.pct_frame.grid(row=3, column=2, sticky="w", padx=5, pady=4)
        
        self.pct_lbl = tk.Label(self.pct_frame, text="EXP %:", bg="#1E1E1E", fg="#888888", font=("Segoe UI", 9))
        self.pct_lbl.pack(side="left")
        
        self.pct_entry = tk.Entry(self.pct_frame, bg="#121212", fg="#FFFFFF", bd=0, insertbackground="#FFFFFF", width=8, font=("Segoe UI", 9, "bold"), justify="center")
        self.pct_entry.pack(side="left", padx=5)
        self.pct_entry.insert(0, "58.0")
        
        self.sync_btn = tk.Button(self.pct_frame, text="SYNC", bg="#FFD600", fg="#121212", activebackground="#FFC400", bd=0, font=("Segoe UI", 8, "bold"), cursor="hand2", padx=6, command=self.sync_level_exp)
        self.sync_btn.pack(side="left", padx=5)
        
        # Row 4 (was 3): Client Process Selection
        self.proc_lbl = tk.Label(self.control_inner, text="Cliente RO:", bg="#1E1E1E", fg="#888888", font=("Segoe UI", 9))
        self.proc_lbl.grid(row=4, column=0, sticky="w", padx=5, pady=8)
        
        self.proc_combo = ttk.Combobox(self.control_inner, values=["Todos los clientes"], state="readonly", width=16)
        self.proc_combo.current(0)
        self.proc_combo.grid(row=4, column=1, sticky="w", padx=5, pady=8)
        self.proc_combo.bind("<<ComboboxSelected>>", self.select_target_process)
        
        self.proc_btn = tk.Button(self.control_inner, text="REFRESCAR", bg="#424242", fg="#FFFFFF", activebackground="#00B0FF", bd=0, font=("Segoe UI", 8, "bold"), cursor="hand2", padx=6, command=self.refresh_process_list)
        self.proc_btn.grid(row=4, column=2, sticky="w", padx=5, pady=8)
        self.bind_hover_effect(self.proc_btn, "#424242", "#2E2E2E")
        
        # ── Level Info Card ───────────────────────────────
        self.level_card = tk.Frame(root, bg="#1E1E1E")
        self.level_card.pack(fill="x", padx=20, pady=5)
        
        self.level_inner = tk.Frame(self.level_card, bg="#1E1E1E", padx=15, pady=10)
        self.level_inner.pack(fill="both")
        
        self.base_lvl_lbl = tk.Label(self.level_inner, text="BASE LVL: --", bg="#1E1E1E", fg="#FFD600", font=("Segoe UI", 12, "bold"))
        self.base_lvl_lbl.pack(side="left", expand=True)
        
        self.job_lvl_lbl = tk.Label(self.level_inner, text="JOB LVL: --", bg="#1E1E1E", fg="#FFD600", font=("Segoe UI", 12, "bold"))
        self.job_lvl_lbl.pack(side="left", expand=True)
        
        self.timer_lbl = tk.Label(self.level_inner, text="TIEMPO: 00:00:00", bg="#1E1E1E", fg="#FFFFFF", font=("Segoe UI", 12, "bold"))
        self.timer_lbl.pack(side="left", expand=True)
        
        # ── Base EXP Metrics Card ──────────────────────────
        self.base_card = tk.Frame(root, bg="#1E1E1E")
        self.base_card.pack(fill="x", padx=20, pady=5)
        
        self.base_inner = tk.Frame(self.base_card, bg="#1E1E1E", padx=15, pady=12)
        self.base_inner.pack(fill="both")
        
        self.base_header = tk.Label(self.base_inner, text="BASE EXPERIENCE", bg="#1E1E1E", fg="#00E676", font=("Segoe UI", 9, "bold"))
        self.base_header.pack(anchor="w")
        
        self.base_rate_lbl = tk.Label(self.base_inner, text="+0 XP/hr", bg="#1E1E1E", fg="#FFFFFF", font=("Segoe UI", 20, "bold"))
        self.base_rate_lbl.pack(anchor="w", pady=2)
        
        self.base_sub_lbl = tk.Label(self.base_inner, text="Ganado en sesión: 0 XP | TTL: --", bg="#1E1E1E", fg="#888888", font=("Segoe UI", 9))
        self.base_sub_lbl.pack(anchor="w", pady=2)
        
        self.base_progress = PremiumProgressBar(self.base_inner, width=390, height=20, bg_color="#2A2A2A", fill_color="#00E676")
        self.base_progress.pack(fill="x", pady=6)
        self.base_progress.set_progress(0, "0.0% (0 / 0)")
        
        # ── Job EXP Metrics Card ───────────────────────────
        self.job_card = tk.Frame(root, bg="#1E1E1E")
        self.job_card.pack(fill="x", padx=20, pady=5)
        
        self.job_inner = tk.Frame(self.job_card, bg="#1E1E1E", padx=15, pady=12)
        self.job_inner.pack(fill="both")
        
        self.job_header = tk.Label(self.job_inner, text="JOB EXPERIENCE", bg="#1E1E1E", fg="#00B0FF", font=("Segoe UI", 9, "bold"))
        self.job_header.pack(anchor="w")
        
        self.job_rate_lbl = tk.Label(self.job_inner, text="+0 XP/hr", bg="#1E1E1E", fg="#FFFFFF", font=("Segoe UI", 20, "bold"))
        self.job_rate_lbl.pack(anchor="w", pady=2)
        
        self.job_sub_lbl = tk.Label(self.job_inner, text="Ganado en sesión: 0 XP | TTL: --", bg="#1E1E1E", fg="#888888", font=("Segoe UI", 9))
        self.job_sub_lbl.pack(anchor="w", pady=2)
        
        self.job_progress = PremiumProgressBar(self.job_inner, width=390, height=20, bg_color="#2A2A2A", fill_color="#00B0FF")
        self.job_progress.pack(fill="x", pady=6)
        self.job_progress.set_progress(0, "0.0% (0 / 0)")
        
        # ── Live Gains Log Card ────────────────────────────
        self.log_card = tk.Frame(root, bg="#1E1E1E")
        self.log_card.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.log_inner = tk.Frame(self.log_card, bg="#1E1E1E", padx=15, pady=10)
        self.log_inner.pack(fill="both", expand=True)
        
        self.log_header = tk.Label(self.log_inner, text="LIVE GAINS LOG", bg="#1E1E1E", fg="#888888", font=("Segoe UI", 8, "bold"))
        self.log_header.pack(anchor="w", pady=2)
        
        self.log_display = scrolledtext.ScrolledText(self.log_inner, bg="#121212", fg="#CFD8DC", font=("Consolas", 9), bd=0, highlightthickness=0, height=6)
        self.log_display.pack(fill="both", expand=True, pady=4)
        
        # Config logs tags colors
        self.log_display.tag_config('base', foreground='#00E676')
        self.log_display.tag_config('job', foreground='#00B0FF')
        self.log_display.tag_config('level_up', foreground='#FFD600', font=('Consolas', 9, 'bold'))
        self.log_display.tag_config('system', foreground='#888888', font=('Consolas', 9, 'italic'))
        
        self.log_message("Sistema listo. Esperando detección del Map Server...", "system")
        
        # Populate process list initially after log_display is ready
        self.refresh_process_list()
        
        # Start periodic GUI updates
        self.update_gui()

    # Styling helper
    def setup_custom_styles(self):
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TCombobox', fieldbackground='#1E1E1E', background='#424242', foreground='#FFFFFF', bd=0, arrowcolor='#00E676')
        style.map('TCombobox', fieldbackground=[('readonly', '#1E1E1E')], selectbackground=[('readonly', '#00E676')], selectforeground=[('readonly', '#121212')])

    # Flat button hover effects
    def bind_hover_effect(self, widget, normal_color, hover_color):
        widget.bind("<Enter>", lambda e: widget.config(bg=hover_color))
        widget.bind("<Leave>", lambda e: widget.config(bg=normal_color))

    # Control logic
    def toggle_tracking(self):
        with state_lock:
            if not state['tracking_active']:
                state['tracking_active'] = True
                state['start_time'] = time.time()
                self.start_btn.config(text="PAUSAR SESIÓN", bg="#FF3D00")
                self.bind_hover_effect(self.start_btn, "#FF3D00", "#D50000")
                self.log_message("Sesión de rastreo iniciada.", "system")
            else:
                state['tracking_active'] = False
                self.start_btn.config(text="REANUDAR SESIÓN", bg="#00E676")
                self.bind_hover_effect(self.start_btn, "#00E676", "#00B254")
                self.log_message("Sesión de rastreo pausada.", "system")

    def reset_tracking(self):
        with state_lock:
            state['total_base_gained'] = 0
            state['total_job_gained'] = 0
            state['gains_log'] = []
            if state['tracking_active']:
                state['start_time'] = time.time()
            else:
                state['start_time'] = None
            self.log_message("Sesión reiniciada. Métricas reseteadas.", "system")

    def open_overlay(self):
        FloatingOverlay(self.root)
        self.log_message("Floating Transparent Overlay abierto.", "system")

    def change_window_size(self, event):
        val = self.win_combo.get()
        with state_lock:
            if val == "1 Minuto":
                state['window_size'] = 60
            elif val == "5 Minutos":
                state['window_size'] = 300
            elif val == "15 Minutos":
                state['window_size'] = 900
            elif val == "Promedio Sesión":
                state['window_size'] = 9999999  # very large window
        self.log_message(f"Ventana de cálculo actualizada a: {val}", "system")
        
    def change_exp_table(self, event):
        global BASE_EXP_TABLE
        val = self.table_combo.get()
        if val == "Adjusted (Reducida)":
            BASE_EXP_TABLE = EXP_TABLE_ADJUSTED
            self.log_message("Tabla activa: ADJUSTED EXP (Reducida)", "system")
        else:
            BASE_EXP_TABLE = EXP_TABLE_SUMMONER
            self.log_message("Tabla activa: STANDARD EXP (Normal)", "system")

    def sync_level_exp(self):
        try:
            lvl = int(self.lvl_entry.get())
            pct = float(self.pct_entry.get())
            if lvl in BASE_EXP_TABLE:
                next_b = BASE_EXP_TABLE[lvl]
                b_exp = int(next_b * (pct / 100.0))
                with state_lock:
                    state['base_level'] = lvl
                    state['base_exp'] = b_exp
                    state['next_base_exp'] = next_b
                    # Initialize Job Level to 70 and Next Job EXP if empty
                    if state['job_level'] == 0:
                        state['job_level'] = 70
                    if state['next_job_exp'] == 0:
                        state['next_job_exp'] = 10000000  # Default dummy
                        state['job_exp'] = 0
                self.log_message(f"Sincronizado: Base Lvl {lvl} al {pct:.2f}% (EXP: {format_exp(b_exp)} / {format_exp(next_b)})", "system")
            else:
                self.log_message("Error: Nivel fuera de rango (1-200)", "system")
        except ValueError:
            self.log_message("Error: Introduce números válidos", "system")

    def refresh_process_list(self):
        try:
            processes = ["Todos los clientes"]
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    name = proc.info['name']
                    pid = proc.info['pid']
                    name_lower = name.lower()
                    
                    is_candidate = "ragexe" in name_lower
                            
                    if is_candidate:
                        processes.append(f"{name} (PID: {pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            unique_procs = sorted(list(set(processes)), key=lambda x: 0 if "Todos" in x else 1)
            self.proc_combo.config(values=unique_procs)
            self.proc_combo.current(0)
            with state_lock:
                state['target_pid'] = None
                state['target_local_port'] = None
        except Exception as e:
            self.log_message(f"Error al listar procesos: {e}", "system")

    def select_target_process(self, event=None):
        val = self.proc_combo.get()
        if val == "Todos los clientes":
            with state_lock:
                state['target_pid'] = None
                state['target_local_port'] = None
            self.log_message("Filtrado desactivado: Escuchando todos los clientes.", "system")
            return
            
        try:
            parts = val.split(" (PID: ")
            pid = int(parts[1].replace(")", ""))
            
            proc = psutil.Process(pid)
            conns = proc.connections(kind="tcp")
            
            local_port = None
            global current_port
            
            for c in conns:
                if c.status == "ESTABLISHED":
                    if current_port and c.raddr and c.raddr.port == current_port:
                        local_port = c.laddr.port
                        break
                        
            if not local_port:
                for c in conns:
                    if c.status == "ESTABLISHED" and c.laddr:
                        local_port = c.laddr.port
                        break
                        
            with state_lock:
                state['target_pid'] = pid
                state['target_local_port'] = local_port
                
            if local_port:
                self.log_message(f"Filtrando cliente: {parts[0]} (PID: {pid}) en Puerto Local: {local_port}", "system")
            else:
                self.log_message(f"Cliente seleccionado: {parts[0]} (PID: {pid}) - Esperando conexión TCP...", "system")
        except Exception as e:
            self.log_message(f"Error al seleccionar proceso: {e}", "system")

    # Log text inserter
    def log_message(self, message, tag='system'):
        t_str = time.strftime("[%H:%M:%S]")
        self.log_display.insert(tk.END, f"{t_str} {message}\n", tag)
        self.log_display.see(tk.END)

    # Flash level up animation
    def trigger_level_up(self, lvl_type, level_val):
        # Sound flash or fancy flash
        def flash(count=0):
            if count >= 6:
                self.root.configure(bg="#121212")
                return
            col = "#FFD600" if count % 2 == 0 else "#121212"
            self.root.configure(bg=col)
            self.root.after(120, lambda: flash(count + 1))
        
        flash()

    # Periodic UI Updater Loop
    def update_gui(self):
        global current_ip, current_port
        try:
            # Flush 10-second EXP buffers
            now = time.time()
            with state_lock:
                if state['last_buffer_flush'] == 0:
                    state['last_buffer_flush'] = now
                    
                elapsed_flush = now - state['last_buffer_flush']
                if elapsed_flush >= 10.0:
                    # Flush Base EXP
                    if state['buffered_base_exp'] > 0:
                        self.log_message(f"+{state['buffered_base_exp']:,} Base EXP (10s)", 'base')
                        state['buffered_base_exp'] = 0
                        
                    # Flush Job EXP
                    if state['buffered_job_exp'] > 0:
                        self.log_message(f"+{state['buffered_job_exp']:,} Job EXP (10s)", 'job')
                        state['buffered_job_exp'] = 0
                        
                    state['last_buffer_flush'] = now

            # Verify and refresh PID port if we are filtering by a specific game client
            with state_lock:
                target_pid = state['target_pid']
                target_local_port = state['target_local_port']
                
            if target_pid:
                try:
                    proc = psutil.Process(target_pid)
                    conns = proc.connections(kind="tcp")
                    new_local_port = None
                    for c in conns:
                        if c.status == "ESTABLISHED":
                            if current_port and c.raddr and c.raddr.port == current_port:
                                new_local_port = c.laddr.port
                                break
                    if not new_local_port:
                        for c in conns:
                            if c.status == "ESTABLISHED" and c.laddr:
                                new_local_port = c.laddr.port
                                break
                    if new_local_port and new_local_port != target_local_port:
                        with state_lock:
                            state['target_local_port'] = new_local_port
                        self.log_message(f"Puerto local actualizado automáticamente a: {new_local_port}", "system")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    with state_lock:
                        state['target_pid'] = None
                        state['target_local_port'] = None
                    self.log_message("El cliente seleccionado se ha cerrado. Volviendo a modo global.", "system")

            # Update connection status label
            if current_ip and current_port:
                self.status_lbl.config(text=f"CONECTADO AL MAP SERVER: {current_ip}:{current_port}", fg="#00E676")
            else:
                self.status_lbl.config(text="Map Server Status: BUSCANDO SERVICIO RO...", fg="#FF9100")
                
            metrics = calculate_metrics()
            
            with state_lock:
                # Update text fields
                b_lvl = state['base_level']
                j_lvl = state['job_level']
                b_exp = state['base_exp']
                j_exp = state['job_exp']
                next_b = state['next_base_exp']
                next_j = state['next_job_exp']
                total_b = state['total_base_gained']
                total_j = state['total_job_gained']
                
            # Update levels
            self.base_lvl_lbl.config(text=f"BASE LVL: {b_lvl if b_lvl > 0 else '--'}")
            self.job_lvl_lbl.config(text=f"JOB LVL: {j_lvl if j_lvl > 0 else '--'}")
            self.timer_lbl.config(text=f"TIEMPO: {format_seconds(metrics['elapsed'])}")
            
            # --- Base EXP Card ---
            # Rate text
            is_session_avg = state['window_size'] > 100000
            rate_base = metrics['session_base_hr'] if is_session_avg else metrics['base_exp_hr']
            self.base_rate_lbl.config(text=f"+{rate_base:,.0f} XP/hr" if rate_base > 0 else "0 XP/hr")
            
            # TTL base
            ttl_base_str = "--"
            if next_b > 0 and b_exp > 0:
                needed = max(0, next_b - b_exp)
                rate = metrics['session_base_sec'] if is_session_avg else metrics['base_exp_sec']
                if rate > 0:
                    ttl_base_str = format_seconds(needed / rate)
            self.base_sub_lbl.config(text=f"Ganado: {total_b:,} XP  |  TTL: {ttl_base_str}")
            
            # Progress bar
            pct_b = (b_exp / next_b) * 100 if next_b > 0 else 0.0
            lbl_b = f"{pct_b:.2f}% ({format_exp(b_exp)} / {format_exp(next_b)})" if next_b > 0 else "0.0% (Sin Sincronizar)"
            self.base_progress.set_progress(pct_b, lbl_b)
            
            # --- Job EXP Card ---
            # Rate text
            rate_job = metrics['session_job_hr'] if is_session_avg else metrics['job_exp_hr']
            self.job_rate_lbl.config(text=f"+{rate_job:,.0f} XP/hr" if rate_job > 0 else "0 XP/hr")
            
            # TTL job
            ttl_job_str = "--"
            if next_j > 0 and j_exp > 0:
                needed = max(0, next_j - j_exp)
                rate = metrics['session_job_sec'] if is_session_avg else metrics['job_exp_sec']
                if rate > 0:
                    ttl_job_str = format_seconds(needed / rate)
            self.job_sub_lbl.config(text=f"Ganado: {total_j:,} XP  |  TTL: {ttl_job_str}")
            
            # Progress bar
            pct_j = (j_exp / next_j) * 100 if next_j > 0 else 0.0
            lbl_j = f"{pct_j:.2f}% ({format_exp(j_exp)} / {format_exp(next_j)})" if next_j > 0 else "0.0% (Sin Sincronizar)"
            self.job_progress.set_progress(pct_j, lbl_j)
            
        except Exception as e:
            pass
            
        # Poll every 500ms
        self.root.after(500, self.update_gui)


# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  ROEXP RAGNAROK ONLINE REAL-TIME EXP TRACKER")
    print("=" * 60)
    print("  Iniciando detector de puerto...")
    
    # Port detector thread
    detector = RoPortDetector(on_detected=lambda p, i: globals().update(current_port=p, current_ip=i))
    detector.detect()
    detector.start_background_watch()
    
    # Scapy sniffer thread
    sniff_thread = threading.Thread(
        target=lambda: sniff(filter="tcp", prn=process_packet, store=False),
        daemon=True
    )
    sniff_thread.start()
    
    # Tkinter Main Loop
    root = tk.Tk()
    app = App(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\n[*] Tracker finalizado por el usuario.")
    finally:
        detector.stop()
        sys.exit(0)
