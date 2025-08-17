import re # Regular expression operations for parsing replies
import socket # one polling thread per detected IP
import threading # one polling thread per detected IP
import time # timing, pacing, epochs (counting seconds since a specific starting point)
import queue # thread-safe queue to handle results to the printer loop
from datetime import datetime
from zoneinfo import ZoneInfo # localize timestamps (America/Chicago)
from typing import Optional, Tuple, List, Dict, Any # type hints

# ======================
# Config
# ======================

IP_CANDIDATES = [
    "192.168.1.2", "192.168.2.2", "192.168.3.2", "192.168.4.2",
    "192.168.5.2", "192.168.6.2", "192.168.7.2", "192.168.8.2"
]

CAEN_PORT = 10001
TDK_PORT  = 8003

# Terminators to try when probing
CAEN_TERMS = ("\r", "\r\n")
TDK_TERMS  = ("\r\n", "\r")   # most SCPI stacks like CRLF; try both

# Terminators to use during steady polling
CAEN_POLL_TERM = "\r"
TDK_POLL_TERM  = "\r\n"

# Socket timeouts (Keep the scanner snappy)
CONNECT_TIMEOUT_S = 0.8
RECV_TIMEOUT_S    = 0.8

# Classifier behavior
STRICT_NEGATIVE_TESTS = True   # penalize devices that look like the other family
CLASSIFY_THRESHOLD    = 4      # min score to accept a label

# ======================
# Runtime state
# ======================

stop_event = threading.Event() # signals all threads to stop
# grouped_queue items: {"ip":..., "device":..., "ts_epoch":..., "ts_local":..., "psID":..., "values":{...}}
grouped_queue: "queue.Queue[Dict[str, Any]]" = queue.Queue() # Pipeline from poller threads -> Printer loop

# ======================
# Utilities
# ======================

def _port_open(ip: str, port: int) -> bool:
    """
    The function `_port_open` checks if a port on a specified IP address is open.
    
    :param ip: The `ip` parameter in the `_port_open` function is a string that represents the IP
    address of the target host to check for an open port
    :type ip: str
    :param port: The `port` parameter in the `_port_open` function is an integer that represents the
    port number on the target IP address that you want to check for connectivity. Ports are
    communication endpoints that allow different services or applications to communicate over a network
    :type port: int
    :return: The function `_port_open` is returning a boolean value. It returns `True` if a connection
    can be successfully established to the specified IP address and port, and `False` if an exception
    occurs during the connection attempt.
    """
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_S):
            return True
    except Exception:
        return False

def _send_recv_once(ip: str, port: int, cmd: str, term: str) -> Optional[str]:
    """
    This function sends a command to a specified IP address and port, receives a response, and returns
    the response as a string.
    
    :param ip: The `ip` parameter is a string representing the IP address of the target server or device
    you want to communicate with
    :type ip: str
    :param port: The `port` parameter in the `_send_recv_once` function is an integer that represents
    the port number to which the socket connection will be made. It specifies the communication endpoint
    for the connection
    :type port: int
    :param cmd: The `cmd` parameter in the `_send_recv_once` function represents the command that you
    want to send to the specified IP address and port. This command will be sent over the socket
    connection to the remote server for execution
    :type cmd: str
    :param term: The `term` parameter in the `_send_recv_once` function is a string that represents the
    termination character or sequence that is appended to the `cmd` string before sending it over the
    network connection. It is used to indicate the end of the command being sent so that the receiving
    end knows when the
    :type term: str
    :return: The function `_send_recv_once` returns a string or `None`. If data is successfully received
    from the socket connection, it returns the decoded and stripped data as a string. If an exception
    occurs during the process, it returns `None`.
    """

    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_S) as s:
            s.settimeout(RECV_TIMEOUT_S)
            s.sendall((cmd + term).encode("ascii", errors="ignore"))
            data = s.recv(4096)
            if not data:
                return None
            return data.decode("ascii", errors="ignore").strip()
    except Exception:
        return None

def _try_terms(ip: str, port: int, cmd: str, terms: Tuple[str, ...]) -> Tuple[Optional[str], Optional[str]]:
    """
    This function tries multiple terminators and returns the first one that receives a response.
    
    :param ip: The `ip` parameter is a string that represents the IP address of the target server or
    device that you want to communicate with
    :type ip: str
    :param port: The `port` parameter in the `_try_terms` function is of type `int` and represents the
    port number to which the function will attempt to connect during its execution
    :type port: int
    :param cmd: The `cmd` parameter in the `_try_terms` function represents the command that will be
    sent to the specified IP address and port. It is a string that contains the command to be executed
    on the remote system
    :type cmd: str
    :param terms: The `terms` parameter is a tuple of strings representing multiple terminators. The
    function `_try_terms` will iterate over each terminator in the `terms` tuple and try sending a
    command with that terminator to receive a response. It will return the first terminator that
    successfully returns a response along with the response
    :type terms: Tuple[str, ...]
    :return: The function `_try_terms` returns a tuple containing two elements: the terminator used
    (`term_used`) and the response received (`resp`). If none of the terminators in the provided tuple
    `terms` result in a response, the function returns a tuple with two `None` values.
    """
    """Try multiple terminators; return (term_used, resp) for the first that returns anything."""
    for t in terms:
        resp = _send_recv_once(ip, port, cmd, t)
        if resp is not None:
            return t, resp
    return None, None

def _parse_idn(resp: str) -> Optional[Tuple[str, str, str, str]]:
    """
    The function `_parse_idn` takes a string input, splits it by commas, and returns a tuple of four
    stripped parts if the input contains exactly four parts, otherwise it returns None.
    
    :param resp: The function `_parse_idn` takes a string `resp` as input and splits it by commas. It
    then checks if the resulting list has exactly 4 parts. If it does, it returns a tuple containing the
    4 parts stripped of any leading or trailing whitespace. If the number of parts
    :type resp: str
    :return: The function `_parse_idn` is returning a tuple containing four elements extracted from the
    input string `resp`. The elements are the result of splitting the input string by commas and
    stripping any leading or trailing whitespace. If the input string does not contain exactly 4 parts
    after splitting, the function returns `None`.
    """
    parts = [p.strip() for p in resp.split(",")]
    if len(parts) != 4:
        return None
    return parts[0], parts[1], parts[2], parts[3]

def format_temperature(value_str: str) -> str:
    """
    The `format_temperature` function takes a string representing a temperature value and formats it to
    have one decimal place followed by the unit "°C".
    
    :param value_str: The `value_str` parameter is a string representing a temperature value
    :type value_str: str
    :return: The `format_temperature` function takes a string `value_str` as input and attempts to
    convert it to a float with one decimal place, then appends "°C" to the end. If the conversion is
    successful, it returns the formatted temperature with "°C". If the conversion fails (due to a
    ValueError), it checks if "°C" is already present in the input string.
    """
    try:
        return f"{float(value_str):.1f}°C"
    except ValueError:
        # Already formatted or tagged; still add °C if not present
        return value_str if "°C" in value_str else f"{value_str}°C"

def format_numeric(value_str: str, unit: str) -> str:
    """
    The function `format_numeric` takes a string representing a numeric value and a unit, converts the
    value to a float, formats it based on its magnitude, and returns the formatted value with the unit.
    
    :param value_str: The `value_str` parameter is a string representing a numeric value that you want
    to format
    :type value_str: str
    :param unit: The `unit` parameter is a string that represents the unit of measurement for the
    numeric value provided in the `value_str` parameter. It could be any unit such as "meters",
    "seconds", "kilograms", "dollars", etc
    :type unit: str
    :return: The `format_numeric` function takes a string `value_str` representing a numeric value and a
    string `unit`, and attempts to convert `value_str` to a float. If successful, it formats the float
    value based on its magnitude and returns the formatted value followed by the `unit`. If the
    conversion to float fails (due to a `ValueError`), it simply returns the original `value
    """
    try:
        val = float(value_str)
        if abs(val) >= 1000: out = f"{val:.0f}"
        elif abs(val) >= 100: out = f"{val:.1f}"
        elif abs(val) >= 1:   out = f"{val:.3f}"
        else:                 out = f"{val:.6f}"
        return f"{out} {unit}"
    except ValueError:
        return f"{value_str} {unit}"

# ======================
# Fingerprints & scoring
# ======================
"""
    re.compile(r'^\s*-?\d+\s*(,\s*".*")?\s*$')
        This pattern is meant to match a line containing a SCPI error response, such as: 
            0,"No error"  or  -113,"Undefined header"
        
        Explanation:
            ^ … $ — Anchors the match to the entire line.

            \s* — Matches any leading whitespace.

            -?\d+ — Matches an optional minus sign followed by one or more digits (the error code).

            \s* — Matches optional whitespace after the number.

            (,\s*".*")? — Optionally matches:

            a comma,

            optional whitespace,

            a quoted string (error message).
            
    Entire match is optional beyond the number — it can be just the code (e.g., 0), or code plus message.

        Examples matched:

        0

        0,"No error"

        -113,"Undefined header"
"""
SCPI_ERR_LINE = re.compile(r'^\s*-?\d+\s*(,\s*".*")?\s*$')  # This pattern is meant to match a line containing a SCPI error response, such as: 0,"No error"  or  -113,"Undefined header"
CAEN_TAG_MRV  = re.compile(r'^\s*#\s*MRV\s*:\s*[-+]?(?:\d+(?:\.\d*)?|\.\d+)\s*$') # Matches the #MRV: tag, with flexible spacing.
CAEN_TAG_MST  = re.compile(r'^\s*#\s*MST\s*:\s*[0-9A-Fa-fxX]+\s*$')

def fingerprint_caen(ip: str) -> Tuple[int, Dict[str, str]]:
    """
    This Python function evaluates the fingerprint of a CAEN device based on specific commands and SCPI
    negatives, returning a score and event dictionary.
    
    :param ip: The `ip` parameter in the `fingerprint_caen` function is a string that represents the IP
    address of the device you want to fingerprint
    :type ip: str
    :return: The function `fingerprint_caen` returns a tuple containing an integer score and a
    dictionary of evaluation results.
    """
    """
    Score CAEN on CAEN_PORT using CAEN-only cmds and SCPI negatives.
      +3 MRV tagged ok
      +2 MST tagged ok
      +1 *IDN? missing or not 4 CSV fields (on CAEN port)
      +1 SYST:ERR? not SCPI-like (on CAEN port)
    If STRICT_NEGATIVE_TESTS, subtract when CAEN looks like SCPI.
    """
    score = 0
    ev: Dict[str, str] = {}

    if not _port_open(ip, CAEN_PORT):
        ev["port"] = "closed"
        return score, ev
    ev["port"] = "open"

    term, r = _try_terms(ip, CAEN_PORT, "MRV:?", CAEN_TERMS)
    ev["MRV:?"] = f"{repr(r)} via {repr(term)}"
    if r and CAEN_TAG_MRV.match(r): score += 3

    term, r = _try_terms(ip, CAEN_PORT, "MST:?", CAEN_TERMS)
    ev["MST:?"] = f"{repr(r)} via {repr(term)}"
    if r and CAEN_TAG_MST.match(r): score += 2

    term, r = _try_terms(ip, CAEN_PORT, "*IDN?", CAEN_TERMS)
    ev["*IDN?"] = f"{repr(r)} via {repr(term)}"
    parsed = _parse_idn(r) if r else None
    if parsed is None: score += 1
    elif STRICT_NEGATIVE_TESTS: score -= 1

    term, r = _try_terms(ip, CAEN_PORT, "SYST:ERR?", CAEN_TERMS)
    ev["SYST:ERR?"] = f"{repr(r)} via {repr(term)}"
    if r and SCPI_ERR_LINE.match(r):
        if STRICT_NEGATIVE_TESTS: score -= 1
    else:
        score += 1

    return score, ev

def fingerprint_tdk(ip: str) -> Tuple[int, Dict[str, str]]:
    """
    This Python function evaluates the performance of a TDK device based on specific SCPI commands and
    criteria, assigning a score and providing evaluation details in a dictionary.
    
    :param ip: The `ip` parameter in the `fingerprint_tdk` function is a string representing the IP
    address of the device you want to fingerprint for TDK evaluation
    :type ip: str
    :return: The function `fingerprint_tdk` returns a tuple containing an integer score and a dictionary
    of evaluation results.
    """
    """
    Score TDK on TDK_PORT using SCPI positives and CAEN-negative.
      +3 *IDN? 4 fields & vendor/model matches TDK/Lambda/Genesys
      +2 SYST:ERR? parseable
      +1 MEAS:VOLT? returns floaty value
      +1 MRV:? yields SCPI error (-113...) (negative CAEN test)
    If STRICT_NEGATIVE_TESTS and MRV:? returns a CAEN tag, subtract.
    """
    score = 0
    ev: Dict[str, str] = {}

    if not _port_open(ip, TDK_PORT):
        ev["port"] = "closed"
        return score, ev
    ev["port"] = "open"

    term, r = _try_terms(ip, TDK_PORT, "*IDN?", TDK_TERMS)
    ev["*IDN?"] = f"{repr(r)} via {repr(term)}"
    parsed = _parse_idn(r) if r else None
    vendor_ok = False
    if parsed:
        v, m, s, f = (parsed[0].lower(), parsed[1].lower(), parsed[2], parsed[3])
        if "tdk" in v or "lambda" in v or "genesys" in m:
            vendor_ok = True
    if parsed and vendor_ok: score += 3

    term, r = _try_terms(ip, TDK_PORT, "SYST:ERR?", TDK_TERMS)
    ev["SYST:ERR?"] = f"{repr(r)} via {repr(term)}"
    if r and SCPI_ERR_LINE.match(r): score += 2

    term, r = _try_terms(ip, TDK_PORT, "MEAS:VOLT?", TDK_TERMS)
    ev["MEAS:VOLT?"] = f"{repr(r)} via {repr(term)}"
    try:
        if r is not None and not SCPI_ERR_LINE.match(r):
            float(r)
            score += 1
    except Exception:
        pass

    term, r = _try_terms(ip, TDK_PORT, "MRV:?", TDK_TERMS)
    ev["MRV:? (neg)"] = f"{repr(r)} via {repr(term)}"
    if r and re.search(r"-113|Undefined header|Command error|Header error", r, re.IGNORECASE):
        score += 1
    elif r and CAEN_TAG_MRV.match(r) and STRICT_NEGATIVE_TESTS:
        score -= 2

    return score, ev

def detect_device(ip: str) -> Tuple[str, Dict[str, Dict[str, str]]]:
    """
    This Python function detects the type of device based on IP address and returns the classification
    along with evidence for both probes.
    
    :param ip: The `ip` parameter in the `detect_device` function is a string representing the IP
    address of the device you want to detect
    :type ip: str
    :return: The function `detect_device` returns a tuple containing a string indicating the detected
    device ("CAEN", "TDK", "NONE", or "AMBIG") and a dictionary with evidence for both probes.
    """
    """
    Returns ("CAEN" | "TDK" | "NONE" | "AMBIG"), and evidence for both probes.
    """
    caen_score, caen_ev = fingerprint_caen(ip)
    tdk_score,  tdk_ev  = fingerprint_tdk(ip)

    if caen_score >= CLASSIFY_THRESHOLD and caen_score > tdk_score + 1:
        return "CAEN", {"CAEN": caen_ev, "TDK": tdk_ev}
    if tdk_score  >= CLASSIFY_THRESHOLD and tdk_score  > caen_score + 1:
        return "TDK", {"CAEN": caen_ev, "TDK": tdk_ev}

    if caen_score == 0 and tdk_score == 0:
        return "NONE", {"CAEN": caen_ev, "TDK": tdk_ev}
    return "AMBIG", {"CAEN": caen_ev, "TDK": tdk_ev}

# ======================
# Variable maps (per vendor) — 1s grouped reporting
# ======================

CAEN_CMDS: List[Tuple[str, str]] = [
    ("psID",           "SN:?"),     # #SN:CDCU-100:21Y1193
    ("voltage",        "MRV:?"),    # #MRV:0
    ("current",        "MRI:?"),
    ("power",          "MRW:?"),
    ("temp_buck",      "MRT:1:?"),
    ("temp_cap_bank",  "MRT:2:?"),
    ("temp_adc",       "MRT:3:?"),
    ("temp_board",     "MRT:4:?"),
]

TDK_CMDS: List[Tuple[str, str]] = [
    ("psID",          "*IDN?"),          # TDK-LAMBDA G20-50 SN:340B305-0003
    ("voltage",       "MEAS:VOLT?"),
    ("current",       "MEAS:CURR?"),
    ("power",         "MEAS:POW?"),      
    ("temp_ambient",  "SYST:TEMP:AMB?"), # Internal rack temperature
]

# ======================
# One-thread-per-IP: grouped 1-second reports
# ======================

def ip_scheduler_grouped(ip: str, device: str, port: int, term: str, commands: List[Tuple[str, str]]):
    """
    This Python function performs scheduled polling of commands on a device over TCP connection,
    aggregates the results, and emits grouped reports at one-second intervals.
    
    :param ip: The `ip_scheduler_grouped` function you provided is designed to poll a list of commands
    on a device at regular intervals and aggregate the results into a grouped report. Here's an
    explanation of the parameters used in the function:
    :type ip: str
    :param device: The `device` parameter in the `ip_scheduler_grouped` function represents the type of
    device being queried for data. It can have two possible values: "CAEN" or "TDK". This parameter is
    used to determine how to process and format the data received from the device based on its
    :type device: str
    :param port: The `port` parameter in the `ip_scheduler_grouped` function is an integer that
    represents the port number to which the function will establish a TCP connection. This port number
    is used when creating a socket connection to the specified IP address
    :type port: int
    :param term: The `term` parameter in the `ip_scheduler_grouped` function is a string that represents
    the termination character to be appended to the command before sending it over the socket
    connection. It is used to indicate the end of a command so that the receiving end knows when the
    command is complete and can process
    :type term: str
    :param commands: The `commands` parameter in the `ip_scheduler_grouped` function is a list of tuples
    where each tuple contains two strings. The first string represents the name of the command, and the
    second string represents the actual command to be executed
    :type commands: List[Tuple[str, str]]
    """
    """
    One TCP connection per IP/device. Every 1 second:
      - Poll each command once in sequence
      - Aggregate into a dict (excluding psID)
      - Emit ONE grouped report (local time, IP, device, psID, values)
    """
    tz = ZoneInfo("America/Chicago")
    # tick = 0.1    # Change read speed to 1.0 seconds; Currently 100ms
    tick = 1.0    # Change read speed to 0.1 seconds; Currently 1.0s
    next_tick = time.perf_counter()

    while not stop_event.is_set():
        # pace to 100ms or 1s boundaries
        now = time.perf_counter()
        if now < next_tick:
            time.sleep(next_tick - now)
        next_tick += tick

        values: Dict[str, str] = {}
        ps_id: str = "N/A"

        try:
            with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_S) as s:
                s.settimeout(RECV_TIMEOUT_S)

                for name, cmd in commands:
                    # Send one command, read one reply
                    try:
                        s.sendall((cmd + term).encode("ascii"))
                        resp = s.recv(4096).decode("ascii", errors="ignore").strip()
                    except socket.timeout:
                        if name != "psID":
                            values[name] = "ERROR: timeout"
                        continue
                    except Exception as e:
                        if name != "psID":
                            values[name] = f"ERROR: {e}"
                        continue

                    # Per-field processing
                    if name == "psID":
                        if device == "CAEN":
                            ps_id = resp
                        else:  # TDK
                            parsed = _parse_idn(resp)
                            if parsed:
                                vendor, model, serial, fw = parsed
                                ps_id = f"{vendor} {model} SN:{serial}"
                            else:
                                ps_id = resp
                        # IMPORTANT: do NOT store psID in values (keeps psID from reappearing at end)
                        continue

                    # Non-psID fields
                    if device == "CAEN":
                        if name.startswith("temp_"):
                            values[name] = format_temperature(resp)
                        elif name == "voltage":
                            values[name] = format_numeric(resp, "V")
                        elif name == "current":
                            values[name] = format_numeric(resp, "A")
                        elif name == "power":
                            values[name] = format_numeric(resp, "W")
                        else:
                            values[name] = resp
                    else:  # TDK
                        if name == "temp_ambient":
                            values[name] = format_temperature(resp)
                        elif name == "voltage":
                            values[name] = format_numeric(resp, "V")
                        elif name == "current":
                            values[name] = format_numeric(resp, "A")
                        elif name == "power":
                            values[name] = format_numeric(resp, "W")
                        else:
                            values[name] = resp

        except Exception as e:
            # Could not open/connect; emit an error report for visibility
            ts_epoch = time.time()
            ts_local = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
            grouped = {
                "ip": ip, "device": device, "psID": "N/A",
                "ts_epoch": ts_epoch, "ts_local": ts_local,
                "values": {"scheduler": f"ERROR: {e}"}
            }
            grouped_queue.put(grouped)
            continue

        # Emit ONE grouped record per second (psID appears once, at the beginning)
        ts_epoch = time.time()
        ts_local = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
        grouped = {
            "ip": ip,
            "device": device,
            "psID": ps_id,
            "ts_epoch": ts_epoch,
            "ts_local": ts_local,
            "values": values
        }
        grouped_queue.put(grouped)

# ======================
# Start one thread per open IP
# ======================

def start_ip_thread(ip: str, device: str) -> threading.Thread:
    """
    This Python function starts a new thread to schedule IP tasks based on the device type provided.
    
    :param ip: The `ip` parameter is a string representing the IP address of the device you want to
    communicate with
    :type ip: str
    :param device: The `device` parameter in the `start_ip_thread` function is used to determine which
    set of port, term, and cmds values to use based on the device type. If the device is "CAEN", it will
    use the CAEN_PORT, CAEN_POLL_TERM, and CAEN_CM
    :type device: str
    :return: A threading.Thread object is being returned.
    """
    if device == "CAEN":
        port, term, cmds = CAEN_PORT, CAEN_POLL_TERM, CAEN_CMDS
    else:
        port, term, cmds = TDK_PORT, TDK_POLL_TERM, TDK_CMDS
    t = threading.Thread(target=ip_scheduler_grouped, args=(ip, device, port, term, cmds), daemon=True)
    t.start()
    return t

# ======================
# Detection wrapper
# ======================

def main_detect() -> List[Tuple[str, str]]:
    """
    The `main_detect` function iterates through a list of IP candidates, detects devices based on their
    labels, and stores evidence for each IP address, returning a list of tuples containing the IP
    address and detected label for devices labeled as "CAEN" or "TDK".
    :return: The `main_detect` function returns a list of tuples, where each tuple contains an IP
    address and a label indicating the detected device type.
    """
    found: List[Tuple[str, str]] = []
    evidence_by_ip: Dict[str, Dict[str, Dict[str, str]]] = {}

    for ip in IP_CANDIDATES:
        label, ev = detect_device(ip)
        evidence_by_ip[ip] = ev
        if label in ("CAEN", "TDK"):
            print(f"[SCAN] {ip}: {label} detected.")
            found.append((ip, label))
        elif label == "AMBIG":
            print(f"[SCAN] {ip}: AMBIGUOUS — inspect evidence below.")
        else:
            print(f"[SCAN] {ip}: no device.")
        # optional debug prints
        caen_ev = ev.get("CAEN", {})
        tdk_ev  = ev.get("TDK", {})
        print(f"  CAEN@{CAEN_PORT}: {caen_ev}")
        print(f"  TDK @{TDK_PORT} : {tdk_ev}")

    return found

# ======================
# Main
# ======================

def main(run_seconds: Optional[int] = None):
    """
    The main function launches threads to process detected IP addresses and their corresponding devices,
    consuming grouped reports and handling keyboard interrupts gracefully.
    
    :param run_seconds: The `run_seconds` parameter in the `main` function is an optional integer
    parameter that specifies the maximum number of seconds the program should run before exiting. If
    this parameter is provided, the program will run for the specified number of seconds and then exit.
    If the parameter is not provided or set to
    :type run_seconds: Optional[int]
    :return: The `main` function returns `None`.
    """
    found = main_detect()
    if not found:
        print("No definitive devices found. Exiting.")
        return

    # Launch one thread per detected IP
    threads: list[threading.Thread] = []
    for ip, kind in found:
        threads.append(start_ip_thread(ip, kind))

    # Consume grouped 1s reports
    try:
        start_time = time.time()
        while True:
            try:
                grouped = grouped_queue.get(timeout=0.5)
                ip     = grouped["ip"]
                device = grouped["device"]
                ps_id  = grouped["psID"]
                ts_loc = grouped["ts_local"]
                vals   = grouped["values"]

                # Header: timestamp, IP, [type], psID ONCE
                header = f"{ts_loc}  {ip} [{device}] psID={ps_id}"

                # Body: ONLY telemetry fields (no psID or psID_raw)
                kv = "  ".join(f"{k}={v}" for k, v in vals.items())

                print(f"{header}  {kv}")

            except queue.Empty:
                pass

            if run_seconds is not None and (time.time() - start_time) >= run_seconds:
                break

    except KeyboardInterrupt:
        print("Stopping (Ctrl+C).")
    finally:
        stop_event.set()
        for t in threads:
            t.join()
        print("All threads terminated.")

# -------- Entry point --------
if __name__ == "__main__":
    # Set run_seconds=None for continuous streaming
    main(run_seconds=3)
