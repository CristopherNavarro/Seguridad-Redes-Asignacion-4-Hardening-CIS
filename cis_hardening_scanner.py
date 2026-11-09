#!/usr/bin/env python3
"""
===============================================================================
INSTITUTO TECNOLÓGICO DE LAS AMÉRICAS (ITLA)
Asignatura: Seguridad de Redes
Asignación 4: Hardening y Auditoría Automatizada basada en CIS Benchmark
Estudiante: Cristopher Navarro
Matrícula: 2025-0720
Docente: Jonathan Esteban Rondón Corniel
===============================================================================
Descripción:
Script automatizado de auditoría y remediación de seguridad basado en las
recomendaciones de Center for Internet Security (CIS Benchmark) para equipos:
- Router Cisco (Cisco 7200 / IOS)
- Switch Cisco (Cisco IOSvL2)
- Firewall Fortinet (FortiGate 7.0.9 / FortiOS)

Modos de Ejecución:
1. Auditoría / Escaneo (Dry-Run):
   python cis_hardening_scanner.py --mode audit
   Genera 'informe_auditoria_cis.txt' sin alterar las configuraciones.

2. Remediación y Reporte Póstumo:
   python cis_hardening_scanner.py --mode remediate
   Aplica los parámetros de hardening y genera 'informe_postumo_cis.txt'.
===============================================================================
"""

import socket
import time
import re
import argparse
import sys
from datetime import datetime

# =============================================================================
# DEFINICIÓN DE EQUIPOS E INFRAESTRUCTURA (Matrícula: 2025-0720)
# =============================================================================
DEVICES = {
    "R1-EDGE": {
        "type": "cisco_router",
        "host": "192.168.6.129",
        "port": 5000,
        "mgmt_ip": "10.25.7.1",
        "description": "Router Perimetral Cisco 7200 (WAN)"
    },
    "SW-CORE-L2": {
        "type": "cisco_switch",
        "host": "192.168.6.129",
        "port": 5003,
        "mgmt_ip": "10.25.7.66",
        "description": "Switch de Distribución Cisco IOSvL2 (LAN)"
    },
    "FW-FORTINET": {
        "type": "fortigate",
        "host": "192.168.6.129",
        "port": 5001,
        "mgmt_ip": "10.25.7.65",
        "description": "Firewall de Próxima Generación FortiGate 7.0.9"
    }
}

def clean_ansi(text):
    """Elimina secuencias de control ANSI y caracteres telnet."""
    ansi_regex = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_regex.sub('', text)

def drain_socket(s):
    """Descarta cualquier residuo del búfer telnet."""
    s.settimeout(0.2)
    while True:
        try:
            chunk = s.recv(8192)
            if not chunk:
                break
        except Exception:
            break

def execute_console_commands(host, port, commands, timeout=1.5):
    """Ejecuta una serie de comandos vía consola Telnet con recolección rápida y confiable."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6.0)
    s.connect((host, port))
    
    drain_socket(s)
    
    # Handshake inicial según el tipo de equipo
    if port == 5001:  # FW-FORTINET
        s.sendall(b"\r\na\r\n")
        time.sleep(0.4)
        buf = ""
        try:
            buf = s.recv(4096).decode('utf-8', errors='ignore')
        except Exception:
            pass
            
        if "login:" in buf.lower():
            s.sendall(b"admin\n")
            time.sleep(0.4)
            try:
                s.recv(4096)
            except Exception:
                pass
            s.sendall(b"Admin12345!\n")
            time.sleep(0.6)
            drain_socket(s)
    else:  # Cisco Devices
        s.sendall(b"\r\n\r\n")
        time.sleep(0.2)
        drain_socket(s)
        s.sendall(b"enable\r\nterminal length 0\r\n")
        time.sleep(0.3)
        drain_socket(s)
        
    output = ""
    for cmd in commands:
        if port == 5001:
            for sub_cmd in cmd.strip().split("\n"):
                s.sendall(sub_cmd.strip().encode('utf-8') + b"\n")
                time.sleep(0.15)
        else:
            s.sendall(cmd.encode('utf-8') + b"\r\n")
            time.sleep(0.2)
            
        t_end = time.time() + timeout
        chunk_buf = ""
        s.settimeout(1.0)
        while time.time() < t_end:
            try:
                raw = s.recv(8192).decode('utf-8', errors='ignore')
                if raw:
                    chunk_buf += raw
                    # En Cisco terminamos al encontrar el fin de config o prompt tras el comando
                    if ("\nend\r\n" in chunk_buf or "\nend\n" in chunk_buf) and ("#" in chunk_buf or ">" in chunk_buf):
                        break
            except socket.timeout:
                if chunk_buf.strip().endswith("#") or chunk_buf.strip().endswith(">"):
                    break
        output += chunk_buf
        
    s.close()
    return clean_ansi(output)

# =============================================================================
# REGLAS Y CHECKS CIS BENCHMARK
# =============================================================================

def audit_cisco_device(dev_name, config_text, dev_type="router"):
    """Audita las recomendaciones CIS Benchmark para equipos Cisco IOS."""
    results = []
    
    # CIS 1.1.1: Password Encryption
    has_pwd_enc = bool(re.search(r'service\s+password-encryption', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS Cisco 1.1.1",
        "title": "Cifrado de Contraseñas del Sistema",
        "expected": "service password-encryption",
        "status": "PASS" if has_pwd_enc else "FAIL",
        "rationale": "Evita el almacenamiento de contraseñas en texto claro dentro del archivo running-config."
    })
    
    # CIS 1.1.2: Enable Secret Configured
    has_enable_sec = bool(re.search(r'enable\s+secret', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS Cisco 1.1.2",
        "title": "Uso de Algoritmo de Hashing Fuerte para Enable Secret",
        "expected": "enable secret <hash>",
        "status": "PASS" if has_enable_sec else "FAIL",
        "rationale": "Protege el acceso privilegiado (modo EXEC) con funciones de derivación criptográfica seguras."
    })
    
    # CIS 1.2.1: Banner de Advertencia Legal (MOTD)
    has_banner = bool(re.search(r'banner\s+motd', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS Cisco 1.2.1",
        "title": "Configuración de Banner de Acceso Restringido",
        "expected": "banner motd configurado",
        "status": "PASS" if has_banner else "FAIL",
        "rationale": "Notifica legalmente a los usuarios que el sistema está monitoreado y restringido a personal autorizado."
    })
    
    # CIS 1.3.1: Deshabilitar Servicios Inseguros
    has_no_http = bool(re.search(r'no\s+ip\s+http\s+server', config_text, re.IGNORECASE)) or not bool(re.search(r'\nip\s+http\s+server\b', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS Cisco 1.3.1",
        "title": "Deshabilitar Servidor HTTP en Texto Plano",
        "expected": "no ip http server",
        "status": "PASS" if has_no_http else "FAIL",
        "rationale": "Mitiga vectores de ataque e intercepción de credenciales sobre interfaces web no cifradas."
    })
    
    # CIS 2.1.1: SSHv2 Exclusivo
    has_ssh2 = bool(re.search(r'ip\s+ssh\s+version\s+2', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS Cisco 2.1.1",
        "title": "Habilitar Protocolo SSH Versión 2",
        "expected": "ip ssh version 2",
        "status": "PASS" if has_ssh2 else "FAIL",
        "rationale": "Deshabilita SSHv1 vulnerable y garantiza canales de gestión con cifrado robusto."
    })
    
    # CIS 2.1.2: Hardening de Líneas VTY (SSH Only + Timeout)
    has_vty_ssh = bool(re.search(r'transport\s+input\s+ssh', config_text, re.IGNORECASE))
    has_vty_timeout = bool(re.search(r'exec-timeout\s+[1-9]', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS Cisco 2.1.2",
        "title": "Seguridad en Líneas Virtuales VTY (SSH + Inactividad)",
        "expected": "transport input ssh & exec-timeout",
        "status": "PASS" if (has_vty_ssh and has_vty_timeout) else "FAIL",
        "rationale": "Bloquea Telnet en líneas remotas y cierra sesiones desatendidas tras inactividad."
    })
    
    # CIS 2.2.1: Timestamps en Logs
    has_timestamps = bool(re.search(r'service\s+timestamps\s+log\s+datetime\s+msec', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS Cisco 2.2.1",
        "title": "Marcas de Tiempo de Alta Precisión en Logs",
        "expected": "service timestamps log datetime msec",
        "status": "PASS" if has_timestamps else "FAIL",
        "rationale": "Facilita la correlación de eventos forenses y análisis cronológico de incidentes."
    })
    
    # CIS L2 Switch Específico: Port Security y BPDU Guard
    if dev_type == "switch":
        has_portsec = bool(re.search(r'switchport\s+port-security', config_text, re.IGNORECASE))
        results.append({
            "control_id": "CIS Cisco L2 3.1",
            "title": "Seguridad de Puerto (Port-Security) en Puertos de Acceso",
            "expected": "switchport port-security habilitado",
            "status": "PASS" if has_portsec else "FAIL",
            "rationale": "Previene ataques de saturación CAM (MAC Flooding) y suplantación de identidad en capa de acceso."
        })
        
        has_bpduguard = bool(re.search(r'spanning-tree\s+bpduguard', config_text, re.IGNORECASE))
        results.append({
            "control_id": "CIS Cisco L2 3.2",
            "title": "Protección de Árbol de Expansión (BPDU Guard)",
            "expected": "spanning-tree bpduguard enable",
            "status": "PASS" if has_bpduguard else "FAIL",
            "rationale": "Protege la topología STP contra switches no autorizados o bucles accidentales."
        })
        
    return results

def audit_fortigate_device(config_text):
    """Audita las recomendaciones CIS Fortinet FortiOS Benchmark."""
    results = []
    
    # CIS FortiOS 1.1: Tiempo de Espera de Administración (Idle Timeout <= 10m)
    admintimeout_match = re.search(r'set\s+admintimeout\s+(\d+)', config_text, re.IGNORECASE)
    timeout_val = int(admintimeout_match.group(1)) if admintimeout_match else 999
    is_timeout_ok = timeout_val <= 10
    results.append({
        "control_id": "CIS FortiOS 1.1",
        "title": "Tiempo de Espera por Inactividad de Administrador",
        "expected": "set admintimeout <= 10",
        "status": "PASS" if is_timeout_ok else "FAIL",
        "rationale": "Cierra automáticamente las sesiones administrativas en la GUI y CLI para evitar accesos desatendidos."
    })
    
    # CIS FortiOS 1.2: Bloqueo de Cuentas por Intentos Fallidos
    lockout_thresh = re.search(r'admin-lockout-threshold[:\s]+(\d+)', config_text, re.IGNORECASE)
    has_lockout = bool(lockout_thresh and int(lockout_thresh.group(1)) <= 5)
    results.append({
        "control_id": "CIS FortiOS 1.2",
        "title": "Política de Bloqueo tras Intentos Fallidos de Inicio de Sesión",
        "expected": "set admin-lockout-threshold <= 5",
        "status": "PASS" if has_lockout else "FAIL",
        "rationale": "Protege el firewall contra ataques de fuerza bruta dirigidos a cuentas de gestión."
    })
    
    # CIS FortiOS 1.3: Política de Contraseñas del Sistema
    has_pwd_policy = bool(re.search(r'set\s+status\s+enable', config_text, re.IGNORECASE)) or bool(re.search(r'password-policy', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS FortiOS 1.3",
        "title": "Exigencia de Complejidad en Contraseñas Administrativas",
        "expected": "password-policy status enable",
        "status": "PASS" if has_pwd_policy else "FAIL",
        "rationale": "Exige longitud mínima, mayúsculas, minúsculas, números y símbolos para credenciales locales."
    })
    
    # CIS FortiOS 1.4: Banner Pre-Login
    has_banner = bool(re.search(r'set\s+pre-login-banner\s+enable', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS FortiOS 1.4",
        "title": "Banner de Advertencia Previo al Inicio de Sesión",
        "expected": "set pre-login-banner enable",
        "status": "PASS" if has_banner else "FAIL",
        "rationale": "Despliega advertencia legal antes de autenticarse en el firewall perimetral."
    })
    
    # CIS FortiOS 3.1: Registro de Todo el Tráfico en Políticas de Firewall
    has_logall = bool(re.search(r'set\s+logtraffic\s+all', config_text, re.IGNORECASE))
    results.append({
        "control_id": "CIS FortiOS 3.1",
        "title": "Registro Completo de Sesiones (Log All Traffic)",
        "expected": "set logtraffic all",
        "status": "PASS" if has_logall else "FAIL",
        "rationale": "Garantiza trazabilidad y auditoría completa de los flujos que atraviesan las políticas de seguridad."
    })
    
    return results

# =============================================================================
# COMANDOS DE REMEDIACIÓN AUTOMÁTICA
# =============================================================================
REMEDIATION_COMMANDS = {
    "R1-EDGE": [
        "enable",
        "configure terminal",
        "service password-encryption",
        "enable secret Itla2025*Sec!",
        "username admin privilege 15 secret Itla2025*Admin!",
        "no ip domain-lookup",
        "ip domain-name itla.edu.do",
        "crypto key generate rsa modulus 2048",
        "ip ssh version 2",
        "ip ssh time-out 60",
        "ip ssh authentication-retries 3",
        "no ip http server",
        "no ip http secure-server",
        "no ip source-route",
        "no ip finger",
        "service timestamps debug datetime msec",
        "service timestamps log datetime msec",
        "logging buffered 64000 informational",
        "banner motd ^C[ACCESO RESTRINGIDO] Solo personal autorizado ITLA - Cristopher Navarro (2025-0720)^C",
        "line con 0",
        "exec-timeout 5 0",
        "logging synchronous",
        "exit",
        "line vty 0 4",
        "login local",
        "transport input ssh",
        "exec-timeout 5 0",
        "exit",
        "end",
        "write memory"
    ],
    "SW-CORE-L2": [
        "enable",
        "configure terminal",
        "service password-encryption",
        "enable secret Itla2025*Sec!",
        "username admin privilege 15 secret Itla2025*Admin!",
        "no ip domain-lookup",
        "ip domain-name itla.edu.do",
        "crypto key generate rsa modulus 2048",
        "ip ssh version 2",
        "ip ssh time-out 60",
        "ip ssh authentication-retries 3",
        "no ip http server",
        "no ip http secure-server",
        "service timestamps debug datetime msec",
        "service timestamps log datetime msec",
        "logging buffered 64000 informational",
        "banner motd ^C[ACCESO RESTRINGIDO] Switch Core ITLA - Cristopher Navarro (2025-0720)^C",
        "interface GigabitEthernet0/1",
        "switchport mode access",
        "switchport access vlan 10",
        "switchport port-security",
        "switchport port-security maximum 2",
        "switchport port-security violation restrict",
        "spanning-tree portfast",
        "spanning-tree bpduguard enable",
        "exit",
        "interface range GigabitEthernet0/2 - 3, GigabitEthernet1/0 - 3, GigabitEthernet2/0 - 3, GigabitEthernet3/0 - 3",
        "shutdown",
        "exit",
        "line con 0",
        "exec-timeout 5 0",
        "logging synchronous",
        "exit",
        "line vty 0 4",
        "login local",
        "transport input ssh",
        "exec-timeout 5 0",
        "exit",
        "end",
        "write memory"
    ],
    "FW-FORTINET": [
        "config system console\nset output standard\nend",
        "config system global\nset admintimeout 10\nset admin-lockout-threshold 3\nset admin-lockout-duration 300\nset pre-login-banner enable\nend",
        "config system password-policy\nset status enable\nset minimum-length 8\nset min-lower-case-letter 1\nset min-upper-case-letter 1\nset min-non-alphanumeric 1\nset min-number 1\nend",
        "config firewall policy\nedit 1\nset logtraffic all\nnext\nedit 2\nset logtraffic all\nnext\nedit 3\nset logtraffic all\nnext\nend"
    ]
}

def get_cisco_config(host, port, dev_name, timeout=12.0):
    """Obtiene la configuración running-config completa de un equipo Cisco IOS."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6.0)
    s.connect((host, port))
    drain_socket(s)
    s.sendall(b"\r\n\r\n")
    time.sleep(0.2)
    drain_socket(s)
    s.sendall(b"enable\r\nterminal length 0\r\nshow running-config\r\n")
    out = ""
    t_end = time.time() + timeout
    s.settimeout(1.0)
    while time.time() < t_end:
        try:
            c = s.recv(8192).decode('utf-8', errors='ignore')
            if c:
                out += c
                if "\nend" in out and (dev_name in out or "#" in out):
                    break
        except socket.timeout:
            continue
    s.close()
    return clean_ansi(out)

def generate_report(audit_data, report_type="Auditoría Inicial (Dry-Run)", filename="informe_auditoria_cis.txt"):
    """Genera un reporte detallado con formato formal de ciberseguridad."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target_path = os.path.join(script_dir, filename)
    
    lines = []
    lines.append("=" * 80)
    lines.append("INSTITUTO TECNOLÓGICO DE LAS AMÉRICAS (ITLA)")
    lines.append("DEPARTAMENTO DE SEGURIDAD EN TECNOLOGÍAS DE LA INFORMACIÓN")
    lines.append("ASIGNATURA: SEGURIDAD DE REDES - ASIGNACIÓN 4 (HARDENING CIS BENCHMARK)")
    lines.append("=" * 80)
    lines.append(f"Estudiante: Cristopher Navarro | Matrícula: 2025-0720")
    lines.append(f"Docente: Jonathan Esteban Rondón Corniel")
    lines.append(f"Fecha de Auditoría: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Tipo de Informe: {report_type}")
    lines.append("=" * 80)
    lines.append("")

    total_controls = 0
    passed_controls = 0

    for dev_name, info in audit_data.items():
        lines.append(f"\n[+] DISPOSITIVO: {dev_name} ({info['description']})")
        lines.append(f"    IP de Gestión: {info['mgmt_ip']} | Consola: {info['host']}:{info['port']}")
        lines.append("-" * 80)
        lines.append(f"{'CONTROL ID':<22} | {'ESTADO':<8} | {'DESCRIPCIÓN'}")
        lines.append("-" * 80)

        for check in info["checks"]:
            total_controls += 1
            if check["status"] == "PASS":
                passed_controls += 1
            lines.append(f"{check['control_id']:<22} | {check['status']:<8} | {check['title']}")
            lines.append(f"  -> Justificación: {check['rationale']}")
            lines.append(f"  -> Parámetro Esperado: {check['expected']}")
            lines.append("")

    score = (passed_controls / total_controls * 100) if total_controls > 0 else 0
    lines.append("=" * 80)
    lines.append(f"RESUMEN EJECUTIVO DE CUMPLIMIENTO CIS:")
    lines.append(f"  * Total de Controles Evaluados: {total_controls}")
    lines.append(f"  * Controles Satisfactorios [PASS]: {passed_controls}")
    lines.append(f"  * Controles Deficientes [FAIL]:    {total_controls - passed_controls}")
    lines.append(f"  * Índice de Conformidad de Seguridad: {score:.1f}%")
    lines.append("=" * 80)

    report_content = "\n".join(lines)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(report_content, flush=True)
    print(f"\n[!] Informe formal exportado exitosamente a: {target_path}\n", flush=True)
    return score

# =============================================================================
# FLUJO PRINCIPAL DE EJECUCIÓN
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Script de Auditoría y Hardening CIS Benchmark - ITLA Seguridad de Redes"
    )
    parser.add_argument(
        "--mode",
        choices=["audit", "remediate"],
        default="audit",
        help="Modo de ejecución: 'audit' (escaneo sin modificar) o 'remediate' (aplica reglas y genera informe póstumo)"
    )
    args = parser.parse_args()

    print("\n" + "=" * 80, flush=True)
    print(f"INICIANDO ESCANER DE HARDENING CIS BENCHMARK (MODO: {args.mode.upper()})", flush=True)
    print("Estudiante: Cristopher Navarro (2025-0720) - ITLA", flush=True)
    print("=" * 80 + "\n", flush=True)

    def perform_scan():
        data = {}
        for dev_name, dev_info in DEVICES.items():
            print(f"[*] Conectando a {dev_name} ({dev_info['host']}:{dev_info['port']})...", flush=True)
            
            if dev_info["type"] in ("cisco_router", "cisco_switch"):
                output = get_cisco_config(dev_info["host"], dev_info["port"], dev_name, timeout=12.0)
                checks = audit_cisco_device(
                    dev_name,
                    output,
                    dev_type="switch" if dev_info["type"] == "cisco_switch" else "router"
                )
            elif dev_info["type"] == "fortigate":
                cmds = [
                    "config system console\nset output standard\nend",
                    "get system global",
                    "show system global",
                    "show system password-policy",
                    "show firewall policy"
                ]
                output = execute_console_commands(dev_info["host"], dev_info["port"], cmds, timeout=2.0)
                checks = audit_fortigate_device(output)
            else:
                checks = []

            data[dev_name] = {
                "description": dev_info["description"],
                "mgmt_ip": dev_info["mgmt_ip"],
                "host": dev_info["host"],
                "port": dev_info["port"],
                "checks": checks
            }
        return data

    if args.mode == "audit":
        audit_data = perform_scan()
        print("\n[*] Generando informe de auditoría inicial...", flush=True)
        generate_report(audit_data, report_type="Auditoría Inicial de Seguridad (Sin Modificar)", filename="informe_auditoria_cis.txt")
    
    elif args.mode == "remediate":
        print("\n[+] APLICANDO REGLAS DE HARDENING CIS EN TODOS LOS DISPOSITIVOS...", flush=True)
        for dev_name, cmds in REMEDIATION_COMMANDS.items():
            dev_info = DEVICES[dev_name]
            print(f"[*] Aplicando {len(cmds)} reglas de remediación en {dev_name}...", flush=True)
            execute_console_commands(dev_info["host"], dev_info["port"], cmds, timeout=3.0)
            time.sleep(0.5)
            
        print("\n[*] Re-escaneando infraestructura para verificación póstuma...", flush=True)
        post_audit_data = perform_scan()

        print("\n[*] Generando informe póstumo de cumplimiento...", flush=True)
        generate_report(post_audit_data, report_type="Informe Póstumo de Cumplimiento (Post-Hardening)", filename="informe_postumo_cis.txt")

if __name__ == "__main__":
    main()
