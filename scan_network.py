
import subprocess
import json
import re
import time
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

def scan_network(target: str = None, ip: str = None, subnet: str = None, ip_range: str = None,
              use_real_nmap: bool = True, max_threads: int = 10, force_single: bool = False) -> Dict:
    """
    Realiza scan de rede com suporte para alvo único ou rede completa
    """

    print(f"[DEBUG] scan_network chamado com:")
    print(f"[DEBUG] - target: {target}")
    print(f"[DEBUG] - ip: {ip}")
    print(f"[DEBUG] - subnet: {subnet}")
    print(f"[DEBUG] - ip_range: {ip_range}")
    print(f"[DEBUG] - force_single: {force_single}")

    # Determinar o alvo do scan - priorizar target se fornecido
    scan_target = target or ip_range

    if not scan_target and ip and subnet:
        try:
            # Converter máscara para CIDR se necessário
            if '.' in subnet:  # Máscara no formato 255.255.255.0
                cidr = _netmask_to_cidr(subnet)
            else:  # Já é CIDR
                cidr = subnet

            rede = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
            scan_target = str(rede)
        except Exception as e:
            print(f"[ERROR] Falha ao calcular IP CIDR: {e}")
            return {
                "scan_range": f"{ip}/{subnet}",
                "hosts": [],
                "scan_time": "0:00",
                "total_hosts": 0,
                "total_ports": 0,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scanner_version": "ENSA v2.0 (Erro de IP)",
                "error": str(e),
                "note": "Erro ao calcular IP CIDR"
            }

    if not scan_target:
        print("[ERROR] Nenhum alvo válido fornecido.")
        return {}

    print(f"[DEBUG] scan_target determinado: {scan_target}")
    print(f"[DEBUG] force_single: {force_single}")

    # LÓGICA CORRIGIDA: Se force_single=True, SEMPRE tratar como alvo único
    if force_single:
        # Se tem CIDR mas foi forçado single, extrair apenas o IP
        if '/' in scan_target:
            scan_target = scan_target.split('/')[0]
        is_single_target = True
        scan_type = "Alvo Único (Forçado)"
        print(f"[INFO] *** FORÇANDO SCAN DE ALVO ÚNICO: {scan_target} ***")
    else:
        # Verificar se é alvo único ou rede naturalmente
        is_single_target = _is_single_ip(scan_target)
        scan_type = "Alvo Único" if is_single_target else "Rede Completa"

    print(f"[INFO] Realizando scan SYN - Tipo: {scan_type}, Alvo: {scan_target}")

    if not use_real_nmap:
        print("[INFO] Real nmap disabled, returning empty results")
        return {
            "scan_range": scan_target,
            "scan_type": scan_type,
            "hosts": [],
            "scan_time": "0:00",
            "total_hosts": 0,
            "total_ports": 0,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_version": "ENSA v2.0 (Disabled)",
            "note": "Real scanning disabled"
        }

    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        nmap_version = result.stdout.decode().split('\n')[0] if result.stdout else 'Unknown'
        print(f"[INFO] Nmap detectado: {nmap_version}")

        start_time = time.time()

        # Escolher estratégia de scan baseada no tipo de alvo
        if is_single_target:
            print(f"[INFO] Executando scan de ALVO ÚNICO: {scan_target}")
            hosts = _perform_single_target_scan(scan_target)
        else:
            print(f"[INFO] Executando scan de REDE COMPLETA: {scan_target}")
            hosts = _perform_network_scan(scan_target, max_threads)

        end_time = time.time()
        scan_duration = end_time - start_time
        scan_time = _format_scan_time(scan_duration)

    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[ERROR] Nmap não disponível: {e}")
        return {
            "scan_range": scan_target,
            "scan_type": scan_type,
            "hosts": [],
            "scan_time": "0:00",
            "total_hosts": 0,
            "total_ports": 0,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_version": "ENSA v2.0 (Error)",
            "error": "Nmap não instalado ou não acessível",
            "note": "Instale o nmap para realizar escaneamento real"
        }

    scan_results = {
        "scan_range": scan_target,
        "scan_type": scan_type,
        "hosts": hosts,
        "scan_time": scan_time,
        "total_hosts": len(hosts),
        "total_ports": sum(len(h['ports']) for h in hosts),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": f"ENSA v2.0 (Enhanced SYN Scan) - {nmap_version}",
        "nmap_command_used": f"nmap -sS {scan_target}",
        "forced_single": force_single
    }

    print(f"[INFO] SYN scan completed in {scan_time}. Found {len(hosts)} hosts with {scan_results['total_ports']} open ports.")
    return scan_results

def _is_single_ip(target: str) -> bool:
    """Verifica se o alvo é um IP único ou uma rede"""
    try:
        # Se não tem '/' é provavelmente um IP único
        if '/' not in target:
            ipaddress.IPv4Address(target)
            return True

        # Se tem '/' verifica se é /32 (IP único)
        network = ipaddress.IPv4Network(target, strict=False)
        return network.num_addresses == 1

    except:
        return False

def _perform_single_target_scan(target: str) -> List[Dict]:
    """Realiza scan otimizado para um único alvo"""
    print(f"[INFO] Executando scan otimizado para alvo único: {target}")

    try:
        # Scan mais agressivo para alvo único
        comando = ['nmap', '-sS', '-T4', '-A', '--top-ports', '1000', target]
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=300)

        if resultado.returncode == 0:
            print("[INFO] Scan de alvo único concluído")
            return parse_syn_scan_output(resultado.stdout)
        else:
            print(f"[ERROR] Erro no scan: {resultado.stderr}")
            return []

    except subprocess.TimeoutExpired:
        print("[WARNING] Timeout no scan, tentando scan básico")
        return _perform_basic_scan(target)
    except Exception as e:
        print(f"[ERROR] Erro no scan: {e}")
        return []

def _perform_network_scan(target: str, max_threads: int) -> List[Dict]:
    """Realiza scan paralelo para rede completa"""
    print(f"[INFO] Executando scan paralelo para rede: {target}")

    try:
        # Primeiro, descobrir hosts ativos
        print("[INFO] Descobrindo hosts ativos...")
        comando_discovery = ['nmap', '-sn', target]
        resultado = subprocess.run(comando_discovery, capture_output=True, text=True, timeout=120)

        if resultado.returncode != 0:
            print("[WARNING] Falha na descoberta, fazendo scan direto")
            return _perform_basic_scan(target)

        # Extrair IPs ativos
        active_ips = _extract_active_ips(resultado.stdout)

        if not active_ips:
            print("[INFO] Nenhum host ativo encontrado")
            return []

        print(f"[INFO] Encontrados {len(active_ips)} hosts ativos, iniciando scan de portas...")

        # Scan paralelo dos hosts ativos
        all_hosts = []
        with ThreadPoolExecutor(max_workers=min(max_threads, len(active_ips))) as executor:
            future_to_ip = {
                executor.submit(_scan_single_host, ip): ip
                for ip in active_ips
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    host_data = future.result(timeout=60)
                    if host_data:
                        all_hosts.extend(host_data)
                except Exception as e:
                    print(f"[WARNING] Erro no scan do host {ip}: {e}")

        return all_hosts

    except Exception as e:
        print(f"[ERROR] Erro no scan de rede: {e}")
        return _perform_basic_scan(target)

def _scan_single_host(ip: str) -> List[Dict]:
    """Scan de um único host (usado em threading)"""
    try:
        comando = ['nmap', '-sS', '-T3', '--top-ports', '100', ip]
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=45)

        if resultado.returncode == 0:
            return parse_syn_scan_output(resultado.stdout)

    except Exception as e:
        print(f"[WARNING] Erro no scan de {ip}: {e}")

    return []

def _perform_basic_scan(target: str) -> List[Dict]:
    """Fallback para scan básico"""
    try:
        comando = ['nmap', '-sS', target]
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=600)

        if resultado.returncode == 0:
            return parse_syn_scan_output(resultado.stdout)

    except Exception as e:
        print(f"[ERROR] Erro no scan básico: {e}")

    return []

def _extract_active_ips(nmap_output: str) -> List[str]:
    """Extrai IPs ativos do output do nmap -sn"""
    ips = []
    lines = nmap_output.split('\n')

    for line in lines:
        if 'Nmap scan report for' in line:
            # Extrair IP da linha
            if '(' in line and ')' in line:
                # Formato: "Nmap scan report for hostname (192.168.1.1)"
                ip = line.split('(')[1].split(')')[0]
            else:
                # Formato: "Nmap scan report for 192.168.1.1"
                ip = line.split()[-1]

            try:
                ipaddress.IPv4Address(ip)
                ips.append(ip)
            except:
                continue

    return ips

def parse_syn_scan_output(nmap_output):
    hosts = []
    lines = nmap_output.split('\n')
    current_host = None

    for line in lines:
        line = line.strip()

        if line.startswith('Nmap scan report for'):
            if current_host and current_host.get('ports'):
                hosts.append(current_host)

            if '(' in line and ')' in line:
                parts = line.split('(')
                hostname = parts[0].replace('Nmap scan report for', '').strip()
                ip = parts[1].replace(')', '').strip()
            else:
                target = line.replace('Nmap scan report for', '').strip()
                hostname = target
                ip = target

            current_host = {
                "hostname": hostname,
                "ip": ip,
                "mac": None,
                "vendor": None,
                "status": "up",
                "ports": []
            }

        elif line.startswith('MAC Address:'):
            if current_host:
                mac_match = re.search(r'MAC Address: ([0-9A-F:]{17})', line, re.IGNORECASE)
                if mac_match:
                    current_host["mac"] = mac_match.group(1).upper()

        elif re.match(r'^\d+/(tcp|udp)\s+\w+\s+\w+', line):
            if current_host:
                parts = line.split()
                if len(parts) >= 3:
                    port_protocol = parts[0]
                    state = parts[1]
                    service = parts[2]
                    port_num, protocol = port_protocol.split('/')

                    port_data = {
                        "port": port_num,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "version": ""
                    }
                    current_host["ports"].append(port_data)

    if current_host and current_host.get('ports'):
        hosts.append(current_host)

    return hosts

def _netmask_to_cidr(netmask: str) -> str:
    """Converte máscara de rede para notação CIDR"""
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen)
    except:
        # Fallback para máscaras comuns
        common_masks = {
            '255.255.255.0': '24',
            '255.255.0.0': '16',
            '255.0.0.0': '8',
            '255.255.255.128': '25',
            '255.255.255.192': '26'
        }
        return common_masks.get(netmask, '24')

def _format_scan_time(duration: float) -> str:
    """Formata tempo de scan"""
    minutes = int(duration // 60)
    seconds = int(duration % 60)
    return f"{minutes}:{seconds:02d}"

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='ENSA Network Scanner v2.0')
    parser.add_argument('target', nargs='?', help='IP único (192.168.1.1) ou rede (192.168.1.0/24)')
    parser.add_argument('--threads', type=int, default=10, help='Número de threads para scan paralelo')
    parser.add_argument('--no-nmap', action='store_true', help='Desabilitar nmap real')
    parser.add_argument('--single', action='store_true', help='Forçar scan de alvo único')

    args = parser.parse_args()

    if not args.target:
        ip = input("Digite o IP base da rede (ex: 192.168.0.1): ")
        mask = input("Digite a máscara (ex: 255.255.255.0): ")
        results = scan_network(ip=ip, subnet=mask, use_real_nmap=not args.no_nmap, max_threads=args.threads)
    else:
        results = scan_network(target=args.target, use_real_nmap=not args.no_nmap, max_threads=args.threads, force_single=args.single)

    print(json.dumps(results, indent=2))
