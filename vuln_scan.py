import subprocess
import json
import re
import time
import ipaddress
import shlex
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional

# Tentar importar CVELookup, mas continuar sem ele se não estiver disponível
try:
    from cve_lookup import CVELookup
    CVE_LOOKUP_AVAILABLE = True
except ImportError:
    CVE_LOOKUP_AVAILABLE = False
    print("[WARNING] CVE lookup não disponível. Instale 'requests' para habilitar busca de CVEs.")

def scan_network(target: str = None, ip: str = None, subnet: str = None, ip_range: str = None,
              use_real_nmap: bool = True, max_threads: int = 3, lookup_cves: bool = True, force_single: bool = False) -> Dict:
    """
    Realiza scan de vulnerabilidades com suporte para alvo único ou rede completa
    """

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
                "total_vulnerabilities": 0,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scanner_version": "ENSA v2.0 (Erro de IP)",
                "error": str(e),
                "note": "Erro ao calcular IP CIDR"
            }

    if not scan_target:
        print("[ERROR] Nenhum alvo válido fornecido.")
        return {}

    # LÓGICA CORRIGIDA: Se force_single=True, SEMPRE tratar como alvo único
    if force_single:
        # Se tem CIDR mas foi forçado single, extrair apenas o IP
        if '/' in scan_target:
            scan_target = scan_target.split('/')[0]
        is_single_target = True
        scan_type = "Vulnerabilidades - Alvo Único (Forçado)"
        print(f"[INFO] FORÇANDO SCAN DE VULNERABILIDADES DE ALVO ÚNICO: {scan_target}")
    else:
        # Verificar se é alvo único ou rede naturalmente
        is_single_target = _is_single_ip(scan_target)
        scan_type = "Vulnerabilidades - Alvo Único" if is_single_target else "Vulnerabilidades - Rede Completa"

    print(f"[INFO] Realizando scan de vulnerabilidades - Tipo: {scan_type}, Alvo: {scan_target}")

    if not use_real_nmap:
        print("[INFO] Real nmap disabled, returning empty results")
        return {
            "scan_range": scan_target,
            "scan_type": scan_type,
            "hosts": [],
            "scan_time": "0:00",
            "total_hosts": 0,
            "total_ports": 0,
            "total_vulnerabilities": 0,
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
            print(f"[INFO] Executando scan de vulnerabilidades de ALVO ÚNICO: {scan_target}")
            hosts = _perform_single_target_vuln_scan(scan_target)
        else:
            print(f"[INFO] Executando scan de vulnerabilidades de REDE COMPLETA: {scan_target}")
            hosts = _perform_network_vuln_scan(scan_target, max_threads)

        # Buscar informações detalhadas das CVEs se solicitado e disponível
        if lookup_cves and CVE_LOOKUP_AVAILABLE and hosts:
            print("[INFO] Buscando informações detalhadas das CVEs...")
            hosts = _enrich_cve_data(hosts)
        elif lookup_cves and not CVE_LOOKUP_AVAILABLE:
            print("[WARNING] CVE lookup solicitado mas não disponível")

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
            "total_vulnerabilities": 0,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_version": "ENSA v2.0 (Error)",
            "error": "Nmap não instalado ou não acessível",
            "note": "Instale o nmap para realizar escaneamento real"
        }

    # Calcular total de vulnerabilidades
    total_vulns = sum(
        len(port.get('vulnerabilities', []))
        for host in hosts
        for port in host.get('ports', [])
    )

    scan_results = {
        "scan_range": scan_target,
        "scan_type": scan_type,
        "hosts": hosts,
        "scan_time": scan_time,
        "total_hosts": len(hosts),
        "total_ports": sum(len(h.get('ports', [])) for h in hosts),
        "total_vulnerabilities": total_vulns,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scanner_version": f"ENSA v2.0 (Enhanced Vuln Scan) - {nmap_version}",
        "nmap_command_used": f"nmap -sS -T3 --script vuln {scan_target}",
        "forced_single": force_single
    }

    print(f"[INFO] Scan finalizado em {scan_time}. Encontrados {len(hosts)} hosts com {total_vulns} vulnerabilidades.")
    return scan_results

def _is_single_ip(target: str) -> bool:
    """Verifica se o alvo é um IP único"""
    try:
        if '/' not in target:
            ipaddress.IPv4Address(target)
            return True
        network = ipaddress.IPv4Network(target, strict=False)
        return network.num_addresses == 1
    except:
        return False

def _perform_single_target_vuln_scan(target: str) -> List[Dict]:
    """Scan de vulnerabilidades otimizado para alvo único"""
    print(f"[INFO] Executando scan de vulnerabilidades para alvo único: {target}")

    try:
        # Scan mais completo para alvo único
        comando = [
            'nmap', '-sS', '-T3', '-A',
            '--script', 'vuln,safe,discovery',
            '--script-timeout', '300s',
            '--host-timeout', '600s',
            target
        ]

        print(f"[INFO] Comando: {' '.join(comando)}")
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=900)

        if resultado.returncode == 0:
            print("[INFO] Scan de vulnerabilidades concluído")
            return parse_syn_scan_output(resultado.stdout)
        else:
            print(f"[ERROR] Erro no scan: {resultado.stderr}")
            return []

    except subprocess.TimeoutExpired:
        print("[WARNING] Timeout no scan, tentando scan básico")
        return _perform_basic_vuln_scan(target)
    except Exception as e:
        print(f"[ERROR] Erro no scan: {e}")
        return []

def _perform_network_vuln_scan(target: str, max_threads: int) -> List[Dict]:
    """Scan de vulnerabilidades paralelo para rede"""
    print(f"[INFO] Executando scan de vulnerabilidades para rede: {target}")

    try:
        # Primeiro descobrir hosts ativos
        print("[INFO] Descobrindo hosts ativos...")
        comando_discovery = ['nmap', '-sn', '-T4', target]
        resultado = subprocess.run(comando_discovery, capture_output=True, text=True, timeout=120)

        if resultado.returncode != 0:
            print("[WARNING] Falha na descoberta, fazendo scan direto")
            return _perform_basic_vuln_scan(target)

        # Extrair IPs ativos
        active_ips = _extract_active_ips(resultado.stdout)

        if not active_ips:
            print("[INFO] Nenhum host ativo encontrado")
            return []

        print(f"[INFO] Encontrados {len(active_ips)} hosts ativos, iniciando scan de vulnerabilidades...")

        # Limitar número de hosts para scan de vulnerabilidades (muito demorado)
        if len(active_ips) > 10:
            print(f"[WARNING] Muitos hosts ({len(active_ips)}), limitando a 10 para scan de vulnerabilidades")
            active_ips = active_ips[:10]

        # Scan paralelo com menos threads (vulnerabilidades são mais pesadas)
        all_hosts = []
        max_vuln_threads = min(max_threads, 3)  # Máximo 3 threads para vulnerabilidades

        with ThreadPoolExecutor(max_workers=max_vuln_threads) as executor:
            future_to_ip = {
                executor.submit(_scan_single_host_vulns, ip): ip
                for ip in active_ips
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    host_data = future.result(timeout=300)  # 5 minutos por host
                    if host_data:
                        all_hosts.extend(host_data)
                except Exception as e:
                    print(f"[WARNING] Erro no scan de vulnerabilidades do host {ip}: {e}")

        return all_hosts

    except Exception as e:
        print(f"[ERROR] Erro no scan de rede: {e}")
        return _perform_basic_vuln_scan(target)

def _scan_single_host_vulns(ip: str) -> List[Dict]:
    """Scan de vulnerabilidades de um único host"""
    try:
        comando = [
            'nmap', '-sS', '-T3',
            '--script', 'vuln',
            '--script-timeout', '120s',
            '--host-timeout', '180s',
            '--top-ports', '100',
            ip
        ]

        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=240)

        if resultado.returncode == 0:
            return parse_syn_scan_output(resultado.stdout)

    except Exception as e:
        print(f"[WARNING] Erro no scan de vulnerabilidades de {ip}: {e}")

    return []

def _perform_basic_vuln_scan(target: str) -> List[Dict]:
    """Fallback para scan básico de vulnerabilidades"""
    try:
        comando = ['nmap', '-sS', '-T3', '--script', 'vuln', target]
        resultado = subprocess.run(comando, capture_output=True, text=True, timeout=1200)

        if resultado.returncode == 0:
            return parse_syn_scan_output(resultado.stdout)

    except Exception as e:
        print(f"[ERROR] Erro no scan básico: {e}")

    return []

def parse_syn_scan_output(nmap_output):
    hosts = []
    lines = nmap_output.split('\n')
    current_host = None
    current_port = None

    for line in lines:
        line = line.strip()

        if line.startswith('Nmap scan report for'):
            if current_host and current_host.get('ports'):
                hosts.append(current_host)
            current_host = {
                "hostname": "",
                "ip": "",
                "mac": None,
                "vendor": None,
                "status": "up",
                "ports": []
            }
            if '(' in line and ')' in line:
                parts = line.split('(')
                current_host['hostname'] = parts[0].replace('Nmap scan report for', '').strip()
                current_host['ip'] = parts[1].replace(')', '').strip()
            else:
                ip = line.replace('Nmap scan report for', '').strip()
                current_host['hostname'] = ip
                current_host['ip'] = ip

        elif line.startswith('MAC Address:') and current_host:
            mac_match = re.search(r'MAC Address: ([0-9A-F:]{17})', line, re.IGNORECASE)
            if mac_match:
                current_host["mac"] = mac_match.group(1).upper()

        elif re.match(r'^\d+/(tcp|udp)\s+\w+\s+\S+', line):
            parts = line.split()
            if len(parts) >= 3:
                port_protocol = parts[0]
                state = parts[1]
                service = parts[2]
                port_num, protocol = port_protocol.split('/')

                current_port = {
                    "port": port_num,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": "",
                    "vulnerabilities": []
                }
                current_host["ports"].append(current_port)

        elif "|_" in line or "|" in line:
            if current_port:
                cve_match = re.findall(r'CVE[-:]?\d{4}-\d{4,7}', line, re.IGNORECASE)
                vuln_desc = line.strip('|_').strip('|').strip()

                if vuln_desc or cve_match:
                    current_port["vulnerabilities"].append({
                        "description": vuln_desc,
                        "cves": list(set(cve.upper().replace(':', '-') for cve in cve_match)),
                        "severity": "unknown",
                        "score": "N/A"
                    })

    if current_host and current_host.get('ports'):
        hosts.append(current_host)

    return hosts

def _enrich_cve_data(hosts: List[Dict]) -> List[Dict]:
    """Enriquece dados das CVEs com informações da API"""
    if not CVE_LOOKUP_AVAILABLE:
        return hosts

    cve_lookup = CVELookup()
    all_cves = set()

    # Coletar todas as CVEs únicas
    for host in hosts:
        for port in host.get('ports', []):
            for vuln in port.get('vulnerabilities', []):
                for cve in vuln.get('cves', []):
                    if cve and cve.startswith('CVE-'):
                        all_cves.add(cve)

    if not all_cves:
        return hosts

    print(f"[INFO] Buscando informações para {len(all_cves)} CVEs...")

    # Buscar informações das CVEs
    cve_info_map = cve_lookup.get_multiple_cves(list(all_cves))

    # Atualizar dados dos hosts
    for host in hosts:
        for port in host.get('ports', []):
            for vuln in port.get('vulnerabilities', []):
                if vuln.get('cves'):
                    # Pegar a severidade mais alta entre as CVEs
                    severities = []
                    scores = []

                    for cve in vuln['cves']:
                        if cve in cve_info_map:
                            cve_info = cve_info_map[cve]
                            severities.append(cve_info['severity'])
                            if cve_info['score'] != 'N/A':
                                try:
                                    scores.append(float(cve_info['score']))
                                except:
                                    pass

                    # Determinar severidade final
                    if 'critical' in severities:
                        vuln['severity'] = 'critical'
                    elif 'high' in severities:
                        vuln['severity'] = 'high'
                    elif 'medium' in severities:
                        vuln['severity'] = 'medium'
                    elif 'low' in severities:
                        vuln['severity'] = 'low'

                    # Score mais alto
                    if scores:
                        vuln['score'] = str(max(scores))

                    # Adicionar informações detalhadas das CVEs
                    vuln['cve_details'] = {}
                    for cve in vuln['cves']:
                        if cve in cve_info_map:
                            vuln['cve_details'][cve] = cve_info_map[cve]

    return hosts

def _extract_active_ips(nmap_output: str) -> List[str]:
    """Extrai IPs ativos do output do nmap"""
    ips = []
    lines = nmap_output.split('\n')

    for line in lines:
        if 'Nmap scan report for' in line:
            if '(' in line and ')' in line:
                ip = line.split('(')[1].split(')')[0]
            else:
                ip = line.split()[-1]

            try:
                ipaddress.IPv4Address(ip)
                ips.append(ip)
            except:
                continue

    return ips

def _netmask_to_cidr(netmask: str) -> str:
    """Converte máscara para CIDR"""
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen)
    except:
        common_masks = {
            '255.255.255.0': '24',
            '255.255.0.0': '16',
            '255.0.0.0': '8'
        }
        return common_masks.get(netmask, '24')

def _format_scan_time(duration: float) -> str:
    """Formata tempo de scan"""
    minutes = int(duration // 60)
    seconds = int(duration % 60)
    return f"{minutes}:{seconds:02d}"

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='ENSA Vulnerability Scanner v2.0')
    parser.add_argument('target', nargs='?', help='IP único ou rede CIDR')
    parser.add_argument('--threads', type=int, default=3, help='Número de threads')
    parser.add_argument('--no-cve-lookup', action='store_true', help='Não buscar info das CVEs')
    parser.add_argument('--no-nmap', action='store_true', help='Desabilitar nmap')
    parser.add_argument('--single', action='store_true', help='Forçar scan de alvo único')

    args = parser.parse_args()

    if not args.target:
        print("=== SCANNER DE VULNERABILIDADES (SYN + SCRIPT VULN) ===")
        ip = input("Digite o IP base da rede (ex: 192.168.0.1): ").strip()
        mask = input("Digite a máscara (ex: 24 para CIDR): ").strip()

        try:
            ip_cidr = f"{ip}/{mask}"
            rede = ipaddress.IPv4Network(ip_cidr, strict=False)
            print(f"[INFO] IP CIDR calculado: {rede}")
            results = scan_network(ip=ip, subnet=mask, use_real_nmap=not args.no_nmap,
                               max_threads=args.threads, lookup_cves=not args.no_cve_lookup)
        except Exception as e:
            print(f"[ERRO] IP ou máscara inválida: {e}")
            exit(1)
    else:
        results = scan_network(target=args.target, use_real_nmap=not args.no_nmap,
                           max_threads=args.threads, lookup_cves=not args.no_cve_lookup,
                           force_single=args.single)

    print("\n=== RESULTADO FINAL ===")
    print(json.dumps(results, indent=2))
