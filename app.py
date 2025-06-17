from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import logging
import os
import sys
import time

# Adicionar o diretório atual ao path para importar os módulos
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from scan_network import scan_network  # Função do scan básico
    from vuln_scan import scan_network as scan_network_vuln  # Função do scan de vulnerabilidades
except ImportError as e:
    print(f"[ERROR] Erro ao importar módulos: {e}")
    print("[INFO] Certifique-se de que scan_network.py e vuln_scan.py estão no mesmo diretório")
    sys.exit(1)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_target_type(target):
    """
    Analisa o target CIDR e determina se deve fazer scan de rede ou IP único
    baseado no último octeto do IP
    """
    if not target or '/' not in target:
        return False, "Invalid target format"

    try:
        ip_part, cidr_part = target.split('/')
        ip_octets = ip_part.split('.')

        if len(ip_octets) != 4:
            return False, "Invalid IP format"

        last_octet = int(ip_octets[3])

        # Se último octeto é 0, fazer scan de rede
        if last_octet == 0:
            scan_type = "network"
            force_single = False
            logger.info(f"[SMART LOGIC] IP {ip_part} termina em 0 → SCAN DE REDE COMPLETA")
        else:
            # Se último octeto não é 0, fazer scan apenas desse IP
            scan_type = "single"
            force_single = True
            logger.info(f"[SMART LOGIC] IP {ip_part} termina em {last_octet} → SCAN DE IP ÚNICO")

        return force_single, scan_type

    except (ValueError, IndexError) as e:
        logger.error(f"[ERROR] Erro ao analisar target {target}: {e}")
        return False, "Error parsing target"

@app.route('/api/scan', methods=['GET', 'OPTIONS'])
def scan():
    """Endpoint para scan básico - suporta alvo único ou rede"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response

    # Parâmetros de entrada
    target = request.args.get('target')
    ip = request.args.get('ip')
    subnet = request.args.get('subnet')
    ip_range = request.args.get('ip_range')
    threads = request.args.get('threads', '10')

    # NOVA LÓGICA INTELIGENTE: Analisar o target para determinar tipo de scan
    if target and '/' in target:
        force_single, scan_type_info = analyze_target_type(target)
        logger.info(f"[SMART ANALYSIS] Target: {target} → Tipo: {scan_type_info}")
    else:
        # Fallback para lógica antiga
        force_single = request.args.get('force_single', 'false').lower() == 'true'
        if target and '/' not in target and not subnet:
            force_single = True
            logger.info(f"[FALLBACK] FORÇANDO SCAN DE ALVO ÚNICO para {target} (sem CIDR)")
        scan_type_info = "single" if force_single else "network"

    # DEBUG: Log todos os parâmetros recebidos
    logger.info(f"[DEBUG] Parâmetros recebidos:")
    logger.info(f"[DEBUG] - target: {target}")
    logger.info(f"[DEBUG] - ip: {ip}")
    logger.info(f"[DEBUG] - subnet: {subnet}")
    logger.info(f"[DEBUG] - ip_range: {ip_range}")
    logger.info(f"[DEBUG] - force_single (calculado): {force_single}")
    logger.info(f"[DEBUG] - scan_type: {scan_type_info}")

    if force_single:
        logger.info(f"[DEBUG] *** MODO ALVO ÚNICO ATIVADO *** para target: {target}")
    else:
        logger.info(f"[DEBUG] *** MODO REDE COMPLETA *** para target: {target}")

    # Validar parâmetros
    if not target and not ip_range and not (ip and subnet):
        return jsonify({
            "error": "Forneça 'target' (IP único ou CIDR) OU 'ip_range' OU 'ip' e 'subnet'",
            "status": "error",
            "examples": {
                "single_ip": "/api/scan?target=192.168.1.1",
                "network": "/api/scan?target=192.168.1.0/24",
                "legacy": "/api/scan?ip=192.168.1.1&subnet=24"
            }
        }), 400

    try:
        threads_int = int(threads)
        if threads_int < 1 or threads_int > 50:
            threads_int = 10
    except:
        threads_int = 10

    logger.info(f"Executando scan básico - target={target}, ip={ip}, subnet={subnet}, ip_range={ip_range}, threads={threads_int}, force_single={force_single}")

    # Verificar se nmap está disponível
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        nmap_version = result.stdout.decode().split('\n')[0] if result.stdout else 'Unknown'
        logger.info(f"Nmap version: {nmap_version}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return jsonify({
            "error": "Nmap não instalado ou não acessível",
            "status": "error",
            "note": "Instale o nmap: sudo apt-get install nmap"
        }), 500

    try:
        # Chamada para o scan básico com force_single CORRETO
        scan_results = scan_network(
            target=target,
            ip=ip,
            subnet=subnet,
            ip_range=ip_range,
            use_real_nmap=True,
            max_threads=threads_int,
            force_single=force_single  # Agora passa o valor correto
        )

        # Adicionar informações extras na resposta
        scan_results['api_version'] = 'ENSA API v2.1'
        scan_results['endpoint'] = 'basic_scan'
        scan_results['forced_single'] = force_single
        scan_results['mode_used'] = 'single_target' if force_single else 'network_scan'

        return jsonify(scan_results)

    except Exception as e:
        logger.error(f"Erro no scan básico: {str(e)}")
        return jsonify({
            "error": f"Scan básico falhou: {str(e)}",
            "status": "error"
        }), 500

@app.route('/api/scancomplete', methods=['GET', 'OPTIONS'])
def scan_complete():
    """Endpoint para scan completo de vulnerabilidades"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response

    # Parâmetros de entrada
    target = request.args.get('target')
    ip = request.args.get('ip')
    subnet = request.args.get('subnet')
    ip_range = request.args.get('ip_range')
    threads = request.args.get('threads', '3')
    lookup_cves = request.args.get('lookup_cves', 'true').lower() == 'true'

    # NOVA LÓGICA INTELIGENTE: Analisar o target para determinar tipo de scan
    if target and '/' in target:
        force_single, scan_type_info = analyze_target_type(target)
        logger.info(f"[SMART ANALYSIS VULN] Target: {target} → Tipo: {scan_type_info}")
    else:
        # Fallback para lógica antiga
        force_single = request.args.get('force_single', 'false').lower() == 'true'
        if target and '/' not in target and not subnet:
            force_single = True
            logger.info(f"[FALLBACK VULN] FORÇANDO SCAN DE ALVO ÚNICO para {target}")
        scan_type_info = "single" if force_single else "network"

    logger.info(f"[DEBUG VULN] force_single calculado: {force_single}, tipo: {scan_type_info}")

    # Validar parâmetros
    if not target and not ip_range and not (ip and subnet):
        return jsonify({
            "error": "Forneça 'target' (IP único ou CIDR) OU 'ip_range' OU 'ip' e 'subnet'",
            "status": "error",
            "examples": {
                "single_ip": "/api/scancomplete?target=192.168.1.1",
                "network": "/api/scancomplete?target=192.168.1.0/24",
                "no_cve_lookup": "/api/scancomplete?target=192.168.1.1&lookup_cves=false"
            }
        }), 400

    try:
        threads_int = int(threads)
        if threads_int < 1 or threads_int > 10:
            threads_int = 3
    except:
        threads_int = 3

    logger.info(f"Executando scan de vulnerabilidades - target={target}, threads={threads_int}, lookup_cves={lookup_cves}, force_single={force_single}")

    try:
        # Chamada para o scan de vulnerabilidades com force_single CORRETO
        results = scan_network_vuln(
            target=target,
            ip=ip,
            subnet=subnet,
            ip_range=ip_range,
            use_real_nmap=True,
            max_threads=threads_int,
            lookup_cves=lookup_cves,
            force_single=force_single  # Agora passa o valor correto
        )

        # Adicionar informações extras
        results['api_version'] = 'ENSA API v2.1'
        results['endpoint'] = 'vulnerability_scan'
        results['cve_lookup_enabled'] = lookup_cves
        results['forced_single'] = force_single
        results['mode_used'] = 'single_target' if force_single else 'network_scan'

        return jsonify(results)

    except Exception as e:
        logger.error(f"Erro no scan de vulnerabilidades: {str(e)}")
        return jsonify({
            "error": f"Scan de vulnerabilidades falhou: {str(e)}",
            "status": "error"
        }), 500

@app.route('/api/health', methods=['GET', 'OPTIONS'])
def health_check():
    """Health check melhorado"""
    if request.method == 'OPTIONS':
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
        return response

    logger.info("Health check solicitado")

    # Verificar nmap
    nmap_available = False
    nmap_version = "Não instalado"
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, check=True)
        nmap_available = True
        nmap_version = result.stdout.split('\n')[0] if result.stdout else "Versão desconhecida"
    except (subprocess.CalledProcessError, FileNotFoundError):
        nmap_available = False

    # Verificar módulos Python
    modules_status = {}
    try:
        import requests
        modules_status['requests'] = 'OK'
    except ImportError:
        modules_status['requests'] = 'MISSING'

    try:
        from cve_lookup import CVELookup
        modules_status['cve_lookup'] = 'OK'
    except ImportError:
        modules_status['cve_lookup'] = 'MISSING'

    # Verificar conectividade com API de CVEs
    cve_api_status = "Unknown"
    try:
        import requests
        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1", timeout=5)
        if response.status_code == 200:
            cve_api_status = "OK"
        else:
            cve_api_status = f"HTTP {response.status_code}"
    except Exception as e:
        cve_api_status = f"Error: {str(e)}"

    response_data = {
        "status": "ok",
        "message": "ENSA Vulnerability Scanner API v2.1 está rodando",
        "version": "2.1",
        "features": {
            "single_target_scan": True,
            "network_scan": True,
            "vulnerability_detection": True,
            "cve_lookup": modules_status.get('cve_lookup') == 'OK',
            "parallel_scanning": True,
            "force_single_parameter": True  # Nova feature corrigida
        },
        "nmap": {
            "available": nmap_available,
            "version": nmap_version
        },
        "modules": modules_status,
        "external_apis": {
            "nvd_cve_api": cve_api_status
        },
        "endpoints": {
            "/api/scan": "Scan básico (portas e serviços)",
            "/api/scancomplete": "Scan completo (vulnerabilidades + CVEs)",
            "/api/health": "Status da API"
        },
        "examples": {
            "single_ip_basic": "/api/scan?target=192.168.1.1/32",
            "network_basic": "/api/scan?target=192.168.1.0/24",
            "single_ip_vuln": "/api/scancomplete?target=192.168.1.64/24",
            "network_vuln": "/api/scancomplete?target=192.168.1.0/24",
            "smart_logic": "IP terminando em 0 = rede, outros = IP único"
        }
    }

    response = jsonify(response_data)
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

if __name__ == '__main__':
    print("=" * 70)
    print("🚀 Iniciando ENSA Vulnerability Scanner API v2.1 (CORRIGIDA)")
    print("=" * 70)
    print("📡 API estará disponível em: http://0.0.0.0:5000")
    print("🔍 Endpoints disponíveis:")
    print("   • GET /api/health - Status da API")
    print("   • GET /api/scan - Scan básico")
    print("   • GET /api/scancomplete - Scan de vulnerabilidades")
    print("=" * 70)
    print("💡 Exemplos de uso:")
    print("   • Alvo único: /api/scan?target=192.168.1.1&force_single=true")
    print("   • Rede: /api/scan?target=192.168.1.0&subnet=255.255.255.0&force_single=false")
    print("   • Vulnerabilidades: /api/scancomplete?target=192.168.1.1&force_single=true")
    print("=" * 70)
    print("🔧 CORREÇÕES APLICADAS:")
    print("   • API agora RESPEITA o parâmetro force_single da interface")
    print("   • Lógica automática só é aplicada se force_single não for especificado")
    print("   • Logs melhorados para debug")
    print("=" * 70)

    app.run(host='0.0.0.0', port=5000, debug=True)
