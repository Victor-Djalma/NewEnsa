import requests
import json
import time
from typing import Dict, List, Optional
import logging

class CVELookup:
    """Classe para buscar informações de CVEs usando APIs públicas"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ENSA-Scanner/1.0'
        })
        # Cache para evitar requisições repetidas
        self.cache = {}

    def get_cve_info(self, cve_id: str) -> Optional[Dict]:
        """
        Busca informações de uma CVE específica
        """
        if not cve_id or not cve_id.startswith('CVE-'):
            return None

        # Verificar cache primeiro
        if cve_id in self.cache:
            return self.cache[cve_id]

        try:
            # Usar a API do NIST NVD
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()

                if data.get('vulnerabilities'):
                    vuln = data['vulnerabilities'][0]['cve']

                    # Extrair informações relevantes
                    cve_info = {
                        'id': cve_id,
                        'description': self._extract_description(vuln),
                        'severity': self._extract_severity(vuln),
                        'score': self._extract_score(vuln),
                        'vector': self._extract_vector(vuln),
                        'published': vuln.get('published', ''),
                        'modified': vuln.get('lastModified', '')
                    }

                    # Adicionar ao cache
                    self.cache[cve_id] = cve_info
                    return cve_info

        except Exception as e:
            logging.warning(f"Erro ao buscar CVE {cve_id}: {e}")

        # Fallback: retornar informações básicas
        fallback_info = {
            'id': cve_id,
            'description': 'Descrição não disponível',
            'severity': self._guess_severity_from_id(cve_id),
            'score': 'N/A',
            'vector': 'N/A',
            'published': 'N/A',
            'modified': 'N/A'
        }

        self.cache[cve_id] = fallback_info
        return fallback_info

    def get_multiple_cves(self, cve_list: List[str]) -> Dict[str, Dict]:
        """
        Busca informações de múltiplas CVEs
        """
        results = {}

        for cve_id in cve_list:
            if cve_id:
                # Adicionar delay para evitar rate limiting
                time.sleep(0.1)
                cve_info = self.get_cve_info(cve_id)
                if cve_info:
                    results[cve_id] = cve_info

        return results

    def _extract_description(self, vuln_data: Dict) -> str:
        """Extrai descrição da CVE"""
        try:
            descriptions = vuln_data.get('descriptions', [])
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    return desc.get('value', 'Sem descrição')
            return 'Sem descrição'
        except:
            return 'Sem descrição'

    def _extract_severity(self, vuln_data: Dict) -> str:
        """Extrai severidade da CVE"""
        try:
            metrics = vuln_data.get('metrics', {})

            # Tentar CVSS v3.1 primeiro
            if 'cvssMetricV31' in metrics:
                cvss = metrics['cvssMetricV31'][0]['cvssData']
                return cvss.get('baseSeverity', 'UNKNOWN').lower()

            # Fallback para CVSS v3.0
            elif 'cvssMetricV30' in metrics:
                cvss = metrics['cvssMetricV30'][0]['cvssData']
                return cvss.get('baseSeverity', 'UNKNOWN').lower()

            # Fallback para CVSS v2
            elif 'cvssMetricV2' in metrics:
                score = float(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])
                if score >= 7.0:
                    return 'high'
                elif score >= 4.0:
                    return 'medium'
                else:
                    return 'low'

        except:
            pass

        return 'unknown'

    def _extract_score(self, vuln_data: Dict) -> str:
        """Extrai score CVSS da CVE"""
        try:
            metrics = vuln_data.get('metrics', {})

            if 'cvssMetricV31' in metrics:
                return str(metrics['cvssMetricV31'][0]['cvssData']['baseScore'])
            elif 'cvssMetricV30' in metrics:
                return str(metrics['cvssMetricV30'][0]['cvssData']['baseScore'])
            elif 'cvssMetricV2' in metrics:
                return str(metrics['cvssMetricV2'][0]['cvssData']['baseScore'])

        except:
            pass

        return 'N/A'

    def _extract_vector(self, vuln_data: Dict) -> str:
        """Extrai vetor CVSS da CVE"""
        try:
            metrics = vuln_data.get('metrics', {})

            if 'cvssMetricV31' in metrics:
                return metrics['cvssMetricV31'][0]['cvssData']['vectorString']
            elif 'cvssMetricV30' in metrics:
                return metrics['cvssMetricV30'][0]['cvssData']['vectorString']
            elif 'cvssMetricV2' in metrics:
                return metrics['cvssMetricV2'][0]['cvssData']['vectorString']

        except:
            pass

        return 'N/A'

    def _guess_severity_from_id(self, cve_id: str) -> str:
        """
        Tenta adivinhar severidade baseado no ano da CVE
        """
        try:
            year = int(cve_id.split('-')[1])
            if year >= 2020:
                return 'medium'
            else:
                return 'low'
        except:
            return 'unknown'
