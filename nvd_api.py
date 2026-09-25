#!/usr/bin/env python3
"""
Módulo de consulta a la API de NVD (National Vulnerability Database)
Con soporte para API Key configurable

Autor: David Casas M. - Competencia Digital
Licencia: CC BY-NC 4.0
"""

import requests
import time
import json
import os
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode
import re

class NVDAPI:
    """
    Cliente para la API de NVD (National Vulnerability Database)
    
    Sin API key: Rate limit 5 peticiones/30 segundos
    Con API key: Rate limit 50 peticiones/30 segundos
    
    Documentación: https://nvd.nist.gov/developers/vulnerabilities
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_WINDOW_DAYS = 120      # la API rechaza con 404 cualquier rango mayor
    MAX_RESULTS_PER_PAGE = 2000
    MAX_RETRIES = 3
    
    def __init__(self, api_key: str = None):
        """
        Inicializa el cliente de NVD API
        
        Args:
            api_key: API Key de NVD (opcional). Si no se proporciona,
                    se busca en la variable de entorno NVD_API_KEY
        """
        # Si no se proporciona API key, buscar en variables de entorno
        if not api_key:
            api_key = os.environ.get('NVD_API_KEY', None)
        
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({'apiKey': api_key})
            self.rate_limit = 0.6  # 0.6 segundos (50 peticiones/30s)
            self.has_api_key = True
            print("   ✅ API Key de NVD configurada (rate limit: 50 peticiones/30s)")
        else:
            self.rate_limit = 6.0  # 6 segundos (5 peticiones/30s)
            self.has_api_key = False
            print("   ℹ️  Sin API Key (rate limit: 5 peticiones/30s)")
            print("   💡 Registra una API key gratis en: https://nvd.nist.gov/developers/request-an-api-key")
        
        self.last_request = 0
        self.request_count = 0
    
    def set_api_key(self, api_key: str):
        """Permite configurar la API key después de la inicialización"""
        self.api_key = api_key
        if api_key:
            self.session.headers.update({'apiKey': api_key})
            self.rate_limit = 0.6
            self.has_api_key = True
            print("   ✅ API Key de NVD actualizada (rate limit: 50 peticiones/30s)")
        else:
            self.session.headers.pop('apiKey', None)
            self.rate_limit = 6.0
            self.has_api_key = False
            print("   ℹ️  API Key eliminada (rate limit: 5 peticiones/30s)")
    
    def _wait_for_rate_limit(self):
        """Espera el tiempo necesario para respetar el rate limit"""
        elapsed = time.time() - self.last_request
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request = time.time()
        self.request_count += 1
    
    @staticmethod
    def _clean_version(version: str):
        """
        Extrae la versión numérica de un banner tipo '7.4.3-1' o '1.24.0 (Ubuntu)'.
        Devuelve None si no hay una versión utilizable.
        """
        if not version:
            return None
        match = re.match(r'^[vV]?(\d+(?:\.\d+)*)', str(version).strip())
        return match.group(1) if match else None
    
    def _build_cpe_query(self, technology: str, version: str = None) -> Optional[str]:
        """
        Construye una consulta CPE para la búsqueda en NVD
        
        Formato: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        
        La API de NVD rechaza con HTTP 404 cualquier CPE con comodín en la
        versión, por lo que sin versión no se puede consultar por CPE.
        """
        tech_lower = technology.lower()
        version_clean = self._clean_version(version)
        
        if not version_clean:
            return None
        
        # Mapeo de tecnologías a sus vendor/product reales en CPE
        cpe_map = {
            'nginx': ('f5', 'nginx'),
            'apache': ('apache', 'http_server'),
            'httpd': ('apache', 'http_server'),
            'wordpress': ('wordpress', 'wordpress'),
            'php': ('php', 'php'),
            'mysql': ('oracle', 'mysql'),
            'mariadb': ('mariadb', 'mariadb'),
            'postgresql': ('postgresql', 'postgresql'),
            'openssl': ('openssl', 'openssl'),
            'python': ('python', 'python'),
            'nodejs': ('nodejs', 'node.js'),
            'node': ('nodejs', 'node.js'),
            'django': ('djangoproject', 'django'),
            'odoo': ('odoo', 'odoo'),
            'joomla': ('joomla', 'joomla'),
            'drupal': ('drupal', 'drupal'),
            'rails': ('rubyonrails', 'rails'),
            'rubyonrails': ('rubyonrails', 'rails'),
            'express': ('expressjs', 'express'),
            'jquery': ('jquery', 'jquery'),
            'bootstrap': ('twbs', 'bootstrap'),
            'react': ('facebook', 'react'),
            'angular': ('angular', 'angular'),
            'vuejs': ('vuejs', 'vue.js'),
            'tomcat': ('apache', 'tomcat'),
            'iis': ('microsoft', 'internet_information_services'),
            'caddy': ('caddyserver', 'caddy'),
            'jetty': ('eclipse', 'jetty'),
            'gunicorn': ('gunicorn', 'gunicorn'),
            'uwsgi': ('unbit', 'uwsgi'),
        }
        
        vendor, product = cpe_map.get(tech_lower, (tech_lower, tech_lower))
        return f"cpe:2.3:a:{vendor}:{product}:{version_clean}:*:*:*:*:*:*:*"
    
    @staticmethod
    def _date_windows(days_back: int, max_days: int = None):
        """
        Genera ventanas (inicio, fin) de como máximo MAX_WINDOW_DAYS días.
        La API de NVD devuelve 404 si el rango supera 120 días.
        """
        max_days = max_days or NVDAPI.MAX_WINDOW_DAYS
        end = datetime.now()
        start = end - timedelta(days=days_back)
        windows = []
        while start < end:
            window_end = min(start + timedelta(days=max_days), end)
            windows.append((start, window_end))
            start = window_end
        return windows
    
    @staticmethod
    def _format_date(dt: datetime) -> str:
        """NVD exige el formato yyyy-MM-dd'T'HH:mm:ss.SSS"""
        return dt.strftime('%Y-%m-%dT%H:%M:%S.000')
    
    def _get(self, params: dict):
        """
        Realiza una petición GET aplicando rate limit y reintentos acotados.
        Devuelve (response, None) o (None, mensaje de error).
        """
        for attempt in range(self.MAX_RETRIES):
            self._wait_for_rate_limit()
            
            try:
                response = self.session.get(self.BASE_URL, params=params, timeout=45)
            except requests.exceptions.Timeout:
                print("      ❌ Timeout en la petición a NVD")
                time.sleep(2 * (attempt + 1))
                continue
            except requests.exceptions.RequestException as e:
                print(f"      ❌ Error de red: {e}")
                time.sleep(2 * (attempt + 1))
                continue
            
            if response.status_code == 200:
                return response, None
            
            # 403/429: límite alcanzado. Backoff acotado (nunca recursión infinita)
            if response.status_code in (403, 429):
                retry_after = response.headers.get('Retry-After')
                if retry_after and retry_after.isdigit():
                    wait = int(retry_after)
                else:
                    wait = int(30 * (attempt + 1))
                wait = min(wait, 120)
                if attempt < self.MAX_RETRIES - 1:
                    print(f"      ⚠️  Límite de API alcanzado. Reintento {attempt + 1}/{self.MAX_RETRIES} en {wait}s...")
                    time.sleep(wait)
                    continue
                return None, "Límite de peticiones alcanzado (403/429)"
            
            if response.status_code == 404:
                return None, "404 (CPE o rango de fechas no válido)"
            
            return None, f"HTTP {response.status_code}: {response.text[:150]}"
        
        return None, "Se agotaron los reintentos"
    
    def search_cves(self, technology: str, version: str = None, 
                   max_results: int = 50, days_back: int = 730) -> List[Dict]:
        """
        Busca CVEs para una tecnología específica usando la API de NVD
        
        Args:
            technology: Nombre de la tecnología (ej. nginx, wordpress, php)
            version: Versión específica (opcional). Sin versión se usa
                     búsqueda por keyword, menos precisa.
            max_results: Máximo de resultados a devolver
            days_back: Días hacia atrás para buscar (default: 730 días = 2 años)
            
        Returns:
            Lista de CVEs encontrados
        """
        tech_display = f"{technology} {version if version else ''}".strip()
        print(f"\n   🔍 Buscando {tech_display} en NVD API...")
        
        cpe_query = self._build_cpe_query(technology, version)
        
        if cpe_query:
            print(f"      📌 CPE: {cpe_query}")
        else:
            print(f"      📌 Sin versión utilizable: se usará búsqueda por palabra clave")
        
        results = []
        seen_ids = set()
        windows = self._date_windows(days_back)
        
        for start, end in windows:
            params = {
                'resultsPerPage': min(max_results, self.MAX_RESULTS_PER_PAGE),
                'startIndex': 0,
                'pubStartDate': self._format_date(start),
                'pubEndDate': self._format_date(end)
            }
            
            if cpe_query:
                params['cpeName'] = cpe_query
            else:
                params['keywordSearch'] = technology
                params['keywordExactMatch'] = 'true'
            
            print(f"      ⏳ Ventana {start.strftime('%Y-%m-%d')} → {end.strftime('%Y-%m-%d')} ({len(windows)} en total)")
            response, error = self._get(params)
            
            if error:
                print(f"      ❌ {error}")
                # Un 404 con keyword puede ser normal: seguir con el resto de ventanas
                if error.startswith('404'):
                    continue
                break
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            total_results = data.get('totalResults', 0)
            
            for vuln in vulnerabilities:
                cve_data = vuln.get('cve', {})
                cve_info = self._extract_cve_info(cve_data)
                cve_id = cve_info.get('id')
                if cve_id and cve_id in seen_ids:
                    continue
                if cve_id:
                    seen_ids.add(cve_id)
                results.append(cve_info)
            
            if total_results:
                print(f"      📊 {len(results)} CVE(s) acumulado(s) (total en la ventana: {total_results})")
            
            if len(results) >= max_results:
                break
        
        results = results[:max_results]
        
        if results:
            print(f"      ✅ Devueltos: {len(results)} CVEs")
        else:
            print(f"      ℹ️  No se encontraron CVEs para {tech_display}")
        
        return results
    
    def _extract_cve_info(self, cve_data: Dict) -> Dict:
        """Extrae información relevante de un CVE"""
        cve_id = cve_data.get('id', 'Unknown')
        
        description = ""
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        severity = self._extract_severity(cve_data.get('metrics', {}))
        
        return {
            'id': cve_id,
            'descriptions': [{'lang': 'en', 'value': description}] if description else [],
            'severity': severity,
            'published': cve_data.get('published', ''),
            'lastModified': cve_data.get('lastModified', ''),
            'vulnStatus': cve_data.get('vulnStatus', '')
        }
    
    @staticmethod
    def _extract_severity(metrics: Dict) -> Dict:
        """
        Extrae la severidad de las métricas CVSS.

        Ojo: en CVSS v3.x baseSeverity vive dentro de cvssData, mientras que
        en v2 está en el nivel de la métrica. El score siempre está en
        cvssData.baseScore.
        """
        severity = {
            'score': 'N/A',
            'severity': 'UNKNOWN',
            'vector': 'N/A',
            'version': 'N/A'
        }
        
        for key, version in (('cvssMetricV40', '4.0'), ('cvssMetricV31', '3.1'),
                             ('cvssMetricV30', '3.0'), ('cvssMetricV2', '2.0')):
            entries = metrics.get(key)
            if not entries:
                continue
            
            metric = entries[0]
            cvss = metric.get('cvssData', {})
            
            score = cvss.get('baseScore', metric.get('baseScore'))
            if isinstance(score, (int, float, Decimal)):
                score = float(score)
            else:
                score = 'N/A'
            
            severity['score'] = score
            severity['vector'] = cvss.get('vectorString', 'N/A')
            severity['version'] = version
            # v3.x: dentro de cvssData / v2: en el nivel de la métrica
            severity['severity'] = cvss.get('baseSeverity') or metric.get('baseSeverity', 'UNKNOWN')
            
            # Si no vino la severidad, derivarla del score (umbrales CVSS)
            if severity['severity'] == 'UNKNOWN' and isinstance(score, float):
                if score >= 9.0:
                    severity['severity'] = 'CRITICAL'
                elif score >= 7.0:
                    severity['severity'] = 'HIGH'
                elif score >= 4.0:
                    severity['severity'] = 'MEDIUM'
                else:
                    severity['severity'] = 'LOW'
            break
        
        return severity
    
    def search_cves_for_site(self, technologies: List[Tuple[str, str]], 
                             days_back: int = 730) -> Dict[str, List[Dict]]:
        """Busca CVEs para múltiples tecnologías"""
        results = {}
        total_tech = len(technologies)
        current = 0
        
        print("\n" + "=" * 70)
        print("🌐 CONSULTANDO NVD API")
        print("=" * 70)
        print(f"📋 Tecnologías a consultar: {total_tech}")
        print(f"📊 Rate limit: {'50' if self.has_api_key else '5'} peticiones cada 30 segundos")
        print("=" * 70 + "\n")
        
        for tech, version in technologies:
            current += 1
            print(f"\n   📌 [{current}/{total_tech}] {tech} {version}")
            print("   " + "-" * 50)
            
            cves = self.search_cves(tech, version, max_results=50, days_back=days_back)
            
            # Si no hay resultados y la búsqueda CPE no yielded nada,
            # reintentar por palabra clave (menos precisa pero más cobertura)
            if not cves and version and self._clean_version(version):
                cves = self.search_cves(tech, None, max_results=50, days_back=days_back)
            
            results[f"{tech} {version}"] = {
                'count': len(cves),
                'cves': cves
            }
            
            if len(cves) > 0:
                print(f"\n   ✅ {tech} {version}: {len(cves)} CVEs encontrados")
                for i, cve in enumerate(cves[:3], 1):
                    sev = cve.get('severity', {}).get('severity', 'UNKNOWN')
                    score = cve.get('severity', {}).get('score', 'N/A')
                    print(f"      {i}. {cve.get('id')} [{sev}] Score: {score}")
                if len(cves) > 3:
                    print(f"      ... y {len(cves) - 3} más")
            else:
                print(f"\n   ℹ️ {tech} {version}: 0 CVEs encontrados")
                print(f"      💡 Sugerencia: Prueba con la base de datos FKIE-CAD (opción 5)")
            
            # El rate limit ya se aplica dentro de search_cves vía _wait_for_rate_limit
            
        print("\n" + "=" * 70)
        print(f"✅ BÚSQUEDA COMPLETADA ({self.request_count} peticiones a NVD)")
        print("=" * 70)
        
        return results
