#!/usr/bin/env python3
"""
Módulo de análisis de CVEs offline usando feeds de FKIE-CAD
Versión con soporte de rangos de versión (versionStartIncluding / versionEndExcluding)

Autor: David Casas M. - Competencia Digital
Licencia: CC BY-NC 4.0
"""

import os
import json
import lzma
import time
import hashlib
import requests
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import gc
import re

from nvd_api import NVDAPI

try:
    import ijson
    IJSON_AVAILABLE = True
except ImportError:
    IJSON_AVAILABLE = False
    print("❌ Falta la librería 'ijson', necesaria para leer la base de datos de CVEs.")
    print("   Instálala con:  pip install -r requeriments.txt")
    print("   (o:  python3 -m pip install ijson)")
    sys.exit(1)


class LocalCVEDatabase:
    """Gestor de base de datos local de CVEs - Con soporte de rangos de versión"""

    BASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/"
    # Ojo: el asset se llama 'CVE-all.json.xz' con 'all' en minúscula
    ALL_CVES_FILE = "CVE-all.json.xz"
    METADATA_URL = "https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest"
    # SHA-256 y tamaño los publica upstream en <asset>.meta
    META_FILE = "CVE-all.meta"
    #: La API de GitHub permite 60 peticiones/hora sin token: se cachea.
    VERSION_CACHE_SECONDS = 300

    def __init__(self, cache_dir: str = "./cve_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)

        self.cves_file = self.cache_dir / self.ALL_CVES_FILE
        self.metadata_file = self.cache_dir / "metadata.json"
        self.last_update = None
        self.version = None
        self.total_cves = None
        self.expected_sha256 = None
        self.expected_xz_size = None
        self.last_modified_date = None
        self.is_loaded = False
        self._version_cache = None
        self._version_cache_at = 0.0

        self._load_metadata()

    def _load_metadata(self):
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    self.version = data.get('version')
                    if data.get('last_update'):
                        self.last_update = datetime.fromisoformat(data.get('last_update'))
                    self.total_cves = data.get('cves_count')
                    self.expected_sha256 = data.get('expected_sha256')
                    self.expected_xz_size = data.get('expected_xz_size')
            except (OSError, ValueError, TypeError):
                # Metadatos ausentes o corruptos: se reconstruyen al descargar.
                pass

    def _save_metadata(self):
        data = {
            'version': self.version,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'file_size': self.cves_file.stat().st_size if self.cves_file.exists() else 0,
            'cves_count': self.total_cves,
            'expected_sha256': self.expected_sha256,
            'expected_xz_size': self.expected_xz_size,
            'last_modified_date': self.last_modified_date
        }
        tmp = self.metadata_file.with_suffix('.json.tmp')
        with open(tmp, 'w') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.metadata_file)

    def _fetch_feed_meta(self) -> Tuple[Optional[int], Optional[str]]:
        """Lee xzSize y sha256 del .meta que publica upstream junto al feed.

        Ojo: el sha256 corresponde al JSON DESCOMPRIMIDO (3,1 GB), no al .xz,
        así que no se puede comprobar sin descomprimir. El xzSize sí.
        """
        try:
            resp = requests.get(
                f"{self.BASE_URL}{self.META_FILE}", timeout=15
            )
            resp.raise_for_status()
            text = resp.text
        except requests.RequestException:
            return None, None

        xz_size = sha256 = None
        for line in text.splitlines():
            key, _, value = line.partition(':')
            value = value.strip()
            if key.strip() == 'xzSize' and value.isdigit():
                xz_size = int(value)
            elif key.strip() == 'sha256':
                sha256 = value
            elif key.strip() == 'lastModifiedDate':
                self.last_modified_date = value
        return xz_size, sha256

    def _get_latest_version_info(self) -> Tuple[Optional[str], Optional[str]]:
        now = time.time()
        if self._version_cache and now - self._version_cache_at < self.VERSION_CACHE_SECONDS:
            return self._version_cache

        self.last_modified_date = None
        self.expected_xz_size, self.expected_sha256 = self._fetch_feed_meta()

        try:
            response = requests.get(self.METADATA_URL, timeout=10)
            response.raise_for_status()
            data = response.json()
            version = data.get('tag_name', 'unknown')
            download_url = None
            for asset in data.get('assets', []):
                if asset.get('name') == self.ALL_CVES_FILE:
                    download_url = asset.get('browser_download_url')
                    break
            if download_url is None:
                download_url = f"{self.BASE_URL}{self.ALL_CVES_FILE}"
        except (requests.RequestException, ValueError) as e:
            print(f"⚠️  Error obteniendo versión: {e}")
            # Sin metadatos de la API seguimos con la URL estable 'latest'.
            return None, f"{self.BASE_URL}{self.ALL_CVES_FILE}"

        self._version_cache = (version, download_url)
        self._version_cache_at = now
        return self._version_cache

    def check_update_needed(self) -> Tuple[bool, str]:
        latest_version, download_url = self._get_latest_version_info()
        if not latest_version or not download_url:
            return False, "No se pudo verificar"
        if not self.version:
            return True, f"Nueva versión {latest_version} disponible"
        if self.version != latest_version:
            return True, f"Nueva versión {latest_version} disponible"
        if not self.cves_file.exists():
            return True, "Archivo local no encontrado"
        return False, f"Versión actualizada ({self.version})"

    def verify_integrity(self) -> bool:
        """Comprueba el SHA-256 del feed descomprimido frente al publicado
        por upstream. Descomprime ~3 GB, así que tarda del orden de un minuto.
        """
        if not self.cves_file.exists():
            print("❌ No hay base de datos local que verificar.")
            return False
        if not self.expected_sha256:
            resp = requests.get(
                f"{self.BASE_URL}{self.META_FILE}", timeout=15
            )
            if resp.ok:
                for line in resp.text.splitlines():
                    key, _, value = line.partition(':')
                    if key.strip() == 'sha256':
                        self.expected_sha256 = value.strip()
        if not self.expected_sha256:
            print("❌ Upstream no publica un sha256 con el que comparar.")
            return False

        print("🔍 Verificando SHA-256 (descomprime el feed, puede tardar ~1 min)...")
        digest = hashlib.sha256()
        try:
            with lzma.open(self.cves_file, 'rb') as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b''):
                    digest.update(chunk)
        except (lzma.LZMAError, OSError) as e:
            print(f"❌ Archivo ilegible o corrupto: {e}")
            return False

        real = digest.hexdigest()
        if real == self.expected_sha256:
            print("✅ Integridad correcta: SHA-256 coincide con el publicado.")
            return True
        print(f"❌ SHA-256 incorrecto.")
        print(f"   esperado: {self.expected_sha256}")
        print(f"   obtenido: {real}")
        print("   Borra cve_cache/ y vuelve a descargar.")
        return False

    def download_cves(self, force: bool = False) -> bool:
        if not force and self.cves_file.exists():
            needs_update, _ = self.check_update_needed()
            if not needs_update:
                print(f"✅ Archivo CVEs ya existe y está actualizado")
                return True

        print(f"📥 Descargando base de datos de CVEs...")
        print(f"   (esto puede tomar varios minutos)")

        part_file = self.cves_file.with_suffix(self.cves_file.suffix + '.part')
        try:
            latest_version, download_url = self._get_latest_version_info()
            if not download_url:
                download_url = f"{self.BASE_URL}{self.ALL_CVES_FILE}"

            response = requests.get(download_url, stream=True, timeout=120)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            with open(part_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\r   Progreso: {percent:.1f}%", end='')
            print(f"\n✅ Descarga completada")

            # Descarga truncada: no se publica el fichero a medias.
            if self.expected_xz_size and downloaded != self.expected_xz_size:
                part_file.unlink(missing_ok=True)
                print(f"❌ Descarga incompleta: {downloaded} bytes, "
                      f"esperados {self.expected_xz_size}")
                return False

            # Renombrado atómico: hasta aquí el .part no se usa para nada.
            os.replace(part_file, self.cves_file)

            self.version = latest_version
            self.last_update = datetime.now()
            # Contar exigiría una pasada completa sobre 3,1 GB: mejor no
            # inventar la cifra.
            self.total_cves = None
            self._save_metadata()

            if self.expected_sha256:
                print(f"ℹ️  SHA-256 esperado: {self.expected_sha256}")
                print(f"   Verifícalo cuando quieras con la opción de "
                      f"integridad del gestor de la base de datos.")
            return True

        except Exception as e:
            part_file.unlink(missing_ok=True)
            print(f"\n❌ Error descargando CVEs: {e}")
            return False

    def load_cves(self) -> bool:
        if not self.cves_file.exists():
            print("❌ Archivo de CVEs no encontrado")
            return False

        self.is_loaded = True
        size_mb = self.cves_file.stat().st_size / (1024 * 1024)
        count = f"~{self.total_cves}" if self.total_cves else "sin contar"
        print(f"✅ Base de datos disponible: {self.cves_file}")
        print(f"   Tamaño: {size_mb:.1f} MB")
        print(f"   CVEs en base de datos: {count}")
        return True

    def _parse_version(self, version_str: str) -> Tuple[int, ...]:
        """Convierte una versión a tupla para comparación"""
        if not version_str or version_str == 'N/A' or version_str == '*':
            return ()
        try:
            # Limpiar la versión
            version_str = version_str.strip()
            # Si tiene prefijo 'v', quitarlo
            if version_str.startswith('v'):
                version_str = version_str[1:]
            # Separar por puntos y convertir a números
            parts = []
            for part in version_str.split('.'):
                try:
                    parts.append(int(part))
                except ValueError:
                    # Si no es número, intentar extraer números
                    nums = re.findall(r'\d+', part)
                    if nums:
                        parts.append(int(nums[0]))
                    else:
                        parts.append(0)
            return tuple(parts)
        except (AttributeError, TypeError, ValueError):
            return ()

    def _version_in_range(self, version: str, start: str, end: str) -> bool:
        """Verifica si una versión está dentro de un rango"""
        if not version:
            return True
        
        ver = self._parse_version(version)
        if not ver:
            return True
        
        # Verificar inicio
        if start and start != 'N/A' and start != '*':
            start_ver = self._parse_version(start)
            if start_ver and ver < start_ver:
                return False
        
        # Verificar fin
        if end and end != 'N/A' and end != '*':
            end_ver = self._parse_version(end)
            if end_ver and ver >= end_ver:
                return False
        
        return True

    def search_cves_by_technology(self, technology: str, version: str = None, max_results: int = 50) -> List[Dict]:
        """
        Busca CVEs usando ijson - Con soporte de rangos de versión
        """
        results = self.search_cves_for_technologies(
            [(technology, version)], max_results_per_tech=max_results
        )
        return results.get(f"{technology} {version}", {}).get('cves', [])

    @staticmethod
    def _technology_matches(criteria: str, tech_lower: str) -> bool:
        """
        Indica si un criterio CPE corresponde a la tecnología buscada.

        Se compara con el vendor y el product del CPE, no con la cadena
        completa: 'apache' como vendor (p.ej. tomcat) también debe contar.
        """
        parts = criteria.split(':')
        if len(parts) < 6:
            return False
        vendor, product = parts[3], parts[4]
        return tech_lower in (vendor, product)

    def search_cves_for_technologies(self, technologies: List[Tuple[str, str]],
                                    max_results_per_tech: int = 50) -> Dict[str, Dict]:
        """
        Busca CVEs para varias tecnologías en una sola pasada sobre el feed.

        Comprimir y descomprimir el .xz es la operación cara: hacerlo una vez
        por tecnología multiplicaba el tiempo por N.
        """
        if not self.cves_file.exists():
            print("⚠️  Base de datos no descargada")
            return {}

        results = {f"{tech} {version}": {'count': 0, 'cves': []}
                   for tech, version in technologies}
        versions = {f"{tech} {version}": version for tech, version in technologies}
        tech_names = {f"{tech} {version}": tech.lower() for tech, version in technologies}

        print(f"   🔍 Buscando en la base de datos local "
              f"({len(technologies)} tecnología(s), una sola pasada)...")

        try:
            with lzma.open(self.cves_file, 'rb') as f:
                # use_float: ijson devuelve Decimal por defecto, que no es
                # serializable a JSON ni comparable con float
                cves_iterator = ijson.items(f, 'cve_items.item', use_float=True)

                processed = 0

                for cve_data in cves_iterator:
                    processed += 1

                    configs = cve_data.get('configurations', [])

                    for key, tech_lower in tech_names.items():
                        bucket = results[key]
                        if len(bucket['cves']) >= max_results_per_tech:
                            continue

                        version_str = versions[key]
                        if not self._cve_matches(cve_data, configs, tech_lower, version_str):
                            continue

                        bucket['cves'].append(self._extract_cve_info(cve_data))

                    if processed % 5000 == 0:
                        print(f"\r   Procesados: {processed:,} CVEs", end='')

            print(f"\r   ✅ Procesados: {processed:,} CVEs              ")

        except MemoryError:
            print("   ❌ Error: Memoria insuficiente")
            return {}
        except Exception as e:
            print(f"   ❌ Error buscando CVEs: {e}")
            return {}

        for key, bucket in results.items():
            bucket['count'] = len(bucket['cves'])

        for key, bucket in results.items():
            if bucket['count'] > 0:
                print(f"   ✅ {key}: {bucket['count']} CVEs")
            else:
                print(f"   ℹ️  {key}: 0 CVEs")

        return results

    def _cve_matches(self, cve_data: Dict, configs: List[Dict],
                     tech_lower: str, version_str: str) -> bool:
        """Comprueba si un CVE aplica a la tecnología (y versión) dada"""
        for config in configs:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    if not cpe_match.get('vulnerable', True):
                        continue

                    # FKIE-CAD usa 'criteria' en lugar de 'cpe23Uri'
                    criteria = cpe_match.get('criteria', '').lower()
                    if not criteria or not self._technology_matches(criteria, tech_lower):
                        continue

                    # Sin versión específica: basta con que el producto coincida
                    if not version_str:
                        return True

                    # Verificar rangos de versión
                    version_start = cpe_match.get('versionStartIncluding', '')
                    version_end = cpe_match.get('versionEndExcluding', '')
                    if self._version_in_range(version_str, version_start, version_end):
                        return True

                    # También comprobar la versión exacta del CPE.
                    # Comparación por subcadena: "1.2" casaba con "1.20.1"
                    parts = criteria.split(':')
                    if len(parts) > 4 and parts[4] == version_str:
                        return True

        return False

    def _extract_cve_info(self, cve_data: Dict) -> Dict:
        """Extrae información de un CVE"""
        severity = self._get_severity(cve_data)
        
        description = ""
        for desc in cve_data.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        return {
            'id': cve_data.get('id', 'Unknown'),
            'descriptions': [{'lang': 'en', 'value': description}] if description else [],
            'severity': severity,
            'published': cve_data.get('published', ''),
            'lastModified': cve_data.get('lastModified', ''),
            'vulnStatus': cve_data.get('vulnStatus', '')
        }

    def _get_severity(self, cve_data: Dict) -> Dict:
        """Extrae severidad de los datos del CVE"""
        return NVDAPI._extract_severity(cve_data.get('metrics', {}))

    def get_cves_for_site(self, technologies: List[Tuple[str, str]]) -> Dict[str, List[Dict]]:
        results = self.search_cves_for_technologies(technologies, max_results_per_tech=50)
        return results

    def get_statistics(self) -> Dict:
        disponible = self.cves_file.exists()
        return {
            'status': 'Disponible' if disponible else 'No cargada',
            'total_cves': self.total_cves if disponible else None,
            'version': self.version,
            'last_update': self.last_update.isoformat() if self.last_update else 'Unknown',
            'file_size_mb': round(self.cves_file.stat().st_size / (1024 * 1024), 1)
                            if disponible else None
        }
