#!/usr/bin/env python3
"""
Módulo de análisis avanzado de recursos web
Extrae información de JavaScripts, CSS, recursos externos, cookies y tracking

Autor: David Casas M. - Competencia Digital
Licencia: CC BY-NC 4.0
"""

import re
import json
from urllib.parse import urlparse, urljoin
from collections import defaultdict
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime

from http_utils import is_httponly, get_samesite

class WebAnalyzerAdvanced:
    """Analizador avanzado de recursos web"""
    
    def __init__(self, url: str, html: str, headers: Dict, cookies: List):
        self.url = url
        self.html = html
        # Normalizar a minúsculas: las cabeceras reales llegan como 'Server', 'Content-Type', etc.
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.cookies = cookies
        self.domain = urlparse(url).netloc
        
        # Resultados
        self.results = {
            'scripts': [],
            'styles': [],
            'frameworks': [],
            'external_domains': set(),
            'tracking': [],
            'cookies_detail': [],
            'metadata': {},
            'security_headers': {},
            'resources_count': {}
        }
    
    def analyze_all(self) -> Dict:
        """Ejecuta todos los análisis"""
        self._analyze_scripts()
        self._analyze_styles()
        self._analyze_frameworks()
        self._analyze_tracking()
        self._analyze_cookies_detail()
        self._analyze_metadata()
        self._analyze_security_headers()
        self._analyze_resources_count()
        
        # Convertir set a lista para JSON
        self.results['external_domains'] = list(self.results['external_domains'])
        
        return self.results
    
    def _analyze_scripts(self):
        """Analiza scripts JavaScript"""
        scripts = []
        
        # Buscar scripts en HTML
        pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(pattern, self.html, re.IGNORECASE)
        
        for src in matches:
            script_info = {
                'src': src,
                'type': 'external',
                'domain': urlparse(src).netloc if src.startswith(('http://', 'https://')) else 'local'
            }
            
            # Verificar si es de un CDN conocido
            cdn = self._detect_cdn(src)
            if cdn:
                script_info['cdn'] = cdn
            
            # Verificar si es de terceros
            if script_info['domain'] and script_info['domain'] != self.domain:
                script_info['third_party'] = True
                self.results['external_domains'].add(script_info['domain'])
            else:
                script_info['third_party'] = False
            
            scripts.append(script_info)
        
        # Buscar scripts inline (sin src)
        inline_pattern = r'<script[^>]*>(.*?)</script>'
        inline_matches = re.findall(inline_pattern, self.html, re.IGNORECASE | re.DOTALL)
        for match in inline_matches[:5]:  # Limitar a 5 para no saturar
            scripts.append({
                'type': 'inline',
                'length': len(match),
                'preview': match[:100] + ('...' if len(match) > 100 else '')
            })
        
        self.results['scripts'] = scripts
    
    def _analyze_styles(self):
        """Analiza hojas de estilo CSS"""
        styles = []
        
        # Buscar CSS externos
        pattern = r'<link[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(pattern, self.html, re.IGNORECASE)
        
        for href in matches:
            style_info = {
                'href': href,
                'domain': urlparse(href).netloc if href.startswith(('http://', 'https://')) else 'local'
            }
            
            if style_info['domain'] and style_info['domain'] != self.domain:
                style_info['third_party'] = True
                self.results['external_domains'].add(style_info['domain'])
            else:
                style_info['third_party'] = False
            
            styles.append(style_info)
        
        # Buscar CSS inline
        inline_pattern = r'<style[^>]*>(.*?)</style>'
        inline_matches = re.findall(inline_pattern, self.html, re.IGNORECASE | re.DOTALL)
        for match in inline_matches[:3]:
            styles.append({
                'type': 'inline',
                'length': len(match),
                'preview': match[:100] + ('...' if len(match) > 100 else '')
            })
        
        self.results['styles'] = styles
    
    def _analyze_frameworks(self):
        """Detecta frameworks y librerías - CORREGIDO"""
        frameworks = []
        
        # Lista de frameworks/librerías a detectar - PATRONES CORREGIDOS
        framework_patterns = [
            ('jQuery', r'jquery[.-]?([0-9.]+)\.min\.js'),
            ('jQuery', r'jQuery'),
            ('Bootstrap', r'bootstrap[.-]?([0-9.]+)\.min\.(css|js)'),
            ('Bootstrap', r'bootstrap'),
            ('React', r'react[.-]?([0-9.]+)\.js'),
            ('React', r'React'),
            ('Vue.js', r'vue[.-]?([0-9.]+)\.js'),
            ('Vue.js', r'Vue'),
            ('Angular', r'angular[.-]?([0-9.]+)\.js'),
            ('Angular', r'angular'),
            ('Django', r'django'),
            ('Django', r'csrfmiddlewaretoken'),
            ('WordPress', r'wp-content'),
            ('WordPress', r'wp-includes'),
            ('Odoo', r'odoo'),
            ('Font Awesome', r'font-awesome'),
            ('Font Awesome', r'fontawesome'),
            ('Google Analytics', r'google-analytics'),
            ('Google Analytics', r'ga\.js'),
            ('Facebook Pixel', r'fbq\('),
            ('Facebook Pixel', r'facebook'),
            ('Stripe', r'stripe\.js'),
            ('Leaflet', r'leaflet\.js'),
            ('Chart.js', r'chart\.js'),
            ('D3.js', r'd3\.js'),
        ]
        
        detected = set()
        
        for name, pattern in framework_patterns:
            try:
                if re.search(pattern, self.html, re.IGNORECASE):
                    if name not in detected:
                        frameworks.append({'name': name, 'detected_by': pattern})
                        detected.add(name)
            except re.error:
                # Si hay error en la regex, pasar al siguiente patrón
                continue
        
        self.results['frameworks'] = frameworks
    
    def _analyze_tracking(self):
        """Detecta herramientas de tracking y análisis"""
        tracking = []
        
        tracking_services = [
            ('Google Analytics', r'google-analytics\.com/ga\.js|gtag\(|ga\('),
            ('Google Tag Manager', r'googletagmanager\.com/gtm\.js'),
            ('Facebook Pixel', r'fbq\(|connect\.facebook\.net'),
            ('Twitter Pixel', r'twq\('),
            ('LinkedIn Insight', r'linkedin\.com/insight'),
            ('Hotjar', r'hotjar\.com|hj\.'),
            ('Mixpanel', r'mixpanel\.com'),
            ('Amplitude', r'amplitude\.com'),
            ('Segment', r'segment\.com'),
            ('Heap', r'heapanalytics\.com'),
            ('Crazy Egg', r'crazyegg\.com'),
            ('FullStory', r'fullstory\.com'),
            ('Pendo', r'pendo\.io'),
            ('Intercom', r'intercom\.io'),
            ('Drift', r'drift\.com'),
            ('HubSpot', r'hs-scripts\.com'),
            ('Salesforce', r'salesforce\.com'),
        ]
        
        for name, pattern in tracking_services:
            try:
                if re.search(pattern, self.html, re.IGNORECASE):
                    tracking.append({'name': name, 'type': 'tracking'})
            except re.error:
                continue
        
        self.results['tracking'] = tracking
    
    def _analyze_cookies_detail(self):
        """Analiza cookies en detalle"""
        cookies_detail = []
        
        if self.cookies:
            for cookie in self.cookies:
                cookie_info = {
                    'name': cookie.name,
                    'value': cookie.value[:30] + ('...' if len(cookie.value) > 30 else ''),
                    'domain': cookie.domain or self.domain,
                    'path': cookie.path or '/',
                    'secure': cookie.secure,
                    'httponly': is_httponly(cookie),
                    'samesite': get_samesite(cookie),
                    'expires': cookie.expires if hasattr(cookie, 'expires') else None,
                    'type': self._classify_cookie(cookie)
                }
                
                # Verificar si es cookie de terceros
                if cookie.domain and cookie.domain != self.domain:
                    cookie_info['third_party'] = True
                
                cookies_detail.append(cookie_info)
        
        self.results['cookies_detail'] = cookies_detail
    
    def _classify_cookie(self, cookie) -> str:
        """Clasifica el tipo de cookie"""
        name = cookie.name.lower()
        
        if 'session' in name or 'sid' in name or 'auth' in name:
            return 'sesion'
        if 'lang' in name or 'locale' in name:
            return 'idioma'
        if '_ga' in name or 'analytics' in name or 'track' in name:
            return 'analytics'
        if '_fbp' in name or 'facebook' in name:
            return 'social_media'
        if 'cart' in name or 'basket' in name:
            return 'carrito'
        if 'csrf' in name or 'token' in name:
            return 'seguridad'
        if 'consent' in name or 'cookie' in name:
            return 'consentimiento'
        if 'pref' in name or 'theme' in name:
            return 'preferencias'
        
        return 'otros'
    
    def _analyze_metadata(self):
        """Analiza metadatos de la página"""
        metadata = {}
        
        # Título
        title_match = re.search(r'<title>(.*?)</title>', self.html, re.IGNORECASE)
        if title_match:
            metadata['title'] = title_match.group(1)
        
        # Meta description
        desc_match = re.search(r'<meta\s+name=["\']description["\']\s+content=["\']([^"\']*)["\']', 
                              self.html, re.IGNORECASE)
        if desc_match:
            metadata['description'] = desc_match.group(1)
        
        # Meta keywords
        keywords_match = re.search(r'<meta\s+name=["\']keywords["\']\s+content=["\']([^"\']*)["\']', 
                                  self.html, re.IGNORECASE)
        if keywords_match:
            metadata['keywords'] = keywords_match.group(1)
        
        # Open Graph
        og = {}
        og_pattern = r'<meta\s+property=["\']og:([^"\']+)["\']\s+content=["\']([^"\']+)["\']'
        for match in re.findall(og_pattern, self.html, re.IGNORECASE):
            og[match[0]] = match[1]
        if og:
            metadata['open_graph'] = og
        
        # Twitter Cards
        twitter = {}
        twitter_pattern = r'<meta\s+name=["\']twitter:([^"\']+)["\']\s+content=["\']([^"\']+)["\']'
        for match in re.findall(twitter_pattern, self.html, re.IGNORECASE):
            twitter[match[0]] = match[1]
        if twitter:
            metadata['twitter_cards'] = twitter
        
        # Charset
        charset_match = re.search(r'<meta\s+charset=["\']([^"\']+)["\']', self.html, re.IGNORECASE)
        if charset_match:
            metadata['charset'] = charset_match.group(1)
        
        # Viewport
        viewport_match = re.search(r'<meta\s+name=["\']viewport["\']\s+content=["\']([^"\']*)["\']', 
                                  self.html, re.IGNORECASE)
        if viewport_match:
            metadata['viewport'] = viewport_match.group(1)
        
        # Robots
        robots_match = re.search(r'<meta\s+name=["\']robots["\']\s+content=["\']([^"\']*)["\']', 
                                self.html, re.IGNORECASE)
        if robots_match:
            metadata['robots'] = robots_match.group(1)
        
        # Generator
        generator_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']*)["\']', 
                                   self.html, re.IGNORECASE)
        if generator_match:
            metadata['generator'] = generator_match.group(1)
        
        self.results['metadata'] = metadata
    
    def _analyze_security_headers(self):
        """Analiza cabeceras de seguridad adicionales"""
        security = {}
        
        # Cabeceras de seguridad comunes
        headers_map = {
            'content-security-policy': 'CSP',
            'strict-transport-security': 'HSTS',
            'x-frame-options': 'XFO',
            'x-content-type-options': 'XCTO',
            'x-xss-protection': 'XSS',
            'referrer-policy': 'Referrer',
            'permissions-policy': 'Permissions',
            'cross-origin-opener-policy': 'COOP',
            'cross-origin-embedder-policy': 'COEP',
            'cross-origin-resource-policy': 'CORP',
            'x-permitted-cross-domain-policies': 'XPCDP',
            'x-download-options': 'XDO'
        }
        
        for header, name in headers_map.items():
            value = self.headers.get(header)
            if value:
                security[name] = value
            elif header in self.headers:
                security[name] = self.headers[header]
        
        self.results['security_headers'] = security
    
    def _analyze_resources_count(self):
        """Cuenta recursos de la página"""
        resources = {}
        
        # Imágenes
        images = len(re.findall(r'<img[^>]*src=["\']([^"\']+)["\']', self.html, re.IGNORECASE))
        resources['images'] = images
        
        # Enlaces (links)
        links = len(re.findall(r'<a[^>]*href=["\']([^"\']+)["\']', self.html, re.IGNORECASE))
        resources['links'] = links
        
        # Iframes
        iframes = len(re.findall(r'<iframe[^>]*src=["\']([^"\']+)["\']', self.html, re.IGNORECASE))
        resources['iframes'] = iframes
        
        # Videos
        videos = len(re.findall(r'<video[^>]*src=["\']([^"\']+)["\']', self.html, re.IGNORECASE))
        resources['videos'] = videos
        
        # Audios
        audios = len(re.findall(r'<audio[^>]*src=["\']([^"\']+)["\']', self.html, re.IGNORECASE))
        resources['audios'] = audios
        
        # Canvas
        canvas = len(re.findall(r'<canvas', self.html, re.IGNORECASE))
        resources['canvas'] = canvas
        
        # SVG
        svg = len(re.findall(r'<svg', self.html, re.IGNORECASE))
        resources['svg'] = svg
        
        # Formularios
        forms = len(re.findall(r'<form', self.html, re.IGNORECASE))
        resources['forms'] = forms
        
        self.results['resources_count'] = resources
    
    def _detect_cdn(self, url: str) -> Optional[str]:
        """Detecta si el recurso viene de un CDN conocido"""
        cdn_patterns = {
            'cdnjs.cloudflare.com': 'Cloudflare CDN',
            'cdn.jsdelivr.net': 'jsDelivr CDN',
            'unpkg.com': 'UNPKG CDN',
            'ajax.googleapis.com': 'Google CDN',
            'ajax.aspnetcdn.com': 'Microsoft CDN',
            'cdnjs.com': 'cdnjs CDN',
            'cdn.staticfile.org': 'Staticfile CDN',
            'cdn.socket.io': 'Socket.io CDN',
            'cdn.polyfill.io': 'Polyfill.io CDN',
            'cdn.embedly.com': 'Embedly CDN',
            'cdn.webfonts.com': 'Webfonts CDN'
        }
        
        for domain, name in cdn_patterns.items():
            if domain in url:
                return name
        return None
