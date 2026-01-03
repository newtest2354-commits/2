import os
import re
import json
import base64
import hashlib
import socket
import pickle
import threading
import concurrent.futures
import requests
import zipfile
import tarfile
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import time
import logging
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.warning("geoip2 not installed. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "geoip2"])
    import geoip2.database
    GEOIP2_AVAILABLE = True

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "dnspython"])
    import dns.resolver
    DNS_AVAILABLE = True

class GeoIPManager:
    def __init__(self):
        self.geolite_dir = "geolite_data"
        self.country_db = os.path.join(self.geolite_dir, "GeoLite2-Country.mmdb")
        self.asn_db = os.path.join(self.geolite_dir, "GeoLite2-ASN.mmdb")
        self.country_reader = None
        self.asn_reader = None
        self.lock = threading.Lock()
        self.cdn_asns = {
            13335: "CLOUDFLARE",
            20940: "AKAMAI",
            54113: "FASTLY",
            15169: "GOOGLE",
            16509: "AMAZON",
            8075: "MICROSOFT",
            398324: "GITHUB",
            46489: "LIMELIGHT",
            54600: "EDGECAST",
            60626: "STACKPATH"
        }
        self.datacenter_asns = {
            24940: "HETZNER",
            16276: "OVH",
            51167: "CONTABO",
            14061: "DIGITALOCEAN",
            23352: "SERVERIUS",
            60781: "LEASEWEB",
            35470: "CHOOPA",
            20473: "AS-CHOOPA",
            1508: "COLOGNE",
            32934: "FACEBOOK",
            393406: "SCALEWAY",
            21409: "PONYNET",
            40065: "GCP",
            14618: "AMAZON-AWS",
            15133: "EDGIO",
            30081: "MIVOS",
            9009: "M247",
            397233: "VULTR",
            23470: "RELIABLESITE",
            46844: "SHARKTECH"
        }
        
        self.setup_databases()
    
    def setup_databases(self):
        os.makedirs(self.geolite_dir, exist_ok=True)
        
        if not os.path.exists(self.country_db):
            logger.info("Downloading GeoLite2 Country database...")
            try:
                country_url = "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@release/GeoLite2-Country.mmdb"
                response = requests.get(country_url, stream=True, timeout=30)
                if response.status_code == 200:
                    with open(self.country_db, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    logger.info("GeoLite2 Country database downloaded successfully")
                else:
                    logger.error(f"Failed to download Country database. Status: {response.status_code}")
            except Exception as e:
                logger.error(f"Error downloading Country database: {e}")
        
        if not os.path.exists(self.asn_db):
            logger.info("Downloading GeoLite2 ASN database...")
            try:
                asn_url = "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@release/GeoLite2-ASN.mmdb"
                response = requests.get(asn_url, stream=True, timeout=30)
                if response.status_code == 200:
                    with open(self.asn_db, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    logger.info("GeoLite2 ASN database downloaded successfully")
                else:
                    logger.error(f"Failed to download ASN database. Status: {response.status_code}")
            except Exception as e:
                logger.error(f"Error downloading ASN database: {e}")
        
        if os.path.exists(self.country_db):
            try:
                self.country_reader = geoip2.database.Reader(self.country_db)
                logger.info("GeoLite2 Country database loaded successfully")
            except Exception as e:
                logger.error(f"Error loading Country database: {e}")
                self.country_reader = None
        
        if os.path.exists(self.asn_db):
            try:
                self.asn_reader = geoip2.database.Reader(self.asn_db)
                logger.info("GeoLite2 ASN database loaded successfully")
            except Exception as e:
                logger.error(f"Error loading ASN database: {e}")
                self.asn_reader = None
    
    def get_country_geolite(self, ip):
        if not self.country_reader:
            return None
        
        try:
            with self.lock:
                response = self.country_reader.country(ip)
                return response.country.iso_code
        except Exception as e:
            logger.debug(f"GeoLite2 country lookup failed for {ip}: {e}")
            return None
    
    def get_asn_info(self, ip):
        if not self.asn_reader:
            return None
        
        try:
            with self.lock:
                response = self.asn_reader.asn(ip)
                return {
                    'asn': response.autonomous_system_number,
                    'org': response.autonomous_system_organization or '',
                    'prefix_len': response.network.prefixlen if hasattr(response.network, 'prefixlen') else 24
                }
        except Exception as e:
            logger.debug(f"ASN lookup failed for {ip}: {e}")
            return None
    
    def is_anycast(self, asn_info):
        if not asn_info:
            return False
        
        prefix_len = asn_info.get('prefix_len', 24)
        org_lower = asn_info.get('org', '').lower()
        
        if prefix_len <= 20:
            return True
        
        anycast_keywords = ['anycast', 'global', 'edge network', 'cdn', 'cloudfront']
        if any(keyword in org_lower for keyword in anycast_keywords):
            return True
        
        return False
    
    def is_cdn_asn(self, asn_info):
        if not asn_info:
            return False
        
        asn_number = asn_info.get('asn')
        org_lower = asn_info.get('org', '').lower()
        
        if asn_number in self.cdn_asns:
            return True
        
        cdn_keywords = ['cloudflare', 'akamai', 'fastly', 'google edge', 'amazon cloudfront', 
                       'aws edge', 'azure edge', 'cdn', 'cloudfront', 'edgecast', 'stackpath',
                       'limelight', 'imperva', 'incapsula']
        
        if any(keyword in org_lower for keyword in cdn_keywords):
            return True
        
        return False
    
    def is_datacenter_asn(self, asn_info):
        if not asn_info:
            return False
        
        asn_number = asn_info.get('asn')
        org_lower = asn_info.get('org', '').lower()
        
        if asn_number in self.datacenter_asns:
            return True
        
        dc_keywords = ['hetzner', 'ovh', 'contabo', 'digitalocean', 'serverius', 'leaseweb',
                      'choopa', 'vultr', 'linode', 'upcloud', 'scaleway', 'alibaba', 'tencent',
                      'huawei cloud', 'oracle cloud', 'ibm cloud', 'godaddy', 'hostinger',
                      'namecheap', 'bluehost', 'siteground', 'a2 hosting', 'dreamhost']
        
        if any(keyword in org_lower for keyword in dc_keywords):
            return True
        
        return False
    
    def classify_ip_type(self, ip):
        asn_info = self.get_asn_info(ip)
        if not asn_info:
            return "UNKNOWN"
        
        if self.is_anycast(asn_info):
            return "CDN"
        
        if self.is_cdn_asn(asn_info):
            return "CDN"
        
        if self.is_datacenter_asn(asn_info):
            return "FIXED_IP"
        
        org_lower = asn_info.get('org', '').lower()
        residential_keywords = ['isp', 'telecom', 'communication', 'broadband', 'cable', 
                              'fiber', 'dsl', 'adsl', 'residential', 'home', 'consumer']
        
        if any(keyword in org_lower for keyword in residential_keywords):
            return "RESIDENTIAL"
        
        return "UNKNOWN"
    
    def close(self):
        if self.country_reader:
            self.country_reader.close()
        if self.asn_reader:
            self.asn_reader.close()

class DNSResolver:
    def __init__(self):
        self.cache = {}
        self.cache_file = 'dns_cache.pkl'
        self.lock = threading.Lock()
        self.dns_servers = [
            '8.8.8.8',
            '8.8.4.4',
            '1.1.1.1',
            '1.0.0.1',
            '9.9.9.9',
            '149.112.112.112',
            '208.67.222.222',
            '208.67.220.220'
        ]
        
        self.load_cache()
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    self.cache = pickle.load(f)
        except:
            self.cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.cache, f)
        except:
            pass
    
    def resolve_domain(self, domain):
        if not domain:
            return []
        
        domain = domain.lower().strip()
        
        with self.lock:
            if domain in self.cache:
                cached_result = self.cache[domain]
                if time.time() - cached_result['timestamp'] < 3600:
                    return cached_result['ips']
        
        ips = []
        
        for dns_server in self.dns_servers[:3]:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 3
                resolver.lifetime = 3
                
                try:
                    answers = resolver.resolve(domain, 'A')
                    for answer in answers:
                        ip = str(answer)
                        if self.is_valid_ip(ip):
                            ips.append(ip)
                except:
                    pass
                
                try:
                    answers = resolver.resolve(domain, 'AAAA')
                    for answer in answers:
                        ip = str(answer)
                        if self.is_valid_ipv6(ip):
                            ips.append(ip)
                except:
                    pass
                
                if ips:
                    break
            except Exception as e:
                logger.debug(f"DNS resolution failed for {domain} using {dns_server}: {e}")
                continue
        
        if not ips:
            try:
                ips_from_socket = socket.getaddrinfo(domain, None)
                for result in ips_from_socket:
                    ip = result[4][0]
                    if self.is_valid_ip(ip) or self.is_valid_ipv6(ip):
                        ips.append(ip)
            except:
                pass
        
        unique_ips = list(set(ips))
        
        with self.lock:
            self.cache[domain] = {
                'ips': unique_ips,
                'timestamp': time.time()
            }
        
        return unique_ips
    
    def is_valid_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def is_valid_ipv6(self, ip):
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False
    
    def get_clean_cache(self):
        current_time = time.time()
        clean_cache = {}
        for domain, data in self.cache.items():
            if current_time - data['timestamp'] < 86400:
                clean_cache[domain] = data
        return clean_cache

class GeoIPClassifier:
    def __init__(self):
        self.geoip_manager = GeoIPManager()
        self.dns_resolver = DNSResolver()
        self.ipapi_cache = {}
        self.cache_file = 'geoip_cache.pkl'
        self.lock = threading.Lock()
        self.ipapi_requests = 0
        self.last_ipapi_request = 0
        
        self.load_cache()
        self.stats = {
            'geolite_success': 0,
            'ipapi_success': 0,
            'failed': 0,
            'cdn_detected': 0,
            'fixed_ip': 0,
            'residential': 0
        }
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    self.ipapi_cache = pickle.load(f)
        except:
            self.ipapi_cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.ipapi_cache, f)
        except:
            pass
    
    def get_country_by_ipapi(self, ip):
        current_time = time.time()
        
        if current_time - self.last_ipapi_request < 1:
            time.sleep(1.1 - (current_time - self.last_ipapi_request))
        
        try:
            with self.lock:
                if ip in self.ipapi_cache:
                    cached_data = self.ipapi_cache[ip]
                    if current_time - cached_data['timestamp'] < 86400:
                        return cached_data['country']
            
            if self.ipapi_requests >= 140:
                time.sleep(65)
                self.ipapi_requests = 0
            
            self.ipapi_requests += 1
            self.last_ipapi_request = time.time()
            
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,countryCode,isp,as,asname,org,mobile,proxy,hosting", 
                                  timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('countryCode', 'UNKNOWN')
                    
                    with self.lock:
                        self.ipapi_cache[ip] = {
                            'country': country,
                            'timestamp': time.time(),
                            'isp': data.get('isp', ''),
                            'as': data.get('as', ''),
                            'hosting': data.get('hosting', False),
                            'mobile': data.get('mobile', False),
                            'proxy': data.get('proxy', False)
                        }
                    
                    return country
        except Exception as e:
            logger.debug(f"IP-API failed for {ip}: {e}")
        
        return "UNKNOWN"
    
    def get_country_for_ip(self, ip):
        ip_type = self.geoip_manager.classify_ip_type(ip)
        
        if ip_type == "CDN":
            self.stats['cdn_detected'] += 1
            return 'CDN'
        elif ip_type == "FIXED_IP":
            self.stats['fixed_ip'] += 1
        elif ip_type == "RESIDENTIAL":
            self.stats['residential'] += 1
        
        country = self.geoip_manager.get_country_geolite(ip)
        if country:
            self.stats['geolite_success'] += 1
            return country
        
        if ip_type == "FIXED_IP":
            country = self.get_country_by_ipapi(ip)
            if country != 'UNKNOWN':
                self.stats['ipapi_success'] += 1
            else:
                self.stats['failed'] += 1
            return country
        
        return "UNKNOWN"
    
    def get_country_for_domain(self, domain):
        ips = self.dns_resolver.resolve_domain(domain)
        if not ips:
            return 'UNRESOLVED'
        
        for ip in ips:
            ip_type = self.geoip_manager.classify_ip_type(ip)
            if ip_type == "FIXED_IP":
                country = self.get_country_for_ip(ip)
                if country and country not in ['UNKNOWN', 'CDN']:
                    return country
        
        if ips:
            first_ip = ips[0]
            ip_type = self.geoip_manager.classify_ip_type(first_ip)
            if ip_type == "CDN":
                return 'CDN'
        
        return 'UNKNOWN'
    
    def get_stats(self):
        return self.stats
    
    def cleanup(self):
        self.dns_resolver.save_cache()
        self.save_cache()
        self.geoip_manager.close()
        
        with self.lock:
            current_time = time.time()
            clean_cache = {}
            for ip, data in self.ipapi_cache.items():
                if current_time - data['timestamp'] < 86400:
                    clean_cache[ip] = data
            self.ipapi_cache = clean_cache

class ConfigParser:
    def __init__(self):
        self.lock = threading.Lock()
    
    def extract_domain_from_url(self, url):
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                netloc = parsed.netloc
                if '@' in netloc:
                    netloc = netloc.split('@')[-1]
                if ':' in netloc:
                    netloc = netloc.split(':')[0]
                return netloc
        except:
            pass
        return ''
    
    def parse_vmess(self, config_str):
        try:
            base64_part = config_str[8:]
            if len(base64_part) % 4 != 0:
                base64_part += '=' * (4 - len(base64_part) % 4)
            config_data = json.loads(base64.b64decode(base64_part).decode('utf-8'))
            
            address = config_data.get('add', '')
            host = config_data.get('host', '')
            sni = config_data.get('sni', '')
            
            target_host = address
            detection_host = address
            
            if sni and self.is_domain(sni):
                detection_host = sni
            elif host and self.is_domain(host):
                detection_host = host
            
            return {
                'protocol': 'vmess',
                'host': address,
                'port': int(config_data.get('port', 0)),
                'target_host': target_host,
                'detection_host': detection_host,
                'raw': config_str,
                'sni': sni,
                'ps': config_data.get('ps', '')
            }
        except:
            return None
    
    def parse_vless(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            host, port_str = host_port.split(':')
            port = int(port_str.split('?')[0]) if '?' in port_str else int(port_str)
            
            query_params = parse_qs(parsed.query)
            sni = ''
            host_param = ''
            
            if 'sni' in query_params:
                sni = query_params['sni'][0]
            if 'host' in query_params:
                host_param = query_params['host'][0]
            
            target_host = host
            detection_host = host
            
            if sni and self.is_domain(sni):
                detection_host = sni
            elif host_param and self.is_domain(host_param):
                detection_host = host_param
            
            return {
                'protocol': 'vless',
                'host': host,
                'port': port,
                'target_host': target_host,
                'detection_host': detection_host,
                'raw': config_str,
                'sni': sni,
                'host_param': host_param
            }
        except:
            return None
    
    def parse_trojan(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            host, port_str = host_port.split(':')
            port = int(port_str.split('#')[0]) if '#' in port_str else int(port_str)
            
            query_params = parse_qs(parsed.query)
            sni = ''
            
            if 'sni' in query_params:
                sni = query_params['sni'][0]
            
            target_host = host
            detection_host = host
            
            if sni and self.is_domain(sni):
                detection_host = sni
            
            return {
                'protocol': 'trojan',
                'host': host,
                'port': port,
                'target_host': target_host,
                'detection_host': detection_host,
                'raw': config_str,
                'sni': sni
            }
        except:
            return None
    
    def parse_ss(self, config_str):
        try:
            parts = config_str.split('#', 1)
            base_part = parts[0][5:]
            
            if '@' not in base_part:
                if len(base_part) % 4 != 0:
                    base_part += '=' * (4 - len(base_part) % 4)
                decoded = base64.b64decode(base_part).decode('utf-8')
                if '@' in decoded:
                    method_pass, server_part = decoded.split('@', 1)
                else:
                    return None
            else:
                encoded_method_pass, server_part = base_part.split('@', 1)
                
            server, port_str = server_part.split(':', 1)
            port = int(port_str)
            
            return {
                'protocol': 'ss',
                'host': server,
                'port': port,
                'target_host': server,
                'detection_host': server,
                'raw': config_str
            }
        except:
            return None
    
    def parse_hysteria(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            host, port_str = host_port.split(':')
            port = int(port_str)
            
            query_params = parse_qs(parsed.query)
            sni = ''
            
            if 'sni' in query_params:
                sni = query_params['sni'][0]
            
            target_host = host
            detection_host = host
            
            if sni and self.is_domain(sni):
                detection_host = sni
            
            return {
                'protocol': 'hysteria',
                'host': host,
                'port': port,
                'target_host': host,
                'detection_host': detection_host,
                'raw': config_str
            }
        except:
            return None
    
    def parse_tuic(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            host, port_str = host_port.split(':')
            port = int(port_str)
            
            return {
                'protocol': 'tuic',
                'host': host,
                'port': port,
                'target_host': host,
                'detection_host': host,
                'raw': config_str
            }
        except:
            return None
    
    def parse_wireguard(self, config_str):
        try:
            parsed = urlparse(config_str)
            params = parsed.query
            host = ''
            
            for param in params.split('&'):
                if param.startswith('endpoint='):
                    endpoint = param[9:]
                    if ':' in endpoint:
                        host = endpoint.split(':')[0]
                    break
            
            return {
                'protocol': 'wireguard',
                'host': host,
                'port': 51820,
                'target_host': host,
                'detection_host': host,
                'raw': config_str
            }
        except:
            return None
    
    def is_ip_address(self, host):
        if not host:
            return False
        
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, host):
            parts = host.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True
        
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return True
        except socket.error:
            pass
        
        return False
    
    def is_domain(self, host):
        if not host:
            return False
        
        if self.is_ip_address(host):
            return False
        
        if '.' in host and len(host) > 3:
            return True
        
        return False
    
    def parse_config(self, config_str):
        config_str = config_str.strip()
        
        if config_str.startswith('vmess://'):
            return self.parse_vmess(config_str)
        elif config_str.startswith('vless://'):
            return self.parse_vless(config_str)
        elif config_str.startswith('trojan://'):
            return self.parse_trojan(config_str)
        elif config_str.startswith('ss://'):
            return self.parse_ss(config_str)
        elif config_str.startswith('hysteria://') or config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
            return self.parse_hysteria(config_str)
        elif config_str.startswith('tuic://'):
            return self.parse_tuic(config_str)
        elif config_str.startswith('wireguard://'):
            return self.parse_wireguard(config_str)
        
        return None

class CountryClassifier:
    def __init__(self, max_workers=20):
        self.parser = ConfigParser()
        self.geoip = GeoIPClassifier()
        self.max_workers = max_workers
        self.results_lock = threading.Lock()
        self.results = {}
        self.stats = {
            'total': 0,
            'processed': 0,
            'failed': 0,
            'ip_based': 0,
            'domain_based': 0,
            'cdn_detected': 0,
            'fixed_ip': 0,
            'residential': 0,
            'unresolved': 0,
            'by_country': {},
            'by_protocol': {},
            'detection_method': {
                'geolite': 0,
                'ipapi': 0,
                'cdn': 0
            }
        }
    
    def process_single_config(self, config_str):
        try:
            parsed = self.parser.parse_config(config_str)
            if not parsed:
                return None
            
            detection_host = parsed.get('detection_host', '')
            if not detection_host:
                return None
            
            is_ip = self.parser.is_ip_address(detection_host)
            country = 'UNKNOWN'
            detection_method = 'unknown'
            ip_type = 'UNKNOWN'
            
            if is_ip:
                country = self.geoip.get_country_for_ip(detection_host)
                geoip_stats = self.geoip.get_stats()
                
                if country == 'CDN':
                    detection_method = 'cdn'
                    ip_type = 'CDN'
                elif geoip_stats['fixed_ip'] > self.stats['fixed_ip']:
                    detection_method = 'geolite'
                    ip_type = 'FIXED_IP'
                elif geoip_stats['residential'] > self.stats['residential']:
                    detection_method = 'ipapi'
                    ip_type = 'RESIDENTIAL'
            else:
                country = self.geoip.get_country_for_domain(detection_host)
                if country == 'UNRESOLVED':
                    ip_type = 'UNRESOLVED'
                elif country == 'CDN':
                    ip_type = 'CDN'
                    detection_method = 'cdn'
                else:
                    ip_type = 'DOMAIN_RESOLVED'
            
            return {
                'config': config_str,
                'parsed': parsed,
                'ip': detection_host if is_ip else None,
                'domain': detection_host if not is_ip else None,
                'country': country,
                'is_ip': is_ip,
                'detection_method': detection_method,
                'ip_type': ip_type
            }
        except Exception as e:
            logger.debug(f"Failed to process config: {e}")
            return None
    
    def process_configs(self, configs):
        logger.info(f"Processing {len(configs)} configurations...")
        
        self.results = {}
        self.stats = {
            'total': len(configs),
            'processed': 0,
            'failed': 0,
            'ip_based': 0,
            'domain_based': 0,
            'cdn_detected': 0,
            'fixed_ip': 0,
            'residential': 0,
            'unresolved': 0,
            'by_country': {},
            'by_protocol': {},
            'detection_method': {
                'geolite': 0,
                'ipapi': 0,
                'cdn': 0
            }
        }
        
        unique_configs = []
        seen = set()
        
        for config in configs:
            config_hash = hashlib.md5(config.encode()).hexdigest()
            if config_hash not in seen:
                seen.add(config_hash)
                unique_configs.append(config)
        
        logger.info(f"After deduplication: {len(unique_configs)} unique configs")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_config = {executor.submit(self.process_single_config, config): config for config in unique_configs}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_config):
                completed += 1
                if completed % 100 == 0:
                    logger.info(f"Processed {completed}/{len(unique_configs)} configs")
                
                result = future.result()
                if result:
                    with self.results_lock:
                        self.stats['processed'] += 1
                        
                        if result['is_ip']:
                            self.stats['ip_based'] += 1
                        else:
                            self.stats['domain_based'] += 1
                        
                        country = result['country']
                        protocol = result['parsed']['protocol']
                        method = result['detection_method']
                        ip_type = result['ip_type']
                        
                        if method in self.stats['detection_method']:
                            self.stats['detection_method'][method] += 1
                        
                        if ip_type == 'CDN':
                            self.stats['cdn_detected'] += 1
                        elif ip_type == 'FIXED_IP':
                            self.stats['fixed_ip'] += 1
                        elif ip_type == 'RESIDENTIAL':
                            self.stats['residential'] += 1
                        elif ip_type == 'UNRESOLVED':
                            self.stats['unresolved'] += 1
                        
                        if country not in self.results:
                            self.results[country] = {}
                        
                        if protocol not in self.results[country]:
                            self.results[country][protocol] = []
                        
                        self.results[country][protocol].append(result['config'])
                        
                        self.stats['by_country'][country] = self.stats['by_country'].get(country, 0) + 1
                        self.stats['by_protocol'][protocol] = self.stats['by_protocol'].get(protocol, 0) + 1
                else:
                    self.stats['failed'] += 1
        
        geoip_stats = self.geoip.get_stats()
        self.stats['detection_method']['geolite'] = geoip_stats['geolite_success']
        self.stats['detection_method']['ipapi'] = geoip_stats['ipapi_success']
        self.stats['fixed_ip'] = geoip_stats['fixed_ip']
        self.stats['residential'] = geoip_stats['residential']
        
        self.geoip.cleanup()
        
        return {
            'results': self.results,
            'stats': self.stats
        }
    
    def save_results(self, results, output_dir='configs/country'):
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        valid_countries = [c for c in results['results'].keys() if c not in ['UNKNOWN', 'UNRESOLVED', 'CDN']]
        
        for country in valid_countries:
            protocols = results['results'][country]
            
            country_dir = os.path.join(output_dir, country)
            os.makedirs(country_dir, exist_ok=True)
            
            all_country_configs = []
            
            for protocol, configs in protocols.items():
                if configs:
                    protocol_file = os.path.join(country_dir, f"{protocol}.txt")
                    content = f"# {country} - {protocol.upper()} Configurations\n"
                    content += f"# Updated: {timestamp}\n"
                    content += f"# Count: {len(configs)}\n"
                    content += f"# Country Code: {country}\n\n"
                    content += "\n".join(configs)
                    
                    with open(protocol_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    all_country_configs.extend(configs)
            
            if all_country_configs:
                all_file = os.path.join(country_dir, "all.txt")
                content = f"# All Configurations for {country}\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(all_country_configs)}\n"
                content += f"# Country Code: {country}\n\n"
                content += "\n".join(all_country_configs)
                
                with open(all_file, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        special_categories = ['UNKNOWN', 'UNRESOLVED', 'CDN']
        for category in special_categories:
            if category in results['results']:
                category_dir = os.path.join(output_dir, category)
                os.makedirs(category_dir, exist_ok=True)
                
                category_configs = []
                for protocol, configs in results['results'][category].items():
                    category_configs.extend(configs)
                
                if category_configs:
                    category_file = os.path.join(category_dir, "all.txt")
                    
                    if category == 'CDN':
                        content = f"# CDN-Based Configurations\n"
                        content += f"# Updated: {timestamp}\n"
                        content += f"# Total Count: {len(category_configs)}\n"
                        content += "# Note: These configs use CDN IP addresses (Cloudflare, Akamai, etc.)\n\n"
                    elif category == 'UNRESOLVED':
                        content = f"# Unresolved Configurations\n"
                        content += f"# Updated: {timestamp}\n"
                        content += f"# Total Count: {len(category_configs)}\n"
                        content += "# Note: These configs have unresolvable domains\n\n"
                    else:
                        content = f"# Unknown Country Configurations\n"
                        content += f"# Updated: {timestamp}\n"
                        content += f"# Total Count: {len(category_configs)}\n"
                        content += "# Note: Country could not be determined\n\n"
                    
                    content += "\n".join(category_configs)
                    
                    with open(category_file, 'w', encoding='utf-8') as f:
                        f.write(content)
        
        summary_file = os.path.join(output_dir, "summary.txt")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"# Country Classification Summary\n")
            f.write(f"# Updated: {timestamp}\n\n")
            f.write(f"Total configs processed: {results['stats']['total']}\n")
            f.write(f"Successfully processed: {results['stats']['processed']}\n")
            f.write(f"Failed to process: {results['stats']['failed']}\n\n")
            
            f.write(f"IP-based configs: {results['stats']['ip_based']}\n")
            f.write(f"Domain-based configs: {results['stats']['domain_based']}\n\n")
            
            f.write(f"IP Type Classification:\n")
            f.write(f"  FIXED_IP (Datacenter): {results['stats']['fixed_ip']}\n")
            f.write(f"  CDN detected: {results['stats']['cdn_detected']}\n")
            f.write(f"  Residential IPs: {results['stats']['residential']}\n")
            f.write(f"  Unresolved domains: {results['stats']['unresolved']}\n\n")
            
            f.write("Detection Methods:\n")
            f.write(f"  GeoLite2: {results['stats']['detection_method']['geolite']}\n")
            f.write(f"  IP-API: {results['stats']['detection_method']['ipapi']}\n")
            f.write(f"  CDN: {results['stats']['detection_method']['cdn']}\n\n")
            
            f.write("Configurations by Country (Top 20):\n")
            ip_countries = {k: v for k, v in results['stats']['by_country'].items() 
                          if k not in ['UNKNOWN', 'UNRESOLVED', 'CDN']}
            for country, count in sorted(ip_countries.items(), key=lambda x: x[1], reverse=True)[:20]:
                f.write(f"  {country}: {count} configs\n")
            
            f.write("\nBy Protocol:\n")
            for protocol, count in sorted(results['stats']['by_protocol'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {protocol}: {count} configs\n")
            
            f.write("\nSpecial Categories:\n")
            for category in ['UNKNOWN', 'UNRESOLVED', 'CDN']:
                if category in results['stats']['by_country']:
                    f.write(f"  {category}: {results['stats']['by_country'][category]} configs\n")
        
        stats_file = os.path.join(output_dir, "stats.json")
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(results['stats'], f, indent=2)
        
        logger.info(f"Results saved to {output_dir}")

def read_all_configs():
    configs = []
    
    combined_file = 'configs/combined/all.txt'
    if os.path.exists(combined_file):
        try:
            with open(combined_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        configs.append(line)
        except:
            pass
    
    if not configs:
        sources = [
            'configs/telegram/all.txt',
            'configs/github/all.txt'
        ]
        
        for filepath in sources:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                configs.append(line)
                except:
                    pass
    
    return configs

def main():
    print("=" * 60)
    print("ENHANCED IP-BASED COUNTRY CONFIG CLASSIFIER")
    print("=" * 60)
    
    try:
        max_workers = int(os.environ.get('MAX_WORKERS', 20))
        logger.info(f"Using max workers: {max_workers}")
        
        configs = read_all_configs()
        if not configs:
            logger.error("No configurations found to process")
            return
        
        logger.info(f"Found {len(configs)} configurations")
        
        classifier = CountryClassifier(max_workers=max_workers)
        start_time = time.time()
        
        results = classifier.process_configs(configs)
        
        elapsed_time = time.time() - start_time
        
        classifier.save_results(results)
        
        print(f"\n✅ CLASSIFICATION COMPLETE")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Total configs: {results['stats']['total']}")
        print(f"Successfully processed: {results['stats']['processed']}")
        print(f"Failed to process: {results['stats']['failed']}")
        
        print(f"\n📊 IP Type Classification:")
        print(f"  FIXED_IP (Datacenter): {results['stats']['fixed_ip']}")
        print(f"  CDN detected: {results['stats']['cdn_detected']}")
        print(f"  Residential IPs: {results['stats']['residential']}")
        
        print(f"\n📍 Top Countries (IP-based):")
        ip_countries = {k: v for k, v in results['stats']['by_country'].items() 
                       if k not in ['UNKNOWN', 'UNRESOLVED', 'CDN']}
        top_countries = sorted(ip_countries.items(), key=lambda x: x[1], reverse=True)[:10]
        
        for country, count in top_countries:
            print(f"  {country}: {count} configs")
        
        print(f"\n📁 Output saved to: configs/country/")
        print("=" * 60)
        
    except Exception as e:
        logger.error(f"Error in main: {e}")

if __name__ == "__main__":
    main()
