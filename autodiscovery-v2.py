import sys
import nmap
import pynetbox
import ipaddress
import urllib3
import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Общие переменные
netbox_url = 'https://netbox.skpari.local/'
netbox_api = '968c39c7ea73d24d6ff4f5a0d79e6c3682c5b706'
nb = pynetbox.api(url=netbox_url, token=netbox_api)

# Отключение SSL и предупреждений SSL
nb.http_session.verify = False
urllib3.disable_warnings()

def read_subnets_from_file(file_path):
    """Чтение подсетей из файла."""
    with open(file_path, 'r') as file:
        subnets = [line.strip() for line in file if line.strip()]
    return subnets

def app_run(subnets):
    for subnet in subnets:
        ip_network = ipaddress.ip_network(subnet)  # Получаем объект сети
        prefixlen = ip_network.prefixlen  # Получаем длину префикса сети
        ip_list = list(ip_network.hosts())  # Получаем список IP-адресов в сети
        total_ips = len(ip_list)  # Общее количество IP-адресов в подсети

        logging.info(f"Начато сканирование подсети {subnet}, всего IP-адресов: {total_ips}")

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(process_ip, ip, prefixlen, total_ips): ip for ip in ip_list}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Ошибка при обработке IP: {e}")

def process_ip(ip, prefixlen, total_ips):
    last_octet = str(ip).split('.')
    if (int(last_octet[-1]) != 255) and (int(last_octet[-1]) != 0):
        logging.info(f"Сканирование IP: {ip} ({total_ips} всего)")
        nmap_host_state = ip_scan(str(ip))
        netbox_ip_id, netbox_ip = ip_check(str(ip))
        netb_ipam_update(netbox_ip_id, str(ip), prefixlen, nmap_host_state)

def ip_scan(ip_address):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments='-sP -R')
    if len(nm.all_hosts()) != 0:
        return nm[ip_address]['status']['state']
    else:
        return 'down'

def ip_check(ip_address):
    ip_search_status = nb.ipam.ip_addresses.filter(address=ip_address)
    if ip_search_status:
        for item in ip_search_status:
            return item.id, item.display
    return 0, '0.0.0.0/0'

def netb_ipam_update(netbox_ip_id, netbox_ip, prefix, nmap_host_state):
    if (nmap_host_state == 'up') and (netbox_ip_id == 0):
        netbox_add_ip(netbox_ip, prefix)
    elif (nmap_host_state == 'up') and (netbox_ip_id != 0):
        # Если IP уже существует, проверяем и обновляем DNS имя
        ip_dns_name = get_dns_from_ip(netbox_ip)
        if ip_dns_name is None:
            ip_dns_name = ''
        
        if not is_valid_dns_name(ip_dns_name):
            ip_dns_name = ''
        
        # Получаем текущий IP-адрес из Netbox
        current_ip = nb.ipam.ip_addresses.get(netbox_ip_id)
        
        # Если DNS имя изменилось, обновляем его
        if current_ip.dns_name != ip_dns_name:
            current_ip.dns_name = ip_dns_name
            current_ip.save()
            logging.info(f'Обновлено DNS имя для IP: {netbox_ip}/{prefix}, новое DNS имя: {ip_dns_name}')
    elif (nmap_host_state == 'down') and (netbox_ip_id != 0):
        netbox_remove_ip(netbox_ip_id)
    return True

def netbox_add_ip(ip, prefix):
    ip_dns_name = get_dns_from_ip(ip)
    
    if ip_dns_name is None:
        ip_dns_name = ''
    
    if not is_valid_dns_name(ip_dns_name):
        ip_dns_name = ''
    
    ip_add_result = nb.ipam.ip_addresses.create(
        address=f'{ip}/{prefix}',
        dns_name=ip_dns_name
    )
    logging.info(f'Добавлен IP: {ip}/{prefix}, DNS имя: {ip_dns_name}')

def is_valid_dns_name(dns_name):
    if dns_name is None or len(dns_name) == 0:
        return False
    
    allowed_chars = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._")
    return all(c in allowed_chars for c in dns_name)

def netbox_remove_ip(ip_id):
    ip_search_result = nb.ipam.ip_addresses.get(id=ip_id)
    if ip_search_result is not None:
        ip_search_result.delete()
        logging.info(f'Удален IP с ID: {ip_id}')

def get_dns_by_host(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return None

def get_dns_from_ip(ip_address):
    return get_dns_by_host(ip_address)

if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("Вы не указали файл с подсетями, пожалуйста, запустите: \n -> python .\\autodiscovery.py subnets.txt")
    else:
        file_path = sys.argv[1]
        subnets = read_subnets_from_file(file_path)
        app_run(subnets)
        print("Скрипт завершен. Консоль готова для ввода.")
