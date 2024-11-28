# backup_switches.py

from netmiko import ConnectHandler
import json
import datetime
import os

# Crear directorio de backups si no existe
backup_dir = 'static/backups/'
os.makedirs(backup_dir, exist_ok=True)

# Cargar la lista de switches
with open('devices/switches.json') as f:
    switches = json.load(f)

# Obtener fecha y hora actual en formato legible
fecha = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

for switch in switches:
    try:
        # Obtener hostname para el nombre del archivo
        hostname = switch.get('hostname', switch['host'])
        
        # Crear un diccionario sin 'hostname' para pasar a ConnectHandler
        switch_params = {k: v for k, v in switch.items() if k != 'hostname'}
        
        net_connect = ConnectHandler(**switch_params)
        net_connect.enable()  # Entra en modo privilegiado si es necesario
        output = net_connect.send_command('show running-config')
        
        # Crear el nombre del archivo de backup con formato legible
        filename = f"{backup_dir}{hostname}_{fecha}.cfg"
        with open(filename, 'w') as file:
            file.write(output)
        net_connect.disconnect()
        print(f"Backup exitoso para {hostname}: {filename}")
    except Exception as e:
        print(f"Error al conectar con {switch['host']}: {e}")
