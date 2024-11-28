# app.py

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from netmiko import ConnectHandler
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json
import os
import logging
from logging.handlers import RotatingFileHandler
from nornir import InitNornir
from nornir.core.exceptions import NornirExecutionError
from nornir_utils.plugins.functions import print_result
from nornir_netmiko.tasks import netmiko_send_config, netmiko_save_config

app = Flask(__name__)

# Inicializar Nornir
nr = InitNornir(config_file="configuration.yml")

app = Flask(__name__)
app.config.from_pyfile('config.py')  

# Configurar logging
if not os.path.exists('logs'):
    os.makedirs('logs')

handler = RotatingFileHandler('logs/app.log', maxBytes=100000, backupCount=3)
handler.setLevel(logging.DEBUG)  # Cambiar a DEBUG para capturar todos los logs
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

app.logger.setLevel(logging.DEBUG)  # Cambiar a DEBUG
app.logger.info('Aplicación iniciada')

# Configurar Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Nombre de la función de vista para la página de login

# Clase de Usuario Ficticio
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# Cargar usuarios desde un archivo JSON o base de datos (simplificado aquí)
USERS = {'admin': {'password': 'password'}}  # Reemplaza con una fuente de usuarios más segura en producción

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = USERS.get(username)
        if user and user['password'] == password:
            user_obj = User(id=username)
            login_user(user_obj)
            flash('Has iniciado sesión correctamente.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Credenciales inválidas.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

# Ruta de cierre de sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

# Cargar la lista de switches
with open(app.config['SWITCHES_FILE']) as f:
    switches = json.load(f)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/vlans')
@login_required
def vlans():
    vlan_info = []
    for switch in switches:
        try:
            net_connect = ConnectHandler(**switch)
            net_connect.enable()
            output = net_connect.send_command('show vlan brief')
            vlan_info.append({'host': switch['host'], 'output': output})
            net_connect.disconnect()
        except Exception as e:
            vlan_info.append({'host': switch['host'], 'output': f'Error: {e}'})
            app.logger.error(f"Error al obtener VLANs de {switch['host']}: {e}")
    return render_template('vlans.html', vlan_info=vlan_info)

@app.route('/add_vlan', methods=['GET', 'POST'])
@login_required
def add_vlan():
    if request.method == 'POST':
        vlan_id = request.form['vlan_id'].strip()
        vlan_name = request.form['vlan_name'].strip()
        
        # Validaciones básicas
        if not vlan_id.isdigit():
            flash('El ID de VLAN debe ser un número.', 'danger')
            return redirect(url_for('add_vlan'))
        
        commands = [f'vlan {vlan_id}', f'name {vlan_name}']
        for switch in switches:
            try:
                net_connect = ConnectHandler(**switch)
                net_connect.enable()
                output = net_connect.send_config_set(commands)
                net_connect.disconnect()
                app.logger.info(f"VLAN {vlan_id} - {vlan_name} agregada en switch {switch['host']}")
            except Exception as e:
                app.logger.error(f"Error al agregar VLAN en {switch['host']}: {e}")
                flash(f'Error al conectar con {switch["host"]}: {e}', 'danger')
                return f'Error al conectar con {switch["host"]}: {e}', 500
        flash('VLAN agregada correctamente en todos los switches.', 'success')
        return redirect(url_for('vlans'))
    return render_template('add_vlan.html')

@app.route('/assign_vlan', methods=['GET', 'POST'])
@login_required
def assign_vlan():
    if request.method == 'POST':
        vlan_id = request.form['vlan_id'].strip()
        port = request.form['port'].strip()
        switch_name = request.form['switch'].strip()  # Nombre del switch según inventario
        
        # Validaciones básicas
        if not vlan_id.isdigit():
            flash('El ID de VLAN debe ser un número.', 'danger')
            return redirect(url_for('assign_vlan'))
        
        if not port:
            flash('El puerto no puede estar vacío.', 'danger')
            return redirect(url_for('assign_vlan'))
        
        # Buscar el switch en el inventario
        device = nr.inventory.hosts.get(switch_name)
        if not device:
            flash('Switch no encontrado en el inventario.', 'danger')
            return redirect(url_for('assign_vlan'))
        
        try:
            # Ejecutar configuración en el dispositivo
            result = nr.run(
                task=netmiko_send_config,
                name=f"Asignar VLAN {vlan_id} al puerto {port}",
                config_commands=[
                    f'interface {port}',
                    'switchport mode access',
                    f'switchport access vlan {vlan_id}',
                    'no shutdown',
                    'exit'
                ],
                on_good="Comandos enviados correctamente",
                on_failed="Error al enviar comandos"
            )
            
            # Guardar configuración
            save_result = nr.run(
                task=netmiko_save_config,
                name="Guardar configuración"
            )
            
            # Log y notificación
            print_result(result)
            print_result(save_result)
            
            flash(f'VLAN {vlan_id} asignada al puerto {port} en switch {switch_name}.', 'success')
        except NornirExecutionError as e:
            flash(f'Error durante la ejecución de tareas: {e}', 'danger')
            return redirect(url_for('assign_vlan'))
        
        return redirect(url_for('vlans'))
    
    # Cargar switches desde el inventario
    switches = [{'name': h, 'hostname': nr.inventory.hosts[h].hostname} for h in nr.inventory.hosts]
    return render_template('assign_vlan.html', switches=switches)

@app.route('/backups')
@login_required
def backups():
    backup_dir = app.config['BACKUP_DIR']
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    backup_files = os.listdir(backup_dir)
    return render_template('backups.html', backup_files=backup_files)

@app.route('/download_backup/<filename>')
@login_required
def download_backup(filename):
    backup_dir = app.config['BACKUP_DIR']
    return send_from_directory(directory=backup_dir, path=filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
