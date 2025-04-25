import time
import yara
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import os

# Carregar regras YARA (substitua pelo caminho de um arquivo .yar real)
try:
    rules = yara.compile(filepath='ransomware_rules.yar')  # Baixe de https://github.com/Yara-Rules/rules
except FileNotFoundError:
    # Regra de exemplo para demonstração
    rules = yara.compile(source='''
    rule Ransomware {
        meta:
            description = "Detecta padrões comuns de ransomware"
        strings:
            $s1 = "encrypted" ascii
            $s2 = ".locked" ascii
            $s3 = "WannaDecryptor" ascii
        condition:
            any of them
    }
    ''')

# Dicionário para rastrear processos suspeitos
suspicious_processes = {}

class FileMonitor(FileSystemEventHandler):
    def __init__(self, monitor_path):
        self.modification_count = 0
        self.last_time = time.time()
        self.monitor_path = monitor_path

    def on_modified(self, event):
        if not event.is_directory:
            self.handle_event()

    def on_moved(self, event):
        if not event.is_directory:
            self.handle_event()

    def handle_event(self):
        self.modification_count += 1
        current_time = time.time()
        if current_time - self.last_time > 5:  # Janela de 5 segundos
            if self.modification_count > 10:  # Limite de eventos
                print(f"Atividade suspeita detectada em {self.monitor_path}: {self.modification_count} eventos")
                for proc in psutil.process_iter(['pid', 'open_files']):
                    try:
                        open_files = [f.path for f in proc.info['open_files'] or []]
                        if any(file.startswith(self.monitor_path) for file in open_files):
                            suspicious_processes[proc.info['pid']] = suspicious_processes.get(proc.info['pid'], 0) + 1
                            print(f"Processo suspeito com arquivos abertos em {self.monitor_path}: PID {proc.info['pid']}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
                        pass
            self.modification_count = 0
            self.last_time = current_time

def monitor_processes():
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                cpu = proc.cpu_percent(interval=0.1)
                io = proc.io_counters()
                if cpu > 80 or io.write_bytes > 1000000:  # Limites arbitrários
                    print(f"Processo suspeito: {proc.name()} (PID: {proc.pid})")
                    suspicious_processes[proc.pid] = suspicious_processes.get(proc.pid, 0) + 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.NotImplementedError):
                pass
        time.sleep(10)

def scan_processes():
    while True:
        for proc in psutil.process_iter(['pid', 'exe']):
            try:
                exe_path = proc.info['exe']
                if exe_path and os.path.exists(exe_path):
                    matches = rules.match(exe_path)
                    if matches:
                        print(f"Ransomware detectado no processo: {proc.info['pid']} ({matches})")
                        suspicious_processes[proc.info['pid']] = suspicious_processes.get(proc.info['pid'], 0) + 2
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        time.sleep(30)

def mitigate():
    while True:
        for pid, flags in list(suspicious_processes.items()):
            if flags >= 2:
                try:
                    p = psutil.Process(pid)
                    p.terminate()
                    print(f"Processo encerrado: {pid}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    print(f"Não foi possível encerrar o processo: {pid}")
                finally:
                    if pid in suspicious_processes:
                        del suspicious_processes[pid]
        time.sleep(5)

if __name__ == "__main__":
    # Obter lista de drives
    monitor_paths = [partition.mountpoint for partition in psutil.disk_partitions()]

    # Configurar observadores
    observer = Observer()
    for path in monitor_paths:
        if os.path.isdir(path):
            event_handler = FileMonitor(path)
            observer.schedule(event_handler, path=path, recursive=True)
            print(f"Monitorando {path}")
        else:
            print(f"Não é possível monitorar {path}")

    observer.start()

    # Iniciar threads para monitoramento e mitigação
    threading.Thread(target=monitor_processes, daemon=True).start()
    threading.Thread(target=scan_processes, daemon=True).start()
    threading.Thread(target=mitigate, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Encerrando o antivírus...")
        observer.stop()
    observer.join()