import os
import json
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_paths, urls, nameservidores):
        self.log_paths = [os.path.abspath(path) for path in log_paths]  # Normaliza os caminhos
        self.urls = urls
        self.nameservidores = nameservidores
        self.positions = {path: 0 for path in self.log_paths}  # Posições por caminho de arquivo
        print(f"Handler criado para os arquivos: {self.log_paths}")

    def on_modified(self, event):
        if event.is_directory:
            return  # Ignora modificações em diretórios

        log_path = os.path.abspath(event.src_path)
        if log_path in self.positions:
            print(f"Arquivo modificado detectado: {log_path}")
            self.send_new_logs(log_path)
        else:
            print(f"O arquivo {log_path} não está sendo monitorado.")

    def send_new_logs(self, log_path):
        print(f"Entrou em send_new_logs para o arquivo: {log_path}")
        try:
            with open(log_path, 'r') as file:
                file.seek(self.positions[log_path])
                lines = file.readlines()
                if lines:
                    print(f"Novas linhas lidas: {len(lines)}")
                    index = self.log_paths.index(log_path)
                    url = self.urls[index]
                    nameservidor = self.nameservidores[index]
                    for line in lines:
                        line = line.strip()
                        if line:
                            print(f"Enviando linha: {line}")
                            send_to_graylog(line, url, nameservidor)
                else:
                    print("Nenhuma nova linha encontrada.")
                self.positions[log_path] = file.tell()  # Atualiza a posição do arquivo
                print(f"Nova posição do arquivo: {self.positions[log_path]}")
        except Exception as e:
            print(f"Erro ao ler arquivo: {e}")
            messagebox.showerror("Erro", f"Erro ao ler arquivo: {log_path} - {e}")

def send_to_graylog(log_message, url, nameservidor):
    print(f"Preparando para enviar log: {log_message} para URL: {url}")
    
    gelf_message = {
        "version": "1.1",
        "host": nameservidor,
        "short_message": log_message,
        "level": 6,
        "timestamp": time.time()
    }
    
    try:
        response = requests.post(url, json=gelf_message)
        response.raise_for_status()
        print(f"Resposta do servidor: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Erro ao enviar log: {log_message} - {e}")
        messagebox.showerror("Erro", f"Erro ao enviar log: {log_message} - {e}")

class LogMonitor:
    def __init__(self):
        self.observer = None
        self.monitoring = False

    def start_monitoring(self, log_files, urls, nameservidores):
        if not self.monitoring:
            print("Iniciando monitoramento...")
            handler = LogFileHandler(log_files, urls, nameservidores)
            self.observer = Observer()
            for log_file in log_files:
                self.observer.schedule(handler, os.path.dirname(log_file), recursive=False)
            self.observer.start()
            self.monitoring = True
            print("Monitoramento iniciado.")

    def stop_monitoring(self):
        if self.monitoring:
            print("Parando monitoramento...")
            self.observer.stop()
            self.observer.join()
            self.monitoring = False
            print("Monitoramento parado.")

# Funções de interface
def browse_file(entry):
    filename = filedialog.askopenfilename()
    if filename:
        entry.delete(0, tk.END)
        entry.insert(0, filename)

def add_file_entry():
    row = len(log_files_entries) + 1
    
    ttk.Label(log_files_frame, text="Caminho do Log:").grid(row=row, column=0, padx=10, pady=5, sticky=tk.W)
    log_file_entry = ttk.Entry(log_files_frame, width=50)
    log_file_entry.grid(row=row, column=1, padx=10, pady=5, sticky=(tk.W, tk.E))
    
    ttk.Label(log_files_frame, text="Nome do Servidor:").grid(row=row, column=2, padx=10, pady=5, sticky=tk.W)
    server_name_entry = ttk.Entry(log_files_frame, width=30)
    server_name_entry.grid(row=row, column=3, padx=10, pady=5, sticky=(tk.W, tk.E))
    
    browse_btn = ttk.Button(log_files_frame, text="Browse", command=lambda: browse_file(log_file_entry))
    browse_btn.grid(row=row, column=4, padx=10, pady=5, sticky=tk.E)
    
    log_files_entries.append((log_file_entry, server_name_entry))

def start_monitoring():
    host = host_entry.get()
    port = port_entry.get()
    if not host or not port:
        messagebox.showerror("Erro", "Por favor, preencha todos os campos de servidor.")
        return
    
    url = f"http://{host}:{port}/gelf"
    log_files = [log_file_entry.get() for log_file_entry, _ in log_files_entries]
    nameservidores = [server_name_entry.get() for _, server_name_entry in log_files_entries]
    
    if len(log_files) != len(nameservidores):
        messagebox.showerror("Erro", "Número de arquivos de log e servidores não coincidem.")
        return
    
    log_monitor.start_monitoring(log_files, [url]*len(log_files), nameservidores)

def stop_monitoring():
    log_monitor.stop_monitoring()

# Configurando a janela principal
root = tk.Tk()

logo = tk.PhotoImage(file="img/logo.png")
logo_label = ttk.Label(root, image=logo)
logo_label.pack(pady=10)
root.title("Logs centralizado (Simoc)")
root.geometry("900x600")
root.resizable(False, False)

log_frame = ttk.Frame(root, padding="20")
log_frame.pack(pady=10, expand=True)

ttk.Label(log_frame, text="Arquivos de Log e Servidores:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

log_files_frame = ttk.Frame(log_frame)
log_files_frame.grid(row=1, column=0, columnspan=5, padx=10, pady=10)

# Adiciona o primeiro conjunto de campos
log_files_entries = []
add_file_entry()

add_entry_button = ttk.Button(log_frame, text="+ Adicionar Campo", command=add_file_entry)
add_entry_button.grid(row=2, column=0, pady=10, sticky=tk.W)

ttk.Label(log_frame, text="IP do Servidor Graylog:").grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
host_entry = ttk.Entry(log_frame, width=50)
host_entry.grid(row=3, column=1, padx=10, pady=10, sticky=(tk.W, tk.E))

ttk.Label(log_frame, text="Porta:").grid(row=4, column=0, padx=10, pady=10, sticky=tk.W)
port_entry = ttk.Entry(log_frame, width=50)
port_entry.grid(row=4, column=1, padx=10, pady=10, sticky=(tk.W, tk.E))

start_btn = ttk.Button(log_frame, text="Start", command=start_monitoring)
start_btn.grid(row=5, column=0, pady=20, sticky=tk.N)

stop_btn = ttk.Button(log_frame, text="Stop", command=stop_monitoring)
stop_btn.grid(row=5, column=1, pady=20, sticky=tk.N)

log_monitor = LogMonitor()

root.mainloop()
