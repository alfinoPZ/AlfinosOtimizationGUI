import customtkinter
from tkinter import *
import os
import subprocess
import threading
import colorama
from colorama import Style, Fore
from PIL import Image, ImageTk
from tkinter import messagebox
import shutil
import random
import time
import uuid
import winreg
import pyautogui

messagebox.showinfo("Alfino's Otimization", "AVISO/WARNING: UM CMD FICARA ABERTO JUNTO COM APP MOSTRANDO TUDO QUE ESTARA OCORRENDO!\nNO SPOOFER VOCÊ TERA QUE USA-LO")

colorama.init()

app = customtkinter.CTk()
app.geometry("1080x570")
app.config(bg="#000000")
app.title("Alfino's Otimization v2.1")
app.resizable(False ,False)

    # Functions
def center_window(root, width, height):
    # Obtém as dimensões da tela do computador
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Calcula as coordenadas x e y para a posição central da janela
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)

        # Define a posição inicial da janela
    root.geometry(f"{width}x{height}+{x}+{y}")

checkbox_var = BooleanVar()
checkbox_var.set(False)

# Criar a janela do prompt
prompt_window = Toplevel()
prompt_window.title("Command Prompt")
prompt_window.geometry("600x400")
prompt_window.resizable(False, False)
prompt_window.withdraw()  # Esconde a janela do prompt inicialmente
prompt_window.config(bg="#000000")

def disable_prompt_window_close():
    pass

prompt_window.protocol("WM_DELETE_WINDOW", disable_prompt_window_close)

# Text widget para exibir o prompt
prompt_text = Text(prompt_window, wrap=WORD, font=('Courier', 12))
prompt_text.pack(fill=BOTH, expand=True)

# Variável para controlar o estado da janela do prompt
prompt_window = None

# Função para mostrar ou esconder a janela do prompt
def show_prompt_window():
    global prompt_window
    if checkbox_var.get():
        if not prompt_window:
            create_prompt_window()
            update_prompt_position()
        else:
            prompt_window.deiconify()
    else:
        if prompt_window:
            prompt_window.withdraw()

# Função para atualizar a posição da janela do prompt
def update_prompt_position():
    global prompt_window
    if prompt_window:
        prompt_x = app.winfo_x() + app.winfo_width()
        prompt_y = app.winfo_y()
        prompt_window.geometry(f"+{prompt_x}+{prompt_y}")
        app.after(100, update_prompt_position)  # Continua atualizando se a checkbox estiver marcada

# Variável para controlar a janela do prompt
prompt_window = None

# Função para criar a janela do prompt
def create_prompt_window():
    global prompt_window
    prompt_window = Toplevel()
    prompt_window.title("Command Prompt")
    prompt_window.geometry("700x400")
    prompt_window.resizable(False, False)
    prompt_window.iconbitmap(r"cmd.ico")

    # Configuração para desabilitar o fechamento da janela do prompt
    prompt_window.protocol("WM_DELETE_WINDOW", lambda: None)

    # Text widget para exibir o prompt
    global prompt_text
    prompt_text = Text(prompt_window, wrap=WORD, font=('Courier', 12), bg='black', fg='white')
    prompt_text.pack(fill=BOTH, expand=True)

    # Adicionar barra de rolagem ao Text widget
    scrollbar = Scrollbar(prompt_window, command=prompt_text.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    prompt_text.config(yscrollcommand=scrollbar.set)

# Função para atualizar a checkbox
def update_checkbox():
    checkbox_var.set(False)

# Monitora o evento de redimensionamento da janela principal
def on_resize(event):
    if event.widget.winfo_width() == 1 and event.widget.winfo_height() == 1:
        update_checkbox()

app.bind("<Configure>", on_resize)

# Função para executar os comandos usando o módulo subprocess em uma thread separada
def execute_command():
    commands = [
        'echo Windows IP Configuration',
        'echo ',
        'echo Successfully flushed the DNS Resolver Cache.',
        'echo off /t 5'
        'takeown /f "%temp%" /r /d y',
        'RD /S /Q %temp%',
        'MKDIR %temp%',
        'takeown /f "%temp%" /r /d y',
        'takeown /f "C:\Windows\Temp" /r /d y',
        'RD /S /Q C:\Windows\Temp',
        'MKDIR C:\Windows\Temp',
        'takeown /f "C:\Windows\Temp" /r /d y',
        'net stop wuauserv',
        'net stop UsoSvc',
        'rd /s /q C:\Windows\SoftwareDistribution',
        'md C:\Windows\SoftwareDistribution',
        'FOR %F IN ("%SystemRoot%\\servicing\\Packages\\Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")',
        'FOR %F IN ("%SystemRoot%\\servicing\\Packages\\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum") DO (DISM /Online /NoRestart /Add-Package:"%F")',
        'wevtutil cl Security',
        'wevtutil cl System',
        'wevtutil cl Application',
        'rd /s /q "C:\\Program Files\\*.msi"',
        'cd C:/ & del *.log /a /s /q /f',
        'echo DONE'
    ]

    os.system("ipconfig /flushdns")

    # Função para executar os comandos em segundo plano
    def run_commands():
        for command in commands:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            while True: 
                output = process.stdout.readline()
                if not output and process.poll() is not None:
                    break

                prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
                prompt_text.insert(END, output)   # Insere a saída no Text widget
                prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
                prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget

        # Inserir "DONE" após a execução de todos os comandos e limpar o prompt com "cls"
        prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
        prompt_text.insert(END, "DONE\n")
        prompt_text.insert(END, "\n")
        prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
        prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget

    # Cria e inicia a thread para executar os comandos
    command_thread = threading.Thread(target=run_commands)
    command_thread.start()

# Função para atualizar a posição da janela do prompt
def update_prompt_position():
    global prompt_window
    if prompt_window:
        prompt_x = app.winfo_x() + app.winfo_width()
        prompt_y = app.winfo_y()
        prompt_window.geometry(f"+{prompt_x}+{prompt_y}")
        app.after(100, update_prompt_position)

# Função para executar os comandos em segundo plano
def run_commands(commands):
    for command in commands:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        while True:
            output = process.stdout.readline()
            if not output and process.poll() is not None:
                break

            prompt_text.config(state=NORMAL)
            prompt_text.insert(END, output)
            prompt_text.see(END)
            prompt_text.config(state=DISABLED)

    prompt_text.config(state=NORMAL)
    prompt_text.insert(END, "DONE\n")
    prompt_text.insert(END, "\n")
    prompt_text.see(END)
    prompt_text.config(state=DISABLED)

def betterfpswindows():
    app.withdraw()
    prompt_window = None
    fps = customtkinter.CTk()
    fps.geometry("1080x570")
    fps.config(bg="#000000")
    fps.title("Alfino's Otimization v2.1 - FPS")
    fps.resizable(False ,False)

    label_clean = customtkinter.CTkLabel(fps, text="BETTER FPS & INPUTLAG", font=('Arial', 32), fg_color="#000000")
    label_clean.place(x=360, y=10)

    label_warning = customtkinter.CTkLabel(fps, text="WARNING: (pt-br) Se você apenas fechar está aba, o aplicativo continuara aberto em segundo plano!", font=('Arial', 12), text_color="red", fg_color="#000000", bg_color="#000000")
    label_warning.place(x=250, y=535)

    def fps_and_input():
        pass

    def windows_defender():
        commands = [
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\wdboot" -Name "Start" -Value 4 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\wdfilter" -Name "Start" -Value 4 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" -Name "Start" -Value 4 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService" -Name "Start" -Value 4 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\wdnisdrv" -Name "Start" -Value 4 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\mssecflt" -Name "Start" -Value 4 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\WdNisSvc" -Name "Start" -Value 4 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Sense" -Name "Start" -Value 4 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\wscsvc" -Name "Start" -Value 4 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" -Name "ServiceKeepAlive" -Value 0 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" -Name "DisableIOAVProtection" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Reporting" -Name "DisableEnhancedNotifications" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications" -Name "DisableNotifications" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKCU:\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" -Name "NoToastApplicationNotification" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKCU:\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord'
            ]
        
        def run_commands():
            for command in commands:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                while True: 
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break

                    prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
                    prompt_text.insert(END, output)   # Insere a saída no Text widget
                    prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
                    prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget

            # Inserir "DONE" após a execução de todos os comandos e limpar o prompt com "cls"
            prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
            prompt_text.insert(END, "DONE\n")
            prompt_text.insert(END, "\n")
            prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
            prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget
            messagebox.showinfo('CLEAN', "DONE")

        # Cria e inicia a thread para executar os comandos
        command_thread = threading.Thread(target=run_commands)
        command_thread.start()

    def xbox_services():
        commands = [
            'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f',
            'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f',
            'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f'
            ]
        
        def run_commands():
            for command in commands:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                while True: 
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break

                    prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
                    prompt_text.insert(END, output)   # Insere a saída no Text widget
                    prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
                    prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget

            # Inserir "DONE" após a execução de todos os comandos e limpar o prompt com "cls"
            prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
            prompt_text.insert(END, "DONE\n")
            prompt_text.insert(END, "\n")
            prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
            prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget
            messagebox.showinfo('CLEAN', "DONE")

        # Cria e inicia a thread para executar os comandos
        command_thread = threading.Thread(target=run_commands)
        command_thread.start()


    def services():
        commands = [
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f'
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FontCache3.0.0.0" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f',
                'REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f'
                ]

        def run_commands():
            for command in commands:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                while True: 
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break

                    prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
                    prompt_text.insert(END, output)   # Insere a saída no Text widget
                    prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
                    prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget

            # Inserir "DONE" após a execução de todos os comandos e limpar o prompt com "cls"
            prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
            prompt_text.insert(END, "DONE\n")
            prompt_text.insert(END, "\n")
            prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
            prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget
            messagebox.showinfo('CLEAN', "DONE")

        # Cria e inicia a thread para executar os comandos
        command_thread = threading.Thread(target=run_commands)
        command_thread.start()

    def memory_compressionn():
        commands = 'PowerShell "Disable-MMAgent -MemoryCompression"'
    
        def run_commands():
            for command in commands:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                while True: 
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break

                    prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
                    prompt_text.insert(END, output)   # Insere a saída no Text widget
                    prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
                    prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget

            # Inserir "DONE" após a execução de todos os comandos e limpar o prompt com "cls"
            prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
            prompt_text.insert(END, "DONE\n")
            prompt_text.insert(END, "\n")
            prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
            prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget
            messagebox.showinfo('CLEAN', "DONE")

        # Cria e inicia a thread para executar os comandos
        command_thread = threading.Thread(target=run_commands)
        command_thread.start()

    def other_things():
        commands = [
            'bcdedit /set disabledynamictick yes'
            'bcdedit /deletevalue useplatformclock'
            'bcdedit /set useplatformtick yes'
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" -Name "NetworkThrottlingIndex" -Value 10 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "Affinity" -Value 0 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "Background Only" -Value "False" -Type String',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "Clock Rate" -Value 10000 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "GPU Priority" -Value 8 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "Priority" -Value 6 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "Scheduling Category" -Value "High" -Type String',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile\\Tasks\\Games" -Name "SFIO Priority" -Value "High" -Type String',
            'Set-ItemProperty -Path "HKCU:\\System\\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord',
            'Set-ItemProperty -Path "HKCU:\\System\\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord',
            'Set-ItemProperty -Path "HKCU:\\System\\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Value 0 -Type DWord',
            'Set-ItemProperty -Path "HKCU:\\System\\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKCU:\\System\\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Value 0 -Type DWord',
            'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "AutoEndTasks" -Value "1" -Type String',
            'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "HungAppTimeout" -Value "1000" -Type String',
            'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "WaitToKillAppTimeout" -Value "2000" -Type String',
            'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "LowLevelHooksTimeout" -Value "1000" -Type String',
            'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "MenuShowDelay" -Value "0" -Type String',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control" -Name "WaitToKillServiceTimeout" -Value "2000" -Type String',
            'Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Maintenance" -Name "MaintenanceDisabled" -Value 1 -Type DWord',
            'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Power" -Name "HibernateEnabled" -Value 0 -Type DWord'
            ]

        def run_commands():
            for command in commands:
                process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                while True: 
                    output = process.stdout.readline()
                    if not output and process.poll() is not None:
                        break

                    prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
                    prompt_text.insert(END, output)   # Insere a saída no Text widget
                    prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
                    prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget

            # Inserir "DONE" após a execução de todos os comandos e limpar o prompt com "cls"
            prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
            prompt_text.insert(END, "DONE\n")
            prompt_text.insert(END, "\n")
            prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
            prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget
            messagebox.showinfo('CLEAN', "DONE")

        # Cria e inicia a thread para executar os comandos
        command_thread = threading.Thread(target=run_commands)
        command_thread.start()

    fps_ping_button = customtkinter.CTkButton(fps, text="Optimize FPS and INPUTLAG",
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=fps_and_input,
                                    border_color="#3b3b3b")
    fps_ping_button.place(x=20, y=60)

    windows_defender_button = customtkinter.CTkButton(fps, text="Disable Windows Defender", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=windows_defender,
                                    border_color="#3b3b3b")
    windows_defender_button.place(x=20, y=200)

    xbox_button = customtkinter.CTkButton(fps, text="Disable Xbox's Services", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=xbox_services,
                                    border_color="#3b3b3b")
    xbox_button.place(x=20, y=340)

    services_button = customtkinter.CTkButton(fps, text="Disable Trash Services", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=services,
                                    border_color="#3b3b3b")
    services_button.place(x=530, y=60)

    memory_compression = customtkinter.CTkButton(fps, text="Disable Memory Compression", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=memory_compressionn,
                                    border_color="#3b3b3b")
    memory_compression.place(x=530, y=200)

    resto = customtkinter.CTkButton(fps, text="Other Things", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=other_things,
                                    border_color="#3b3b3b")
    resto.place(x=530, y=340)

    def sair():
        exit(0)
        
    def back():
        fps.destroy()
        app.deiconify()
        if prompt_window:
             prompt_window.deiconify()

    back = customtkinter.CTkButton(fps, text="Go Back", 
                                    font=('Poppins', 24), 
                                    width=300, 
                                    height=50, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=back,
                                    border_color="#3b3b3b")
    back.place(x=20, y=480)
        
    def create_system_restore_point(description):
        command = f'wmic.exe /Namespace:\\\\root\\default Path SystemRestore Call CreateRestorePoint "{description}", 100, 7'
        subprocess.run(command, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
        prompt_text.insert(END, command)   # Insere a saída no Text widget
        prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
        prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget

        # Inserir "DONE" após a execução de todos os comandos e limpar o prompt com "cls"
        prompt_text.config(state=NORMAL)  # Habilita a edição do Text widget
        prompt_text.insert(END, "DONE\n")
        prompt_text.insert(END, "\n")
        prompt_text.see(END)  # Faz o Text widget rolar automaticamente para a última linha inserida
        prompt_text.config(state=DISABLED)  # Desabilita a edição do Text widget
        
    description = "Ponto de restauração criado pelo Cleaner - AlfinoPZ"

    restirePointButton = customtkinter.CTkButton(fps, text="CREATE A RESTORE POINT",
                                    font=('Poppins', 24), 
                                    width=300, 
                                    height=50, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="red",
                                    command=lambda: create_system_restore_point(description),
                                    border_color="#3b3b3b")
    restirePointButton.place(x=360, y=480)

    leave = customtkinter.CTkButton(fps, text="Exit",
                                    font=('Poppins', 24), 
                                    width=300, 
                                    height=50, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b",
                                    text_color="#5f615f",
                                    command=sair,
                                    border_color="#3b3b3b")
    leave.place(x=730, y=480)

    fps.mainloop()
        
###################################################
center_window(app, 1080, 570)

# Frames
leftFrame = customtkinter.CTkFrame(app, width=540, height=570, fg_color="#000000")
leftFrame.place(x=0, y=0)

rightFrame = customtkinter.CTkFrame(app, width=540, height=570, fg_color="#000000")
rightFrame.place(x=539, y=0)

middleFrame = customtkinter.CTkFrame(app, width=10, height=570, fg_color="#242424", corner_radius=0)
middleFrame.place(x=535, y=0)

# Labels
label_clean = customtkinter.CTkLabel(leftFrame, text="Cleaner Options", font=('Arial', 32))
label_clean.place(x=160, y=10)

label_fivem = customtkinter.CTkLabel(rightFrame, text="FiveM Options", font=('Arial', 32))
label_fivem.place(x=160, y=10)

label_alfino = customtkinter.CTkLabel(leftFrame, text="ALFINO’S OTIMIZATION", font=('Arial', 32))
label_alfino.place(x=90, y=450)

label_alfino = customtkinter.CTkLabel(leftFrame, text="® 2023, Alfino Otimization consta com muitas versões. Você esta na: v2.1", font=('Arial', 12), text_color="red")
label_alfino.place(x=90, y=535)

def sair():
    exit(0)

# Buttons
button_clean = customtkinter.CTkButton(leftFrame, text="CLEAN ALL MY PC\n&\nBETTER PING",
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=execute_command,
                                    border_color="#3b3b3b")
button_clean.place(x=20, y=60)

button_fps = customtkinter.CTkButton(leftFrame, text="BETTER FPS\n&\nINCREASE INPUT LAG", 
                                    font=('Poppins', 24), 
                                    width=500, height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b",
                                    text_color="#5f615f",
                                    command=betterfpswindows,
                                    border_color="#3b3b3b")
button_fps.place(x=20, y=190)

def betterfpswindows():
    app.withdraw()
    prompt_window = None
    apps = customtkinter.CTk()
    apps.geometry("1080x570")
    apps.config(bg="#000000")
    apps.title("Alfino's Otimization v2.1 - Apps")
    apps.resizable(False ,False)

    def sair():
        exit(0)
        
    def back():
        apps.destroy()
        app.deiconify()
        if prompt_window:
             prompt_window.deiconify()

    back = customtkinter.CTkButton(apps, text="Go Back",
                                    font=('Poppins', 24), 
                                    width=300, 
                                    height=50, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=back,
                                    border_color="#3b3b3b")
    back.place(x=380, y=480)

    leave = customtkinter.CTkButton(apps, text="Exit",
                                    font=('Poppins', 24), 
                                    width=300, 
                                    height=50, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b",
                                    text_color="#5f615f",
                                    command=sair,
                                    border_color="#3b3b3b")
    leave.place(x=20, y=480)

    def next():
        apps.withdraw()
        prompt_window = None
        next_window = customtkinter.CTk()
        next_window.geometry("1080x570")
        next_window.config(bg="#000000")
        next_window.title("Alfino's Otimization v2.1 - Apps - Next Page")
        next_window.resizable(False ,False)

        label = customtkinter.CTkLabel(next_window, text="APPS - Next Page", font=('Arial', 32), fg_color="black", bg_color="black")
        label.pack(pady=5)

        def sair():
            exit(0)
            
        def back():
            next_window.destroy()
            apps.deiconify()
            if prompt_window:
                prompt_window.deiconify()

        back = customtkinter.CTkButton(next_window, text="Go Back",
                                        font=('Poppins', 24), 
                                        width=300, 
                                        height=50, 
                                        fg_color="#242424", 
                                        corner_radius=0, 
                                        border_spacing=2, 
                                        border_width=3, 
                                        hover_color="#3b3b3b", 
                                        text_color="#5f615f",
                                        command=back,
                                        border_color="#3b3b3b")
        back.place(x=540, y=250)

        leave = customtkinter.CTkButton(next_window, text="Exit",
                                        font=('Poppins', 24), 
                                        width=300, 
                                        height=50, 
                                        fg_color="#242424", 
                                        corner_radius=0, 
                                        border_spacing=2, 
                                        border_width=3, 
                                        hover_color="#3b3b3b",
                                        text_color="#5f615f",
                                        command=sair,
                                        border_color="#3b3b3b")
        leave.place(x=210, y=250)

        def process():
            os.system("start https://cdn.discordapp.com/attachments/1083214209174737008/1126767247944335410/Process_Explorer.exe")

        def network():
            os.system("start https://cdn.discordapp.com/attachments/1083214209174737008/1126768848096477285/NetworkLatencyView.rar")

        process_explorer = customtkinter.CTkButton(next_window, text="Process Explorer",
                                        font=('Poppins', 24), 
                                        width=500, 
                                        height=110, 
                                        fg_color="#242424", 
                                        corner_radius=0, 
                                        border_spacing=2, 
                                        border_width=3, 
                                        hover_color="#3b3b3b", 
                                        text_color="#5f615f",
                                        command=process,
                                        border_color="#3b3b3b")
        process_explorer.place(x=20, y=60)

        NetworkLatencyView = customtkinter.CTkButton(next_window, text="NetworkLatencyView", 
                                        font=('Poppins', 24), 
                                        width=500, 
                                        height=110, 
                                        fg_color="#242424", 
                                        corner_radius=0, 
                                        border_spacing=2, 
                                        border_width=3, 
                                        hover_color="#3b3b3b", 
                                        text_color="#5f615f",
                                        command=network,
                                        border_color="#3b3b3b")
        NetworkLatencyView.place(x=530, y=60)

        next_window.mainloop()

    label = customtkinter.CTkLabel(apps, text="APPS", font=('Arial', 32), fg_color="black", bg_color="black")
    label.pack(pady=5)

    next_page = customtkinter.CTkButton(apps, text="Next Page",
                                    font=('Poppins', 24), 
                                    width=300, 
                                    height=50, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b",
                                    text_color="#5f615f",
                                    command=next,
                                    border_color="#3b3b3b")
    next_page.place(x=730, y=480)

    def clean():
        os.system("start https://cdn.discordapp.com/attachments/1083214209174737008/1126759123694932048/cleanmgr-1-38-1200.zip")

    Cleanmgr = customtkinter.CTkButton(apps, text="Cleanmgr+",
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=clean,
                                    border_color="#3b3b3b")
    Cleanmgr.place(x=20, y=60)
    
    def auto():
        os.system("start https://download.sysinternals.com/files/Autoruns.zip")

    Autoruns = customtkinter.CTkButton(apps, text="Autoruns", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=auto,
                                    border_color="#3b3b3b")
    Autoruns.place(x=20, y=200)

    def tcp():
        os.system("start https://cdn.discordapp.com/attachments/1083214209174737008/1126766724046409778/TCPView.exe")

    TCPView = customtkinter.CTkButton(apps, text="TCP View", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=tcp,
                                    border_color="#3b3b3b")
    TCPView.place(x=20, y=340)

    def memory():
        os.system("start https://cdn.discordapp.com/attachments/1083214209174737008/1126761653569069186/memorycleaner.exe")

    MemoryCleaner = customtkinter.CTkButton(apps, text="Memory Cleaner", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=memory,
                                    border_color="#3b3b3b")
    MemoryCleaner.place(x=530, y=60)

    def msi():
        os.system("start https://cdn.discordapp.com/attachments/1083214209174737008/1126761801573470208/MSI_util_v3.exe")

    MSIModeUtility = customtkinter.CTkButton(apps, text="MSI Mode Utility", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command="",
                                    border_color="#3b3b3b")
    MSIModeUtility.place(x=530, y=200)

    def dduu():
        os.system("start https://cdn.discordapp.com/attachments/1083214209174737008/1126762245490217010/Guru3D.com-DDU.zip")

    ddu = customtkinter.CTkButton(apps, text="Display Driver Uninstaller (DDU)", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=110, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#5f615f",
                                    command=dduu,
                                    border_color="#3b3b3b")
    ddu.place(x=530, y=340)

    apps.mainloop()

def buttons():
        button_apps = customtkinter.CTkButton(leftFrame, text="BETTER APPS", 
                                            font=('Poppins', 24), 
                                            width=500, 
                                            height=110, 
                                            fg_color="#242424", 
                                            corner_radius=0, 
                                            border_spacing=2, 
                                            border_width=3, 
                                            hover_color="#3b3b3b", 
                                            text_color="#5f615f",
                                            command=betterfpswindows, 
                                            border_color="#3b3b3b")
        button_apps.place(x=20, y=320)

        def sair():
            exit(0)

        left = customtkinter.CTkButton(leftFrame, text="E\nX\nI\nT",
                                            font=('Poppins', 24), 
                                            width=50, 
                                            height=120, 
                                            fg_color="#242424", 
                                            corner_radius=0, 
                                            border_spacing=2, 
                                            border_width=3, 
                                            hover_color="#3b3b3b", 
                                            text_color="#5f615f",
                                            command=sair,
                                            border_color="#3b3b3b")
        left.place(x=20, y=445)

def clean_fivem():
    appdata_folder = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'FiveM', 'FiveM.app')
        
    folders_to_clean = ['data', 'logs', 'crashes']

    prompt_text.config(state=NORMAL)
    prompt_text.insert(END, f"> Limpando arquivos em {appdata_folder}...\n")
    prompt_text.config(state=DISABLED)

    try:
        for folder in folders_to_clean:
            target_folder = os.path.join(appdata_folder, folder)
            if os.path.exists(target_folder):
                # Verifica se é "data" e mantém "game-storage"
                if folder == 'data':
                    sub_folder_path = os.path.join(target_folder, 'game-storage')
                    if os.path.exists(sub_folder_path):
                        # Exclui todos os arquivos, exceto "game-storage"
                        delete_command = f'del /q "{target_folder}\\*" & rmdir /s /q "{target_folder}"'
                        subprocess.run(delete_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                else:
                    # Exclui todos os arquivos dentro da pasta
                    delete_command = f'del /q "{target_folder}\\*" & rmdir /s /q "{target_folder}"'
                    subprocess.run(delete_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                prompt_text.config(state=NORMAL)
                prompt_text.insert(END, f"> Pasta {target_folder} limpa com sucesso.\n")
                prompt_text.see(END)
                prompt_text.config(state=DISABLED)
            else:
                prompt_text.config(state=NORMAL)
                prompt_text.insert(END, f"> A pasta {target_folder} não existe.\n")
                prompt_text.see(END)
                prompt_text.config(state=DISABLED)
    except Exception as e:
        prompt_text.config(state=NORMAL)
        prompt_text.insert(END, f"> Erro ao limpar arquivos: {str(e)}\n")
        prompt_text.see(END)
        prompt_text.config(state=DISABLED)

button_clean_fivem = customtkinter.CTkButton(rightFrame, text="CLEAN FIVEM", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=70, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#C7A36E",
                                    command=clean_fivem,
                                    border_color="#3b3b3b")
button_clean_fivem.place(x=20, y=390)

def unlick():
    targetFolder = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'DigitalEntitlements')

    if os.path.exists(targetFolder):
        prompt_text.config(state=NORMAL)
        prompt_text.insert(END, f"> Excluindo a pasta... {targetFolder}...\n")
        prompt_text.config(state=DISABLED)

        try:
            shutil.rmtree(targetFolder)
            prompt_text.config(state=NORMAL)
            prompt_text.insert(END, f"> Pasta {targetFolder} excluída com sucesso.\n")
            prompt_text.see(END)
            prompt_text.config(state=DISABLED)
        except Exception as e:
            prompt_text.config(state=NORMAL)
            prompt_text.insert(END, f"> Erro ao excluir a pasta {targetFolder}: {str(e)}\n")
            prompt_text.see(END)
            prompt_text.config(state=DISABLED)
    else:
        prompt_text.config(state=NORMAL)
        prompt_text.insert(END, f"> A pasta {targetFolder} não existe.\n")
        prompt_text.see(END)
        prompt_text.config(state=DISABLED)

button_unlink_fivem = customtkinter.CTkButton(rightFrame, text="UNLINK FIVEM", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=70, 
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="#C7A36E", 
                                    command=unlick,
                                    border_color="#3b3b3b")
button_unlink_fivem.place(x=20, y=310)

# Funções para o SPOOFER!!!

def execute_command(command):
    try:
        time.sleep(0.7)
        os.system(command)
    except Exception as e:
        print(f"Erro ao executar o comando '{command}': {e}")

def clean_valorant():
    messagebox.showwarning('SPOOFER', "AVISO! TUDO ISSO SERA FEITO MANUALMENTE\nEXCLUA TUDO QUE ESTEJA RELACIONADO A VALORANT")
    user_profile = os.path.expanduser("~")

    commands = [
        f'start {user_profile}\\AppData\\Local\\Temp',
        'start C:\\Windows\\Temp',
        f'explorer "C:\\Program Files (x86)"',
        f'explorer "C:\\Program Files"',
        f'start {user_profile}\\Documents',
        f'start {user_profile}\\AppData\\Local',
        'start C:\\ProgramData'
    ]

    for command in commands:
        execute_command(command)

def create_hwid_folder(hwid):
    local_hwid_dir = os.path.join(os.path.expandvars(r"%LOCALAPPDATA%"), '0101010', hwid)
    os.makedirs(local_hwid_dir, exist_ok=True)

def is_hwid_folder_exists(hwid):
    local_hwid_dir = os.path.join(os.path.expandvars(r"%LOCALAPPDATA%"), '0101010', hwid)
    return os.path.exists(local_hwid_dir)

def spoof_hwid():
    # Caminho para a chave MachineGuid
    machine_guid_registry_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography"

    # Caminho para a chave HwProfileGuid
    hwprofile_guid_registry_path = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001"

    try:
        # Abrir a chave MachineGuid no registro
        key_machine_guid = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, machine_guid_registry_path, 0, winreg.KEY_WRITE)

        lista_hwid = [
            'ec26da81-d4c1-4713-bfbb-fddb6a6eaccc',
            '4ef327af-a7dc-41a3-b365-424fcd4c359e',
            '0c246ede-7f29-407f-a8c2-5224b5f10b57',
            'dedee27e-90dc-4916-a0d1-2935cdbd803a',
            '8bf376aa-e178-4907-b0b4-083032571700',
            'f9982040-c487-4d6f-9a9d-c9ad9f1cb725',
            '9c92f9f5-99f2-4b59-8149-db4bc582a868'
        ]

        while True:
            # Escolher um HWID aleatoriamente da lista
            hwid = random.choice(lista_hwid)

            # Verificar se a pasta com o nome do HWID já existe em %LOCALAPPDATA%
            if not is_hwid_folder_exists(hwid):
                # Gerar um novo valor UUID para a chave MachineGuid
                new_machine_guid = str(uuid.uuid4())

                # Criar a pasta com o nome '0101010' em %LOCALAPPDATA% e, dentro dela, a pasta com o nome do HWID
                create_hwid_folder(hwid)

                # Modificar a entrada MachineGuid com o novo valor
                winreg.SetValueEx(key_machine_guid, "MachineGuid", 0, winreg.REG_SZ, new_machine_guid)

                # Fechar a chave do registro MachineGuid
                winreg.CloseKey(key_machine_guid)

                # Abrir a chave HwProfileGuid no registro
                key_hwprofile_guid = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, hwprofile_guid_registry_path, 0, winreg.KEY_WRITE)

                # Modificar a entrada HwProfileGuid com o valor do HWID
                winreg.SetValueEx(key_hwprofile_guid, "HwProfileGuid", 0, winreg.REG_SZ, "{" + hwid + "}")

                # Fechar a chave do registro HwProfileGuid
                winreg.CloseKey(key_hwprofile_guid)

                print(f"Pasta '0101010' criada em %LOCALAPPDATA%.")
                print(f"Pasta '{hwid}' criada dentro da pasta '0101010'.")
                print(f"Chave 'MachineGuid' alterada com sucesso para: {new_machine_guid}")
                print(f"Chave 'HwProfileGuid' alterada com sucesso para: {{{hwid}}}")
                messagebox.showinfo('Spoofer', "DONE")
                break

    except Exception as e:
        print("Erro ao criar pasta ou alterar as entradas no registro:", str(e))

def vpn():
    os.system("start https://cdn.discordapp.com/attachments/1083214209174737008/1135344092604272681/OperaGXSetup.exe")
    os.system("start https://apps.microsoft.com/store/detail/vpn-unlimited%C2%AE/9NRQBLR605RG?hl=pt-br&gl=br&rtc=1")

def spoof_disk():
    messagebox.showwarning('Spoofer', "AO PRESSIONAR OK, UM SCRIPT NO CMD ABERTO SERÁ EXECUTADO.\n O APP FICARÁ SEM RESPONDER ATÉ VOCÊ COMPLETAR A AÇÃO")
    commands =[
        r'@echo off',
        r'''move "C:\HWID Bypass\STEP 4 - Change your Disk's Serial NumberID\_\Volumeid.exe" "C:\" >nul''',
        r'''move "C:\HWID Bypass\STEP 4 - Change your Disk's Serial NumberID\_\Volumeid64.exe" "C:\" >nul''',
        r'echo Volume ID Files were moved to C: drive',
        r'@Echo Off',
        r'Setlocal EnableDelayedExpansion',
        r'Set _RNDLength=4',
        r'Set _Alphanumeric=0123456789ABCDEF',
        r'Set _Str=%_Alphanumeric%987654321',
        r':_LenLoop',
        r'IF NOT "%_Str:~18%"=="" SET _Str=%_Str:~9%& SET /A _Len+=9& GOTO :_LenLoop',
        r'SET _tmp=%_Str:~9,1%',
        r'SET /A _Len=_Len+_tmp',
        r'Set _count=0',
        r'SET _RndAlphaNum=',
        r':_loop',
        r'Set /a _count+=1',
        r'SET _RND=%Random%',
        r'Set /A _RND=_RND%%%_Len%',
        r'SET _RNDZ=%Random%',
        r'Set /A _RNDZ=_RNDZ%%%_Len%',
        r'SET _RndAlphaNum=!_RndAlphaNum!!_Alphanumeric:~%_RND%,1!',
        r'SET _RndAlphaNumz=!_RndAlphaNumz!!_Alphanumeric:~%_RNDZ%,1!',
        r'If !_count! lss %_RNDLength% goto _loop',
        r'@echo off',
        r'@echo ----------------------------------------------------------------------------------------------------------------',
        r'@echo ----------------------------------------------------------------------------------------------------------------',
        r'@echo Below you can see a full list with all your drives: '
        r'fsutil fsinfo drives',
        r'@echo ----------------------------------------------------------------------------------------------------------------',
        r'@echo ----------------------------------------------------------------------------------------------------------------',
        r'set /p drive= Which drive ID do you want to change?(Just type the letter of the drive):  ',
        r''''cd c:\'''',
        r'vol %drive%:',
        r'@echo SN/IDs will be changed on next step',
        r'pause',
        r'@echo Drive %drive% id will be changed to !_RndAlphaNum!-!_RndAlphaNumz!',
        r'pause',
        r'@echo Press any key to continue:',
        r'volumeid.exe %drive%: !_RndAlphaNum!-!_RndAlphaNumz!',
        r'@echo Drive %drive% id was successfully changed to !_RndAlphaNum!-!_RndAlphaNumz!',
        r'pause'
    ]

    for command in commands:
        subprocess.run(command, shell=True)

    messagebox.showinfo('Spoofer', "DONE")

def hwids():
    messagebox.showwarning('Spoofer', "AO PRESSIONAR OK, UM SCRIPT NO CMD ABERTO SERÁ EXECUTADO.\n O APP FICARÁ SEM RESPONDER ATÉ VOCÊ COMPLETAR A AÇÃO")
    commands = [
        r'@echo off',
        r'Setlocal EnableDelayedExpansion',
        r'Set _RNDLength=2',
        r'Set _Alphanumeric=0123456789ABCDEF',
        r'Set _Str=%_Alphanumeric%987654321',
        r':_LenLoop',
        r'IF NOT "%_Str:~18%"=="" SET _Str=%_Str:~9%& SET /A _Len+=9& GOTO :_LenLoop',
        r'SET _tmp=%_Str:~9,1%',
        r'SET /A _Len=_Len+_tmp',
        r'Set _count=0',
        r'SET _RndAlphaNum=',
        r':_loop',
        r'Set /a _count+=1',
        r'SET _RNDCS=%Random%',
        r'Set /A _RNDCS=_RNDCS%%%_Len%',
        r'SET _RNDBS=%Random%',
        r'Set /A _RNDBS=_RNDBS%%%_Len%',
        r'SET _RNDPSN=%Random%',
        r'Set /A _RNDPSN=_RNDPSN%%%_Len%',
        r'SET _RNDSS=%Random%',
        r'Set /A _RNDSS=_RNDSS%%%_Len%',
        r'SET _RNDSU=%Random%',
        r'Set /A _RNDSU=_RNDSU%%%_Len%',
        r'SET _RndAlphaNumCS=!_RndAlphaNumCS!!_Alphanumeric:~%_RNDCS%,1!',
        r'SET _RndAlphaNumBS=!_RndAlphaNumBS!!_Alphanumeric:~%_RNDBS%,1!',
        r'SET _RndAlphaNumPSN=!_RndAlphaNumPSN!!_Alphanumeric:~%_RNDPSN%,1!',
        r'SET _RndAlphaNumSS=!_RndAlphaNumSS!!_Alphanumeric:~%_RNDSS%,1!',
        r'SET _RndAlphaNumSU=!_RndAlphaNumSU!!_Alphanumeric:~%_RNDSU%,1!',
        r'If !_count! lss %_RNDLength% goto _loop',
        r'@echo off',
        r'@echo ----------------------------------------------------------------------------------------------------------------',
        r'@echo ----------------------------------------------------------------------------------------------------------------',
        r'cd C:\HWID Bypass\STEP 5 - Change the HWIDs of everything\_',
        r'@echo ----------------------------------------------------------------------------------------------------------------',
        r'@echo ----------------------------------------------------------------------------------------------------------------',
        r'@echo CHANGING ALL HWIDs',
        r'@echo CS will be changed to !_RndAlphaNumCS!!_RndAlphaNumBS!!_RndAlphaNumPSN!',
        r'@echo BS will be changed to !_RndAlphaNumBS!!_RndAlphaNumPSN!!_RndAlphaNumSU!!_RndAlphaNumBS!',
        r'@echo PSN will be changed to !_RndAlphaNumPSN!!_RndAlphaNumPSN!!_RndAlphaNumPSN!!_RndAlphaNumCS!!_RndAlphaNumBS!!_RndAlphaNumPSN!!_RndAlphaNumSS!',
        r'@echo SS will be changed to !_RndAlphaNumSS!!_RndAlphaNumPSN!!_RndAlphaNumCS!!_RndAlphaNumBS!',
        r'@echo SU will be changed Automatically',
        r'pause',
        r'@echo Press any key to change all your HWIDs:',
        r'cd C:\HWID Bypass\STEP 5 - Change the HWIDs of everything\_',
        r'AMIDEWINx64.EXE /CS > nul !_RndAlphaNumCS!!_RndAlphaNumBS!!_RndAlphaNumPSN!',
        r'AMIDEWINx64.EXE /BS > nul !_RndAlphaNumBS!!_RndAlphaNumPSN!!_RndAlphaNumSU!!_RndAlphaNumBS!',
        r'AMIDEWINx64.EXE /PSN > nul !_RndAlphaNumPSN!!_RndAlphaNumPSN!!_RndAlphaNumPSN!!_RndAlphaNumCS!!_RndAlphaNumBS!!_RndAlphaNumPSN!!_RndAlphaNumSS!',
        r'AMIDEWINx64.EXE /SS > nul !_RndAlphaNumSS!!_RndAlphaNumPSN!!_RndAlphaNumCS!!_RndAlphaNumBS!',
        r'AMIDEWINx64.EXE /SU > nul AUTO',
        r'@echo CS successfully changed to !_RndAlphaNumCS!!_RndAlphaNumBS!!_RndAlphaNumPSN!',
        r'@echo BS successfully changed to !_RndAlphaNumBS!!_RndAlphaNumPSN!!_RndAlphaNumSU!!_RndAlphaNumBS!',
        r'@echo PSN successfully changed to !_RndAlphaNumPSN!!_RndAlphaNumPSN!!_RndAlphaNumPSN!!_RndAlphaNumCS!!_RndAlphaNumBS!!_RndAlphaNumPSN!!_RndAlphaNumSS!',
        r'@echo SS successfully changed to !_RndAlphaNumSS!!_RndAlphaNumPSN!!_RndAlphaNumCS!!_RndAlphaNumBS!',
        r'@echo SU changed Automatically',
        r'pause',
        r'@echo ALL HWID IDs Have Been Changed',
    ]

    for command in commands:
        subprocess.run(command, shell=True)

    messagebox.showinfo('Spoofer', "DONE")

def create_mac_folder(hwid):
    # Obter o diretório Local do usuário (AppData\Local)
    local_dir = os.path.expandvars(r"%LOCALAPPDATA%")
        
    # Criar o diretório '823756' dentro do diretório Local
    local_hwid_dir = os.path.join(local_dir, '823756')
    os.makedirs(local_hwid_dir, exist_ok=True)
        
    # Criar uma pasta com o nome do HWID dentro do diretório '823756'
    hwid_dir = os.path.join(local_hwid_dir, hwid)
    os.makedirs(hwid_dir, exist_ok=True)

def spoofer_mac():
    # Caminho
    registry_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001"
        
    try:
        # Abrir a chave no registro
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_WRITE)

        lista_hwid = [
            '00E04D82242D', # 0
            '4281D5B7EED7', # 1
            '02BA259DBB12', # 2
            '7361B0C0B8C6', # 3
            '7CBCC4D75122', # 4
            '2EFC9AF89281', # 5
            '31F4A764D3E4' # 6
        ]
            
        # Loop para encontrar um HWID que ainda não tenha sido usado como nome de pasta
        while True:
            hwid = random.choice(lista_hwid)

            # Verificar se a pasta com o nome do HWID já existe no diretório Local
            local_hwid_dir = os.path.join(os.path.expandvars(r"%LOCALAPPDATA%"), '823756', hwid)
            if not os.path.exists(local_hwid_dir):
                # Se a pasta não existe, criar a estrutura de diretórios
                create_mac_folder(hwid)
                # Valor que será atribuído à entrada NetworkAddress
                value_data = hwid
                    
                # Criar a entrada NetworkAddress com o valor atribuído
                winreg.SetValueEx(key, "NetworkAddress", 0, winreg.REG_SZ, value_data)
                    
                # Fechar a chave do registro
                winreg.CloseKey(key)
                    
                print("Entrada 'NetworkAddress' criada com sucesso no registro e pasta criada no diretório Local.")
                messagebox.showinfo('Spoofer', "DONE")
                break
    except Exception as e:
        print("Erro ao criar a entrada no registro ou pasta:", str(e))

def account():
    messagebox.showwarning('Spoofer', "NÃO MEXA NO TECLADO E NEM NO MOUSE")
    pyautogui.press('win')
    time.sleep(0.5)
    pyautogui.write("opera")
    time.sleep(0.5)
    pyautogui.press('Enter')
    time.sleep(3)
    messagebox.showinfo('Spoofer', "PRESSIONE OK QUANDO JA TIVER ATIVADO O VPN")
    pyautogui.write("https://auth.riotgames.com/login#client_id=prod-xsso-riotgames&code_challenge=VOYca7eYf9VgII3srdkszRFk7QKZbjfY4xug-mu_Bi8&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fxsso.riotgames.com%2Fredirect&response_type=code&scope=openid%20account%20email&state=bdcf507adfa5bdadf93f87d91f")
    time.sleep(1.5)
    pyautogui.press('Enter')

def windows_spoofer():
    spoof_window = customtkinter.CTk()
    spoof_window.geometry("1080x570")
    spoof_window.config(bg="#000000")
    spoof_window.title("Alfino's Otimization v2.1 - Spoofer")
    spoof_window.resizable(False ,False)
    center_window(spoof_window, 1080, 570)

    left_frame = customtkinter.CTkFrame(spoof_window, width=140, height=570, fg_color="gray", bg_color="gray")
    left_frame.place(x=0, y=0)

    right_frame = customtkinter.CTkFrame(spoof_window, width= 1080, height=570, fg_color="black", bg_color="gray", corner_radius=0)
    right_frame.place(x=140, y=0)

    def show_valorant_frame():
        button_valorant_clean = customtkinter.CTkButton(right_frame, text="CLEAN VALORANT", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="#242424", command=clean_valorant)
        button_valorant_clean.place(x=10, y=5)

        button_hwid = customtkinter.CTkButton(right_frame, text="SPOOF HWID", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="#242424", command=spoof_hwid)
        button_hwid.place(x=10, y=40)

        button_vpn = customtkinter.CTkButton(right_frame, text="DOWNLOAD OPERAGX\n(VPN)", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="#242424", command=vpn)
        button_vpn.place(x=10, y=75)

        button_disk = customtkinter.CTkButton(right_frame, text="SPOOF DISK SERIAL NUMBER", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="#242424", command=spoof_disk)
        button_disk.place(x=150, y=5)

        button_allhwids = customtkinter.CTkButton(right_frame, text="SPOOF ALL HWIDs", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="#242424", command=hwids)
        button_allhwids.place(x=150, y=40)

        button_mac = customtkinter.CTkButton(right_frame, text="SPOOF MAC", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="#242424", command=spoofer_mac)
        button_mac.place(x=150, y=75)

        button_account = customtkinter.CTkButton(right_frame, text="CREATE AN ACCOUNT", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="#242424", command=account)
        button_account.place(x=70, y=120)

        label_spoofer = customtkinter.CTkLabel(right_frame, text="S P O O F E R", font=('Arial', 60), fg_color="black", text_color="gray")
        label_spoofer.place(x=25, y=500)

        label_valorant = customtkinter.CTkLabel(right_frame, text="V A L O R A N T", font=('Arial', 60), fg_color="black", text_color="red")
        label_valorant.place(x=445, y=500)

    button_valorant = customtkinter.CTkButton(left_frame, text="SPOOFER VALORANT", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="#9e1313", command=show_valorant_frame)
    button_valorant.place(x=6, y=5)

    button_fivem = customtkinter.CTkButton(left_frame, text="SPOOFER FIVEM\n(currently unavailable)", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="orange")
    button_fivem.place(x=6, y=40)

    def sair():
        spoof_window.destroy()

    button_exit = customtkinter.CTkButton(left_frame, text="Exit", fg_color="#6b6e73", width=120, corner_radius=0, hover_color="gray", text_color="#242424", command=sair)
    button_exit.place(x=10, y=95)

    spoof_window.mainloop()

button_spoofer_fivem = customtkinter.CTkButton(rightFrame, text="SPOOFER OPTIONS", 
                                    font=('Poppins', 24), 
                                    width=500, 
                                    height=70,
                                    fg_color="#242424", 
                                    corner_radius=0, 
                                    border_spacing=2, 
                                    border_width=3, 
                                    hover_color="#3b3b3b", 
                                    text_color="red", 
                                    command=windows_spoofer,
                                    border_color="#3b3b3b")
button_spoofer_fivem.place(x=20, y=470)

# Imgs
img1 = PhotoImage(file=r"fivem.png")

img_fivem = customtkinter.CTkLabel(rightFrame, text="", image=img1)
img_fivem.place(x=150, y=60)

# Check Box
checkbox = customtkinter.CTkCheckBox(leftFrame, text="Ativar prompt", fg_color="#242424", hover_color="#3b3b3b", variable=checkbox_var, command=show_prompt_window)
checkbox.place(x=90, y=500)

# Loop principal do tkinter
buttons()
app.mainloop()
