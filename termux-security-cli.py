#!/usr/bin/env python3
"""
🔒 Termux Security & System Monitor CLI
A comprehensive security-focused CLI tool for Termux
Author: santoislamsh-eng
Version: 1.0.0
"""

import typer
import sys
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pathlib import Path

# Import modules
from modules.system_monitor import SystemMonitor
from modules.security_audit import SecurityAudit
from modules.network_security import NetworkSecurity
from modules.crypto_utils import CryptoUtils
from modules.device_harden import DeviceHarden
from modules.threat_detection import ThreatDetection
from modules.logger import Logger

# Initialize
app = typer.Typer(help="🔒 Termux Security CLI - System monitoring & security tools")
console = Console()
logger = Logger()

# ==================== SYSTEM COMMANDS ====================
@app.command()
def system_status():
    """📊 Show quick system status"""
    monitor = SystemMonitor()
    status = monitor.get_status()
    
    table = Table(title="🔍 System Status", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="green")
    table.add_column("Value", style="yellow")
    
    for key, value in status.items():
        table.add_row(key, str(value))
    
    console.print(table)
    logger.log("system_status", "System status checked")

@app.command()
def system_monitor():
    """⏱️ Real-time system monitoring (press Ctrl+C to stop)"""
    monitor = SystemMonitor()
    try:
        monitor.monitor_realtime()
    except KeyboardInterrupt:
        console.print("\n[red]Monitoring stopped[/red]")
        logger.log("system_monitor", "Real-time monitoring stopped")

@app.command()
def system_processes():
    """🔄 List running processes"""
    monitor = SystemMonitor()
    processes = monitor.get_processes()
    
    table = Table(title="🔄 Running Processes", show_header=True, header_style="bold magenta")
    table.add_column("PID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("CPU %", style="yellow")
    table.add_column("Memory %", style="red")
    
    for proc in processes[:20]:  # Show top 20
        table.add_row(
            str(proc.get('pid')),
            proc.get('name', 'unknown'),
            f"{proc.get('cpu_percent', 0):.1f}",
            f"{proc.get('memory_percent', 0):.1f}"
        )
    
    console.print(table)
    logger.log("system_processes", f"Listed {len(processes)} processes")

# ==================== SECURITY COMMANDS ====================
@app.command()
def security_audit():
    """🛡️ Full security audit"""
    audit = SecurityAudit()
    console.print("[bold cyan]Starting security audit...[/bold cyan]")
    
    results = audit.full_audit()
    
    for category, checks in results.items():
        console.print(f"\n[bold yellow]{category}[/bold yellow]")
        for check, status in checks.items():
            icon = "✅" if status else "❌"
            console.print(f"  {icon} {check}")
    
    logger.log("security_audit", f"Security audit completed: {results}")

@app.command()
def security_permissions():
    """🔐 Check file and directory permissions"""
    audit = SecurityAudit()
    perms = audit.check_permissions()
    
    table = Table(title="🔐 Permissions Check", show_header=True, header_style="bold green")
    table.add_column("Path", style="cyan")
    table.add_column("Permissions", style="yellow")
    table.add_column("Owner", style="magenta")
    table.add_column("Status", style="red")
    
    for path, perm_info in perms.items():
        table.add_row(
            path,
            perm_info.get('mode', 'unknown'),
            perm_info.get('owner', 'unknown'),
            perm_info.get('status', 'unknown')
        )
    
    console.print(table)
    logger.log("security_permissions", "Permissions checked")

@app.command()
def security_ssh_keys():
    """🔑 Check SSH keys and manage them"""
    audit = SecurityAudit()
    ssh_info = audit.check_ssh_keys()
    
    console.print(Panel(
        f"[cyan]SSH Keys Found:[/cyan] {ssh_info.get('keys_count', 0)}\n"
        f"[cyan]Public Keys:[/cyan] {ssh_info.get('public_keys', 0)}\n"
        f"[cyan]Private Keys:[/cyan] {ssh_info.get('private_keys', 0)}\n"
        f"[yellow]Status:[/yellow] {ssh_info.get('status', 'unknown')}",
        title="🔑 SSH Key Management",
        border_style="green"
    ))
    logger.log("security_ssh_keys", f"SSH keys checked: {ssh_info}")

# ==================== NETWORK COMMANDS ====================
@app.command()
def network_scan():
    """🔍 Scan network ports and connections"""
    net_sec = NetworkSecurity()
    console.print("[bold cyan]Scanning network...[/bold cyan]")
    
    scan_results = net_sec.scan_ports()
    
    table = Table(title="🔍 Open Ports", show_header=True, header_style="bold blue")
    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("State", style="yellow")
    table.add_column("Protocol", style="magenta")
    
    for port_info in scan_results:
        table.add_row(
            str(port_info.get('port', 'unknown')),
            port_info.get('service', 'unknown'),
            port_info.get('state', 'unknown'),
            port_info.get('protocol', 'unknown')
        )
    
    console.print(table)
    logger.log("network_scan", f"Network scan completed: {len(scan_results)} ports found")

@app.command()
def network_connections():
    """🌐 Show active network connections"""
    net_sec = NetworkSecurity()
    connections = net_sec.get_connections()
    
    table = Table(title="🌐 Active Connections", show_header=True, header_style="bold cyan")
    table.add_column("Local Address", style="green")
    table.add_column("Remote Address", style="yellow")
    table.add_column("Status", style="magenta")
    table.add_column("PID", style="cyan")
    
    for conn in connections[:15]:  # Show top 15
        table.add_row(
            conn.get('local_addr', 'N/A'),
            conn.get('remote_addr', 'N/A'),
            conn.get('status', 'N/A'),
            str(conn.get('pid', 'N/A'))
        )
    
    console.print(table)
    logger.log("network_connections", f"Listed {len(connections)} connections")

@app.command()
def network_threats():
    """🚨 Check for network threats"""
    net_sec = NetworkSecurity()
    threats = net_sec.detect_threats()
    
    if threats:
        console.print("[bold red]⚠️ THREATS DETECTED![/bold red]")
        for threat in threats:
            console.print(f"  [red]●[/red] {threat}")
    else:
        console.print("[bold green]✅ No threats detected[/bold green]")
    
    logger.log("network_threats", f"Threat detection: {len(threats)} issues found")

# ==================== CRYPTO COMMANDS ====================
@app.command()
def crypto_hash_file(filepath: str):
    """🔐 Calculate file hash (SHA-256)"""
    crypto = CryptoUtils()
    try:
        file_hash = crypto.hash_file(filepath)
        console.print(f"[green]File:[/green] {filepath}")
        console.print(f"[cyan]SHA-256:[/cyan] {file_hash}")
        logger.log("crypto_hash_file", f"Hashed file: {filepath}")
    except FileNotFoundError:
        console.print(f"[red]Error: File not found - {filepath}[/red]")
        logger.log("crypto_hash_file", f"Error: File not found - {filepath}")

@app.command()
def crypto_encrypt(filepath: str, password: Optional[str] = None):
    """🔒 Encrypt a file with AES-256"""
    crypto = CryptoUtils()
    try:
        if not password:
            password = typer.prompt("Enter encryption password", hide_input=True)
        
        output_file = crypto.encrypt_file(filepath, password)
        console.print(f"[green]✅ File encrypted:[/green] {output_file}")
        logger.log("crypto_encrypt", f"Encrypted file: {filepath}")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        logger.log("crypto_encrypt", f"Error encrypting: {str(e)}")

@app.command()
def crypto_decrypt(filepath: str, password: Optional[str] = None):
    """🔓 Decrypt a file"""
    crypto = CryptoUtils()
    try:
        if not password:
            password = typer.prompt("Enter decryption password", hide_input=True)
        
        output_file = crypto.decrypt_file(filepath, password)
        console.print(f"[green]✅ File decrypted:[/green] {output_file}")
        logger.log("crypto_decrypt", f"Decrypted file: {filepath}")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        logger.log("crypto_decrypt", f"Error decrypting: {str(e)}")

@app.command()
def crypto_generate_password(
    length: int = typer.Option(16, "--length", "-l", help="Password length"),
    include_special: bool = typer.Option(True, "--special", "-s", help="Include special chars")
):
    """🔑 Generate a secure random password"""
    crypto = CryptoUtils()
    password = crypto.generate_password(length, include_special)
    
    console.print(Panel(
        f"[bold green]{password}[/bold green]",
        title="🔑 Generated Password",
        border_style="cyan"
    ))
    console.print("[yellow]📋 Copied to clipboard (if available)[/yellow]")
    logger.log("crypto_generate_password", f"Generated password of length {length}")

# ==================== HARDENING COMMANDS ====================
@app.command()
def harden_check():
    """✅ Check device hardening status"""
    harden = DeviceHarden()
    console.print("[bold cyan]Checking device hardening...[/bold cyan]")
    
    checks = harden.check_all()
    
    for check_name, result in checks.items():
        icon = "✅" if result.get('status') else "❌"
        console.print(f"{icon} {check_name}: {result.get('message', 'N/A')}")
    
    logger.log("harden_check", f"Hardening check completed: {checks}")

@app.command()
def harden_apply():
    """🛡️ Apply security hardening measures"""
    harden = DeviceHarden()
    console.print("[bold yellow]Applying hardening measures...[/bold yellow]")
    
    results = harden.apply_hardening()
    
    for action, result in results.items():
        icon = "✅" if result else "⚠️"
        console.print(f"{icon} {action}")
    
    console.print("[bold green]Hardening applied![/bold green]")
    logger.log("harden_apply", f"Hardening applied: {results}")

# ==================== THREAT DETECTION COMMANDS ====================
@app.command()
def threat_scan():
    """🚨 Scan for suspicious activity and threats"""
    threat = ThreatDetection()
    console.print("[bold cyan]Scanning for threats...[/bold cyan]")
    
    threats = threat.full_scan()
    
    if threats['found']:
        console.print(f"[bold red]⚠️ {len(threats['threats'])} THREATS DETECTED![/bold red]")
        for t in threats['threats']:
            console.print(f"  [red]●[/red] {t['type']}: {t['description']}")
    else:
        console.print("[bold green]✅ No threats detected[/bold green]")
    
    logger.log("threat_scan", f"Threat scan: {threats}")

# ==================== LOGS COMMANDS ====================
@app.command()
def logs_view(lines: int = typer.Option(20, "--lines", "-l", help="Number of lines to show")):
    """📋 View security logs"""
    logger_instance = Logger()
    logs = logger_instance.get_logs(lines)
    
    console.print(Panel(
        "\n".join(logs) if logs else "[yellow]No logs available[/yellow]",
        title="📋 Security Logs",
        border_style="blue"
    ))

@app.command()
def logs_clear():
    """🗑️ Clear all security logs"""
    if typer.confirm("Are you sure you want to clear all logs?"):
        logger_instance = Logger()
        logger_instance.clear_logs()
        console.print("[green]✅ Logs cleared[/green]")
    else:
        console.print("[yellow]Cancelled[/yellow]")

# ==================== REPORT COMMANDS ====================
@app.command()
def report_generate():
    """📊 Generate comprehensive security report"""
    console.print("[bold cyan]Generating security report...[/bold cyan]")
    
    monitor = SystemMonitor()
    audit = SecurityAudit()
    net_sec = NetworkSecurity()
    threat = ThreatDetection()
    
    report = {
        "system": monitor.get_status(),
        "security": audit.full_audit(),
        "network": net_sec.get_connections(),
        "threats": threat.full_scan()
    }
    
    console.print(Panel(
        f"[cyan]System Status:[/cyan] Complete\n"
        f"[cyan]Security Audit:[/cyan] Complete\n"
        f"[cyan]Network Analysis:[/cyan] Complete\n"
        f"[cyan]Threat Scan:[/cyan] Complete",
        title="📊 Security Report Generated",
        border_style="green"
    ))
    
    logger.log("report_generate", "Report generated")

# ==================== HELP/INFO COMMANDS ====================
@app.command()
def info():
    """ℹ️ Show CLI information"""
    console.print(Panel(
        "[bold cyan]🔒 Termux Security CLI[/bold cyan]\n"
        "[yellow]Version:[/yellow] 1.0.0\n"
        "[yellow]Author:[/yellow] santoislamsh-eng\n"
        "[yellow]Purpose:[/yellow] Security monitoring & system auditing for Termux\n\n"
        "[bold]Features:[/bold]\n"
        "  • System monitoring & processes\n"
        "  • Security auditing & permissions\n"
        "  • Network scanning & threat detection\n"
        "  • File encryption & password generation\n"
        "  • Device hardening checks\n"
        "  • Real-time threat detection\n"
        "  • Comprehensive logging",
        border_style="green",
        title="ℹ️ About"
    ))

def main():
    """Main entry point"""
    try:
        app()
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        logger.log("main", f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
