"""
System Monitoring Module
Handles CPU, RAM, disk, process monitoring
"""

import psutil
import time
from rich.console import Console
from rich.live import Live
from rich.table import Table
from datetime import datetime

console = Console()

class SystemMonitor:
    def __init__(self):
        self.console = Console()
    
    def get_status(self):
        """Get current system status"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
            
            return {
                "CPU Usage": f"{cpu_percent}%",
                "Memory Used": f"{memory.percent}%",
                "Memory (GB)": f"{memory.used / (1024**3):.2f} / {memory.total / (1024**3):.2f}",
                "Disk Used": f"{disk.percent}%",
                "Disk (GB)": f"{disk.used / (1024**3):.2f} / {disk.total / (1024**3):.2f}",
                "System Uptime": boot_time,
                "Processes Running": psutil.pids().__len__()
            }
        except Exception as e:
            return {"Error": str(e)}
    
    def monitor_realtime(self, interval=2):
        """Monitor system in real-time"""
        try:
            while True:
                table = Table(title="⏱️ Real-Time System Monitor", show_header=True, header_style="bold cyan")
                table.add_column("Metric", style="green")
                table.add_column("Value", style="yellow")
                
                status = self.get_status()
                for key, value in status.items():
                    table.add_row(key, str(value))
                
                # Live update
                with Live(table, refresh_per_second=1, console=self.console):
                    time.sleep(interval)
        except KeyboardInterrupt:
            pass
    
    def get_processes(self, limit=20):
        """Get top processes by CPU/Memory usage"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_percent'])
                    processes.append(pinfo)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by CPU usage
            processes = sorted(processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)
            return processes[:limit]
        except Exception as e:
            self.console.print(f"[red]Error getting processes: {str(e)}[/red]")
            return []
    
    def get_network_stats(self):
        """Get network interface statistics"""
        try:
            stats = psutil.net_if_stats()
            result = {}
            for interface, info in stats.items():
                result[interface] = {
                    "status": "up" if info.isup else "down",
                    "speed": f"{info.speed} Mbps" if info.speed else "unknown"
                }
            return result
        except Exception as e:
            return {"error": str(e)}
    
    def check_cpu_temperature(self):
        """Check CPU temperature (if available)"""
        try:
            temps = psutil.sensors_temperatures()
            if temps:
                return temps
            return {"status": "Temperature sensors not available"}
        except:
            return {"status": "Temperature monitoring not available"}
