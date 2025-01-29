import socket
import typer
import psutil
from rich.panel import Panel
from rich.text import Text
from rich.console import Console
from rich.table import Table
from enum import Enum
import httpx
import speedtest

app = typer.Typer()
console = Console()


class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    RAW = "RAW"
    RDM = "RDM"
    SCTP = "SCTP"
    UNKNOWN = "UNKNOWN"


def get_proto_from_stype(ptype: socket.SocketKind) -> Protocol:
    match ptype:
        case socket.SOCK_STREAM:
            proto = Protocol.TCP
        case socket.SOCK_DGRAM:
            proto = Protocol.UDP
        case socket.SOCK_RAW:
            proto = Protocol.RAW
        case socket.SOCK_RDM:
            proto = Protocol.RDM
        case socket.SOCK_SEQPACKET:
            proto = Protocol.SCTP
        case _:
            proto = Protocol.UNKNOWN

    return proto


def get_addr_str(conn) -> tuple[str, str]:
    if not conn.laddr:
        laddr = "-"
    elif hasattr(conn.laddr, "ip"):
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
    else:
        laddr = f"{conn.laddr[0]}:{conn.laddr[1]}"

    if not conn.raddr:
        raddr = "-"
    elif hasattr(conn.raddr, "ip"):
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}"
    else:
        raddr = f"{conn.raddr[0]}:{conn.raddr[1]}"

    return laddr, raddr


def create_conns_table():
    table = Table(
        title="[bold cyan]Network Connections[/bold cyan]",
        show_lines=True,
        header_style="bold",
        border_style="bright_blue",
        title_style="bold",
    )

    table.add_column("Protocol", style="bold yellow")
    table.add_column("L-Address", style="bold green")
    table.add_column("R-Address", style="bold green")
    table.add_column("Status", style="bold magenta")
    table.add_column("PID", style="bold cyan", justify="right")
    table.add_column("P-Name", style="bold red")

    return table


@app.command()
def conns(
    protocol: str = typer.Option(
        None, "--proto", help="Filter by protocol (TCP, UDP, etc.)"
    ),
    port: int = typer.Option(None, help="Filter by exact port"),
    pid: int = typer.Option(None, help="Filter by PID"),
    status: str = typer.Option(
        None, help="Filter by status (LISTEN, ESTABLISHED, etc.)"
    ),
    ipv4_only: bool = typer.Option(False, "--ipv4", help="Only show IPv4 connections"),
    ipv6_only: bool = typer.Option(False, "--ipv6", help="Only show IPv6 connections"),
):
    """
    Display a detailed list of active network connections on your system.
    """
    if ipv4_only and ipv6_only:
        console.print(
            Panel.fit(
                Text(
                    "Parameters ipv4-only and ipv6-only are incompatible",
                    style="bold red",
                ),
                title="[ERROR]",
                border_style="red",
            )
        )
        return

    connections = psutil.net_connections()
    if not connections:
        console.print(
            Panel.fit(
                Text("No active connections found", style="yellow"),
                title="[WARNING]",
                border_style="yellow",
            )
        )
        return

    table = create_conns_table()

    for conn in connections:
        if ipv4_only and conn.family != socket.AF_INET:
            continue
        if ipv6_only and conn.family != socket.AF_INET6:
            continue

        stype = conn.type
        conn_protocol = get_proto_from_stype(stype)

        if protocol and conn_protocol.value != protocol.upper():
            continue

        conn_status = conn.status

        if status and conn_status.upper() != status.upper():
            continue

        conn_pid = conn.pid

        if pid is not None and conn_pid != pid:
            continue

        try:
            pname = psutil.Process(conn_pid).name() if conn_pid else "-"
        except psutil.NoSuchProcess:
            pname = "-"

        conn_pid_str = str(conn_pid) if conn_pid else "-"

        if port is not None:
            local_port = conn.laddr.port if conn.laddr else None
            remote_port = conn.raddr.port if conn.raddr else None
            if local_port != port and remote_port != port:
                continue

        laddr, raddr = get_addr_str(conn)

        table.add_row(
            conn_protocol.value, laddr, raddr, conn_status, conn_pid_str, pname
        )

    console.print(table)


@app.command()
def ip():
    """
    Display your public IP and geolocation information.
    """
    try:
        url = "https://ipinfo.io/json"
        response = httpx.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        console.print(
            Panel.fit(
                f"[bold cyan]Public IP:[/bold cyan] {data.get('ip', 'N/A')}\n"
                f"[bold green]City:[/bold green] {data.get('city', 'N/A')}\n"
                f"[bold yellow]Region:[/bold yellow] {data.get('region', 'N/A')}\n"
                f"[bold blue]Country:[/bold blue] {data.get('country', 'N/A')}\n"
                f"[bold magenta]Location:[/bold magenta] {data.get('loc', 'N/A')}\n"
                f"[bold red]ISP:[/bold red] {data.get('org', 'N/A')}",
                title="[bold]Public IP & Geolocation[/bold]",
                border_style="blue",
            )
        )

    except httpx.HTTPStatusError as e:
        console.print(
            Panel.fit(
                Text(f"HTTP error occurred: {e}", style="bold red"),
                title="[ERROR]",
                border_style="red",
            )
        )
    except httpx.RequestError as e:
        console.print(
            Panel.fit(
                Text(f"Network error occurred: {e}", style="bold red"),
                title="[ERROR]",
                border_style="red",
            )
        )


@app.command()
def speed(
    only_upload: bool = typer.Option(False, "-u", help="Only test upload speed"),
    only_download: bool = typer.Option(False, "-d", help="Only test download speed"),
):
    """
    Measure and display both download and upload speeds.
    """
    console.print(
        Panel.fit(
            "[bold cyan]Testing internet speed... Please wait.[/bold cyan]",
            border_style="cyan",
        )
    )

    try:
        if only_upload and only_download:
            console.print(
                Panel.fit(
                    Text(
                        "Parameters only-upload and only-download are incompatible",
                        style="bold red",
                    ),
                    title="[ERROR]",
                    border_style="red",
                )
            )
            return

        st = speedtest.Speedtest()
        st.get_best_server()

        results = []

        if only_upload or not only_download:
            console.print("[bold yellow]Measuring upload speed...[/bold yellow]")
            upload_speed_mbps = st.upload() / 1_000_000
            results.append(
                f"[bold white]Upload Speed:[/bold white] {upload_speed_mbps:.2f} Mbps"
            )
        if only_download or not only_upload:
            console.print("[bold yellow]Measuring download speed...[/bold yellow]")
            download_speed_mbps = st.download() / 1_000_000
            results.append(
                f"[bold white]Download Speed:[/bold white] {download_speed_mbps:.2f} Mbps"
            )

        result_text = "\n".join(results)
        console.print(
            Panel.fit(
                result_text,
                title="[bold]Internet Speed Test[/bold]",
                border_style="green",
            )
        )

    except Exception as e:
        console.print(
            Panel.fit(
                Text(f"Error during speed test: {e}", style="bold red"),
                title="[ERROR]",
                border_style="red",
            )
        )


if __name__ == "__main__":
    app()
