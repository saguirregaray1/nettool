import socket
import typer
import psutil
from rich import print
from rich.console import Console
from rich.table import Table
from enum import Enum

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
    connections = psutil.net_connections()
    if not connections:
        print("[bold red]No active connections found.")
        return

    table = Table("Protocol", "L-Address", "R-Address", "Status", "PID", "P-Name")
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
def hello():
    print("hello")


if __name__ == "__main__":
    app()
