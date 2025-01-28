from sys import stderr
from typing import Annotated

import typer
from dacite import from_dict
from httpx import Client, HTTPError
from icecream import ic
from loguru import logger
from rich import print as rprint

from criminal_ip.__version__ import __version__
from criminal_ip.datatypes import SuspiciousInfoReport


def set_logging_level(verbosity: int) -> None:
    """Set the global logging level"""

    # Default level
    log_level = "ERROR"

    if verbosity is not None:
        if verbosity == 1:
            log_level = "INFO"
        elif verbosity > 1:
            log_level = "DEBUG"

    logger.remove(0)
    # noinspection PyUnboundLocalVariable
    logger.add(stderr, level=log_level)


def print_account_info(client: Client) -> None:
    url = "/v1/user/me"
    try:
        response = client.post(url)
    except HTTPError as e:
        logger.error(f"HTTP Error: {e}")
        raise typer.Exit(1) from None

    account_info = response.json()
    ic(account_info)

    raise typer.Exit(0)


def get_full_ip_report(client: Client, ip: str) -> dict:
    url = "/v1/asset/ip/report"
    params = {"ip": ip, "full": "true"}

    try:
        response = client.get(url, params=params)
    except HTTPError as e:
        logger.error(f"HTTP Error: {e}")
        raise typer.Exit(1) from None

    return response.json()


def get_isp_summary_report(client: Client, ip: str) -> dict:
    url = "/v1/asset/ip/summary"
    params = {"ip": ip}

    try:
        response = client.get(url, params=params)
    except HTTPError as e:
        logger.error(f"HTTP Error: {e}")
        raise typer.Exit(1) from None

    return response.json()


def get_summary_ip_report(client: Client, ip: str) -> dict:
    url = "/v1/asset/ip/report/summary"
    params = {"ip": ip}

    try:
        response = client.get(url, params=params)
    except HTTPError as e:
        logger.error(f"HTTP Error: {e}")
        raise typer.Exit(1) from None

    return response.json()


def get_suspicious_info_report(client: Client, ip: str) -> SuspiciousInfoReport:
    url = "/v2/feature/ip/suspicious-info"
    params = {"ip": ip}

    try:
        response = client.get(url, params=params)
    except HTTPError as e:
        logger.error(f"HTTP Error: {e}")
        raise typer.Exit(1) from None

    suspicious_info_report: SuspiciousInfoReport = from_dict(data_class=SuspiciousInfoReport, data=response.json())

    return suspicious_info_report


def print_suspicious_info_report(report: SuspiciousInfoReport) -> None:
    """Print the results of a Suspicious Info Report"""

    print(f"IP: {report.ip}")
    print(f"Status: {report.status}")
    print(f"Score: {report.score}")
    print(f"Abuse Record Count: {report.abuse_record_count}")

    if report.ids and report.ids.count:
        print("IDS Alerts")
        print(f"IDS Alert Count: {report.ids.count}")
        for alert in report.ids.data:
            print(f"{alert}")
        print()

    if report.current_opened_port and report.current_opened_port.count > 0:
        print("Current Open Ports")
        print(f"Open Port Count: {report.current_opened_port.count}")
        for port in report.current_opened_port.data:
            print(f"{port}")
            print()

    print(f"Representative Domain: {report.representative_domain}")

    if report.whois and report.whois.count:
        print("Whois")
        print(f"Whois Count: {report.whois.count}")
        for record in report.whois.data:
            print(f"{record}")
            print()

    if report.issues:
        print("Issues")
        print(report.issues)
        print()

    return None


app = typer.Typer(add_completion=False, context_settings={"help_option_names": ["-h", "--help"]})


def version_callback(value: bool) -> None:
    if value:
        print(f"update-shodan version {__version__}")

        raise typer.Exit(0)


@app.command()
def main(
    ip: Annotated[str, typer.Argument(..., help="IP address to check")] = "",
    api_key: Annotated[
        str, typer.Option("--api-key", "-k", envvar="CRIMINAL_IP_API_KEY", help="Criminal IP API Key")
    ] = "",
    print_api_info: Annotated[bool, typer.Option("--account", "-a", help="Print account info and exit")] = False,
    verbosity: Annotated[
        int,
        typer.Option(
            "--verbose",
            "-v",
            count=True,
            help="Verbose mode. Repeat for increased verbosity",
        ),
    ] = 0,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            show_default=False,
            help="Show version and exit",
        ),
    ] = False,  # noinspection PyUnusedLocal
) -> None:
    """
    Python client for Criminal IP API

    Requires an API key from https://criminalip.io

    The API key should be provided via the CRIMINAL_IP_API_KEY environment variable.
    """

    set_logging_level(verbosity)

    base_url: str = "https://api.criminalip.io/"

    if not api_key:
        message: str = """No API key provided.

        This script requires an API key from https://criminalip.io

        The API key should be provided via the CRIMINAL_IP_API_KEY environment variable."""
        raise typer.BadParameter(message)

    headers = {
        "x-api-key": f"{api_key}",
    }

    client: Client = Client(headers=headers, base_url=base_url)

    if print_api_info:
        rprint("[green]Retrieving Account Info[/green]")
        print_account_info(client)
        return None

    if not ip:
        raise typer.BadParameter("IP address is required")

    # rprint(f"[green]Retrieving Summary IP Report for {ip}[/green]")
    # summary_ip_report: dict = get_summary_ip_report(client, ip)
    # rprint(f"[green]Retrieving Full IP Report for {ip}[/green]")
    # full_ip_report: dict = get_full_ip_report(client, ip)
    # rprint(f"[green]Retrieving ISP Summary Report for {ip}[/green]")
    # isp_summary_report: dict = get_isp_summary_report(client, ip)
    rprint(f"[green]Retrieving Suspicious Info Report for {ip}[/green]")
    report: SuspiciousInfoReport = get_suspicious_info_report(client, ip)
    print_suspicious_info_report(report)

    # ic(summary_ip_report)
    # ic(full_ip_report)
    # ic(isp_summary_report)
    # ic(suspicious_info_report)


if __name__ == "__main__":
    app()
