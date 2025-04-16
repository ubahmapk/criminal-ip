from dataclasses import dataclass, field


@dataclass(slots=True)
class OpenPort:  # noqa: D101
    port: int | None = None
    is_vulnerability: bool = False
    product_name: str | None = None
    product_version: str | None = None
    protocol: str | None = None
    socket_type: str | None = None
    confirmed_time: str | None = None

    def __str__(self):
        message: str = (
            f"Port {self.port}\n"
            f"Vulnerability: {self.is_vulnerability}\n"
            f"Product Name: {self.product_name}\n"
            f"Product Version: {self.product_version}\n"
            f"Protocol: {self.protocol}\n"
            f"Socket Type: {self.socket_type}\n"
            f"Confirmed Time: {self.confirmed_time}"
        )

        return message


@dataclass(slots=True)
class IDSAlert:  # noqa: D101
    classification: str | None = None
    confirmed_time: str | None = None
    message: str | None = None
    source_system: str | None = None
    url: str | None = None

    def __str__(self) -> str:
        message: str = (
            f"Classification: {self.classification}\n"
            f"Confirmed Time: {self.confirmed_time}\n"
            f"Message: {self.message}\n"
            f"Source System: {self.source_system}\n"
            f"URL: {self.url}"
        )

        return message


@dataclass(slots=True)
class CurrentOpenedPorts:  # noqa: D101
    count: int
    data: list[OpenPort] = field(default_factory=list)


@dataclass(slots=True)
class IDSAlerts:  # noqa: D101
    count: int
    data: list[IDSAlert] = field(default_factory=list)


@dataclass(slots=True)
class Issues:  # noqa: D101
    is_vpn: bool = False
    is_proxy: bool = False
    is_cloud: bool = False
    is_tor: bool = False
    is_hosting: bool = False
    is_mobile: bool = False
    is_darkweb: bool = False
    is_scanner: bool = False
    is_snort: bool = False
    is_anonymous_vpn: bool = False

    def __str__(self) -> str:
        message: str = (
            f"VPN: {self.is_vpn}\n"
            f"Proxy: {self.is_proxy}\n"
            f"Cloud: {self.is_cloud}\n"
            f"Tor: {self.is_tor}\n"
            f"Hosting: {self.is_hosting}\n"
            f"Mobile: {self.is_mobile}\n"
            f"DarkWeb: {self.is_darkweb}\n"
            f"Scanner: {self.is_scanner}\n"
            f"Snort: {self.is_snort}\n"
            f"Anonymous VPN: {self.is_anonymous_vpn}"
        )

        return message


@dataclass(slots=True)
class WhoisRecord:  # noqa: D101
    as_name: str | None = None
    as_no: int | None = None
    city: str | None = None
    region: str | None = None
    org_name: str | None = None
    postal_code: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    org_country_code: str | None = None
    confirmed_time: str | None = None

    def __str__(self) -> str:
        message: str = (
            f"AS Name: {self.as_name}\n"
            f"AS Number: {self.as_no}\n"
            f"City: {self.city}\n"
            f"Region: {self.region}\n"
            f"Organization Name: {self.org_name}\n"
            f"Postal Code: {self.postal_code}\n"
            f"Latitude: {self.latitude}\n"
            f"Longitude: {self.longitude}\n"
            f"Organization Country Code: {self.org_country_code}\n"
            f"Confirmed Time: {self.confirmed_time}"
        )

        return message


@dataclass(slots=True)
class Whois:  # noqa: D101
    count: int = 0
    data: list[WhoisRecord] = field(default_factory=list)


@dataclass(slots=True)
class SuspiciousInfoReport:  # noqa: D101
    abuse_record_count: int = 0
    current_opened_port: CurrentOpenedPorts | None = None
    ids: IDSAlerts | None = None
    ip: str | None = None
    issues: Issues | None = None
    representative_domain: str | None = None
    score: dict[str, str] = field(default_factory=dict)
    status: int | None = None
    whois: Whois | None = None
