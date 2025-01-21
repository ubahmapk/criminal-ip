from dataclasses import dataclass, field


@dataclass(slots=True)
class OpenPort:
    port: int | None = None
    is_vulnerability: bool = False
    product_name: str | None = None
    product_version: str | None = None
    protocol: str | None = None
    socket_type: str | None = None
    confirmed_time: str | None = None

    def __str__(self):
        message: str = f"Port {self.port}\n"
        message += f"Vulnerability: {self.is_vulnerability}\n"
        message += f"Product Name: {self.product_name}\n"
        message += f"Product Version: {self.product_version}\n"
        message += f"Protocol: {self.protocol}\n"
        message += f"Socket Type: {self.socket_type}\n"
        message += f"Confirmed Time: {self.confirmed_time}"

        return message


@dataclass(slots=True)
class IDSAlert:
    classification: str | None = None
    confirmed_time: str | None = None
    message: str | None = None
    source_system: str | None = None
    url: str | None = None

    def __str__(self) -> str:
        message: str = f"Classification: {self.classification}\n"
        message += f"Confirmed Time: {self.confirmed_time}\n"
        message += f"Message: {self.message}\n"
        message += f"Source System: {self.source_system}\n"
        message += f"URL: {self.url}"

        return message


@dataclass(slots=True)
class CurrentOpenedPorts:
    count: int
    data: list[OpenPort] = field(default_factory=list)


@dataclass(slots=True)
class IDSAlerts:
    count: int
    data: list[IDSAlert] = field(default_factory=list)


@dataclass(slots=True)
class Issues:
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
        message: str = f"VPN: {self.is_vpn}\n"
        message += f"Proxy: {self.is_proxy}\n"
        message += f"Cloud: {self.is_cloud}\n"
        message += f"Tor: {self.is_tor}\n"
        message += f"Hosting: {self.is_hosting}\n"
        message += f"Mobile: {self.is_mobile}\n"
        message += f"DarkWeb: {self.is_darkweb}\n"
        message += f"Scanner: {self.is_scanner}\n"
        message += f"Snort: {self.is_snort}\n"
        message += f"Anonymous VPN: {self.is_anonymous_vpn}"

        return message


@dataclass(slots=True)
class WhoisRecord:
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
        message: str = f"AS Name: {self.as_name}\n"
        message += f"AS Number: {self.as_no}\n"
        message += f"City: {self.city}\n"
        message += f"Region: {self.region}\n"
        message += f"Organization Name: {self.org_name}\n"
        message += f"Postal Code: {self.postal_code}\n"
        message += f"Latitude: {self.latitude}\n"
        message += f"Longitude: {self.longitude}\n"
        message += f"Organization Country Code: {self.org_country_code}\n"
        message += f"Confirmed Time: {self.confirmed_time}"

        return message


@dataclass(slots=True)
class Whois:
    count: int = 0
    data: list[WhoisRecord] = field(default_factory=list)


@dataclass(slots=True)
class SuspiciousInfoReport:
    abuse_record_count: int = 0
    current_opened_port: CurrentOpenedPorts | None = None
    ids: IDSAlerts | None = None
    ip: str | None = None
    issues: Issues | None = None
    representative_domain: str | None = None
    score: dict[str, str] = field(default_factory=dict)
    status: int | None = None
    whois: Whois | None = None
