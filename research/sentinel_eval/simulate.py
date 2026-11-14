"""Seeded simulator of a small network with labelled benign and malicious entities.

An *entity* is a source IP address (network and sign-in activity), a Windows computer or a
cloud account. Each entity has one role: a benign profile or an attack family. The simulator
writes the events such a role would produce over a two-hour horizon, in the event format the
detection engine consumes.

It deliberately includes hard cases on both sides:

* benign activity that looks like an attack (a user mistyping a password, a NAT gateway with
  failed sign-ins from many users, a scheduled port scanner, administrators using PowerShell
  from Office, installers running from Temp, approved cloud changes), and
* attacks built to stay under the rules' thresholds (slow brute force, slow spraying, slow
  scanning).

The ground truth is the one the simulator wrote. It reflects the authors' assumptions about
what normal and malicious activity look like, and the rules were written by the same people, so
results measure behaviour under these assumptions and are not a false-positive rate for a real
network. See research/README.md.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

START = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)  # on a ten-minute boundary
HORIZON = 7200  # seconds

COMMON_PORTS = (53, 80, 123, 443)
SERVICE_PORTS = (22, 25, 53, 80, 110, 123, 143, 389, 443, 445, 993, 3306, 3389, 5432, 8080, 8443)

WINDOWS_SOURCE = "windows.security"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
EXPLORER = r"C:\Windows\explorer.exe"
OFFICE = {
    "winword": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "excel": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    "outlook": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    "powerpnt": r"C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE",
}
SCRIPT_HOSTS = {
    "wscript": r"C:\Windows\System32\wscript.exe",
    "cscript": r"C:\Windows\System32\cscript.exe",
    "mshta": r"C:\Windows\System32\mshta.exe",
}
WMI = r"C:\Windows\System32\wbem\WmiPrvSE.exe"

# role -> (relative weight among benign roles)
BENIGN_ROLES = {
    "workstation": 0.30,
    "forgetful_user": 0.10,
    "server": 0.08,
    "nat_gateway": 0.06,
    "scheduled_scanner": 0.03,
    "dns_resolver": 0.03,
    "ordinary_endpoint": 0.18,
    "admin_automation": 0.12,
    "installer_endpoint": 0.04,
    "approved_cloud_change": 0.04,
    "cloud_reader": 0.02,
}

# Benign roles that look like attacks to a rule. Their share of the benign population is the main
# assumption of the whole evaluation, so it is a parameter (`hard_scale`) and results are shown for two values.
HARD_ROLES = frozenset({
    "forgetful_user", "nat_gateway", "scheduled_scanner", "admin_automation",
    "installer_endpoint", "approved_cloud_change",
})


def hard_share(hard_scale: float) -> float:
    """Fraction of benign entities that are hard cases for a given scale."""
    weights = {role: w * (hard_scale if role in HARD_ROLES else 1.0) for role, w in BENIGN_ROLES.items()}
    return sum(w for role, w in weights.items() if role in HARD_ROLES) / sum(weights.values())


# attack family -> category used in the report
ATTACKS = {
    "brute_force_fast": "sign-in and network",
    "brute_force_then_success": "sign-in and network",
    "slow_brute_force": "sign-in and network",
    "password_spray": "sign-in and network",
    "slow_spray": "sign-in and network",
    "port_scan_fast": "sign-in and network",
    "port_scan_slow": "sign-in and network",
    "lateral_sweep": "sign-in and network",
    "dns_tunnel_like": "sign-in and network",
    "office_macro_powershell": "endpoint process",
    "wmi_execution": "endpoint process",
    "script_host_shell": "endpoint process",
    "dropped_binary": "endpoint process",
    "persistence_or_tampering": "endpoint change",
    "cloud_defense_evasion": "cloud",
    "cloud_iam_abuse": "cloud",
}


@dataclass
class Entity:
    entity_id: str
    role: str
    malicious: bool
    category: str


class Simulation:
    def __init__(self, seed: int, size: int, prevalence: float, hard_scale: float = 1.0) -> None:
        self.rng = random.Random(seed)  # noqa: S311 - seeded simulation, not security
        self.counter = 0
        self.events: list[dict] = []
        self.entities: list[Entity] = []
        attackers = round(size * prevalence)
        families = list(ATTACKS)
        roles = [(families[i % len(families)], True) for i in range(attackers)]
        names = list(BENIGN_ROLES)
        weights = [w * (hard_scale if role in HARD_ROLES else 1.0) for role, w in BENIGN_ROLES.items()]
        roles += [(name, False) for name in self.rng.choices(names, weights=weights, k=size - attackers)]
        self.rng.shuffle(roles)
        for index, (role, malicious) in enumerate(roles):
            category = ATTACKS.get(role, "benign")
            entity = self._entity_id(role, index)
            self.entities.append(Entity(entity, role, malicious, category))
            getattr(self, f"_{role}")(entity)

    # -- plumbing -------------------------------------------------------------------------
    def _entity_id(self, role: str, index: int) -> str:
        endpoint = role in {
            "ordinary_endpoint", "admin_automation", "installer_endpoint", "office_macro_powershell",
            "wmi_execution", "script_host_shell", "dropped_binary", "persistence_or_tampering",
        }
        cloud = role in {"approved_cloud_change", "cloud_reader", "cloud_defense_evasion", "cloud_iam_abuse"}
        if endpoint:
            return f"pc-{index:05d}"
        if cloud:
            return f"acct-{index:05d}"
        return f"10.{index // 65000}.{(index // 250) % 250}.{index % 250 + 1}"

    def _when(self, seconds: float) -> datetime:
        return START + timedelta(seconds=min(max(seconds, 0), HORIZON - 1))

    def _emit(self, entity: str, event_type: str, seconds: float, **fields) -> None:
        self.counter += 1
        event = {
            "id": f"ev{self.counter}",
            "event_time": self._when(seconds),
            "event_type": event_type,
            "src_ip": None,
            "dst_ip": None,
            "dst_port": None,
            "host_id": None,
            "username": None,
            "severity": "low",
            "attributes": {},
            "entity": entity,
        }
        event.update(fields)
        self.events.append(event)

    def _base(self, duration: float) -> float:
        return self.rng.uniform(0, max(HORIZON - duration, 1))

    def _user(self) -> str:
        return f"user{self.rng.randrange(400)}"

    def _conns(self, entity: str, count: int, ports: list[int], targets: int, start: float, span: float) -> None:
        pool = [f"192.0.2.{self.rng.randrange(1, 255)}" for _ in range(max(targets, 1))]
        for _ in range(count):
            self._emit(
                entity, "net.conn", start + self.rng.uniform(0, span),
                src_ip=entity, dst_ip=self.rng.choice(pool), dst_port=self.rng.choice(ports),
            )

    def _auth(self, entity: str, kind: str, seconds: float, user: str) -> None:
        self._emit(entity, kind, seconds, src_ip=entity, username=user)

    def _process(self, entity: str, child: str, parent: str, seconds: float) -> None:
        self._emit(
            entity, "process.start", seconds, host_id=entity,
            attributes={"source_name": WINDOWS_SOURCE, "process_name": child, "parent_process_name": parent},
        )

    def _windows_change(self, entity: str, event_type: str, seconds: float) -> None:
        self._emit(entity, event_type, seconds, host_id=entity, attributes={"source_name": WINDOWS_SOURCE})

    def _aws(self, entity: str, service: str, action: str, seconds: float) -> None:
        self._emit(
            entity, "cloud.aws.cloudtrail", seconds, host_id=entity,
            attributes={"account_id": entity, "service": service, "action": action, "cloud_status": "success"},
        )

    def _azure(self, entity: str, action: str, seconds: float) -> None:
        self._emit(
            entity, "cloud.azure.activity", seconds, host_id=entity,
            attributes={"subscription_id": entity, "action": action, "outcome": "success"},
        )

    # -- benign roles ------------------------------------------------------------------------
    def _workstation(self, e: str) -> None:
        r = self.rng
        self._conns(e, r.randint(20, 120), r.sample(COMMON_PORTS, r.randint(2, 4)), r.randint(3, 15), 0, HORIZON)
        user = self._user()
        for _ in range(r.randint(0, 2)):
            self._auth(e, "auth.failure", r.uniform(0, HORIZON), user)
        for _ in range(r.randint(1, 4)):
            self._auth(e, "auth.success", r.uniform(0, HORIZON), user)

    def _forgetful_user(self, e: str) -> None:
        r = self.rng
        self._conns(e, r.randint(20, 120), r.sample(COMMON_PORTS, r.randint(2, 4)), r.randint(3, 15), 0, HORIZON)
        user = self._user()
        moment = self._base(400)
        for _ in range(r.randint(3, 7)):
            self._auth(e, "auth.failure", moment, user)
            moment += r.uniform(10, 40)
        self._auth(e, "auth.success", moment + r.uniform(5, 30), user)

    def _server(self, e: str) -> None:
        r = self.rng
        self._conns(e, r.randint(100, 500), r.sample(SERVICE_PORTS, r.randint(3, 8)), r.randint(5, 40), 0, HORIZON)
        for _ in range(r.randint(0, 3)):
            self._auth(e, "auth.success", r.uniform(0, HORIZON), self._user())

    def _nat_gateway(self, e: str) -> None:
        r = self.rng
        self._conns(e, r.randint(400, 1500), r.sample(SERVICE_PORTS, r.randint(6, 12)), r.randint(40, 150), 0, HORIZON)
        users = [self._user() for _ in range(r.randint(6, 15))]
        for _ in range(r.randint(15, 40)):
            self._auth(e, "auth.failure", r.uniform(0, HORIZON), r.choice(users))
        for _ in range(r.randint(20, 60)):
            self._auth(e, "auth.success", r.uniform(0, HORIZON), r.choice(users))

    def _scheduled_scanner(self, e: str) -> None:
        r = self.rng
        for _ in range(r.randint(2, 4)):
            ports = r.sample(range(1, 1024), r.randint(15, 40))
            start = self._base(60)
            for port in ports:
                self._emit(e, "net.conn", start + r.uniform(0, 60), src_ip=e,
                           dst_ip=f"192.0.2.{r.randrange(1, 255)}", dst_port=port)

    def _dns_resolver(self, e: str) -> None:
        for _ in range(self.rng.randint(100, 400)):
            self._emit(e, "dns.query", self.rng.uniform(0, HORIZON), src_ip=e)

    def _ordinary_endpoint(self, e: str) -> None:
        for _ in range(self.rng.randint(1, 4)):
            self._process(e, self.rng.choice([
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r"C:\Windows\System32\notepad.exe",
                r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
            ]), EXPLORER, self.rng.uniform(0, HORIZON))

    def _admin_automation(self, e: str) -> None:
        r = self.rng
        # Legitimate automation that the process rules cannot tell from an attack by name alone.
        # It is scheduled or habitual, so it recurs several times in the period.
        choice = r.choice(["office", "wmi", "script"])
        for moment in sorted(r.uniform(0, HORIZON) for _ in range(r.randint(3, 8))):
            if choice == "office":
                self._process(e, PS, OFFICE[r.choice(list(OFFICE))], moment)
            elif choice == "wmi":
                self._process(e, r.choice([CMD, PS]), WMI, moment)
            else:
                self._process(e, PS, SCRIPT_HOSTS[r.choice(["wscript", "cscript"])], moment)

    def _installer_endpoint(self, e: str) -> None:
        folder = self.rng.choice([
            r"C:\Users\ann\AppData\Local\Temp\setup.exe",
            r"C:\Users\ann\Downloads\vendor-installer.exe",
        ])
        self._process(e, folder, EXPLORER, self.rng.uniform(0, HORIZON))

    def _approved_cloud_change(self, e: str) -> None:
        r = self.rng
        if r.random() < 0.5:
            self._aws(e, "iam.amazonaws.com", r.choice(["CreateAccessKey", "AttachUserPolicy"]), r.uniform(0, HORIZON))
        else:
            self._azure(e, "Microsoft.Authorization/roleAssignments/write", r.uniform(0, HORIZON))

    def _cloud_reader(self, e: str) -> None:
        for _ in range(self.rng.randint(1, 5)):
            self._aws(e, "ec2.amazonaws.com", "DescribeInstances", self.rng.uniform(0, HORIZON))

    # -- attack families ---------------------------------------------------------------------
    def _brute_force_fast(self, e: str) -> None:
        user = self._user()
        start = self._base(180)
        for _ in range(self.rng.randint(40, 200)):
            self._auth(e, "auth.failure", start + self.rng.uniform(0, 180), user)

    def _brute_force_then_success(self, e: str) -> None:
        user = self._user()
        start = self._base(300)
        for _ in range(self.rng.randint(12, 25)):
            self._auth(e, "auth.failure", start + self.rng.uniform(0, 240), user)
        self._auth(e, "auth.success", start + 260, user)

    def _slow_brute_force(self, e: str) -> None:
        user = self._user()
        moment = self.rng.uniform(0, 300)
        while moment < HORIZON:
            self._auth(e, "auth.failure", moment, user)
            moment += self.rng.uniform(240, 360)

    def _password_spray(self, e: str) -> None:
        start = self._base(480)
        for user in [self._user() for _ in range(self.rng.randint(10, 20))]:
            for _ in range(self.rng.randint(1, 2)):
                self._auth(e, "auth.failure", start + self.rng.uniform(0, 480), user)

    def _slow_spray(self, e: str) -> None:
        start = self._base(5400)
        for user in [self._user() for _ in range(self.rng.randint(10, 20))]:
            self._auth(e, "auth.failure", start + self.rng.uniform(0, 5400), user)

    def _port_scan_fast(self, e: str) -> None:
        start = self._base(90)
        for port in self.rng.sample(range(1, 10000), self.rng.randint(100, 600)):
            self._emit(e, "net.conn", start + self.rng.uniform(0, 90), src_ip=e,
                       dst_ip="192.0.2.10", dst_port=port)

    def _port_scan_slow(self, e: str) -> None:
        for port in self.rng.sample(range(1, 10000), self.rng.randint(60, 150)):
            self._emit(e, "net.conn", self.rng.uniform(0, HORIZON), src_ip=e,
                       dst_ip="192.0.2.10", dst_port=port)

    def _lateral_sweep(self, e: str) -> None:
        start = self._base(300)
        for index in range(self.rng.randint(40, 120)):
            self._emit(e, "net.conn", start + self.rng.uniform(0, 300), src_ip=e,
                       dst_ip=f"192.0.2.{index % 250 + 1}", dst_port=445)

    def _dns_tunnel_like(self, e: str) -> None:
        start = self._base(120)
        for _ in range(self.rng.randint(200, 600)):
            self._emit(e, "dns.query", start + self.rng.uniform(0, 120), src_ip=e)

    def _office_macro_powershell(self, e: str) -> None:
        # An attack on a computer usually shows up once or twice; a rare third try is possible.
        for _ in range(self.rng.randint(1, 3)):
            self._process(e, PS, OFFICE[self.rng.choice(list(OFFICE))], self.rng.uniform(0, HORIZON))

    def _wmi_execution(self, e: str) -> None:
        self._process(e, self.rng.choice([CMD, PS]), WMI, self.rng.uniform(0, HORIZON))

    def _script_host_shell(self, e: str) -> None:
        self._process(e, PS, SCRIPT_HOSTS[self.rng.choice(list(SCRIPT_HOSTS))], self.rng.uniform(0, HORIZON))

    def _dropped_binary(self, e: str) -> None:
        path = self.rng.choice([
            r"C:\Users\ann\AppData\Local\Temp\a1b2.exe",
            r"C:\Users\Public\update.exe",
            r"C:\Users\ann\Downloads\invoice.exe",
        ])
        self._process(e, path, self.rng.choice([EXPLORER, CMD]), self.rng.uniform(0, HORIZON))

    def _persistence_or_tampering(self, e: str) -> None:
        kind = self.rng.choice([
            "endpoint.persistence.service_install", "endpoint.persistence.scheduled_task",
            "endpoint.persistence.scheduled_task_changed", "endpoint.identity.account_created",
            "endpoint.identity.group_member_added", "endpoint.security.log_cleared",
            "endpoint.security.audit_policy_change",
        ])
        self._windows_change(e, kind, self.rng.uniform(0, HORIZON))

    def _cloud_defense_evasion(self, e: str) -> None:
        pick = self.rng.choice(["trail", "diagnostic", "nsg"])
        when = self.rng.uniform(0, HORIZON)
        if pick == "trail":
            self._aws(e, "cloudtrail.amazonaws.com", self.rng.choice(["StopLogging", "DeleteTrail"]), when)
        elif pick == "diagnostic":
            self._azure(e, "Microsoft.Insights/diagnosticSettings/delete", when)
        else:
            self._azure(e, "Microsoft.Network/networkSecurityGroups/securityRules/write", when)

    def _cloud_iam_abuse(self, e: str) -> None:
        self._aws(e, "iam.amazonaws.com", self.rng.choice(["CreateAccessKey", "AttachUserPolicy", "PutUserPolicy"]),
                  self.rng.uniform(0, HORIZON))
