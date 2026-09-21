import asyncio
import base64
import logging
import ssl
import time
from dataclasses import dataclass, field
from typing import Literal

from pqc_scan.models import Target
from pqc_scan.netutil import close_quietly
from pqc_scan.tls_probe import enumerate_groups, probe_legacy_cipher, probe_negotiated, tls_groups


class RateLimiter:
    def __init__(self, requests_per_second: float = 10.0):
        self.locks: dict[str, asyncio.Lock] = {}
        self.requests_per_second = requests_per_second
        self._rate_lock = asyncio.Lock()
        self._next_request = 0.0

    def get_lock(self, hostname: str) -> asyncio.Lock:
        if hostname not in self.locks:
            self.locks[hostname] = asyncio.Lock()
        return self.locks[hostname]

    async def wait_for_slot(self) -> None:
        if self.requests_per_second <= 0:
            return
        interval = 1.0 / self.requests_per_second
        async with self._rate_lock:
            now = asyncio.get_running_loop().time()
            delay = max(0.0, self._next_request - now)
            self._next_request = max(now, self._next_request) + interval
        if delay:
            await asyncio.sleep(delay)

@dataclass
class HostObservation:
    """Everything observed for ONE host.

    Per-host state lives here and is returned to the caller. It must never be stored on the
    collector: one collector instance serves every host in a concurrent batch, so an attribute
    would leak one host's results onto another whose probe failed earlier.
    """

    pems: list[str] = field(default_factory=list)
    tls_version: str | None = None
    cipher_suite: str | None = None
    negotiated_group: str = "unknown"
    validation_failures: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    obsolete_tls_only: bool = False
    max_supported_tls: str | None = None
    supported_groups: list[str] = field(default_factory=list)




# The STARTTLS dialects _perform_starttls actually implements. The port map is checked
# against this list, because the two used to be able to drift: port 3306 advertised
# "starttls:mysql" that no code implemented, so every MySQL target was silently unmeasured.
SUPPORTED_STARTTLS = frozenset({
    "starttls:smtp", "starttls:imap", "starttls:ldap", "starttls:postgres",
    "starttls:ftp", "starttls:pop3",
})


class ServiceUnavailable(Exception):
    """The server answered, and told us to go away.

    A 4xx or 5xx greeting - "too many connections", "usage quota exceeded", "service closing"
    - is the server declining to serve us right now. It says nothing about the endpoint's
    cryptography, so it must not be reported as a finding, and it is not a scanner defect
    either. It is a reachability condition, and naming it is the difference between a useful
    message and an IncompleteReadError the operator cannot act on.
    """


class NoTLSOffered(Exception):
    """The service is reachable and speaks its protocol, but will not upgrade to TLS.

    Distinct from a scan error: we measured the endpoint and the answer is that traffic here
    is in the clear. ISM-1139 requires TLS for these services, so it belongs in the findings.
    """


async def _read_greeting(reader: asyncio.StreamReader) -> bytes:
    """Read a multi-line RFC 959 / RFC 5321 greeting up to its final line.

    A continuation line is not always prefixed with the reply code: Rebex's FTP banner
    indents its continuation with spaces. Only a line whose first three bytes are digits
    followed by a space ends the greeting.
    """
    while True:
        line = await reader.readuntil(b"\r\n")
        if len(line) >= 4 and line[:3].isdigit() and line[3:4] == b" ":
            if line[0:1] in (b"4", b"5"):
                raise ServiceUnavailable(line.decode("utf-8", "replace").strip())
            return line

def _weak_cipher_failures(cipher_suite: str | None, error_text: str) -> list[str]:
    """Name the specific weakness so the report says why, not just that it is old."""
    failures: list[str] = []
    if "dh key too small" in error_text or "key too small" in error_text:
        failures.append("weak_dh_parameters")
    name = (cipher_suite or "").upper()
    if "NULL" in name or "EXPORT" in name or "DES40" in name:
        failures.append("null_or_export_cipher")
    elif "RC4" in name:
        failures.append("broken_stream_cipher")
    elif "3DES" in name or "DES_EDE" in name or "DES-CBC3" in name or "_DES_" in name or name.endswith("-DES-CBC-SHA"):
        failures.append("obsolete_cipher")
    return failures

class NativeTLSCollector:
    def __init__(self, timeout: float = 10.0, no_pq_probe: bool = False, verbose: bool = False):
        self.timeout = timeout
        self.no_pq_probe = no_pq_probe
        self.verbose = verbose
        self.pq_groups = [group for group in tls_groups() if "MLKEM" in group.upper()]

    def _debug_phase(self, phase: str, started: float) -> None:
        if self.verbose:
            logging.getLogger(__name__).debug(
                "%s phase=%s elapsed=%.3fs", self.__class__.__name__, phase, time.perf_counter() - started
            )

    async def _perform_starttls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, protocol: str) -> None:
        if protocol == "starttls:smtp":
            await reader.readuntil(b"\r\n")
            writer.write(b"EHLO pqc-scanner.local\r\n")
            await writer.drain()
            await _read_greeting(reader)
            writer.write(b"STARTTLS\r\n")
            await writer.drain()
            await reader.readuntil(b"\r\n")
        elif protocol == "starttls:imap":
            greeting = await reader.readuntil(b"\r\n")
            if self.verbose:
                logging.getLogger(__name__).debug("IMAP << %r", greeting)
            if not greeting.startswith(b"*"):
                raise ValueError("IMAP greeting was not received")
            if self.verbose:
                logging.getLogger(__name__).debug("IMAP >> %r", b"a1 STARTTLS\r\n")
            writer.write(b"a1 STARTTLS\r\n")
            await writer.drain()
            response = await reader.readuntil(b"\r\n")
            if self.verbose:
                logging.getLogger(__name__).debug("IMAP << %r", response)
            if not response.lower().startswith(b"a1 ok"):
                raise ValueError("IMAP STARTTLS was rejected")
        elif protocol == "starttls:ldap":
            writer.write(b"\x30\x1d\x02\x01\x01\x77\x18\x80\x16\x31.3.6.1.4.1.1466.20037")
            await writer.drain()
            response = await reader.read(4096)
            if not response or b"\x0a\x01\x00" not in response:
                raise ValueError("LDAP STARTTLS was rejected")
        elif protocol == "starttls:postgres":
            writer.write(b"\x00\x00\x00\x08\x04\xd2\x16/")
            await writer.drain()
            response = await reader.readexactly(1)
            if response != b"S":
                raise ValueError("PostgreSQL STARTTLS was rejected")
        elif protocol == "starttls:ftp":
            await _read_greeting(reader)
            writer.write(b"AUTH TLS\r\n")
            await writer.drain()
            response = await reader.readuntil(b"\r\n")
            if not response.startswith(b"234"):
                # The server answered, it just will not upgrade. That is a plaintext service,
                # which is a finding in its own right rather than a scan failure.
                raise NoTLSOffered(f"FTP server refused AUTH TLS: {response.decode(errors='replace').strip()}")
        elif protocol == "starttls:pop3":
            await reader.readuntil(b"\r\n")
            writer.write(b"STLS\r\n")
            await writer.drain()
            response = await reader.readuntil(b"\r\n")
            if not response.upper().startswith(b"+OK"):
                raise ValueError("POP3 STARTTLS was rejected")
        else:
            raise ValueError(f"unsupported_protocol: {protocol}")

    def _legacy_tls_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # ALL:COMPLEMENTOFALL reaches eNULL and aNULL; DEFAULT deliberately excludes them,
        # which is why a NULL-cipher host could not be measured at all.
        context.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.minimum_version = ssl.TLSVersion.TLSv1
        return context

    async def collect_tls(self, target: Target) -> HostObservation:
        der_certs: list[bytes] = []
        pems: list[str] = []
        errors: list[str] = []
        validation_failures: list[str] = []
        tls_version, cipher_suite, max_supported_tls = None, None, None
        negotiated_group = "unknown"
        obsolete_tls_only = False
        supported_groups: list[str] = []
        phase_name = "TLS connection"

        def observation() -> HostObservation:
            return HostObservation(
                pems=pems, tls_version=tls_version, cipher_suite=cipher_suite,
                negotiated_group=negotiated_group, validation_failures=validation_failures,
                errors=errors, obsolete_tls_only=obsolete_tls_only,
                max_supported_tls=max_supported_tls, supported_groups=supported_groups,
            )

        if target.protocol and target.protocol.startswith("starttls:") and target.protocol not in SUPPORTED_STARTTLS:
            errors.append(f"unsupported_protocol: {target.protocol}")
            return observation()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Closed in the finally below rather than on each exit path. Every branch used to
        # close it for itself, and the branches that did not - an SSLError from start_tls, a
        # failure in the certificate loop or in group enumeration - leaked the socket until
        # garbage collection. Those are precisely the weak-crypto hosts this tool exists to
        # find, so a scan of a legacy estate ran out of file descriptors.
        writer: asyncio.StreamWriter | None = None
        try:
            # Each phase below has its own timeout; there is intentionally no shared budget.
            phase_name = "TCP connect"
            phase_started = time.perf_counter()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.hostname, target.port), self.timeout
                )
            except TimeoutError:
                errors.append(f"timed out after {self.timeout}s during TCP connect")
                return observation()
            self._debug_phase("tcp_connect", phase_started)
            if writer is None:  # open_connection returns a writer or raises; this is belt and braces.
                errors.append("tcp connect returned no connection")
                return observation()
            if target.protocol and target.protocol.startswith("starttls:"):
                phase_name = "STARTTLS negotiation"
                phase_started = time.perf_counter()
                try:
                    await asyncio.wait_for(self._perform_starttls(reader, writer, target.protocol), self.timeout)
                except TimeoutError:
                    errors.append(f"timed out after {self.timeout}s during STARTTLS negotiation")
                    return observation()
                phase_name = "TLS handshake"
                phase_started = time.perf_counter()
            try:
                await asyncio.wait_for(writer.start_tls(ctx, server_hostname=target.hostname), self.timeout)
            except TimeoutError:
                errors.append(f"timed out after {self.timeout}s during TLS handshake")
                return observation()
            self._debug_phase("tls_handshake", phase_started)

            ssl_obj = writer.get_extra_info('ssl_object')
            tls_version = ssl_obj.version()
            cipher_info = ssl_obj.cipher()
            if cipher_info:
                cipher_suite = cipher_info[0]

            phase_name = "certificate chain extraction"
            phase_started = time.perf_counter()
            if hasattr(ssl_obj, 'get_unverified_chain') and ssl_obj.get_unverified_chain():
                der_certs = list(ssl_obj.get_unverified_chain())
            for der in der_certs:
                b64 = base64.b64encode(der).decode("utf-8")
                # The join is hoisted out of the f-string: a backslash inside an f-string
                # expression is a syntax error before Python 3.12, and requiring 3.13 to
                # format a PEM block is not a trade worth making.
                body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
                pems.append(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----")
            self._debug_phase("certificate_chain_extraction", phase_started)

            # Only TLS 1.3 can negotiate any of these groups, so enumerating them against
            # a TLS 1.2 server is 17 pointless connections per host. Skipping them cuts the
            # load enough to stop small servers rate-limiting us and reporting false timeouts.
            if tls_version == "TLSv1.3":
                capability_results = await enumerate_groups(
                    target.hostname, target.port, self.timeout, target.protocol, self._perform_starttls
                )
            else:
                capability_results = []
            supported_groups = [
                result.group for result in capability_results
                if result.status == "supported" and result.group
            ]

            phase_name = "native group probe"
            phase_started = time.perf_counter()
            probe = await probe_negotiated(
                target.hostname, target.port, self.timeout, target.protocol, self._perform_starttls
            )
            negotiated_group = probe.group or "unknown"
            if probe.status == "not_testable":
                errors.append(f"native_group_probe:{probe.reason or 'not_testable'}")
            self._debug_phase("native_group_probe", phase_started)

        except ServiceUnavailable as e:
            errors.append(f"service_unavailable: {e}")

        except NoTLSOffered as e:
            # Measured, not failed: the service answered and declined to encrypt. Recording
            # it as a validation failure puts it in the report where it belongs instead of
            # in the errors list where operators treat it as a scanner problem.
            validation_failures.append("no_tls_offered")
            errors.append(str(e))

        except Exception as e:
            err_str = str(e).lower()
            # Anything the strict context refused is worth one permissive retry. Hosts that
            # only speak weak crypto are the ones a readiness report most needs to name, so
            # "could not measure" is the wrong answer for them.
            weak_signals = (
                "handshake failure", "protocol version", "sslv3", "dh key too small",
                "no cipher", "unsupported protocol", "wrong signature", "excessive message size",
                "key too small", "unsafe legacy",
            )
            if any(signal in err_str for signal in weak_signals):
                fallback_writer = None
                try:
                    fb_ctx = self._legacy_tls_context()
                    _, fallback_writer = await asyncio.wait_for(
                        asyncio.open_connection(target.hostname, target.port, ssl=fb_ctx, server_hostname=target.hostname),
                        self.timeout,
                    )
                    ssl_object = fallback_writer.get_extra_info("ssl_object")
                    if ssl_object is None:
                        raise ValueError("legacy TLS fallback produced no SSL object")
                    max_supported_tls = ssl_object.version()
                    obsolete_tls_only = True
                    weak_cipher = (ssl_object.cipher() or ("unknown",))[0]
                    cipher_suite = cipher_suite or weak_cipher
                except TimeoutError:
                    errors.append(f"timed out after {self.timeout}s during legacy TLS fallback")
                except Exception as fb_e:
                    # OpenSSL 3.5 has no 3DES, RC4, NULL or EXPORT suites left in its TLS
                    # cipher list, so a host that only speaks those cannot be reached through
                    # ssl.SSLContext at all. Build the ClientHello ourselves and read the
                    # server's choice out of the ServerHello instead of giving up.
                    raw = await probe_legacy_cipher(
                        target.hostname, target.port, timeout=self.timeout,
                        protocol=target.protocol, starttls_prelude=self._perform_starttls,
                    )
                    if raw.status == "supported" and raw.cipher_suite:
                        max_supported_tls = raw.version
                        obsolete_tls_only = True
                        cipher_suite = cipher_suite or raw.cipher_suite
                    else:
                        errors.append(f"Obsolete TLS probe failed: {fb_e}")
                finally:
                    await close_quietly(fallback_writer)

            if obsolete_tls_only:
                for failure in _weak_cipher_failures(cipher_suite, err_str):
                    if failure not in validation_failures:
                        validation_failures.append(failure)

            if not obsolete_tls_only:
                if isinstance(e, asyncio.TimeoutError):
                    errors.append(f"timed out after {self.timeout}s during {phase_name}")
                else:
                    errors.append(f"{type(e).__name__}: {str(e) or 'TLS connection failed'}")

        finally:
            await close_quietly(writer)

        if not obsolete_tls_only and pems:
            strict_ctx = ssl.create_default_context()
            default_cafile = ssl.get_default_verify_paths().cafile
            if default_cafile:
                strict_ctx.load_verify_locations(cafile=default_cafile)
            strict_ctx.check_hostname = True
            strict_ctx.verify_mode = ssl.CERT_REQUIRED
            try:
                phase_started = time.perf_counter()
                sr, sw = await asyncio.wait_for(asyncio.open_connection(target.hostname, target.port), self.timeout)
                if target.protocol and target.protocol.startswith("starttls:"):
                    await asyncio.wait_for(self._perform_starttls(sr, sw, target.protocol), self.timeout)
                await asyncio.wait_for(sw.start_tls(strict_ctx, server_hostname=target.hostname), self.timeout)
                # start_tls returning IS the verification result. Teardown is not part of the
                # answer: servers that send a session ticket after close_notify (Gmail and
                # Microsoft 365 both do) made wait_closed raise, and a perfectly valid
                # certificate was reported to the operator as a scary strict_verify_error.
                self._debug_phase("strict_verify", phase_started)
                await close_quietly(sw)
            except ssl.SSLCertVerificationError as e:
                reason = str(e).lower()
                if "self-signed certificate in certificate chain" in reason:
                    validation_failures.append("untrusted_root")
                elif "self-signed certificate" in reason:
                    validation_failures.append("self_signed")
                elif "unable to get local issuer certificate" in reason:
                    validation_failures.append("incomplete_chain_or_unknown_issuer")
                elif "expired" in reason:
                    validation_failures.append("expired")
                elif "not yet valid" in reason:
                    validation_failures.append("not_yet_valid")
                elif "hostname mismatch" in reason:
                    validation_failures.append("hostname_mismatch")
                else:
                    validation_failures.append(f"verify_error:{e!s}")
            except TimeoutError:
                errors.append(f"timed out after {self.timeout}s during strict certificate verification")
            except Exception as e:
                logging.getLogger(__name__).warning("strict certificate verification failed: %s", e)
                errors.append(f"strict_verify_error:{e or 'unknown error'}")

        return observation()

    async def probe_pq_groups(
        self,
        target: Target,
        tls_version: str | None,
        already_negotiated: str,
        supported_groups: list[str] | None = None,
    ) -> tuple[list[str], Literal["supported", "not_supported", "not_determinable"], list[str]]:
        """Return (pq groups supported, status, probe errors) for ONE host.

        Stateless by design: the caller passes the capability results collected for this host
        and receives this host's errors back. Nothing is stored on the collector.
        """
        probe_errors: list[str] = []
        if self.no_pq_probe:
            return [], "not_determinable", probe_errors
        # Version is decisive on its own. Post-quantum key exchange only exists in TLS 1.3,
        # so a host that tops out below it is definitively "no PQ" even when the handshake
        # was too weak to name a group. Reporting those as "not measured" hid the hosts that
        # most need the work.
        if tls_version and tls_version not in ("TLSv1.3",):
            return [], "not_supported", probe_errors
        if not tls_version or already_negotiated == "unknown":
            return [], "not_determinable", probe_errors

        if already_negotiated in self.pq_groups:
            return [already_negotiated], "supported", probe_errors

        if supported_groups is None:
            results = await enumerate_groups(
                target.hostname, target.port, self.timeout, target.protocol, self._perform_starttls
            )
            error_counts: dict[str, int] = {}
            supported = []
            for result in results:
                if result.group in self.pq_groups and result.status == "supported":
                    supported.append(result.group)
                if result.status == "not_testable":
                    reason = f"PQ group probe {result.reason or 'not_testable'}"
                    error_counts[reason] = error_counts.get(reason, 0) + 1
            probe_errors = [
                f"{reason} (x{count})" if count > 1 else reason
                for reason, count in error_counts.items()
            ]
        else:
            supported = [group for group in supported_groups if group in self.pq_groups]

        if supported:
            return supported, "supported", probe_errors
        return [], "not_supported", probe_errors
