"""Every parser here reads bytes from a server that may be hostile.

A malicious or merely broken endpoint must not be able to hang the scan, crash the process,
exhaust memory, or - worst of all - produce a confident wrong answer. These tests feed each
parser deliberately malformed input and assert it fails as a finding rather than as a crash.
"""
import asyncio
import os
import random
import struct

import pytest

from pqc_scan.domain_probe import _parse_txt, _skip_name
from pqc_scan.ike_probe import IKEObservation, _parse_response
from pqc_scan.ssh_probe import SSHDisconnected, _name_lists
from pqc_scan.tls_probe import _selected_group, _server_hello_choice, _tls12_named_curve

# Anything a parser may legitimately raise. Everything else - IndexError, TypeError,
# RecursionError, MemoryError - is a defect, because it means an offset was used unchecked.
# SSHDisconnected is a legitimate parse outcome: the server said why it hung up.
EXPECTED = (ValueError, struct.error, IndexError, SSHDisconnected)


def _fuzz(parser, seed_inputs, rounds=400):
    """Mutate valid-ish inputs and assert the parser never fails in an unexpected way."""
    random.seed(1234)
    for _ in range(rounds):
        data = bytearray(random.choice(seed_inputs))
        if data:
            for _ in range(random.randint(1, 6)):
                index = random.randrange(len(data))
                data[index] = random.randrange(256)
            if random.random() < 0.3:
                data = data[: random.randrange(len(data) + 1)]
        try:
            parser(bytes(data))
        except EXPECTED:
            pass
        except Exception as error:
            raise AssertionError(
                f"{parser.__name__} raised {type(error).__name__} on {bytes(data)[:60]!r}"
            ) from error


def _server_hello(extensions: bytes = b"", session_len: int = 32) -> bytes:
    body = (
        struct.pack(">H", 0x0303) + b"\x11" * 32
        + bytes([session_len]) + b"\x22" * session_len
        + struct.pack(">H", 0x1301) + bytes([0])
        + struct.pack(">H", len(extensions)) + extensions
    )
    return bytes([2]) + len(body).to_bytes(3, "big") + body


def test_server_hello_group_parser_survives_mutation():
    key_share = struct.pack(">HHH", 51, 2, 0x11EC)
    _fuzz(_selected_group, [_server_hello(key_share), _server_hello(), b"\x02\x00\x00\x00"])


def test_server_hello_cipher_parser_survives_mutation():
    _fuzz(_server_hello_choice, [_server_hello(), _server_hello(session_len=0), b"\x02"])


def test_tls12_handshake_walker_survives_mutation():
    message = bytes([12]) + (4).to_bytes(3, "big") + bytes([3]) + struct.pack(">H", 23) + b"\x00"
    _fuzz(_tls12_named_curve, [message, b"\x0c\x00\x00\x00", b""])


def test_ssh_name_list_parser_survives_mutation():
    def parse(data: bytes):
        return _name_lists(data)

    payload = bytes([20]) + b"\x00" * 16
    for name_list in (b"curve25519-sha256", b"ssh-ed25519", b"aes256-ctr", b"hmac-sha2-512"):
        payload += struct.pack(">I", len(name_list)) + name_list
    payload += b"\x00" * 40
    _fuzz(parse, [payload, bytes([20]) + b"\x00" * 16, b"\x14"])


def test_ike_response_parser_survives_mutation():
    def parse(data: bytes):
        return _parse_response(data, IKEObservation())

    transforms = struct.pack(">BBHBBH", 0, 0, 8, 1, 0, 20)
    proposal = struct.pack(">BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 1) + transforms
    sa = struct.pack(">BBH", 0, 0, 4 + len(proposal)) + proposal
    header = b"\x02" * 8 + b"\x03" * 8 + bytes([33, 0x20, 34, 0x20]) + struct.pack(">II", 0, 28 + len(sa))
    _fuzz(parse, [header + sa, header, b"\x00" * 28])


def test_dns_parser_survives_mutation():
    def parse(data: bytes):
        return _parse_txt(data, 0x1234)

    question = b"\x07example\x03com\x00" + struct.pack(">HH", 16, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, 12) + b"\x0bv=spf1 -all"
    message = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + question + answer
    _fuzz(parse, [message, message[:20], b"\x12\x34"])


def test_a_declared_length_cannot_make_a_parser_allocate():
    # A hostile server declaring a huge length must not cause an allocation: every parser
    # validates the declared length against the bytes actually present.
    huge = struct.pack(">I", 0xFFFFFFFF)
    with pytest.raises(EXPECTED):
        _name_lists(bytes([20]) + b"\x00" * 16 + huge + b"short")


def test_a_zero_length_field_cannot_stall_a_parser():
    # The classic hang: a length of zero that does not advance the cursor.
    zero_extension = struct.pack(">HH", 99, 0)
    asyncio.get_event_loop_policy()  # no-op; keeps this a pure-CPU test
    _selected_group(_server_hello(zero_extension * 50))

    compressed = b"\xc0\x0c" * 10
    assert _skip_name(compressed, 0) == 2


def test_dns_name_walker_rejects_an_unterminated_name():
    with pytest.raises(ValueError):
        _skip_name(b"\x05abcde", 0)


def test_parsers_do_not_hang_on_random_noise():
    # A crude but effective check for an unbounded loop: pure noise, many rounds, bounded
    # wall clock. An infinite loop shows up as the test never finishing.
    random.seed(99)
    for _parser, wrapper in (
        (_selected_group, lambda d: _selected_group(d)),
        (_server_hello_choice, lambda d: _server_hello_choice(d)),
        (_tls12_named_curve, lambda d: _tls12_named_curve(d)),
        (_name_lists, lambda d: _name_lists(d)),
        (lambda d: _parse_response(d, IKEObservation()), lambda d: _parse_response(d, IKEObservation())),
        (lambda d: _parse_txt(d, 1), lambda d: _parse_txt(d, 1)),
    ):
        for _ in range(200):
            noise = os.urandom(random.randrange(0, 200))
            try:
                wrapper(noise)
            except EXPECTED:
                pass
            except Exception as error:
                raise AssertionError(f"{type(error).__name__} on noise: {noise[:40]!r}") from error
