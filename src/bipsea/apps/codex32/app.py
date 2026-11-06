from typing import Any

from codex32 import Codex32String

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int
from bipsea.drng import DRNG

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CANONICAL_SHARE_INDICES = "acdefghjk"
MAX_IDENTIFIER_INDEX = 2**20
# BIP93 master seeds of 16, 20, 24, 28, 32 or 64 bytes
PAYLOAD_LENS = (26, 32, 39, 45, 52, 103)


def _validate_payload_len(payload_len: int) -> None:
    if payload_len not in PAYLOAD_LENS:
        raise ValueError(f"Invalid profile-0 payload length: {payload_len}")


def _decode_header(threshold: int, identifier_index: int, share_idx: int) -> str:
    if not (0 <= identifier_index < MAX_IDENTIFIER_INDEX):
        raise ValueError(f"Identifier index must be in [0, {MAX_IDENTIFIER_INDEX})")
    if threshold not in (0, 2, 3, 4, 5, 6, 7, 8, 9):
        raise ValueError(f"Invalid codex32 threshold: {threshold}")
    if not (
        (threshold == 0 and share_idx == 0)
        or (threshold >= 2 and 1 <= share_idx <= threshold)
    ):
        raise ValueError("Share ordinal is outside the canonical initial basis")
    identifier = "".join(
        BECH32_CHARSET[(identifier_index >> shift) & 31] for shift in (15, 10, 5, 0)
    )
    share_index = ("s" + CANONICAL_SHARE_INDICES)[share_idx]
    return f"{threshold}{identifier}{share_index}"


def _payload_chars(entropy: bytes, payload_len: int, share_index: str) -> str:
    bit_len = 5 * payload_len
    byte_len, pad_len = divmod(bit_len, 8)
    drng = DRNG(entropy)

    if share_index == "s":
        payload = int.from_bytes(drng.read(byte_len), "big") << pad_len
    else:
        read_len = (bit_len + 7) // 8
        payload = int.from_bytes(drng.read(read_len), "big")
        payload >>= read_len * 8 - bit_len

    return "".join(
        BECH32_CHARSET[(payload >> shift) & 31] for shift in range(bit_len - 5, -1, -5)
    )


class Codex32App:
    name = "codex32"
    code = "93'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "payload_len",
                ("-n", "--number"),
                int,
                default=26,
                range=(26, 103),
                help="Codex32 payload length in bech32 characters (26, 32, 39, 45, 52, or 103)",
                role="number",
            ),
            Param(
                "threshold",
                ("--threshold",),
                int,
                default=0,
                help="Ordinary codex32 threshold: 0 or 2..9",
            ),
            Param(
                "share_idx",
                ("--share-idx",),
                int,
                default=0,
                help="Share ordinal in sacdefghjk: 0 for s, 1 for a, ..., 9 for k",
            ),
        ]

    def path_segments(
        self,
        index: int,
        payload_len: int = 26,
        threshold: int = 0,
        share_idx: int = 0,
        **_,
    ) -> list[str]:
        _validate_payload_len(payload_len)
        _decode_header(threshold, index, share_idx)
        return ["0'", f"{payload_len}'", f"{threshold}'", f"{index}'", f"{share_idx}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        if len(segments) != 5:
            raise ValueError(
                "Codex32 paths require profile, payload length, threshold, identifier index, and share ordinal"
            )

        profile, payload_len, threshold, identifier_index, share_idx = map(
            hardened_int, segments
        )
        if profile != 0:
            raise ValueError(f"Unsupported codex32 profile: {profile}")
        _validate_payload_len(payload_len)
        _decode_header(threshold, identifier_index, share_idx)
        return {
            "payload_len": payload_len,
            "threshold": threshold,
            "identifier_index": identifier_index,
            "share_idx": share_idx,
        }

    def apply(
        self,
        entropy: bytes,
        payload_len: int,
        identifier_index: int,
        threshold: int = 0,
        share_idx: int = 0,
        **_,
    ) -> dict[str, Any]:
        _validate_payload_len(payload_len)
        header = _decode_header(threshold, identifier_index, share_idx)
        payload = _payload_chars(entropy, payload_len, header[5])
        codex32 = Codex32String.from_unchecksummed_string(f"ms1{header}{payload}")
        return {"entropy": entropy, "application": str(codex32).lower()}

    @property
    def vectors(self) -> list[TestVector]:
        master = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
        return [
            TestVector(
                master=master,
                path="m/83696968'/93'/0'/26'/0'/550659'/0'",
                entropy="d92e0ee55a59ec6e0d5a906c47cb78f68c088df04de61e4dea96823e0c0dbb9b7d311a448ed6e2ee2a695fec8828f2f4a1ffe7613883c4d18a8c2b79b8df5ce8",
                output="ms10secrsd3hrsfh8q7fxdcckhd40erla5qqv6k77kxuk8qk",
            ),
            TestVector(
                master=master,
                path="m/83696968'/93'/0'/26'/2'/548771'/1'",
                entropy="26cb7e63dde27e32a4faca53d05467b7d5db3d39872d355b4fd32688b1141a98c0aa731e48bedc494ae46d0d4eecf5c826b514b49d3944347031b85ccb7bf913",
                output="ms12sharakkl9gzadqpmpglp0aagm6jvvwn9ufzcz7zzrh8z",
            ),
            TestVector(
                master=master,
                path="m/83696968'/93'/0'/26'/2'/548771'/2'",
                entropy="28ec528b05a74077a3224198a76a01ef8d62840545ea675263ca83b4d07784aae079a915bbc512d13b98ff85e686d12ea86f8c77b569b93f8a45c8016801a054",
                output="ms12sharc9fff6m0ntaf2j7tslw69yfjpnel3mgy293gkmff",
            ),
        ]


app = Codex32App()
