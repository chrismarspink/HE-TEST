"""
HWP (Hancom Office) 파일에서 평문 텍스트를 추출하는 헬퍼.

전략:
  1) pyhwp 패키지의 `hwp5txt` CLI 가 PATH 에 있으면 그것을 사용 (가장 정확).
     → pip install pyhwp
  2) 사용 불가 시 olefile + 자체 바이너리 파서로 폴백.
     HWP v5 = OLE Compound Document → BodyText/Section* 스트림 zlib 해제
     → HWP 레코드 스트림 워크 → HWPTAG_PARA_TEXT 의 UTF-16-LE 텍스트 디코드.

호출:  text = extract_hwp_text(raw_bytes)
"""

from __future__ import annotations

import io
import logging
import os
import shutil
import struct
import subprocess
import tempfile
import zlib
from typing import Optional

log = logging.getLogger("hwp")

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def extract_hwp_text(raw: bytes) -> str:
    text = _try_pyhwp_cli(raw)
    if text is not None:
        return text
    log.info("pyhwp(hwp5txt) 미사용/실패 → 자체 olefile 파서로 폴백")
    return _extract_manual(raw)


# ---------------------------------------------------------------------------
# 1) pyhwp 의 CLI (hwp5txt) 사용
# ---------------------------------------------------------------------------

_HWP5TXT_PATH: Optional[str] = None
_HWP5TXT_CHECKED = False


def _hwp5txt_path() -> Optional[str]:
    global _HWP5TXT_PATH, _HWP5TXT_CHECKED
    if _HWP5TXT_CHECKED:
        return _HWP5TXT_PATH
    _HWP5TXT_CHECKED = True
    p = shutil.which("hwp5txt") or shutil.which("hwp5txt.exe")
    if p:
        log.info("hwp5txt found at: %s", p)
    _HWP5TXT_PATH = p
    return p


def _try_pyhwp_cli(raw: bytes) -> Optional[str]:
    exe = _hwp5txt_path()
    if not exe:
        return None
    fd, tmp = tempfile.mkstemp(suffix=".hwp")
    try:
        os.write(fd, raw)
        os.close(fd)
        try:
            result = subprocess.run(
                [exe, tmp],
                capture_output=True,
                timeout=30,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("hwp5txt 실행 실패: %s", e)
            return None
        if result.returncode != 0:
            log.warning(
                "hwp5txt 비0 종료(%s): %s",
                result.returncode,
                (result.stderr or b"").decode("utf-8", errors="replace")[:200],
            )
            return None
        return result.stdout.decode("utf-8", errors="replace")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 2) olefile + 자체 바이너리 파서
# ---------------------------------------------------------------------------

# HWP v5 paragraph text record tag
HWPTAG_BEGIN = 0x10
HWPTAG_PARA_TEXT = HWPTAG_BEGIN + 0x32  # = 0x42

# 1-wchar inline 제어문자 (확장 제어구조가 아님)
_INLINE_CTRL = {0x00, 0x0A, 0x0D, 0x18, 0x1E, 0x1F}


def _extract_manual(raw: bytes) -> str:
    try:
        import olefile  # type: ignore
    except ImportError:
        log.error("olefile 미설치 — HWP 파싱 불가. pip install olefile")
        return ""

    if not olefile.isOleFile(io.BytesIO(raw)):
        log.warning("HWP 파일이 OLE 형식이 아님 (HWP v3 등 미지원)")
        return ""

    ole = olefile.OleFileIO(io.BytesIO(raw))
    try:
        compressed = _read_compression_flag(ole)
        section_paths = sorted(
            [
                e for e in ole.listdir()
                if len(e) == 2 and e[0] == "BodyText" and e[1].startswith("Section")
            ],
            key=lambda e: _section_index(e[1]),
        )
        parts = []
        for entry in section_paths:
            try:
                data = ole.openstream(entry).read()
            except Exception as e:  # noqa: BLE001
                log.warning("HWP 섹션 읽기 실패 (%s): %s", entry, e)
                continue
            if compressed:
                data = _zlib_decompress(data)
                if data is None:
                    log.warning("HWP 섹션 zlib 해제 실패 (%s)", entry)
                    continue
            parts.append(_walk_records(data))
        return "\n".join(parts).strip()
    finally:
        ole.close()


def _section_index(name: str) -> int:
    suffix = name.replace("Section", "")
    return int(suffix) if suffix.isdigit() else 0


def _read_compression_flag(ole) -> bool:
    """FileHeader 스트림의 36번째 바이트 bit0 = 압축 여부.
    못 읽으면 압축으로 가정(대부분 압축됨)."""
    try:
        header = ole.openstream("FileHeader").read()
        if len(header) > 36:
            return bool(header[36] & 0x01)
    except Exception:
        pass
    return True


def _zlib_decompress(data: bytes) -> Optional[bytes]:
    # HWP 는 raw deflate 사용 (zlib 헤더 없음, wbits=-15)
    for wbits in (-15, 15):
        try:
            return zlib.decompress(data, wbits)
        except zlib.error:
            continue
    return None


def _walk_records(data: bytes) -> str:
    """HWP v5 record stream 을 워크하며 PARA_TEXT 만 모은다."""
    pos = 0
    out = []
    n = len(data)
    while pos + 4 <= n:
        header = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        tag = header & 0x3FF
        size = (header >> 20) & 0xFFF
        if size == 0xFFF:
            if pos + 4 > n:
                break
            size = struct.unpack_from("<I", data, pos)[0]
            pos += 4
        if pos + size > n:
            break
        record = data[pos : pos + size]
        pos += size
        if tag == HWPTAG_PARA_TEXT:
            t = _decode_para_text(record)
            if t:
                out.append(t)
    return "\n".join(out)


def _decode_para_text(data: bytes) -> str:
    """UTF-16-LE 본문 + HWP 제어문자 (1-wchar inline / 8-wchar extended)."""
    pos = 0
    n = len(data)
    out = []
    while pos + 2 <= n:
        wc = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if wc < 0x20:
            if wc in _INLINE_CTRL:
                if wc == 0x0A or wc == 0x0D:
                    out.append("\n")
                # else: NUL / 0x18 (hyphen marker) / 0x1E / 0x1F — skip
            else:
                # Extended control: 8 wchar 총길이 → 추가로 7 wchar(14 byte) 건너뜀
                pos += 14
        else:
            if 0xD800 <= wc <= 0xDBFF and pos + 2 <= n:
                wc2 = data[pos] | (data[pos + 1] << 8)
                pos += 2
                if 0xDC00 <= wc2 <= 0xDFFF:
                    cp = 0x10000 + ((wc - 0xD800) << 10) + (wc2 - 0xDC00)
                    out.append(chr(cp))
                else:
                    out.append(chr(wc))
            else:
                out.append(chr(wc))
    return "".join(out)
