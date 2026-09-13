"""
Remove chunks extras de arquivos WAV que ficam ENTRE 'fmt ' e 'data'
(ex: LIST/INFO inserido pelo ffmpeg) e garante que sempre sobre um
chunk C2PA no final do arquivo.

- Chunks ANTES do 'data' que nao sejam 'fmt ' (LIST, fact, JUNK etc.)
  sao removidos -- isso e o que quebra o parser de WAV do jogo, que
  espera 'fmt ' seguido direto de 'data'.
- Chunks DEPOIS do 'data' sao preservados como estao.
- Se nao houver NENHUM chunk depois do 'data', um chunk C2PA padrao
  (extraido de um arquivo ja confirmado funcionando no jogo) e
  adicionado automaticamente.

Uso:
    python3 strip_wav_chunks.py arquivo.wav
    python3 strip_wav_chunks.py arquivo.wav saida.wav
    python3 strip_wav_chunks.py pasta_com_wavs/          # processa todos os .wav da pasta
"""

import base64
import struct
import sys
from pathlib import Path

# Chunk C2PA padrao (content-credentials) extraido de um th06_01.wav
# ja confirmado funcionando no jogo. Usado como preenchimento quando
# o wav de entrada nao tem nada depois do 'data'.
_DEFAULT_C2PA_ID = b"C2PA"

def _default_c2pa_body() -> bytes:
    return b""

def strip_wav_chunks(in_path: Path, out_path: Path) -> None:
    data = in_path.read_bytes()

    if data[0:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise ValueError(f"{in_path.name} nao e um WAV RIFF valido")

    fmt_chunk = None
    data_chunk = None
    tail_bytes = b""  # tudo que vem depois do 'data', preservado como esta

    pos = 12
    while pos < len(data):
        chunk_id = data[pos:pos + 4]
        chunk_size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        chunk_body = data[pos + 8:pos + 8 + chunk_size]
        chunk_total = 8 + chunk_size + (chunk_size % 2)

        if chunk_id == b"fmt ":
            fmt_chunk = (chunk_id, chunk_body)
        elif chunk_id == b"data":
            data_chunk = (chunk_id, chunk_body)
            tail_bytes = data[pos + chunk_total:]
            break

        pos += chunk_total

    if fmt_chunk is None or data_chunk is None:
        raise ValueError(f"{in_path.name} nao tem chunk 'fmt ' e/ou 'data'")

    def build_chunk(cid: bytes, body: bytes) -> bytes:
        size = len(body)
        padded = body + (b"\x00" if size % 2 else b"")
        return cid + struct.pack("<I", size) + padded

    if not tail_bytes:
        tail_bytes = build_chunk(_DEFAULT_C2PA_ID, _default_c2pa_body())

    new_fmt = build_chunk(*fmt_chunk)
    new_data = build_chunk(*data_chunk)
    riff_body = b"WAVE" + new_fmt + new_data + tail_bytes
    out_bytes = b"RIFF" + struct.pack("<I", len(riff_body)) + riff_body

    out_path.write_bytes(out_bytes)


def main() -> None:
    src = Path("TouhouNewClassic/wav")

    if src.is_dir():
        wavs = sorted(src.glob("*.wav"))
        if not wavs:
            print(f"Nenhum .wav encontrado em {src}")
            return
        out_dir = src / "cleaned"
        out_dir.mkdir(exist_ok=True)
        for wav in wavs:
            out = out_dir / wav.name
            try:
                strip_wav_chunks(wav, out)
                print(f"OK  {wav.name}")
            except ValueError as e:
                print(f"ERRO {wav.name}: {e}")
        print(f"\nArquivos limpos salvos em: {out_dir}")


if __name__ == "__main__":
    main()
