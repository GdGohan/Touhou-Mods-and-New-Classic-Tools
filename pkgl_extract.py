#!/usr/bin/env python3
"""
Extrator PKGL v2 - Touhou Koumakyou: New Classic (th06nc)

Novidades em relacao ao pkgl_extract.py original:

1. O keystream de 16 bytes do DIRETORIO NAO e fixo entre arquivos .dat
   diferentes (o que o comentario original ja suspeitava). Cada arquivo
   .dat parece ter seu proprio seed/keystream de diretorio. Este script
   recupera esse keystream automaticamente por analise de frequencia:
   para cada posicao i (0..15), assume-se que o byte de texto claro mais
   comum nessa posicao e 0x00 (valido porque a maior parte de cada
   entrada de diretorio e composta por campos numericos pequenos/zerados
   -- ver formato abaixo) e toma o byte mais frequente do CIFRADO nessa
   posicao como o keystream. Isso foi validado contra th06MD.dat (bate
   com o keystream fixo do script original) e contra th06ST.dat (produz
   nomes de arquivo legiveis: ecldata1.ecl, stage1.std, eff01.dds, etc).

2. No th06ST.dat, ao contrario do th06MD.dat, size1 != size2:
   size2 e o tamanho do bloco CIFRADO dentro do .dat (o que fica no
   disco), e size1 e o tamanho do conteudo DEPOIS de descomprimir. O
   conteudo cifrado, uma vez decifrado com o keystream derivado do
   crc32 (mesmo esquema SplitMix64 do script original), comeca com o
   magic de Zstandard (28 B5 2F FD) -- ou seja, o conteudo e comprimido
   com zstd, nao apenas ofuscado com XOR puro como no th06MD.dat.
   O th06MD.dat tem size1==size2 (sem compressao real), entao o script
   original funcionava nele "por acidente" (lendo size1 bytes == size2
   bytes).

3. O campo crc32 de cada entrada do diretorio, quando comparado com
   zlib.crc32() do conteudo final (jah descomprimido), NAO bate --
   nem no th06MD.dat nem no th06ST.dat -- apesar do conteudo decodificar
   corretamente (nomes/tamanhos batem, magic bytes corretos como
   "DDS ", zstd magic, etc). Isso sugere que o campo nao e um CRC32
   IEEE padrao (pode ser outra variante, ou computado sobre outra
   representacao dos dados). Tratamos esse campo apenas como SEED do
   keystream de conteudo (que esta confirmado, pois decodifica
   corretamente); o "aviso" de mismatch e apenas informativo.

Uso:
    python3 pkgl_extract_v2.py caminho/para/th06XX.dat pasta_saida/
"""

import struct
import sys
import os
import zlib
import collections

try:
    import zstandard as zstd
    _HAVE_ZSTD = True
except ImportError:
    _HAVE_ZSTD = False

MASK64 = (1 << 64) - 1
GOLDEN64 = 0x9E3779B97F4A7C15
C1 = 0xBF58476D1CE4E5B9
C2 = 0x94D049BB133111EB
GOLDEN32 = 0x9E3779B1


def splitmix64_mix(z):
    z &= MASK64
    z ^= (z >> 30)
    z = (z * C1) & MASK64
    z ^= (z >> 27)
    z = (z * C2) & MASK64
    z ^= (z >> 31)
    return z & MASK64


def keystream16_from_seed(seed32):
    """Keystream de 16 bytes usado para decifrar o CONTEUDO de cada
    entrada (seed = crc32/campo-crc32 daquela entrada). Confirmado via
    disassembly no script original."""
    seed32 &= 0xFFFFFFFF
    state1 = (((seed32 * GOLDEN32) & MASK64) + 1)
    state1 ^= (seed32 << 32)
    state1 = (state1 + GOLDEN64) & MASK64
    out1 = splitmix64_mix(state1)
    state2 = (state1 + GOLDEN64) & MASK64
    out2 = splitmix64_mix(state2)
    return struct.pack('<QQ', out1, out2)


def xor_with_keystream(buf, keystream16):
    return bytes(b ^ keystream16[i % 16] for i, b in enumerate(buf))


def recover_dir_keystream(dir_cipher):
    """Recupera o keystream de 16 bytes do DIRETORIO por analise de
    frequencia (assume que o byte de texto claro dominante em cada
    posicao mod 16 e 0x00 -- valido para os campos flags/size/offset
    zerados/pequenos do formato de entrada)."""
    counters = [collections.Counter() for _ in range(16)]
    for i, b in enumerate(dir_cipher):
        counters[i % 16][b] += 1
    return bytes(counters[i].most_common(1)[0][0] for i in range(16))


class Entry:
    def __init__(self, flags, crc32, size1, size2, offset, name):
        self.flags = flags
        self.crc32 = crc32
        self.size1 = size1   # tamanho final (apos descompressao, se houver)
        self.size2 = size2   # tamanho do bloco cifrado no disco
        self.offset = offset
        self.name = name

    def __repr__(self):
        return (f"<Entry {self.name!r} size1={self.size1} size2={self.size2} "
                f"offset={self.offset} crc32={self.crc32:08x}>")


def parse_pkgl(data: bytes):
    if data[:4] != b'PKGL':
        raise ValueError("magic invalido, nao e' um arquivo PKGL")

    dirsize = struct.unpack_from('<I', data, 4)[0]
    dir_cipher = data[8:8 + dirsize]

    dir_keystream = recover_dir_keystream(dir_cipher)
    dir_plain = xor_with_keystream(dir_cipher, dir_keystream)

    entries = []
    off = 0
    while off + 32 <= len(dir_plain):
        flags, crc32, size1, size2, offset = struct.unpack_from(
            '<HIQQQ', dir_plain, off)
        off += 2 + 4 + 8 + 8 + 8
        namelen = struct.unpack_from('<H', dir_plain, off)[0]
        off += 2
        name = dir_plain[off:off + namelen].decode('ascii', 'replace')
        off += namelen
        entries.append(Entry(flags, crc32, size1, size2, offset, name))

    return entries, dir_keystream


def extract_entry(data: bytes, entry: Entry) -> bytes:
    # o bloco no disco tem size2 bytes (tamanho comprimido/cifrado);
    # quando nao ha compressao real (ex.: th06MD.dat), size1 == size2.
    cipher = data[entry.offset: entry.offset + entry.size2]
    keystream = keystream16_from_seed(entry.crc32)
    decoded = xor_with_keystream(cipher, keystream)

    if entry.size1 != entry.size2:
        # bloco comprimido com zstd
        if not _HAVE_ZSTD:
            raise RuntimeError(
                "entrada comprimida com zstd, mas o modulo 'zstandard' "
                "nao esta instalado (pip install zstandard)")
        dctx = zstd.ZstdDecompressor()
        plain = dctx.decompress(decoded, max_output_size=entry.size1 + 4096)
    else:
        plain = decoded

    return plain


def main():

    in_path, out_dir = "TouhouNewClassic/th06ST.dat", "TouhouNewClassic/th06ST"
    data = open(in_path, 'rb').read()
    entries, dir_keystream = parse_pkgl(data)

    os.makedirs(out_dir, exist_ok=True)
    print(f"{len(entries)} entradas encontradas em {in_path}")
    print(f"keystream de diretorio recuperado: "
          f"{list(dir_keystream)}\n")

    for e in entries:
        try:
            plain = extract_entry(data, e)
        except Exception as ex:
            sys.stderr.write(f"[erro] falha ao extrair {e.name!r}: {ex}\n")
            continue
        out_path = os.path.join(out_dir, e.name)
        os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
        with open(out_path, 'wb') as f:
            f.write(plain)
        print(f"  {e.name:30s} {len(plain):9d} bytes -> {out_path}")


if __name__ == '__main__':
    main()
