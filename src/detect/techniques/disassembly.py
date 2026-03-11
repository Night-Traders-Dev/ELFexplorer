from detect.utils import read_section_bytes


def _count(data, pattern):
    if not data:
        return 0
    return data.count(pattern)


def score_disassembly_patterns(elf, scores):
    """Disassembly-inspired opcode pattern scoring for stripped/minimal binaries.

    This is lightweight byte-pattern matching by ISA encoding, not full
    instruction decoding, and is therefore intentionally low-weight.
    """
    text = read_section_bytes(elf, ".text", max_bytes=131072)
    if not text:
        return

    machine = str(elf.header.get("e_machine", ""))

    if machine in {"EM_X86_64", "EM_386"}:
        syscall_count = _count(text, b"\x0f\x05") + _count(text, b"\xcd\x80")
        direct_call_count = _count(text, b"\xe8")
        if syscall_count >= 2 and direct_call_count <= 2:
            scores["ASM"] += 4

    if machine == "EM_AARCH64":
        svc_count = _count(text, b"\x01\x00\x00\xd4")
        if svc_count >= 2:
            scores["ASM"] += 3

    if machine == "EM_ARM":
        svc_count = _count(text, b"\x00\x00\x00\xef")
        if svc_count >= 2:
            scores["ASM"] += 3

    if machine in {"EM_RISCV", "EM_RISCV32", "EM_RISCV64"}:
        ecall_count = _count(text, b"\x73\x00\x00\x00")
        if ecall_count >= 2:
            scores["ASM"] += 3
