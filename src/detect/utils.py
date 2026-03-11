def empty_scores(keys):
    return {key: 0 for key in keys}


def read_section_data(elf, section_name, max_bytes=262144):
    section = elf.get_section_by_name(section_name)
    if not section:
        return None

    try:
        return section.data()[:max_bytes].lower()
    except Exception as exc:
        print(f"Error reading {section_name}: {exc}")
        return None


def read_section_bytes(elf, section_name, max_bytes=262144):
    section = elf.get_section_by_name(section_name)
    if not section:
        return None

    try:
        return section.data()[:max_bytes]
    except Exception as exc:
        print(f"Error reading raw bytes from {section_name}: {exc}")
        return None


def collect_symbol_names(symtab, dynsym):
    names = set()
    for section in (symtab, dynsym):
        if not section:
            continue
        try:
            for symbol in section.iter_symbols():
                name = symbol.name.lower()
                if name:
                    names.add(name)
        except Exception as exc:
            print(f"Error collecting symbol names: {exc}")
    return names


def iter_dynamic_needed(dynamic_section):
    if not dynamic_section:
        return

    try:
        for tag in dynamic_section.iter_tags():
            if tag.entry.d_tag != "DT_NEEDED":
                continue
            yield tag.needed.lower()
    except Exception as exc:
        print(f"Error processing dynamic section: {exc}")
        return


def iter_dwarf_top_die_attributes(elf):
    try:
        has_dwarf_info = getattr(elf, "has_dwarf_info", None)
        if not callable(has_dwarf_info) or not elf.has_dwarf_info():
            return

        dwarf_info = elf.get_dwarf_info()
        for compile_unit in dwarf_info.iter_CUs():
            top_die = compile_unit.get_top_DIE()
            if not top_die:
                continue
            yield top_die.attributes
    except Exception as exc:
        print(f"Error reading DWARF info: {exc}")
        return


def normalize_dwarf_attr_value(value):
    if isinstance(value, bytes):
        return value.decode(errors="ignore")
    return value
