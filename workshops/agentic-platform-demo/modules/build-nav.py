#!/usr/bin/env python3
# Regenerates module navigation: card nav bars (top and bottom), linked "Needs" IDs,
# the README contents and per-area index, and tracks/ from "Suggested chains". Idempotent.
# Run after adding or reordering modules: python3 modules/build-nav.py modules
import os
import re
import sys


def slugify_area(area):
    # anchor = area lowercased, spaces replaced by "-", non [a-z0-9-] removed.
    s = area.lower()
    s = s.replace(' ', '-')
    s = re.sub(r'[^a-z0-9-]', '', s)
    return s


def github_anchor(heading):
    # GitHub anchor rule: lowercase, remove characters other than letters, digits, spaces and hyphens, spaces to hyphens.
    s = heading.lower()
    s = re.sub(r'[^a-z0-9 -]', '', s)
    s = s.replace(' ', '-')
    return s


def slugify_audience(audience):
    # slug from audience: lowercase, non-alnum runs to "-", strip "-"
    s = audience.lower()
    s = re.sub(r'[^a-z0-9]+', '-', s)
    s = s.strip('-')
    return s


def parse_readme_table(text, header_pat):
    # Find table with given header pattern. Return list of rows (list of cells).
    lines = text.split('\n')
    rows = []
    i = 0
    n = len(lines)
    while i < n:
        if re.match(header_pat, lines[i]):
            # next line should be separator
            if i + 1 < n and re.match(r'^\|[\s\-:|]+\|$', lines[i+1]):
                j = i + 2
                while j < n and lines[j].startswith('|'):
                    row = [c.strip() for c in lines[j].split('|')[1:-1]]
                    rows.append(row)
                    j += 1
                break
        i += 1
    return rows


def parse_link_cell(cell):
    # Parse a cell like "[G2](G2-mcp-down-scoped-saas.md)" -> ("G2", "G2-mcp-down-scoped-saas.md")
    m = re.match(r'^\[([^\]]*)\]\(([^)]*)\)$', cell)
    if m:
        return m.group(1), m.group(2)
    return cell, None


def strip_links(cell):
    # Remove [text](link) -> text
    return re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', cell)


def replace_between_markers(text, start_marker, end_marker, new_content):
    """Replace content between markers (inclusive). If missing, returns None."""
    start_idx = text.find(start_marker)
    if start_idx == -1:
        return None
    end_idx = text.find(end_marker, start_idx + len(start_marker))
    if end_idx == -1:
        return None
    end_idx += len(end_marker)
    return text[:start_idx] + new_content + text[end_idx:]


def ensure_between_markers(text, start_marker, end_marker, new_content):
    """Ensure content between markers exists. If missing, insert after the first H1 paragraph? 
    Actually we handle specific cases separately."""
    # Try replace first
    result = replace_between_markers(text, start_marker, end_marker, new_content)
    if result is not None:
        return result, True
    return text, False


def build_nav_block(prev_id, prev_file, next_id, next_file, area):
    anchor = slugify_area(area)
    parts = ["[All modules](README.md)", "[{0}](README.md#{1})".format(area, anchor)]
    if prev_id:
        parts.append("Previous: [{0}]({1})".format(prev_id, prev_file))
    if next_id:
        parts.append("Next: [{0}]({1})".format(next_id, next_file))
    nav_line = " · ".join(parts)
    return "<!-- nav:start -->\n" + nav_line + "\n<!-- nav:end -->"


def process_card_nav(text, prev_info, next_info, area):
    """prev_info and next_info are tuples (id, file) or None."""
    block = build_nav_block(
        prev_info[0] if prev_info else None,
        prev_info[1] if prev_info else None,
        next_info[0] if next_info else None,
        next_info[1] if next_info else None,
        area
    )


    lines = text.split('\n')

    # Insert after line 1: one blank line before and after the block.
    # Find first nav block to see if we need to insert one at top.
    # Actually since we replaced all existing, there may be zero or more? We want exactly two: after line1 and at end.
    # Approach: remove all nav blocks first (already replaced with block above - but that only replaces first occurrence).
    # Let's remove ALL nav blocks then insert fresh.

    # Remove all occurrences of nav blocks inclusive
    pattern = re.compile(r'<!-- nav:start -->.*?<!-- nav:end -->', re.DOTALL)
    text = pattern.sub('', text)

    lines = text.split('\n')

    # Insert block after line 1 (index 0), with one blank line before and after.
    # Block itself has no trailing newline. We insert as lines.
    block_lines = block.split('\n')
    # After line 1: we need blank line, block, blank line.
    # But if line 2 already is blank? Spec says with one blank line before and after the block. Keep everything else byte-identical otherwise.
    # We'll insert exactly.
    rest = lines[1:]
    while rest and rest[0] == '':
        rest.pop(0)
    lines = [lines[0], ''] + block_lines + [''] + rest

    # Insert at very end of file (blank line before). If text ends with newline? We keep trailing newline at end overall.
    # Append: blank line then block.
    # Remove empty trailing element from split if file ended with newline.
    while lines and lines[-1] == '':
        lines.pop()
    lines.extend([''] + block_lines)

    return '\n'.join(lines) + '\n'


def link_needs_ids(text, table_map, own_id):
    """Replace bare module IDs on **Needs:** line with links."""
    lines = text.split('\n')
    changed = False
    for i, line in enumerate(lines):
        if line.startswith("**Needs:**"):
            # Replace bare IDs not already inside [..] or a link.
            def repl(m):
                mid = m.group(1)
                # Check if already part of a markdown link: preceding char is ] and next is ( ? 
                # Better: find all existing links and skip positions inside them.
                return None  # placeholder
            # Implement position-aware replacement.
            new_line_parts = []
            pos = 0
            # Find existing link spans [text](url) to exclude.
            spans = []
            for m in re.finditer(r'\[[^\]]*\]\([^)]*\)', line):
                spans.append((m.start(), m.end()))

            def in_span(p):
                for s, e in spans:
                    if s <= p < e:
                        return True
                return False

            last = 0
            result = ''
            for m in re.finditer(r'\b([SPGALXR]\d)\b', line):
                start = m.start()
                end = m.end()
                mid = m.group(1)
                if in_span(start):
                    continue
                if mid == own_id:
                    continue
                if mid not in table_map:
                    continue
                file = table_map[mid]
                result += line[last:start] + "[" + mid + "](" + file + ")"
                last = end
            result += line[last:]
            if result != line:
                lines[i] = result
                changed = True
    return '\n'.join(lines), changed


def main():
    modules_dir = sys.argv[1]

    readme_path = os.path.join(modules_dir, 'README.md')
    with open(readme_path, encoding='utf-8') as f:
        readme_text = f.read()
    readme_original = readme_text

    # Parse Modules table: header "| ID | Area | Module | Min |"
    rows = parse_readme_table(readme_text, r'^\|\s*ID\s*\|\s*Area\s*\|\s*Module\s*\|\s*Min\s*\|$')

    modules = []  # list of dict(id, file, area, title, minutes)
    table_map = {}  # id -> file
    for row in rows:
        if len(row) < 4:
            continue
        id_cell, area_cell, module_cell, min_cell = row[0], row[1], row[2], row[3]
        mid, mfile = parse_link_cell(id_cell)
        # Title may be plain or have parentheses; keep as is.
        modules.append({
            'id': mid,
            'file': mfile,
            'area': area_cell,
            'title': module_cell,
            'minutes': min_cell.strip()
        })
        table_map[mid] = mfile

    # Process each card file for nav and needs links.
    changed_files = []
    n = len(modules)
    for idx, mod in enumerate(modules):
        fpath = os.path.join(modules_dir, mod['file'])
        if not os.path.isfile(fpath):
            continue
        with open(fpath, encoding='utf-8') as f:
            text = f.read()

        prev_info = None
        next_info = None
        if idx > 0:
            prev_info = (modules[idx-1]['id'], modules[idx-1]['file'])
        if idx < n - 1:
            next_info = (modules[idx+1]['id'], modules[idx+1]['file'])

        original_text = text
        text = process_card_nav(text, prev_info, next_info, mod['area'])
        text, needs_changed = link_needs_ids(text, table_map, mod['id'])

        if text != original_text:
            with open(fpath, 'w', encoding='utf-8') as f:
                f.write(text)
            changed_files.append(mod['file'])

    # Task 3: README per-area index and TOC.
    readme_changed = False

    # Areas in first-appearance order
    areas_order = []
    area_modules = {}
    for mod in modules:
        a = mod['area']
        if a not in area_modules:
            areas_order.append(a)
            area_modules[a] = []
        area_modules[a].append(mod)

    # Build areas block content (without markers)
    areas_content_parts = []
    for i, area in enumerate(areas_order):
        parts = ["### " + area]
        for mod in area_modules[area]:
            if mod['minutes'] == '-':
                line = "- [{0} · {1}]({2})".format(mod['id'], mod['title'], mod['file'])
            else:
                line = "- [{0} · {1}]({2}) _({3} min)_".format(mod['id'], mod['title'], mod['file'], mod['minutes'])
            parts.append(line)
        if i < len(areas_order) - 1:
            parts.append("")
        areas_content_parts.extend(parts)
    areas_content = "\n".join(areas_content_parts)

    # Insert/replace between markers <!-- areas:start --> and <!-- areas:end -->
    new_areas_block = "<!-- areas:start -->\n" + areas_content + "\n<!-- areas:end -->"

    if "<!-- areas:start -->" in readme_text:
        replaced = replace_between_markers(readme_text, "<!-- areas:start -->", "<!-- areas:end -->", new_areas_block)
        if replaced is not None and replaced != readme_text:
            readme_text = replaced
            readme_changed = True
    else:
        # Insert right after the Modules table if missing, separated by a blank line.
        # Find end of modules table: last row starting with | after header match.
        lines = readme_text.split('\n')
        insert_idx = None
        i = 0
        while i < len(lines):
            if re.match(r'^\|\s*ID\s*\|\s*Area\s*\|\s*Module\s*\|\s*Min\s*\|$', lines[i]):
                # find separator and rows
                j = i + 2
                while j < len(lines) and lines[j].startswith('|'):
                    j += 1
                insert_idx = j
                break
            i += 1
        if insert_idx is not None:
            insertion = ['', new_areas_block]
            # Insert after table, separated by blank line. If next line already blank? Add exactly one blank then block.
            lines[insert_idx:insert_idx] = ['', new_areas_block]
            readme_text = "\n".join(lines) + ("\n" if not readme_text.endswith('\n') else "")
            # normalize trailing newline handled below
            readme_text = "\n".join(lines)
            readme_changed = True

    # TOC: ## Contents section with markers <!-- toc:start -->/<!-- toc:end --> directly after first paragraph following H1 (before **Personas** line).
    # Find headings "## " in README excluding "Contents"
    lines = readme_text.split('\n')
    h1_idx = None
    for i, l in enumerate(lines):
        if l.startswith('# ') and not l.startswith('## '):
            h1_idx = i
            break

    # Find first paragraph after H1: paragraph ends at blank line. First paragraph following the H1.
    para_end = None
    if h1_idx is not None:
        j = h1_idx + 1
        while j < len(lines) and lines[j].strip() != '':
            j += 1
        # j is first blank after paragraph or end of file
        para_end = j

    # Build toc content
    toc_lines = []
    for l in lines:
        if re.match(r'^## ', l):
            heading = l[3:].strip()
            if heading == 'Contents':
                continue
            anchor = github_anchor(heading)
            toc_lines.append("- [{0}](#{1})".format(heading, anchor))
            if heading == 'Modules':
                for area in areas_order:
                    aanchor = slugify_area(area)
                    toc_lines.append("  - [{0}](#{1})".format(area, aanchor))

    toc_content = "\n".join(toc_lines)
    new_toc_block = "<!-- toc:start -->\n" + toc_content + "\n<!-- toc:end -->"

    # Check if toc block already exists and replace; else insert after first paragraph.
    if "<!-- toc:start -->" in readme_text:
        replaced = replace_between_markers(readme_text, "<!-- toc:start -->", "<!-- toc:end -->", new_toc_block)
        if replaced is not None and replaced != readme_text:
            readme_text = replaced
            readme_changed = True
    else:
        lines = readme_text.split('\n')
        # Find H1 and first paragraph end again after possible areas insertion.
        h1_idx = None
        for i, l in enumerate(lines):
            if l.startswith('# ') and not l.startswith('## '):
                h1_idx = i
                break
        para_end = None
        if h1_idx is not None:
            j = h1_idx + 1
            while j < len(lines) and lines[j].strip() == '':
                j += 1
            while j < len(lines) and lines[j].strip() != '':
                j += 1
            para_end = j
        # Insert directly after first paragraph, before **Personas** line. Spec says directly after the first paragraph following H1 (i.e., before the **Personas** line).
        if para_end is not None:
            lines[para_end:para_end] = ['', '## Contents', '', new_toc_block]
            readme_text = "\n".join(lines)
            readme_changed = True

    # Task 4 tracks
    # README has table under "## Suggested chains" with header "| Audience | Chain | Min |"
    os.makedirs(os.path.join(modules_dir, 'tracks'), exist_ok=True)

    chain_rows = parse_readme_table(readme_text, r'^\|\s*Audience\s*\|\s*Chain\s*\|\s*Min\s*\|$')
    # We need to rewrite README rows. We'll process row by row and replace in text.
    for row in chain_rows:
        if len(row) < 3:
            continue
        audience_cell, chain_cell, min_cell = row[0], row[1], row[2]
        # Audience may already be linked; parse audience text from existing link too.
        audience_text, _ = parse_link_cell(audience_cell)
        # Chain cell may contain links; strip to get IDs separated by >
        chain_plain = strip_links(chain_cell)
        ids = [s.strip() for s in chain_plain.split('>')]

        slug = slugify_audience(audience_text)
        track_file = os.path.join('tracks', slug + '.md')
        track_path = os.path.join(modules_dir, track_file)

        # Build track content
        nav_line = "[All modules](../README.md) · [All tracks](../README.md#suggested-chains)"
        lines_t = ["# Track: " + audience_text]
        lines_t.append("<!-- nav:start -->")
        lines_t.append(nav_line)
        lines_t.append("<!-- nav:end -->")
        lines_t.append("")
        # About <Min> minutes. Start with S0, then run in order.
        # Min cell may be '-'? If so omit? Spec says About <Min> minutes. Use as given.
        min_display = min_cell.strip()
        if min_display == '-':
            lines_t.append("About - minutes. Start with S0, then run in order.")
        else:
            lines_t.append("About {0} minutes. Start with S0, then run in order.".format(min_display))
        lines_t.append("")
        lines_t.append("| Step | Module | Min |")
        lines_t.append("|---|---|---|")
        for step_num, mid in enumerate(ids, 1):
            if mid not in table_map:
                # skip or include? Probably include with no link? Spec says each chain ID becomes [ID](file). If missing maybe leave.
                lines_t.append("| {0} | {1} | - |".format(step_num, mid))
            else:
                mod = next(m for m in modules if m['id'] == mid)
                lines_t.append("| {0} | [{1} · {2}](../{3}) | {4} |".format(step_num, mid, mod['title'], mod['file'], mod['minutes']))

        track_content = "\n".join(lines_t) + "\n"

        if os.path.isfile(track_path):
            with open(track_path, encoding='utf-8') as f:
                old_track = f.read()
            if old_track != track_content:
                with open(track_path, 'w', encoding='utf-8') as f:
                    f.write(track_content)
                changed_files.append(track_file)
        else:
            with open(track_path, 'w', encoding='utf-8') as f:
                f.write(track_content)
            changed_files.append(track_file)

        # Rewrite README row: Audience becomes [<Audience>](tracks/<slug>.md), each chain ID becomes [ID](file), joined by " > ".
        new_audience_cell = "[{0}]({1})".format(audience_text, track_file.replace(os.sep, '/'))
        chain_parts = []
        for mid in ids:
            if mid in table_map:
                chain_parts.append("[{0}]({1})".format(mid, table_map[mid]))
            else:
                chain_parts.append(mid)
        new_chain_cell = " > ".join(chain_parts)

        # Replace the row line in README. Need to find exact original row text.
        # Reconstruct original row from parsed cells? We need to find a line matching the row pattern with these cells.
        # Find line containing the audience cell and chain cell as split parts.
        lines = readme_text.split('\n')
        for i, l in enumerate(lines):
            if not l.startswith('|'):
                continue
            cells = [c.strip() for c in l.split('|')[1:-1]]
            if len(cells) >= 3 and cells[0] == audience_cell and cells[1] == chain_cell and cells[2] == min_cell:
                # Replace this line preserving table formatting? Construct new row with same spacing.
                # Original line starts with | and ends with |. We'll rebuild with single spaces around cells to be safe, but idempotent if already formatted similarly. Better preserve original pipe positions by replacing cell contents via regex? Simpler: generate normalized row.
                new_line = "| {0} | {1} | {2} |".format(new_audience_cell, new_chain_cell, min_cell)
                lines[i] = new_line
                readme_changed = True
                break
        readme_text = "\n".join(lines)

    if readme_changed and (readme_text if readme_text.endswith('\n') else readme_text + '\n') != readme_original:
        with open(readme_path, 'w', encoding='utf-8') as f:
            # Ensure trailing newline
            content = readme_text if readme_text.endswith('\n') else readme_text + '\n'
            f.write(content)
        changed_files.append('README.md')

    for cf in changed_files:
        print(cf)


if __name__ == '__main__':
    main()
