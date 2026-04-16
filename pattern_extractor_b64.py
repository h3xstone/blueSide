import base64
import re
import sys

"""
Generate blob-aligned chunks for target strings to create YARA rules.
Output YARA strings should be aligned with original formatting.
    - Blob: base64 encoded payload containing newline chars
    - Pattern: clear text target string
"""

def find_pattern_chunks(blob_b64, pattern, min_chunk_len):
    """
    - decode base64 blob
    - find plaintext pattern
    - return base64-aligned chunks
    """

    # remove CRLF and spaces
    blob_clean = re.sub(r"[\r\n\s]", "", blob_b64)

    # decode b64
    try:
        blob_dec = base64.b64decode(blob_clean)
    except Exception as e:
        print(f"[!] Base64 decode error: {e}")
        return [], None, None

    blob_str = blob_dec.decode(errors="ignore")

    pos = blob_str.find(pattern)
    if pos == -1:
        return [], None, None

    start_dec = pos
    end_dec = pos + len(pattern)

    """
    - map decoded byte offsets to base64 offsets 
    - every 3 decoded bytes -> 4 base64 chars
    - enlarge range to ensure include all base64 chars
    """
    start_b64 = (start_dec // 3) * 4
    end_b64 = ((end_dec + 2) // 3) * 4
    
    # extract base64 chars from blob preserving line splits

    chunks = []
    clean_pos = 0
    buf = ""

    for c in blob_b64:
        if c in "\r\n":
            if buf:
                if len(buf) >= min_chunk_len:
                    chunks.append(buf)
                buf = ""
            continue

        if start_b64 <= clean_pos < end_b64:
            buf += c

        clean_pos += 1

    if buf and len(buf) >= min_chunk_len:
        chunks.append(buf)

    return chunks, start_dec, end_dec


def calc_patterns(blob_b64, patterns, min_chunk_len=8):
    res = {}

    for p in patterns:
        print(f"\n[*] Analyze pattern: {p}")
        chunks, start_pos, end_pos = find_pattern_chunks(blob_b64, p, min_chunk_len)
        
        if chunks:
            res[p] = chunks
            print(f" |_ [match] POS: {start_pos}-{end_pos}")
            for c in chunks:
                print(f"            B64: {c}")
        else:
            print(" |_ [not found]")
        
    if not res:
        print("\n[!] No patterns found.")
        return

    print("\n[+] Suggested YARA rule:\n")
    print("rule blob_aligned_chunks")
    print("{")
    print("\tstrings:")

    i = 1
    for pat, chunks in res.items():
        for c in chunks:
            print(f'\t\t$s{i} = "{c}"')
            i += 1
        
    print("\tcondition:")
    print("\t\tany of them")
    print("}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <b64_blob_file>")
        sys.exit(1)

    bf = sys.argv[1]

    try:
        with open(bf, "r") as f:
            data = f.read()
    except Exception as e:
        print(f"[!] Error opening file: {e}")
        sys.exit(1)

    data = data.strip()

    # read multiple patterns
    patterns = []
    print("[*] Enter patterns to search (one per line). Leave empty to finish.")

    while True:
        p = input("> ").strip()
        if not p:
            break
        patterns.append(p)

    # choose the accuracy here by changing the min length (default = 8)
    calc_patterns(data, patterns, 8)
