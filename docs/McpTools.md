# MCP Tools

`trace-search-mcp` now exposes the main executable's backend-capable workflows as MCP tools.

This includes:

- file inspection
- line-window reads
- literal and regex search
- single replace and replace-all
- standalone backward taint
- combined search + taint analysis

This does not include purely visual GUI state such as dark mode, font size, wrap mode, or dock layout.

## Run

```bash
cargo run -p arm64-taint-core --bin trace-search-mcp
```

## Common Notes

- Every file path can be absolute or relative.
- Most read/search tools accept an optional `encoding`.
- Common encoding values are `UTF-8`, `UTF-16 LE`, `UTF-16 BE`, and `Windows-1252`.
- Line numbers are 1-based.
- `search_content` returns `byte_offset` and `match_len`, which can be fed into `replace_content_match`.

## `inspect_content_file`

Purpose:

- open a file
- detect or override encoding
- build or reuse the cached line index
- return file size and total line count

Example:

```json
{
  "file_path": "D:/trace/demo.txt"
}
```

Useful when:

- you want the encoding actually used by the server
- you want to know whether the line index was cache-hit or rebuilt
- you need total line count before reading a window

## `read_content_lines`

Purpose:

- read a line window like "jump to line" in the GUI
- return byte range and clipped text per line

Example:

```json
{
  "file_path": "D:/trace/demo.txt",
  "start_line": 120,
  "line_count": 5,
  "clip_chars": 300
}
```

Useful when:

- you already know the target line
- you want context around a taint hit or search hit

## `search_content`

Purpose:

- perform literal or regex search
- optionally count total matches
- page from `start_offset`
- optionally collapse repeated raw hits into distinct lines

Example: literal search with total count

```json
{
  "file_path": "D:/trace/demo.txt",
  "query": "JNI_OnLoad",
  "use_regex": false,
  "case_sensitive": false,
  "include_total_count": true,
  "max_results": 20
}
```

Example: regex search, continue from a previous page

```json
{
  "file_path": "D:/trace/demo.txt",
  "query": "0x[0-9a-fA-F]{8}",
  "use_regex": true,
  "case_sensitive": true,
  "start_offset": 1048576,
  "max_results": 100
}
```

Useful when:

- you need raw search hits with `byte_offset`
- you want line previews without opening the GUI
- you want to feed a specific hit into `replace_content_match`

## `replace_content_match`

Purpose:

- replace one exact match by `byte_offset` and `match_len`
- write in place or create a modified copy

Typical flow:

1. call `search_content`
2. pick one returned hit
3. pass that hit's `byte_offset` and `match_len` into `replace_content_match`

Example:

```json
{
  "input_file": "D:/trace/demo.txt",
  "output_file": "D:/trace/demo.txt.modified",
  "byte_offset": 24576,
  "match_len": 8,
  "replacement": "patched"
}
```

## `replace_content_all`

Purpose:

- run the same streaming replace-all path used by the main executable
- support literal replace and regex replace
- write to a sibling `.modified` file by default, or rewrite in place

Example: safe copy-out replace

```json
{
  "input_file": "D:/trace/demo.txt",
  "query": "old_api",
  "replacement": "new_api",
  "use_regex": false
}
```

Example: in-place regex replace

```json
{
  "input_file": "D:/trace/demo.txt",
  "query": "Item (\\d+)",
  "replacement": "Object $1",
  "use_regex": true,
  "in_place": true
}
```

## `trace_backward`

Purpose:

- run backward taint without needing a prior search
- return a compact summary plus full `report_json`

Example:

```json
{
  "trace_file": "D:/trace/arm64.txt",
  "line_no": 3562,
  "target_kind": "reg",
  "target": "w8",
  "bit_lo": 0,
  "bit_hi": 7,
  "max_depth": 64,
  "max_nodes": 2000
}
```

Useful when:

- you already know the exact trace line and target
- you want the full taint report, not only top roots

## `search_trace_sources`

Purpose:

- search first
- collapse raw hits into distinct source lines
- run backward taint per hit
- return previews, taint summaries, and top root sources

Example:

```json
{
  "trace_file": "D:/trace/arm64.txt",
  "query": "memcmp",
  "use_regex": false,
  "case_sensitive": false,
  "max_matches": 5,
  "target_kind": "reg",
  "target": "x0",
  "taint_line_offset": 0,
  "bit_lo": 0,
  "bit_hi": 63
}
```

Useful when:

- you do not know the final trace line yet
- you want "search + explain data origin" in one call

## Suggested Workflows

Search and patch one hit:

1. `search_content`
2. `replace_content_match`
3. `read_content_lines` to verify output

Find suspicious calls and explain provenance:

1. `search_trace_sources`
2. inspect returned `root_sources`
3. if one hit matters, rerun `trace_backward` on that exact line for the full report

Large-file inspection:

1. `inspect_content_file`
2. `read_content_lines`
3. `search_content`
