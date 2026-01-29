 from __future__ import annotations
 
 from mlsecscan.core.finding import Location
 from mlsecscan.parsing.treesitter import ParsedFile
 from mlsecscan.analysis.ast import node_snippet
 
 
 def location_from_node(parsed: ParsedFile, node) -> Location:
     line = node.start_point[0] + 1
     column = node.start_point[1] + 1
     snippet = node_snippet(parsed, node)
     return Location(path=parsed.path, line=line, column=column, snippet=snippet)
