 import difflib
 
 
 def unified_diff(before: str, after: str, filename: str = "snippet") -> str:
     before_lines = before.splitlines(keepends=True)
     after_lines = after.splitlines(keepends=True)
     diff_lines = difflib.unified_diff(
         before_lines,
         after_lines,
         fromfile=f"{filename}:before",
         tofile=f"{filename}:after",
     )
     return "".join(diff_lines)
