import { useMemo } from "react";
import { Box } from "@mui/material";
import qrcode from "qrcode-generator";

/**
 * A QR code drawn as one SVG path (qrcode-generator 1.4.4, pinned; no innerHTML). Always dark on
 * white with a quiet zone so phone cameras read it in light and dark themes alike.
 */
export function QrCode({ value, size = 184, label }: { value: string; size?: number; label: string }) {
  const drawing = useMemo(() => {
    if (!value) return null;
    try {
      const code = qrcode(0, "M");
      code.addData(value, "Byte");
      code.make();
      const count = code.getModuleCount();
      let path = "";
      for (let row = 0; row < count; row += 1) {
        for (let col = 0; col < count; col += 1) {
          if (code.isDark(row, col)) path += `M${col + 4} ${row + 4}h1v1h-1z`;
        }
      }
      return { path, box: count + 8 };
    } catch {
      return null;
    }
  }, [value]);
  if (!drawing) return null;
  return (
    <Box sx={{ display: "inline-flex", bgcolor: "#fff", borderRadius: 1, p: 0.5, border: 1, borderColor: "divider", lineHeight: 0 }}>
      <svg role="img" aria-label={label} width={size} height={size} viewBox={`0 0 ${drawing.box} ${drawing.box}`} shapeRendering="crispEdges">
        <rect width={drawing.box} height={drawing.box} fill="#fff" />
        <path d={drawing.path} fill="#000" />
      </svg>
    </Box>
  );
}
