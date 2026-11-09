/**
 * The fixed warning bar while an admin is «دیدن به‌جای» a workspace (docs/43 §2, §4): whose space,
 * read-only or not, until when, and one button to stop. It sits above the top bar on every page.
 */
import { Box, Button, Stack, Typography } from "@mui/material";
import VisibilityRoundedIcon from "@mui/icons-material/VisibilityRounded";
import { pick, say, VIEW_AS } from "../copy";
import { RelativeTime, useKit } from "../kit";
import { useMySpace } from "./MySpaceContext";

export const VIEW_AS_BAR_HEIGHT = 52;

export function ViewAsBar() {
  const { language } = useKit();
  const space = useMySpace();
  const session = space.viewAs;
  if (!session) return null;
  const [before, after] = pick(language, VIEW_AS.endsIn).split("{time}");
  return (
    <Box
      role="status"
      aria-live="polite"
      sx={{
        position: "fixed", insetInline: 0, top: 0, zIndex: (theme) => theme.zIndex.drawer + 2, minHeight: VIEW_AS_BAR_HEIGHT,
        bgcolor: "warning.main", color: "warning.contrastText", px: { xs: 1.5, sm: 3 }, py: 0.75, display: "flex", alignItems: "center"
      }}
    >
      <Stack direction="row" alignItems="center" gap={1.25} sx={{ width: "100%", minWidth: 0 }}>
        <VisibilityRoundedIcon aria-hidden />
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography variant="body2" fontWeight={760} noWrap>{say(language, VIEW_AS.bar, { name: session.workspaceName })}</Typography>
          <Typography variant="caption" sx={{ display: { xs: "none", sm: "block" } }} noWrap>
            {pick(language, session.write ? VIEW_AS.canWrite : VIEW_AS.readOnly)}
            {session.expiresAt ? <> · {before}<RelativeTime value={session.expiresAt} />{after}</> : null}
          </Typography>
        </Box>
        <Button variant="contained" color="inherit" onClick={space.stopViewAs} sx={{ minHeight: 40, color: "text.primary", bgcolor: "background.paper", flexShrink: 0, "&:hover": { bgcolor: "background.default" } }}>
          {pick(language, VIEW_AS.stop)}
        </Button>
      </Stack>
    </Box>
  );
}
