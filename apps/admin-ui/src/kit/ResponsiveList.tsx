import { useState, type MouseEvent, type ReactNode } from "react";
import {
  Box, Card, IconButton, ListItemIcon, ListItemText, Menu, MenuItem, Stack, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Typography, useMediaQuery, useTheme
} from "@mui/material";
import MoreVertRoundedIcon from "@mui/icons-material/MoreVertRounded";
import type { SvgIconComponent } from "@mui/icons-material";
import { useKit } from "./useKit";

export type ListColumn<T> = {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  /** Only shown in Advanced mode. */
  advancedOnly?: boolean;
  /** Technical value: LTR. */
  ltr?: boolean;
  align?: "start" | "end" | "center";
  width?: number | string;
  /** Hide from the phone card (the card already shows title/meta/status). */
  hideOnCard?: boolean;
};

export type RowAction<T> = {
  key: string;
  label: string;
  icon?: SvgIconComponent;
  onClick: (row: T) => void;
  danger?: boolean;
  disabled?: (row: T) => boolean;
  hidden?: (row: T) => boolean;
  advancedOnly?: boolean;
};

export type ResponsiveListProps<T> = {
  rows: T[];
  rowKey: (row: T) => string | number;
  columns: ListColumn<T>[];
  /** Phone card layout: title, 1–2 meta lines and a status pill. */
  card: {
    title: (row: T) => ReactNode;
    meta?: (row: T) => ReactNode;
    status?: (row: T) => ReactNode;
  };
  /** Shown in a ⋮ menu (desktop: last column; phone: card corner). */
  actions?: RowAction<T>[];
  /** Accessible name for the table. */
  label: string;
  /** Rendered when `rows` is empty (use <EmptyState/>). */
  empty?: ReactNode;
  onRowClick?: (row: T) => void;
  dense?: boolean;
};

function RowMenu<T>({ row, actions }: { row: T; actions: RowAction<T>[] }) {
  const { c, isAdvanced } = useKit();
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const visible = actions.filter((action) => !(action.hidden?.(row)) && (!action.advancedOnly || isAdvanced));
  if (visible.length === 0) return null;
  return (
    <>
      <IconButton
        aria-label={c.moreActions}
        aria-haspopup="menu"
        onClick={(event: MouseEvent<HTMLElement>) => {
          event.stopPropagation();
          setAnchor(event.currentTarget);
        }}
        sx={{ width: 44, height: 44 }}
      >
        <MoreVertRoundedIcon />
      </IconButton>
      <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)} onClick={(event) => event.stopPropagation()}>
        {visible.map((action) => {
          const Icon = action.icon;
          return (
            <MenuItem
              key={action.key}
              disabled={action.disabled?.(row)}
              onClick={() => {
                setAnchor(null);
                action.onClick(row);
              }}
              sx={{ color: action.danger ? "error.main" : undefined, minHeight: 44 }}
            >
              {Icon && (
                <ListItemIcon sx={{ color: action.danger ? "error.main" : undefined }}>
                  <Icon fontSize="small" />
                </ListItemIcon>
              )}
              <ListItemText>{action.label}</ListItemText>
            </MenuItem>
          );
        })}
      </Menu>
    </>
  );
}

/** A table on desktop (≥ md) and a card list on phones. Columns can be Advanced-only. */
export function ResponsiveList<T>({ rows, rowKey, columns, card, actions, label, empty, onRowClick, dense }: ResponsiveListProps<T>) {
  const theme = useTheme();
  const { isAdvanced } = useKit();
  const isDesktop = useMediaQuery(theme.breakpoints.up("md"));
  const visibleColumns = columns.filter((column) => !column.advancedOnly || isAdvanced);
  if (rows.length === 0) return <>{empty ?? null}</>;

  if (!isDesktop) {
    return (
      <Stack component="ul" aria-label={label} spacing={1.25} sx={{ listStyle: "none", m: 0, p: 0 }}>
        {rows.map((row) => {
          const extra = visibleColumns.filter((column) => !column.hideOnCard);
          return (
            <Card
              component="li"
              key={rowKey(row)}
              variant="outlined"
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              tabIndex={onRowClick ? 0 : undefined}
              onKeyDown={onRowClick ? (event) => { if (event.key === "Enter") onRowClick(row); } : undefined}
              sx={{ p: 1.5, cursor: onRowClick ? "pointer" : undefined }}
            >
              <Stack direction="row" spacing={1} alignItems="flex-start">
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography component="div" variant="body1" sx={{ fontWeight: 700, overflowWrap: "anywhere" }}>{card.title(row)}</Typography>
                  {card.meta && <Typography component="div" variant="body2" color="text.secondary" sx={{ mt: 0.25 }}>{card.meta(row)}</Typography>}
                  {card.status && <Box sx={{ mt: 0.75 }}>{card.status(row)}</Box>}
                </Box>
                {actions && <RowMenu row={row} actions={actions} />}
              </Stack>
              {extra.length > 0 && (
                <Box component="dl" sx={{ m: 0, mt: 1, display: "grid", gridTemplateColumns: "auto 1fr", columnGap: 1.5, rowGap: 0.5 }}>
                  {extra.map((column) => (
                    <Box key={column.key} sx={{ display: "contents" }}>
                      <Typography component="dt" variant="caption" color="text.secondary">{column.header}</Typography>
                      <Typography component="dd" variant="caption" dir={column.ltr ? "ltr" : undefined} sx={{ m: 0, overflowWrap: "anywhere", textAlign: column.ltr ? "start" : undefined }}>
                        {column.render(row)}
                      </Typography>
                    </Box>
                  ))}
                </Box>
              )}
            </Card>
          );
        })}
      </Stack>
    );
  }

  // "left"/"right" are flipped automatically by the RTL style plugin, so "left" means "start".
  const align = (value?: "start" | "end" | "center") => (value === "end" ? "right" : value === "center" ? "center" : "left");
  return (
    <TableContainer>
      <Table size={dense ? "small" : "medium"} aria-label={label}>
        <TableHead>
          <TableRow>
            {visibleColumns.map((column) => (
              <TableCell key={column.key} align={align(column.align)} sx={{ fontWeight: 700, whiteSpace: "nowrap", width: column.width }}>
                {column.header}
              </TableCell>
            ))}
            {actions && <TableCell sx={{ width: 56 }} />}
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map((row) => (
            <TableRow
              key={rowKey(row)}
              hover={Boolean(onRowClick)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              sx={{ cursor: onRowClick ? "pointer" : undefined }}
            >
              {visibleColumns.map((column) => (
                <TableCell key={column.key} dir={column.ltr ? "ltr" : undefined} align={align(column.align)} sx={{ overflowWrap: "anywhere" }}>
                  {column.render(row)}
                </TableCell>
              ))}
              {actions && (
                <TableCell padding="none" sx={{ width: 56 }}>
                  <RowMenu row={row} actions={actions} />
                </TableCell>
              )}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
