// Clean, simple table component with fixed headers and scrollable body
import React, { useState, useEffect, useRef } from 'react';
import { ContextMenu, ContextMenuItem } from './ContextMenu';

interface Column<T> {
  key: keyof T;
  header: string;
  render?: (value: any, item: T) => React.ReactNode;
  sortable?: boolean;
  width?: string;
}

interface DataTableProps<T> {
  data: T[];
  columns: Column<T>[];
  onRowClick?: (item: T) => void;
  emptyMessage?: string;
  loading?: boolean;
  className?: string;
  contextMenuItems?: (selectedItems: T[]) => ContextMenuItem[];
}

export function DataTable<T extends { id: string }>({
  data,
  columns,
  onRowClick,
  emptyMessage = 'No data available',
  loading = false,
  className = '',
  contextMenuItems
}: DataTableProps<T>) {
  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set());
  const [lastSelectedIndex, setLastSelectedIndex] = useState<number>(-1);
  const [focusedIndex, setFocusedIndex] = useState<number>(-1);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number } | null>(null);
  const tableRef = useRef<HTMLDivElement>(null);

  // Keyboard event handling
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (!tableRef.current?.contains(document.activeElement)) return;

      switch (event.key) {
        case 'a':
        case 'A':
          if (event.ctrlKey || event.metaKey) {
            event.preventDefault();
            selectAll();
          }
          break;
        case 'ArrowDown':
          event.preventDefault();
          navigateDown(event);
          break;
        case 'ArrowUp':
          event.preventDefault();
          navigateUp(event);
          break;
        case 'Escape':
          setSelectedItems(new Set());
          setFocusedIndex(-1);
          break;
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [data, selectedItems, lastSelectedIndex, focusedIndex]);

  const selectAll = () => {
    const allIds = new Set(data.map(item => item.id));
    setSelectedItems(allIds);
    setLastSelectedIndex(0);
  };
  const navigateDown = (event: KeyboardEvent) => {
    const nextIndex = Math.min(focusedIndex + 1, data.length - 1);
    setFocusedIndex(nextIndex);

    if (event.shiftKey && lastSelectedIndex !== -1) {
      // Range selection
      const startIndex = Math.min(lastSelectedIndex, nextIndex);
      const endIndex = Math.max(lastSelectedIndex, nextIndex);
      const newSelected = new Set<string>();
      for (let i = startIndex; i <= endIndex; i++) {
        newSelected.add(data[i].id);
      }
      setSelectedItems(newSelected);
    } else if (!event.ctrlKey && !event.metaKey) {
      // Single selection
      setSelectedItems(new Set([data[nextIndex].id]));
      setLastSelectedIndex(nextIndex);
      // Trigger the row click callback for single selection
      onRowClick?.(data[nextIndex]);
    }
  };
  const navigateUp = (event: KeyboardEvent) => {
    const nextIndex = Math.max(focusedIndex - 1, 0);
    setFocusedIndex(nextIndex);

    if (event.shiftKey && lastSelectedIndex !== -1) {
      // Range selection
      const startIndex = Math.min(lastSelectedIndex, nextIndex);
      const endIndex = Math.max(lastSelectedIndex, nextIndex);
      const newSelected = new Set<string>();
      for (let i = startIndex; i <= endIndex; i++) {
        newSelected.add(data[i].id);
      }
      setSelectedItems(newSelected);
    } else if (!event.ctrlKey && !event.metaKey) {
      // Single selection
      setSelectedItems(new Set([data[nextIndex].id]));
      setLastSelectedIndex(nextIndex);
      // Trigger the row click callback for single selection
      onRowClick?.(data[nextIndex]);
    }
  };
  const handleRowClick = (item: T, event: React.MouseEvent) => {
    const currentIndex = data.findIndex(d => d.id === item.id);
    setFocusedIndex(currentIndex);

    if (event.shiftKey && lastSelectedIndex !== -1) {
      // Range selection with Shift
      event.preventDefault();
      const startIndex = Math.min(lastSelectedIndex, currentIndex);
      const endIndex = Math.max(lastSelectedIndex, currentIndex);
      const newSelected = new Set(selectedItems);

      for (let i = startIndex; i <= endIndex; i++) {
        newSelected.add(data[i].id);
      }

      setSelectedItems(newSelected);
    } else if (event.ctrlKey || event.metaKey) {
      // Multi-select with Ctrl/Cmd
      event.preventDefault();
      const newSelected = new Set(selectedItems);
      if (newSelected.has(item.id)) {
        newSelected.delete(item.id);
      } else {
        newSelected.add(item.id);
      }
      setSelectedItems(newSelected);
      setLastSelectedIndex(currentIndex);
    } else {
      // Single select
      setSelectedItems(new Set([item.id]));
      setLastSelectedIndex(currentIndex);
      onRowClick?.(item);
    }
  };
  const handleContextMenu = (event: React.MouseEvent, item: T) => {
    event.preventDefault();

    // If right-clicking on a non-selected item, select only that item
    if (!selectedItems.has(item.id)) {
      setSelectedItems(new Set([item.id]));
      setLastSelectedIndex(data.findIndex(d => d.id === item.id));
      setFocusedIndex(data.findIndex(d => d.id === item.id));
    }

    setContextMenu({ x: event.clientX, y: event.clientY });
  };

  const getSelectedData = () => {
    return data.filter(item => selectedItems.has(item.id));
  };

  if (loading) {
    return (
      <div className={`simple-table-container ${className}`}>
        <div className="table-loading">Loading...</div>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className={`simple-table-container ${className}`}>
        <div className="table-empty">{emptyMessage}</div>
      </div>
    );
  }  return (
    <div
      ref={tableRef}
      className={`simple-table-container ${className}`}
      tabIndex={0}
      style={{ outline: 'none' }}
    >
      <div className="simple-table-header">
        <table className="simple-table">
          <thead>
            <tr>
              {columns.map((column) => (
                <th
                  key={String(column.key)}
                  className={column.sortable ? 'sortable' : ''}
                  style={{ width: column.width }}
                >
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
        </table>
      </div>
      <div className="simple-table-body">
        <table className="simple-table">
          <tbody>
            {data.map((item, index) => (              <tr
                key={item.id}
                onClick={(e) => handleRowClick(item, e)}
                onContextMenu={(e) => handleContextMenu(e, item)}
                data-modified={(item as any).modified === true ? "true" : undefined}
                className={`
                  clickable
                  ${selectedItems.has(item.id) ? 'selected' : ''}
                  ${focusedIndex === index ? 'focused' : ''}
                `.trim()}
              >
                {columns.map((column) => (
                  <td
                    key={String(column.key)}
                    style={{ width: column.width }}
                  >
                    {column.render
                      ? column.render(item[column.key], item)
                      : String(item[column.key] || '')
                    }
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {contextMenuItems && (
        <ContextMenu
          items={contextMenuItems(getSelectedData())}
          position={contextMenu}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  );
}
