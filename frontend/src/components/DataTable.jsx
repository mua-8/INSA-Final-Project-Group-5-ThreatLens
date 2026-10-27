import React, { useState, useMemo } from "react";
import { FiSearch, FiChevronLeft, FiChevronRight, FiFilter } from "react-icons/fi";

export default function DataTable({
  title,
  count,
  columns,
  rows = [],
  emptyText,
  onRowClick,
  badge,
}) {
  const [searchTerm, setSearchTerm] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 10;

  // Filter rows by search query across stringified fields
  const filteredRows = useMemo(() => {
    if (!searchTerm.trim()) return rows;
    const term = searchTerm.toLowerCase();
    return rows.filter((row) => {
      return Object.values(row).some((val) => {
        if (val === null || val === undefined) return false;
        return String(val).toLowerCase().includes(term);
      });
    });
  }, [rows, searchTerm]);

  const totalPages = Math.max(1, Math.ceil(filteredRows.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paginatedRows = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredRows.slice(start, start + pageSize);
  }, [filteredRows, currentPage, pageSize]);

  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/85 backdrop-blur-md shadow-xl overflow-hidden transition-all duration-200">
      {/* Table Header Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800/80 px-5 py-3.5 bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950">
        <div className="flex items-center gap-2.5">
          <h2 className="text-sm font-bold tracking-wide text-white flex items-center gap-2">
            {title}
            {badge && (
              <span className="text-[10px] font-bold uppercase tracking-wider bg-accent/15 text-accent border border-accent/30 px-2 py-0.5 rounded-full">
                {badge}
              </span>
            )}
          </h2>
          <span className="text-[11px] font-mono text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded-md border border-slate-700/60">
            {filteredRows.length} {filteredRows.length === 1 ? "entry" : "entries"}
          </span>
        </div>

        {/* Live Filter Search Input */}
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <div className="relative w-full sm:w-64">
            <FiSearch className="absolute left-3 top-2.5 text-slate-500 text-xs" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
              placeholder="Filter table rows..."
              className="w-full bg-slate-950/80 text-white pl-8 pr-3 py-1.5 rounded-lg border border-slate-700/80 text-xs focus:border-accent focus:outline-none transition font-sans placeholder:text-slate-500"
            />
            {searchTerm && (
              <button
                onClick={() => setSearchTerm("")}
                className="absolute right-2.5 top-2 text-slate-400 hover:text-white text-xs"
              >
                ×
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Table Elements */}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[620px] text-left text-xs">
          <thead className="text-[11px] font-bold text-slate-400 bg-slate-950/40 border-b border-slate-800/70 tracking-wider uppercase">
            <tr>
              {columns.map((c) => (
                <th key={c.key} className="px-5 py-3 font-semibold">
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/50">
            {paginatedRows.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-5 py-12 text-center text-slate-500 text-xs font-medium"
                >
                  <div className="flex flex-col items-center justify-center gap-1.5">
                    <FiFilter className="text-slate-600 text-lg" />
                    <span>{emptyText || "No matching records found."}</span>
                  </div>
                </td>
              </tr>
            ) : (
              paginatedRows.map((row, i) => (
                <tr
                  key={row.id || row.event_id || i}
                  onClick={() => onRowClick && onRowClick(row)}
                  className={`transition-colors duration-150 ${
                    onRowClick
                      ? "cursor-pointer hover:bg-slate-800/60 hover:border-l-2 hover:border-l-accent"
                      : "hover:bg-slate-800/30"
                  }`}
                >
                  {columns.map((c) => (
                    <td
                      key={c.key}
                      className="whitespace-nowrap px-5 py-3 text-slate-300 font-sans"
                    >
                      {c.render(row)}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Table Pagination Footer */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between border-t border-slate-800/80 px-5 py-2.5 bg-slate-950/40 text-xs text-slate-400">
          <div>
            Page <span className="font-semibold text-white">{currentPage}</span> of{" "}
            <span className="font-semibold text-white">{totalPages}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={currentPage <= 1}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 transition"
              title="Previous page"
            >
              <FiChevronLeft size={14} />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage >= totalPages}
              className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 transition"
              title="Next page"
            >
              <FiChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
