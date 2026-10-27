import React, { useState, useEffect } from "react";
import { FaChevronLeft, FaChevronRight } from "react-icons/fa";

export default function DataTable({
  title,
  count,
  columns,
  rows = [],
  emptyText,
  onRowClick,
  pageSize = 10,
  headerAction,
}) {
  const [currentPage, setCurrentPage] = useState(1);

  // Reset to first page when data or row count changes
  useEffect(() => {
    setCurrentPage(1);
  }, [rows.length]);

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const startIndex = (safePage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, rows.length);
  const paginatedRows = rows.slice(startIndex, endIndex);

  return (
    <section className="rounded-xl border border-slate-700/60 bg-card shadow-lg shadow-black/20 overflow-hidden">
      <div className="flex flex-wrap items-center justify-between border-b border-slate-700/60 px-5 py-3.5 gap-2 bg-slate-900/40">
        <div className="flex items-center gap-3">
          <h2 className="font-semibold text-white">{title}</h2>
          <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-400 border border-slate-700/80 font-mono">
            {count ?? rows.length} total
          </span>
        </div>
        {headerAction && <div>{headerAction}</div>}
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left text-sm">
          <thead className="text-xs uppercase tracking-wider text-slate-400 bg-slate-900/80 border-b border-slate-700/60">
            <tr>
              {columns.map((c) => (
                <th key={c.key} className="px-5 py-3 font-semibold">{c.label}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/50">
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-5 py-12 text-center text-slate-500">
                  {emptyText || "No records available."}
                </td>
              </tr>
            ) : (
              paginatedRows.map((row, i) => (
                <tr
                  key={row.id ?? `${safePage}-${i}`}
                  onClick={() => onRowClick && onRowClick(row)}
                  className={`transition ${onRowClick ? "cursor-pointer hover:bg-slate-700/40 hover:border-l-4 hover:border-l-accent" : "hover:bg-slate-700/20"}`}
                >
                  {columns.map((c) => (
                    <td key={c.key} className="whitespace-nowrap px-5 py-3 text-slate-200">
                      {c.render ? c.render(row) : (row[c.key] ?? "-")}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {rows.length > pageSize && (
        <div className="flex flex-wrap items-center justify-between border-t border-slate-700/60 px-5 py-3 gap-2 bg-slate-900/40 text-xs text-slate-400">
          <div>
            Showing <span className="font-mono text-slate-200">{startIndex + 1}</span> to{" "}
            <span className="font-mono text-slate-200">{endIndex}</span> of{" "}
            <span className="font-mono text-slate-200">{rows.length}</span> entries
          </div>

          <div className="flex items-center gap-2">
            <span className="font-mono mr-2">
              Page {safePage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={safePage <= 1}
              aria-label="Previous page"
              className="inline-flex items-center gap-1 rounded bg-slate-800 px-2.5 py-1 text-slate-300 border border-slate-700 transition hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <FaChevronLeft size={10} />
              <span>Prev</span>
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={safePage >= totalPages}
              aria-label="Next page"
              className="inline-flex items-center gap-1 rounded bg-slate-800 px-2.5 py-1 text-slate-300 border border-slate-700 transition hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span>Next</span>
              <FaChevronRight size={10} />
            </button>
          </div>
        </div>
      )}
    </section>
  );
}

