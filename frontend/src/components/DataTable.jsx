export default function DataTable({ title, count, columns, rows, emptyText, onRowClick }) {
  return (
    <section className="rounded-xl border border-slate-700/60 bg-card shadow-lg shadow-black/20">
      <div className="flex items-center justify-between border-b border-slate-700/60 px-5 py-4">
        <h2 className="font-semibold text-white">{title}</h2>
        <span className="text-xs text-slate-400">Latest {count}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[560px] text-left text-sm">
          <thead className="text-xs text-slate-400">
            <tr>
              {columns.map((c) => (
                <th key={c.key} className="px-5 py-3 font-medium">{c.label}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/50">
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-5 py-10 text-center text-slate-500">{emptyText}</td>
              </tr>
            ) : (
              rows.map((row, i) => (
                <tr
                  key={i}
                  onClick={() => onRowClick && onRowClick(row)}
                  className={`transition ${onRowClick ? "cursor-pointer hover:bg-slate-700/50 hover:border-l-4 hover:border-l-accent" : "hover:bg-slate-700/30"}`}
                >
                  {columns.map((c) => (
                    <td key={c.key} className="whitespace-nowrap px-5 py-3 text-slate-200">{c.render(row)}</td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

