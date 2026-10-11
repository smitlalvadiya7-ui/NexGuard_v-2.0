import { useRef, useState } from "react";

function fmtSize(bytes) {
  if (typeof bytes !== "number" || Number.isNaN(bytes)) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/*
 * Shared drag-drop / click-to-browse file picker for every upload scan panel.
 * Uncontrolled: keeps the chosen file only for the chip display and reports
 * each pick upward via onFile(file); the panel owns the file it submits.
 */
export default function UploadDropzone({ accept, onFile, label = "Upload file" }) {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [dragOver, setDragOver] = useState(false);

  function pick(candidate) {
    if (!candidate) return;
    setFile(candidate);
    onFile?.(candidate);
  }

  function handleDrop(e) {
    e.preventDefault();
    setDragOver(false);
    pick(e.dataTransfer?.files?.[0]);
  }

  function handleKeyDown(e) {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      inputRef.current?.click();
    }
  }

  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={label}
      onClick={() => inputRef.current?.click()}
      onKeyDown={handleKeyDown}
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      className={`flex cursor-pointer flex-col items-center justify-center gap-1.5 rounded-lg border border-dashed px-4 py-8 text-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
        dragOver ? "border-accent bg-accent/5" : "border-border bg-panel hover:border-accent/60"
      }`}
    >
      <input
        ref={inputRef}
        data-testid="dropzone-input"
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => pick(e.target.files?.[0])}
      />
      <p className="text-sm font-medium text-text">{label}</p>
      <p className="text-xs text-muted">Drag &amp; drop or click to browse</p>
      {file && (
        <span className="mt-1.5 inline-flex max-w-full items-center gap-2 rounded-full bg-panel-2 px-3 py-1 text-xs text-text">
          <span className="truncate font-medium">{file.name}</span>
          <span className="shrink-0 text-muted">{fmtSize(file.size)}</span>
        </span>
      )}
    </div>
  );
}
