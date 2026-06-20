export default function GeneratedFilePickerModal({
  isOpen,
  folder,
  files,
  selectedFilePath,
  onClose,
  onSelectFile,
}) {
  // Render the in-app dataset picker.  This replaces manual path typing and keeps the
  // "Load logs" workflow aligned to the backend/data/generated folder by default.
  if (!isOpen) {
    return null
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-window file-picker-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-header">
          <div>
            <h2>Load generated logs</h2>
            <p className="modal-subtitle">
              Select a compatible .txt or .json dataset from the generated logs folder.
            </p>
          </div>

          <button type="button" className="secondary-button" onClick={onClose}>
            Close
          </button>
        </div>

        <div className="modal-folder-path">
          <strong>Folder:</strong> {folder || 'Not available'}
        </div>

        {files.length ? (
          <div className="file-list">
            {files.map((file) => {
              const isSelected = file.path === selectedFilePath

              return (
                <button
                  key={file.path}
                  type="button"
                  className={`file-option ${isSelected ? 'file-option-selected' : ''}`}
                  onClick={() => onSelectFile(file)}
                >
                  <span className="file-option-name">{file.name}</span>
                  <span className="file-option-meta">{file.kind_label}</span>
                </button>
              )
            })}
          </div>
        ) : (
          <p className="muted-text">No compatible .txt or .json files were found in the generated folder.</p>
        )}
      </div>
    </div>
  )
}