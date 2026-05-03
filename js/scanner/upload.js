export function initUpload() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const btnChooseFile = document.getElementById('btn-choose-file');
  const fileDisplay = document.getElementById('file-display');
  const fileName = document.getElementById('file-name');
  const fileSize = document.getElementById('file-size');
  const btnRemoveFile = document.getElementById('btn-remove-file');
  const btnAnalyze = document.getElementById('btn-analyze');
  const errorMessage = document.getElementById('error-message');
  const errorText = document.getElementById('error-text');
  
  const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB
  
  function checkTermsAccepted() {
    if (window.hasAcceptedTerms && !window.hasAcceptedTerms()) {
      showBlockedWarning();
      return false;
    }
    return true;
  }

  function showBlockedWarning() {
    // Show require modal
    const modal = document.getElementById('require-terms-modal');
    if (modal) {
      modal.style.display = 'flex';
      setTimeout(() => {
        modal.style.opacity = '1';
        modal.querySelector('.modal-content').style.animation = 'modalAppear 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) forwards';
      }, 10);
    }
  }

  // Open file dialog when clicking dropzone or button
  dropzone.addEventListener('click', (e) => {
    if (!checkTermsAccepted()) return;
    if (e.target !== btnChooseFile) {
      fileInput.click();
    }
  });
  
  btnChooseFile.addEventListener('click', (e) => {
    e.stopPropagation(); // Prevent double click event
    if (!checkTermsAccepted()) return;
    fileInput.click();
  });
  
  // Drag and drop events
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    if (!checkTermsAccepted()) {
      dropzone.style.cursor = 'not-allowed';
      dropzone.classList.add('blocked-interaction');
      setTimeout(() => dropzone.classList.remove('blocked-interaction'), 600);
      return;
    }
    dropzone.classList.add('dragover');
  });
  
  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('dragover');
    dropzone.style.cursor = 'pointer';
  });
  
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    dropzone.style.cursor = 'pointer';
    
    if (!checkTermsAccepted()) return;
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });
  
  // File input change event
  fileInput.addEventListener('change', (e) => {
    if (!checkTermsAccepted()) {
      fileInput.value = '';
      return;
    }
    if (e.target.files && e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  });
  
  // Remove file event
  btnRemoveFile.addEventListener('click', () => {
    fileInput.value = '';
    fileDisplay.style.display = 'none';
    btnAnalyze.setAttribute('disabled', 'true');
    errorMessage.style.display = 'none';
    window.currentUploadedFileContent = null;
  });
  
  function handleFile(file) {
    // Hide previous error
    errorMessage.style.display = 'none';
    
    // Validate file type
    if (!file.name.endsWith('.sol')) {
      showError('⚠️ Only Solidity (.sol) files are supported. Please select a .sol file and try again.');
      return;
    }
    
    // Validate file size
    if (file.size > MAX_FILE_SIZE) {
      showError('⚠️ File size exceeds 2 MB limit. Please upload a smaller file.');
      return;
    }
    
    // Read file contents for real analysis later
    const reader = new FileReader();
    reader.onload = (e) => {
      window.currentUploadedFileContent = e.target.result;
      displayFileInfo(file);
    };
    reader.readAsText(file);
  }
  
  function showError(msg) {
    errorText.textContent = msg;
    errorMessage.style.display = 'flex';
    errorMessage.style.animation = 'shake 0.4s ease-in-out';
    fileDisplay.style.display = 'none';
    btnAnalyze.setAttribute('disabled', 'true');
  }
  
  function displayFileInfo(file) {
    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);
    fileDisplay.style.display = 'block';
    
    // Re-trigger animation
    fileDisplay.style.animation = 'none';
    void fileDisplay.offsetWidth;
    fileDisplay.style.animation = 'fileUploadSuccess 0.5s cubic-bezier(0.34, 1.56, 0.64, 1)';
    
    btnAnalyze.removeAttribute('disabled');
  }
  
  function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
  }
}
