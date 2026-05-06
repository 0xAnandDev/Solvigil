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
  const btnErrorClose = document.getElementById('btn-error-close');
  
  if (btnErrorClose) {
    btnErrorClose.addEventListener('click', (e) => {
      e.stopPropagation();
      errorMessage.style.display = 'none';
    });
  }
  
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
  
  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    if (dropzone.classList.contains('uploading')) return;
    
    if (!checkTermsAccepted()) {
      dropzone.style.cursor = 'not-allowed';
      dropzone.classList.add('blocked-interaction');
      setTimeout(() => dropzone.classList.remove('blocked-interaction'), 600);
      return;
    }
    
    const title = document.getElementById('dropzone-title');
    if (title) title.textContent = 'Drop to upload...';
    dropzone.classList.add('dragover');
  });
  
  dropzone.addEventListener('dragleave', () => {
    if (dropzone.classList.contains('uploading')) return;
    
    const title = document.getElementById('dropzone-title');
    if (title) title.textContent = 'Drop your .sol file here';
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
    window.currentUploadedFile = null;
  });
  
  function handleFile(file) {
    // Hide previous error
    errorMessage.style.display = 'none';
    
    // Validate file type
    if (!file.name.endsWith('.sol')) {
      showError('Only Solidity (.sol) files are supported. Please try again.');
      return;
    }
    
    // Validate file size
    if (file.size > MAX_FILE_SIZE) {
      showError('File size exceeds 2 MB limit. Please upload a smaller file.');
      return;
    }
    
    // Store the actual file object for the backend formData
    window.currentUploadedFile = file;
    
    // Read file contents for code review display
    const reader = new FileReader();
    reader.onload = (e) => {
      window.currentUploadedFileContent = e.target.result;
      simulateUploadProgress(file);
    };
    reader.readAsText(file);
  }
  
  function simulateUploadProgress(file) {
    dropzone.classList.add('uploading');
    
    const progressContainer = document.getElementById('dropzone-progress-container');
    const progressFill = document.getElementById('dropzone-progress-fill');
    const progressText = document.getElementById('dropzone-progress-text');
    const dropzoneSuccess = document.getElementById('dropzone-success');
    
    if (progressContainer) progressContainer.style.display = 'block';
    if (dropzoneSuccess) dropzoneSuccess.style.display = 'none';
    fileDisplay.style.display = 'none';
    btnAnalyze.setAttribute('disabled', 'true');
    
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 20 + 10;
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        
        if (progressFill) progressFill.style.width = '100%';
        if (progressText) progressText.textContent = '100%';
        
        setTimeout(() => {
          if (progressContainer) progressContainer.style.display = 'none';
          if (dropzoneSuccess) dropzoneSuccess.style.display = 'block';
          
          setTimeout(() => {
            dropzone.classList.remove('uploading');
            if (dropzoneSuccess) dropzoneSuccess.style.display = 'none';
            if (progressFill) progressFill.style.width = '0%';
            
            const title = document.getElementById('dropzone-title');
            if (title) title.textContent = 'Drop your .sol file here';
            
            displayFileInfo(file);
          }, 1200); // Wait for success checkmark animation
        }, 300);
      } else {
        if (progressFill) progressFill.style.width = `${progress}%`;
        if (progressText) progressText.textContent = `${Math.floor(progress)}%`;
      }
    }, 100);
  }
  
  function showError(msg) {
    errorText.textContent = msg;
    errorMessage.style.display = 'flex';
    fileDisplay.style.display = 'none';
    btnAnalyze.setAttribute('disabled', 'true');
    
    // Auto-dismiss after 4 seconds
    setTimeout(() => {
      errorMessage.style.display = 'none';
    }, 4000);
  }
  
  function displayFileInfo(file) {
    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);
    fileDisplay.style.display = 'block';
    
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
