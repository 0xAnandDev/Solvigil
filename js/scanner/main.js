import { initModal } from './modal.js';
import { initUpload } from './upload.js';
import { initAnalyzer } from './analyzer.js';

document.addEventListener('DOMContentLoaded', () => {
  console.log('Scanner initialized');
  
  // Initialize modules
  initModal();
  initUpload();
  initAnalyzer();
  
  // Setup View Terms link
  document.getElementById('btn-view-terms').addEventListener('click', () => {
    // Open modal directly without checking localStorage
    const modal = document.getElementById('terms-modal');
    modal.classList.add('active');
  });
});
