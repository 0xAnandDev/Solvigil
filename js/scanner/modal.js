export function initModal() {
  const modal = document.getElementById('terms-modal');
  const checkbox = document.getElementById('terms-checkbox');
  const checkboxUi = document.getElementById('terms-checkbox-ui');
  const btnAccept = document.getElementById('btn-accept-terms');
  const btnDecline = document.getElementById('btn-decline-terms');
  const btnExpand = document.getElementById('btn-expand-terms');
  const fullContent = document.getElementById('terms-full-content');
  const chevron = btnExpand.querySelector('.chevron-icon');
  
  const blockedOverlay = document.getElementById('blocked-overlay');
  const btnReviewTerms = document.getElementById('btn-review-terms');
  const btnViewTerms = document.getElementById('btn-view-terms');
  
  // Animation classes
  modal.style.animation = 'none';

  // Check if terms already accepted in this session/localStorage
  const hasAcceptedTerms = localStorage.getItem('solvigil_terms_accepted');
  const hasDeclinedTerms = localStorage.getItem('solvigil_terms_declined');
  
  if (!hasAcceptedTerms && !hasDeclinedTerms) {
    // Intentionally left blank: Do not auto-show modal on page load
    // Wait for user to interact with the file upload
  } else if (hasDeclinedTerms) {
    showBlockedInterface();
  }
  
  // Require Terms Modal specific logic
  const requireModal = document.getElementById('require-terms-modal');
  const btnCancelRequire = document.getElementById('btn-cancel-require');
  const btnReviewRequire = document.getElementById('btn-review-require');

  if (requireModal) {
    if (btnCancelRequire) {
      btnCancelRequire.addEventListener('click', () => {
        requireModal.style.opacity = '0';
        setTimeout(() => {
          requireModal.style.display = 'none';
        }, 300);
      });
    }

    if (btnReviewRequire) {
      btnReviewRequire.addEventListener('click', () => {
        requireModal.style.opacity = '0';
        setTimeout(() => {
          requireModal.style.display = 'none';
          // Show the main terms modal
          modal.style.display = 'flex';
          setTimeout(() => {
            modal.style.opacity = '1';
            modal.querySelector('.modal-content').style.animation = 'modalAppear 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) forwards';
            const icon = modal.querySelector('.modal-icon');
            if (icon) icon.style.animation = 'iconGlow 1.5s ease-out';
            
            const items = modal.querySelectorAll('.agreement-item');
            items.forEach((item, index) => {
              item.style.animation = `itemSlideIn 0.5s ease-out forwards ${0.2 + (index * 0.15)}s`;
              item.style.opacity = '0';
            });
          }, 10);
        }, 300);
      });
    }
  }
  
  function showBlockedInterface() {
    blockedOverlay.style.display = 'flex';
    document.body.classList.add('modal-open');
    // We add a class to body to prevent scrolling / interaction behind
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
      mainContent.style.pointerEvents = 'none';
      mainContent.style.opacity = '0.5';
    }
  }

  function hideBlockedInterface() {
    blockedOverlay.style.display = 'none';
    document.body.classList.remove('modal-open');
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
      mainContent.style.pointerEvents = 'auto';
      mainContent.style.opacity = '1';
    }
  }
  
  // Expandable terms
  if (btnExpand) {
    btnExpand.addEventListener('click', () => {
      fullContent.classList.toggle('expanded');
      chevron.classList.toggle('chevron-expanded');
      if (chevron.classList.contains('chevron-expanded')) {
        chevron.style.animation = 'chevronRotate 0.3s ease-out forwards';
      } else {
        chevron.style.animation = 'none';
        chevron.style.transform = 'rotate(0deg)';
      }
    });
  }

  // Checkbox toggle
  checkbox.addEventListener('change', (e) => {
    if (e.target.checked) {
      checkboxUi.classList.add('checked');
      checkboxUi.style.animation = 'checkboxCheck 0.4s cubic-bezier(0.34, 1.56, 0.64, 1)';
      btnAccept.removeAttribute('disabled');
    } else {
      checkboxUi.classList.remove('checked');
      checkboxUi.style.animation = 'none';
      btnAccept.setAttribute('disabled', 'true');
    }
  });
  
  // Accept button
  btnAccept.addEventListener('click', () => {
    btnAccept.classList.add('ripple');
    setTimeout(() => {
      localStorage.setItem('solvigil_terms_accepted', 'true');
      localStorage.removeItem('solvigil_terms_declined');
      hideBlockedInterface();
      
      // Close modal
      modal.style.opacity = '0';
      setTimeout(() => {
        modal.style.display = 'none';
      }, 300);
    }, 300);
  });
  
  // Decline button
  btnDecline.addEventListener('click', () => {
    localStorage.setItem('solvigil_terms_declined', 'true');
    localStorage.removeItem('solvigil_terms_accepted');
    
    // Close modal
    modal.style.opacity = '0';
    setTimeout(() => {
      modal.style.display = 'none';
      showBlockedInterface();
    }, 300);
  });

  // Review terms from blocked interface
  if (btnReviewTerms) {
    btnReviewTerms.addEventListener('click', () => {
      modal.style.display = 'flex';
      setTimeout(() => {
        modal.style.opacity = '1';
      }, 10);
    });
  }

  // View terms link from main UI
  if (btnViewTerms) {
    btnViewTerms.addEventListener('click', () => {
      modal.style.display = 'flex';
      setTimeout(() => {
        modal.style.opacity = '1';
      }, 10);
    });
  }

  // Expose check to other modules
  window.hasAcceptedTerms = () => localStorage.getItem('solvigil_terms_accepted') === 'true';
}
