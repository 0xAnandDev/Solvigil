document.addEventListener('DOMContentLoaded', () => {
  // Smooth scrolling for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth'
        });
      }
    });
  });

  // Interactive Wind Animation
  const container = document.querySelector('.wind-animation-container');
  if (container) {
    document.addEventListener('mousemove', (e) => {
      // Calculate mouse position relative to center of screen (values from -1 to 1)
      const mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
      const mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
      
      // Update CSS variables for parallax effect in wind-animation.css
      document.documentElement.style.setProperty('--mouse-x', mouseX);
      document.documentElement.style.setProperty('--mouse-y', mouseY);
    });
  }
});
