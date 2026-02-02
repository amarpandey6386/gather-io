// static/js/animations.js
function animateSelection(cardId) {
    const card = document.getElementById(cardId);
    card.style.transition = "all 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275)";
    card.style.transform = "scale(0.2) rotate(15deg) translateY(-500px)";
    card.style.opacity = "0";
    
    setTimeout(() => {
        card.remove(); // Animation ke baad element hatana
    }, 600);
}