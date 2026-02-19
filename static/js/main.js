function handleVote(ideaId, event) {
    fetch(`/vote/${ideaId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert("Please login to vote!");
            window.location.href = "/login";
            return;
        }

        // Find the vote count element for this specific idea
        const ideaCard = event.target.closest('.idea-card');
        const voteCountElement = ideaCard.querySelector('.vote-count');
        const voteButton = ideaCard.querySelector('.btn-vote');
        
        // Update vote count
        voteCountElement.textContent = `⚡ ${data.count}`;

        // Toggle button style based on action
        if (data.action === 'voted') {
            voteButton.style.background = 'var(--primary)';
            voteButton.style.color = 'white';
            voteButton.textContent = 'Voted ✓';
            
            // Add animation
            voteButton.style.transform = 'scale(1.1)';
            setTimeout(() => {
                voteButton.style.transform = 'scale(1)';
            }, 200);
        } else {
            voteButton.style.background = 'var(--primary-light)';
            voteButton.style.color = 'var(--primary)';
            voteButton.textContent = 'Vote';
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Something went wrong. Please try again.');
    });
}
