function handleVote(ideaId) {
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
            return;
        }

        const countElement = document.getElementById(`count-${ideaId}`);
        const btn = document.querySelector(`#idea-${ideaId} .vote-btn`);
        
        // Update count
        countElement.innerText = data.count;

        // Toggle button style and animation
        if (data.action === 'voted') {
            btn.classList.add('voted');
            btn.style.transform = "scale(1.2)"; // Simple pop effect
            setTimeout(() => btn.style.transform = "scale(1)", 200);
        } else {
            btn.classList.remove('voted');
        }
    })
    .catch(error => console.error('Error:', error));
}

function handleVote(ideaId) {
    const btn = document.querySelector(`#idea-${ideaId} .vote-btn`);
    const countElement = document.getElementById(`count-${ideaId}`);

    fetch(`/vote/${ideaId}`, { method: 'POST' })
    .then(res => res.json())
    .then(data => {
        // Vote Count update
        countElement.innerText = `${data.count} Votes`;

        if (data.action === 'voted') {
            btn.classList.add('voted');
            // Adding a little "Shake" animation on vote
            btn.animate([
                { transform: 'rotate(0deg)' },
                { transform: 'rotate(10deg)' },
                { transform: 'rotate(-10deg)' },
                { transform: 'rotate(0deg)' }
            ], { duration: 200 });
        } else {
            btn.classList.remove('voted');
        }
    });
}