document.addEventListener('DOMContentLoaded', function() {

    // --- Password Reveal Functionality ---
    const revealButtons = document.querySelectorAll('.btn-reveal');

    revealButtons.forEach(button => {
        button.addEventListener('click', function() {
            const itemId = this.dataset.itemId;
            const itemType = this.dataset.itemType;
            const passwordSpan = document.querySelector(`.password-display[data-item-id="${itemId}"][data-item-type="${itemType}"]`);

            if (!passwordSpan) {
                console.error('Password display span not found for item:', itemId, itemType);
                return;
            }

            // Check if password is already revealed
            if (passwordSpan.classList.contains('password-revealed')) {
                passwordSpan.textContent = '********';
                passwordSpan.classList.remove('password-revealed');
                this.innerHTML = '<i class="fas fa-eye"></i>'; // Change icon back
                this.title = 'Reveal Password';
            } else {
                // Fetch the password from the server
                fetch(`/get_password/${itemType}/${itemId}`)
                    .then(response => {
                        if (!response.ok) {
                            throw new Error(`HTTP error! status: ${response.status}`);
                        }
                        return response.json();
                    })
                    .then(data => {
                        if (data.password) {
                            passwordSpan.textContent = data.password;
                            passwordSpan.classList.add('password-revealed');
                            this.innerHTML = '<i class="fas fa-eye-slash"></i>'; // Change icon
                            this.title = 'Hide Password';

                             // Optional: Hide password automatically after a delay
                             setTimeout(() => {
                                if (passwordSpan.classList.contains('password-revealed')) {
                                     passwordSpan.textContent = '********';
                                     passwordSpan.classList.remove('password-revealed');
                                     this.innerHTML = '<i class="fas fa-eye"></i>';
                                     this.title = 'Reveal Password';
                                }
                             }, 15000); // Hide after 15 seconds

                        } else {
                            passwordSpan.textContent = '[Error]';
                            alert('Error retrieving password: ' + (data.error || 'Unknown error'));
                        }
                    })
                    .catch(error => {
                        console.error('Error fetching password:', error);
                        passwordSpan.textContent = '[Error]';
                        alert('Could not fetch password. See console for details.');
                    });
            }
        });
    });

    // --- Password Copy Functionality ---
    const copyButtons = document.querySelectorAll('.btn-copy');

    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const itemId = this.dataset.itemId;
            const itemType = this.dataset.itemType;
            const icon = this.querySelector('i');
            const originalIconClass = icon.className; // Store original icon

            // Fetch the password first
            fetch(`/get_password/${itemType}/${itemId}`)
                .then(response => {
                    if (!response.ok) { throw new Error('Network response was not ok'); }
                    return response.json();
                })
                .then(data => {
                    if (data.password) {
                        // Use the Clipboard API
                        navigator.clipboard.writeText(data.password).then(() => {
                            // Success feedback
                            icon.className = 'fas fa-check text-success'; // Change icon to checkmark
                            this.title = 'Copied!';
                            // Revert icon back after a delay
                            setTimeout(() => {
                                icon.className = originalIconClass;
                                this.title = 'Copy Password';
                            }, 2000); // Revert after 2 seconds
                        }).catch(err => {
                            console.error('Failed to copy password: ', err);
                            alert('Failed to copy password. Your browser might not support this feature or permission was denied.');
                             // Provide error feedback (optional)
                            icon.className = 'fas fa-times text-danger';
                             setTimeout(() => {
                                icon.className = originalIconClass;
                                this.title = 'Copy Password';
                            }, 2000);
                        });
                    } else {
                         alert('Error retrieving password for copying: ' + (data.error || 'Unknown error'));
                    }
                })
                .catch(error => {
                    console.error('Error fetching password for copy:', error);
                    alert('Could not fetch password to copy.');
                });
        });
    });

}); // End DOMContentLoaded