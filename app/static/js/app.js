// Modal utilities
var _previouslyFocused = null;

function isModalVisible(modal) {
    return !modal.classList.contains('d-none') && modal.style.display !== 'none';
}

function showModal(modalId) {
    var modal = document.getElementById(modalId);
    _previouslyFocused = document.activeElement;
    modal.classList.remove('d-none');
    modal.style.display = 'flex';

    // Focus first focusable element
    var focusable = modal.querySelectorAll('button, input, select, textarea, [tabindex]:not([tabindex="-1"])');
    if (focusable.length) {
        focusable[0].focus();
    }

    // Trap focus within modal
    modal._trapFocus = function(e) {
        if (e.key !== 'Tab') return;
        var focusableEls = modal.querySelectorAll('button, input, select, textarea, [tabindex]:not([tabindex="-1"])');
        var first = focusableEls[0];
        var last = focusableEls[focusableEls.length - 1];
        if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
        }
    };
    modal.addEventListener('keydown', modal._trapFocus);
}

function hideModal(modalId) {
    var modal = document.getElementById(modalId);
    modal.classList.add('d-none');
    modal.style.display = 'none';
    if (modal._trapFocus) {
        modal.removeEventListener('keydown', modal._trapFocus);
        delete modal._trapFocus;
    }
    if (_previouslyFocused) {
        _previouslyFocused.focus();
        _previouslyFocused = null;
    }
}

// Close modals on escape
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal').forEach(function(m) {
            if (isModalVisible(m)) {
                hideModal(m.id);
            }
        });
    }
});

// Close modal on backdrop click
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal') && isModalVisible(e.target)) {
        hideModal(e.target.id);
    }
});

// Handle data-dismiss="modal" clicks
document.addEventListener('click', function(e) {
    var btn = e.target.closest('[data-dismiss="modal"]');
    if (btn) {
        var modal = btn.closest('.modal');
        if (modal) {
            hideModal(modal.id);
        }
    }
});

// Confirm dialogs via data attribute
document.addEventListener('click', function(e) {
    const btn = e.target.closest('[data-confirm]');
    if (btn && !confirm(btn.dataset.confirm)) {
        e.preventDefault();
    }
});

// Clipboard with fallback
function copyToClipboard(text, successMessage) {
    successMessage = successMessage || 'Copied!';
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function() {
            alert(successMessage);
        });
    } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        alert(successMessage);
    }
}

// Share type toggle (notes/share.html)
function toggleShareType() {
    var shareType = document.querySelector('input[name="share_type"]:checked');
    if (!shareType) return;
    var userInput = document.getElementById('user-input');
    var teamInput = document.getElementById('team-input');
    if (!userInput || !teamInput) return;

    if (shareType.value === 'user') {
        userInput.classList.remove('d-none');
        teamInput.classList.add('d-none');
    } else {
        userInput.classList.add('d-none');
        teamInput.classList.remove('d-none');
    }
}

// Notes level toggle (dashboard/api_keys_new.html)
function toggleNotesLevel() {
    var selected = document.querySelector('input[name="notes_access"]:checked');
    if (!selected) return;
    var levelSection = document.getElementById('notes-level-section');
    var selectionSection = document.getElementById('notes-selection');

    if (selected.value === 'none') {
        if (levelSection) levelSection.classList.add('d-none');
        if (selectionSection) selectionSection.classList.add('d-none');
    } else if (selected.value === 'all') {
        if (levelSection) levelSection.classList.remove('d-none');
        if (selectionSection) selectionSection.classList.add('d-none');
    } else if (selected.value === 'selected') {
        if (levelSection) levelSection.classList.remove('d-none');
        if (selectionSection) selectionSection.classList.remove('d-none');
    }
}

// Impersonation modal (orgs/settings/members.html)
function showImpersonateModal(userId, email, baseUrl) {
    document.getElementById('impersonateEmail').textContent = email;
    document.getElementById('impersonateForm').action = baseUrl.replace('__USER_ID__', userId);
    document.getElementById('impersonateReason').value = '';
    showModal('impersonateModal');
}

// Toggle element visibility
function toggleElement(elementId) {
    var el = document.getElementById(elementId);
    if (el) el.classList.toggle('d-none');
}

// Event delegation for data attributes
document.addEventListener('DOMContentLoaded', function() {
    // Handle share type radio changes
    document.querySelectorAll('input[name="share_type"]').forEach(function(radio) {
        radio.addEventListener('change', toggleShareType);
    });

    // Handle notes access radio changes
    document.querySelectorAll('input[name="notes_access"]').forEach(function(radio) {
        radio.addEventListener('change', toggleNotesLevel);
    });

    // Handle data-copy-target clicks
    document.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-copy-target]');
        if (btn) {
            var targetId = btn.dataset.copyTarget;
            var target = document.getElementById(targetId);
            if (target) {
                copyToClipboard(target.textContent);
            }
        }
    });

    // Handle data-toggle-target clicks
    document.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-toggle-target]');
        if (btn) {
            toggleElement(btn.dataset.toggleTarget);
        }
    });

    // Handle impersonate button clicks
    document.addEventListener('click', function(e) {
        var btn = e.target.closest('[data-impersonate]');
        if (btn) {
            showImpersonateModal(
                btn.dataset.userId,
                btn.dataset.userEmail,
                btn.dataset.impersonateUrl
            );
        }
    });
});
