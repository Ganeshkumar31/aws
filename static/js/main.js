// Global error handler for AJAX requests
$(document).ajaxError(function(event, jqxhr, settings, thrownError) {
    if (jqxhr.status === 401) {
        // Unauthorized - redirect to login
        window.location.href = '/login';
    } else if (jqxhr.responseJSON && jqxhr.responseJSON.message) {
        alert(jqxhr.responseJSON.message);
    } else {
        alert('An error occurred. Please try again.');
    }
});

// Initialize tooltips
$(function() {
    $('[data-bs-toggle="tooltip"]').tooltip();
});

// Initialize popovers
$(function() {
    $('[data-bs-toggle="popover"]').popover();
});

// Handle session timeout
let idleTime = 0;
$(document).ready(function() {
    // Increment idle time every minute
    const idleInterval = setInterval(timerIncrement, 60000); // 1 minute

    // Zero idle time on mouse movement or key press
    $(this).mousemove(function() {
        idleTime = 0;
    });
    $(this).keypress(function() {
        idleTime = 0;
    });
});

function timerIncrement() {
    idleTime++;
    if (idleTime > 29) { // 30 minutes idle
        alert('You have been idle for too long. You will be logged out.');
        window.location.href = '/logout';
    }
}

// Handle notifications
function showNotification(type, message) {
    const alert = $(`
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `);
    $('#notifications').append(alert);

    // Auto dismiss after 5 seconds
    setTimeout(() => {
        alert.alert('close');
    }, 5000);
}

// Handle form submissions
$('form:not([edit-mode])').submit(function(e) {
    e.preventDefault();
    const form = $(this);
    const submitBtn = form.find('button[type="submit"]');
    const originalText = submitBtn.html();

    // Show loading state
    submitBtn.prop('disabled', true).html('<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...');

    // Submit form via AJAX
    $.ajax({
        url: form.attr('action'),
        method: form.attr('method'),
        data: form.serialize(),
        success: function(response) {
            if (response.redirect) {
                window.location.href = response.redirect;
            } else if (response.message) {
                showNotification('success', response.message);
                form.trigger('reset');
            }
        },
        complete: function() {
            submitBtn.prop('disabled', false).html(originalText);
        }
    });
});