document.addEventListener('DOMContentLoaded', function() {
    // Obtener todos los mensajes flash
    var flashMessages = document.querySelectorAll('.alert-flash');
    flashMessages.forEach(function(message) {
        if (message.classList.contains('alert-success')) {
            // Si es un mensaje de éxito, mostrar un alert de JS
            alert(message.textContent.trim());
        }
    });
});