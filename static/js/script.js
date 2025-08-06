document.addEventListener('DOMContentLoaded', function() {
    // Actualizar el año actual en el footer
    const currentYearElement = document.getElementById('currentYear');
    if (currentYearElement) {
        const currentYear = new Date().getFullYear();
        currentYearElement.textContent = currentYear;
    }

    // Validación de fechas para crear asesorías
    const diaField = document.getElementById('diaField');
    const dateAlert = document.getElementById('dateAlert');
    
    if (diaField && dateAlert) {
        function checkDate() {
            const selectedDate = new Date(diaField.value);
            const today = new Date();
            const tomorrow = new Date(today);
            tomorrow.setDate(tomorrow.getDate() + 1);
            tomorrow.setHours(0, 0, 0, 0);
            
            if (selectedDate < tomorrow) {
                dateAlert.style.display = 'block';
                diaField.classList.add('is-invalid');
            } else {
                dateAlert.style.display = 'none';
                diaField.classList.remove('is-invalid');
            }
        }
        
        diaField.addEventListener('change', checkDate);
        // Verificar al cargar la página si ya hay un valor
        if (diaField.value) {
            checkDate();
        }
    }

    // Obtener todos los mensajes flash
    var flashMessages = document.querySelectorAll('.alert-flash');
    flashMessages.forEach(function(message) {
        if (message.classList.contains('alert-success')) {
            // Si es un mensaje de éxito, mostrar un alert de JS
            alert(message.textContent.trim());
        }
    });
});