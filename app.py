import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date

app = Flask(__name__)
app.config['SECRET_KEY'] = 'una_clave_muy_secreta'

def get_db_connection():
    """Crea una conexión a la base de datos SQLite."""
    # detect_types permite que SQLite convierta automáticamente los tipos TIMESTAMP a objetos datetime de Python
    conn = sqlite3.connect('database.db', detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

class RegistrationForm(FlaskForm):
    nombre = StringField('Nombre', validators=[DataRequired()])
    username = StringField('Nombre de Usuario', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    dni = StringField('DNI', validators=[DataRequired(), Length(min=9, max=9)])
    password = PasswordField('Contraseña', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmar Contraseña', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Registrar')

    def validate_username(self, username):
        conn = get_db_connection()
        user_exists = conn.execute("SELECT id FROM usuarios WHERE username=?", (username.data,)).fetchone()
        conn.close()
        if user_exists:
            raise ValidationError('Este nombre de usuario ya está registrado.')

    def validate_email(self, email):
        conn = get_db_connection()
        email_exists = conn.execute("SELECT id FROM usuarios WHERE email=?", (email.data,)).fetchone()
        conn.close()
        if email_exists:
            raise ValidationError('Este email ya está registrado.')

    def validate_dni(self, dni):
        conn = get_db_connection()
        dni_exists = conn.execute("SELECT id FROM usuarios WHERE dni=?", (dni.data,)).fetchone()
        conn.close()
        if dni_exists:
            raise ValidationError('Este DNI ya está registrado.')

class LoginForm(FlaskForm):
    username = StringField('Nombre de Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Iniciar Sesión')

class AsesoriaForm(FlaskForm):
    """Formulario para crear o editar una asesoría (MODIFICADO)."""
    titulo = StringField('Título de la Asesoría', validators=[DataRequired()])
    descripcion = TextAreaField('Descripción del problema', validators=[DataRequired()])
    fecha = DateField('Fecha', format='%Y-%m-%d', validators=[DataRequired()])
    hora = SelectField('Hora', choices=[], validators=[DataRequired()])
    submit = SubmitField('Crear Asesoría')
    
    def validate_fecha(self, fecha):
        if fecha.data < date.today():
            raise ValidationError("La fecha no puede ser en el pasado.")


@app.route('/create_asesoria', methods=['GET', 'POST'])
def create_asesoria():
    """Página para crear una nueva asesoría (MODIFICADA)."""
    if 'user_id' not in session:
        flash('Debes iniciar sesión para crear una asesoría.', 'danger')
        return redirect(url_for('login'))
    
    form = AsesoriaForm()
    
    horas = []
    for i in range(7, 14):
        horas.append((f'{i:02d}:00', f'{i:02d}:00'))
    for i in range(15, 21):
        horas.append((f'{i:02d}:00', f'{i:02d}:00'))
    form.hora.choices = horas

    if form.validate_on_submit():
        fecha_str = form.fecha.data.strftime('%Y-%m-%d')
        hora_str = form.hora.data
        fecha_hora_str = f"{fecha_str} {hora_str}"
        fecha_hora_asesoria = datetime.strptime(fecha_hora_str, '%Y-%m-%d %H:%M')
        
        # Validamos que la fecha y hora completas sean futuras
        if fecha_hora_asesoria < datetime.now():
            flash('La hora seleccionada ya ha pasado. Por favor, elige una hora futura.', 'danger')
            return render_template('create_asesoria.html', form=form)

        user_id = session['user_id']
        titulo = form.titulo.data
        descripcion = form.descripcion.data
        
        conn = get_db_connection()
        # Guardamos el objeto datetime completo en la base de datos
        conn.execute("INSERT INTO asesorias (user_id, titulo, descripcion, fecha_hora) VALUES (?, ?, ?, ?)",
                     (user_id, titulo, descripcion, fecha_hora_asesoria))
        conn.commit()
        conn.close()
        
        flash('Asesoría creada con éxito.', 'success')
        return redirect(url_for('my_asesorias'))
    
    return render_template('create_asesoria.html', form=form)


@app.route('/asesoria/<int:asesoria_id>')
def asesoria_detalle(asesoria_id):
    """Muestra los detalles de una asesoría específica (MODIFICADA)."""
    if 'user_id' not in session:
        flash('Debes iniciar sesión para ver los detalles de una asesoría.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    asesoria = conn.execute("SELECT * FROM asesorias WHERE id = ?", (asesoria_id,)).fetchone()
    
    if asesoria is None:
        conn.close()
        flash('Asesoría no encontrada.', 'danger')
        return redirect(url_for('asesorias'))

    esta_registrado = conn.execute("SELECT * FROM registros_asesorias WHERE user_id = ? AND asesoria_id = ?",
                                      (session['user_id'], asesoria_id)).fetchone()
    creador = conn.execute("SELECT username FROM usuarios WHERE id = ?", (asesoria['user_id'],)).fetchone()
    es_creador = (session['user_id'] == asesoria['user_id'])
    asistentes = None
    if es_creador:
        asistentes = conn.execute('''SELECT u.username FROM registros_asesorias r JOIN usuarios u ON r.user_id = u.id
                                     WHERE r.asesoria_id = ?''', (asesoria_id,)).fetchall()
    conn.close()
    
    # Pasamos la fecha y hora actual a la plantilla para poder comparar
    return render_template('asesoria_detalle.html', 
                           asesoria=asesoria, 
                           esta_registrado=esta_registrado, 
                           creador=creador['username'],
                           es_creador=es_creador,
                           asistentes=asistentes,
                           now=datetime.now())


@app.route('/apuntar/<int:asesoria_id>')
def apuntarse(asesoria_id):
    """Registra al usuario actual en una asesoría (MODIFICADA)."""
    if 'user_id' not in session:
        flash('Debes iniciar sesión para apuntarte a una asesoría.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    asesoria = conn.execute("SELECT * FROM asesorias WHERE id = ?", (asesoria_id,)).fetchone()
    
    # Comprobamos si la asesoría ya ha pasado
    if asesoria['fecha_hora'] < datetime.now():
        flash('No puedes apuntarte a una asesoría que ya ha pasado.', 'warning')
        conn.close()
        return redirect(url_for('asesoria_detalle', asesoria_id=asesoria_id))

    if asesoria['user_id'] == session['user_id']:
        flash('No puedes apuntarte a tu propia asesoría.', 'danger')
        conn.close()
        return redirect(url_for('asesoria_detalle', asesoria_id=asesoria_id))

    try:
        conn.execute("INSERT INTO registros_asesorias (user_id, asesoria_id) VALUES (?, ?)",
                     (session['user_id'], asesoria_id))
        conn.commit()
        flash('Te has apuntado a la asesoría con éxito.', 'success')
    except sqlite3.IntegrityError:
        flash('Ya estás apuntado a esta asesoría.', 'info')
    finally:
        conn.close()
    
    return redirect(url_for('asesoria_detalle', asesoria_id=asesoria_id))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        flash('Ya tienes una sesión iniciada.', 'info')
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        nombre = form.nombre.data
        username = form.username.data
        email = form.email.data
        dni = form.dni.data
        password_hash = generate_password_hash(form.password.data)
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO usuarios (nombre, username, email, password, dni) VALUES (?, ?, ?, ?, ?)",
                         (nombre, username, email, password_hash, dni))
            conn.commit()
            user = conn.execute("SELECT id FROM usuarios WHERE username=?", (username,)).fetchone()
            session['username'] = username
            session['user_id'] = user['id']
            flash(f'¡Tu cuenta ha sido creada con éxito!', 'success')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash("Ocurrió un error inesperado al registrar el usuario.", 'danger')
            return redirect(url_for('register'))
        finally:
            conn.close()
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        flash('Ya tienes una sesión iniciada.', 'info')
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM usuarios WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['user_id'] = user['id']
            flash(f'¡Hola, {user["nombre"]}! Has iniciado sesión correctamente.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nombre de usuario o contraseña incorrectos.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('Debes iniciar sesión para acceder a esta página.', 'danger')
        return redirect(url_for('login'))


@app.route('/asesorias')
def asesorias():
    conn = get_db_connection()
    asesorias_disponibles = conn.execute('''
        SELECT a.id, a.titulo, a.descripcion, a.fecha_hora, u.username as creador
        FROM asesorias a
        JOIN usuarios u ON a.user_id = u.id
        WHERE a.fecha_hora > ?
        ORDER BY a.fecha_hora ASC
    ''', (datetime.now(),)).fetchall()
    conn.close()
    return render_template('asesorias.html', asesorias=asesorias_disponibles)


@app.route('/cancelar/<int:asesoria_id>')
def cancelar(asesoria_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para cancelar tu registro.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    conn.execute("DELETE FROM registros_asesorias WHERE user_id = ? AND asesoria_id = ?",
                 (session['user_id'], asesoria_id))
    conn.commit()
    conn.close()
    flash('Has cancelado tu registro a la asesoría.', 'info')
    return redirect(url_for('asesoria_detalle', asesoria_id=asesoria_id))


@app.route('/my_asesorias')
def my_asesorias():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para ver tus asesorías.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    asesorias = conn.execute("SELECT * FROM asesorias WHERE user_id = ? ORDER BY fecha_hora ASC", (session['user_id'],)).fetchall()
    conn.close()
    return render_template('my_asesorias.html', asesorias=asesorias)


@app.route('/my_apuntes')
def my_apuntes():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para ver tus apuntes.', 'danger')
        return redirect(url_for('login'))
    conn = get_db_connection()
    apuntes = conn.execute('''
        SELECT a.id, a.titulo, a.descripcion, a.fecha_hora, u.username as creador
        FROM registros_asesorias r
        JOIN asesorias a ON r.asesoria_id = a.id
        JOIN usuarios u ON a.user_id = u.id
        WHERE r.user_id = ?
        ORDER BY a.fecha_hora ASC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('my_apuntes.html', apuntes=apuntes)

if __name__ == '__main__':
    app.run(debug=True)