from flask import Flask, jsonify, request, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Inicializamos la aplicación
app = Flask(__name__)

# Configuración de la base de datos y la clave secreta
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SECRET_KEY'] = 'mi_clave_secreta'  # Cambia esto por una clave más segura en producción
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelo de Usuario
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# Carga el usuario
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ruta para la página principal
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# Ruta para registro de usuario
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Usuario creado con éxito. Ahora puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Ruta para inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        # Verificamos si el usuario existe
        if user is None:
            flash('Usuario no encontrado. Verifica tu email.', 'danger')
        # Verificamos si la contraseña es correcta
        elif not bcrypt.check_password_hash(user.password, password):
            flash('Contraseña incorrecta. Intenta nuevamente.', 'danger')
        else:
            login_user(user)
            return redirect(url_for('index'))

    return render_template('login.html')


# Ruta para cerrar sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# CRUD de ejemplo
items = []

# Ruta para obtener todos los items
@app.route('/items', methods=['GET'])
@login_required
def get_items():
    return jsonify(items)

# Ruta para crear un nuevo item
@app.route('/items', methods=['POST'])
@login_required
def create_item():
    data = request.json
    item = {
        'id': len(items) + 1,
        'name': data['name'],
        'description': data['description']
    }
    items.append(item)
    return jsonify(item), 201

# Ruta para actualizar un item existente
@app.route('/items/<int:item_id>', methods=['PUT'])
@login_required
def update_item(item_id):
    data = request.json
    item = next((item for item in items if item['id'] == item_id), None)
    if item is None:
        return jsonify({'error': 'Item no encontrado'}), 404

    item['name'] = data['name']
    item['description'] = data['description']
    return jsonify(item)

# Ruta para eliminar un item
@app.route('/items/<int:item_id>', methods=['DELETE'])
@login_required
def delete_item(item_id):
    global items
    items = [item for item in items if item['id'] != item_id]
    return jsonify({'message': 'Item eliminado'}), 204

# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(debug=True)
