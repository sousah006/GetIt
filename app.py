import os
from flask import Flask, render_template, send_from_directory, redirect, url_for, session, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask import render_template, redirect, url_for, flash, session
from sqlalchemy.exc import IntegrityError


os.chdir(r"C:\Users\Utilizador\Desktop\PAP\server")



app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Configurações para uploads
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['UPLOAD_VIPFOLDER'] = 'uploads/vipphotos'
app.config['ALLOWED_EXTENSIONS'] = {'zip', 'jpg', 'jpeg', 'png' , 'gif'}
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///uploads.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['IMAGE_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'images')
app.config['GIFT_FOLDER'] = os.path.join(app.config['UPLOAD_FOLDER'], 'gifts')

app.config['TEMPLATE_FOLDER'] = 'templates/details'  


db = SQLAlchemy(app)

# Configurações para upload de arquivos e pastas extras
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'zip'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['EXTRA_FILES'] = [
    os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], 'index1'),
    os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], 'index2'),
    os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], 'index3'),
    os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], 'index4'),  
    os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], 'index5'),  
]

                            

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    orders = db.relationship('ProjectOrder', back_populates='user')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(255))
    filename = db.Column(db.String(120), nullable=False, unique=True)
    destination = db.Column(db.String(50))
    photo_filename = db.Column(db.String(100))
    saved_by = db.Column(db.String(20), nullable=True)
    details = db.Column(db.String(255))  # Novo campo adicionado


class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref=db.backref('feedbacks', lazy=True))

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))

class VipChat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('vip_messages', lazy=True))
    message = db.Column(db.Text, nullable=True)
    image_filename = db.Column(db.String(120), nullable=True)
    gift_filename = db.Column(db.String(120), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class UserFavoriteProjects(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'))
    user = db.relationship('User', backref=db.backref('favorite_projects_association'))
    
    
# Configuração do caminho para salvar os arquivos de detalhes
DETAILS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates/details')
os.makedirs(DETAILS_DIR, exist_ok=True)





# Definição do modelo BasicPlanUser
class WaitingBasicPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)


# Definição do modelo BasicPlanUser
class WaitingGoldPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

# Definição do modelo BasicPlanUser
class WaitingDiamondPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)


# Definição do modelo BasicPlanUser
class BasicPlanUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

# Definição do modelo GoldPlanUser
class GoldPlanUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

# Definição do modelo DiamondPlanUser
class DiamondPlanUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    
class ProjectOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', back_populates='orders')



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def main():
    return redirect('/main')

@app.route('/main')
def main_page():
    files = File.query.filter_by(destination='main').all()
    logged_in = 'logged_in' in session and session['logged_in']
    is_admin = session.get('username') == 'admin' if logged_in else False

    # Verifica se o usuário atual está registrado como GoldPlanUser ou DiamondPlanUser
    if logged_in:
        current_username = session.get('username')
        is_gold_plan_user = GoldPlanUser.query.filter_by(username=current_username).first() is not None
        is_diamond_plan_user = DiamondPlanUser.query.filter_by(username=current_username).first() is not None
    else:
        is_gold_plan_user = False
        is_diamond_plan_user = False

    return render_template('main.html', files=files, logged_in=logged_in, is_admin=is_admin,
                           is_gold_plan_user=is_gold_plan_user, is_diamond_plan_user=is_diamond_plan_user)


@app.route('/WaitingUsers')
def WaitingUsers():
    basic_plan_users = WaitingBasicPlan.query.all()
    gold_plan_users = WaitingGoldPlan.query.all()
    diamond_plan_users = WaitingDiamondPlan.query.all()

    return render_template('WaitingUsers.html', basic_plan_users=basic_plan_users, gold_plan_users=gold_plan_users, diamond_plan_users=diamond_plan_users)
    
@app.route('/order_projects', methods=['GET', 'POST'])
def order_projects():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('main'))

    current_username = session.get('username')
    current_user = User.query.filter_by(username=current_username).first()

    if not current_user:
        flash('User not found.')
        return redirect(url_for('main'))

    is_admin = current_username == 'admin'
    is_gold_plan_user = GoldPlanUser.query.filter_by(username=current_username).first() is not None
    is_diamond_plan_user = DiamondPlanUser.query.filter_by(username=current_username).first() is not None

    is_authorized = is_admin or is_gold_plan_user or is_diamond_plan_user

    if not is_authorized:
        flash('Access denied. Only authorized users can access this page.')
        return redirect(url_for('main'))

    if request.method == 'POST':
        project_details = request.form.get('project_details')

        if project_details:
            new_order = ProjectOrder(user_id=current_user.id, details=project_details)
            db.session.add(new_order)
            db.session.commit()
            flash('Project order submitted successfully.')
            return redirect(url_for('order_projects'))

    project_orders = ProjectOrder.query.all()

    return render_template('order_projects.html', current_user=current_user, is_admin=is_admin,
                           is_gold_plan_user=is_gold_plan_user, is_diamond_plan_user=is_diamond_plan_user,
                           project_orders=project_orders)



@app.route('/delete_orders', methods=['POST'])
def delete_orders():
    try:
        data = request.json
        order_ids = data.get('order_ids')

        if not order_ids:
            return jsonify({'success': False, 'message': 'No order IDs provided.'}), 400

        orders_to_delete = ProjectOrder.query.filter(ProjectOrder.id.in_(order_ids)).all()

        if not orders_to_delete:
            return jsonify({'success': False, 'message': 'No orders found with the provided IDs.'}), 404

        for order in orders_to_delete:
            db.session.delete(order)

        db.session.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


    
@app.route('/submitWaitingBasicPlan', methods=['POST'])
def submit_waiting_basic_plan():
    username = session.get('username')  # Certifique-se de configurar isso corretamente

    # Obtenha os dados do formulário
    email = request.form.get('basicEmail')

    # Tente inserir o novo usuário
    try:
        new_waiting_basic_plan_user = WaitingBasicPlan(username=username, email=email)
        db.session.add(new_waiting_basic_plan_user)
        db.session.commit()
        return jsonify(success=True, message='User added successfully'), 200
    except IntegrityError as e:
        db.session.rollback()  # Rollback para evitar mudanças na base de dados
        return jsonify(success=False, message='Email already exists'), 400  # Retorne status 400 para indicar erro
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500  # Trate outros erros de forma adequada



@app.route('/submitBasicPlan', methods=['POST'])
def submit_basic_plan():
    username = session.get('username')  # Certifique-se de configurar isso corretamente

    # Obtenha os dados do formulário
    email = request.form.get('basicEmail')

    # Tente inserir o novo usuário
    try:
        new_basic_plan_user = BasicPlanUser(username=username, email=email)
        db.session.add(new_basic_plan_user)
        db.session.commit()
        return jsonify(success=True, message='User added successfully'), 200
    except IntegrityError as e:
        db.session.rollback()  # Rollback para evitar mudanças na base de dados
        return jsonify(success=False, message='Email already exists'), 400  # Retorne status 400 para indicar erro
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500  # Trate outros erros de forma adequada

@app.route('/submitWaitingGoldPlan', methods=['POST'])
def submit_waiting_gold_plan():
    username = session.get('username')  # Certifique-se de configurar isso corretamente

    # Obtenha os dados do formulário
    email = request.form.get('goldEmail')

    # Tente inserir o novo usuário
    try:
        new_waiting_gold_plan_user = WaitingGoldPlan(username=username, email=email)
        db.session.add(new_waiting_gold_plan_user)
        db.session.commit()
        return jsonify(success=True, message='User added successfully'), 200
    except IntegrityError as e:
        db.session.rollback()  # Rollback para evitar mudanças na base de dados
        return jsonify(success=False, message='Email already exists'), 400  # Retorne status 400 para indicar erro
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500  # Trate outros erros de forma adequada

@app.route('/submitGoldPlan', methods=['POST'])
def submit_gold_plan():
    username = session.get('username')  # Ensure this is set appropriately in your app

    if not username:
        return jsonify(success=False, message="User not logged in"), 401

    email = request.form.get('goldEmail')

    if not email:
        return jsonify(success=False, message="Email is required"), 400

    try:
        new_user = GoldPlanUser(username=username, email=email)
        db.session.add(new_user)
        db.session.commit()
        return jsonify(success=True, message="User registered successfully"), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify(success=False, message="Email already exists"), 400
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500


@app.route('/submitWaitingDiamondPlan', methods=['POST'])
def submit_waiting_diamond_plan():
    username = session.get('username')  # Certifique-se de configurar isso corretamente

    # Obtenha os dados do formulário
    email = request.form.get('diamondEmail')

    # Tente inserir o novo usuário
    try:
        new_waiting_diamond_plan_user = WaitingDiamondPlan(username=username, email=email)
        db.session.add(new_waiting_diamond_plan_user)
        db.session.commit()
        return jsonify(success=True, message='User added successfully'), 200
    except IntegrityError as e:
        db.session.rollback()  # Rollback para evitar mudanças na base de dados
        return jsonify(success=False, message='Email already exists'), 400  # Retorne status 400 para indicar erro
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500  # Trate outros erros de forma adequada
    

@app.route('/submitDiamondPlan', methods=['POST'])
def submit_diamond_plan():
    username = session.get('username')  # Ensure this is set appropriately in your app

    if not username:
        return jsonify(success=False, message="User not logged in"), 401

    email = request.form.get('diamondEmail')

    if not email:
        return jsonify(success=False, message="Email is required"), 400

    try:
        new_user = DiamondPlanUser(username=username, email=email)
        db.session.add(new_user)
        db.session.commit()
        return jsonify(success=True, message="User registered successfully"), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify(success=False, message="Email already exists"), 400
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, message=str(e)), 500
    
    
@app.route('/plans')
def plans():
    if 'logged_in' in session and session['logged_in'] and session.get('username') == 'admin':
        basic_plan_users = BasicPlanUser.query.all()
        gold_plan_users = GoldPlanUser.query.all()
        diamond_plan_users = DiamondPlanUser.query.all()
        return render_template('plans.html', 
                               basic_plan_users=basic_plan_users, 
                               gold_plan_users=gold_plan_users, 
                               diamond_plan_users=diamond_plan_users)
    else:
        flash('Acesso restrito. Apenas o administrador pode acessar esta página.', 'error')
        return redirect(url_for('main'))
    
@app.route('/add_user', methods=['POST'])
def add_user():
    plan = request.form['plan']
    username = request.form['username']
    email = request.form['email']
    
    if plan == 'basic':
        if BasicPlanUser.query.filter((BasicPlanUser.username == username) | (BasicPlanUser.email == email)).first():
            flash('Username ou Email já existe no Basic Plan.', 'error')
        else:
            new_user = BasicPlanUser(username=username, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash('User successfully added to Basic Plan.', 'success')
    elif plan == 'gold':
        if GoldPlanUser.query.filter((GoldPlanUser.username == username) | (GoldPlanUser.email == email)).first():
            flash('Username or Email already exists in the Gold Plan.', 'error')
        else:
            new_user = GoldPlanUser(username=username, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash('User successfully added to the Gold Plan.', 'success')
    elif plan == 'diamond':
        if DiamondPlanUser.query.filter((DiamondPlanUser.username == username) | (DiamondPlanUser.email == email)).first():
            flash('Username or Email already exists in the Diamond Plan.', 'error')
        else:
            new_user = DiamondPlanUser(username=username, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash('User successfully added to Diamond Plan.', 'success')

    return redirect(url_for('plans'))

@app.route('/remove_user', methods=['POST'])
def remove_user():
    plan = request.form['plan']
    user_id = request.form['user_id']
    
    if plan == 'basic':
        user = BasicPlanUser.query.get(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User removed from Basic Plan.', 'success')
    elif plan == 'gold':
        user = GoldPlanUser.query.get(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User removed from Gold Plan.', 'success')
    elif plan == 'diamond':
        user = DiamondPlanUser.query.get(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User removed from Diamond Plan.', 'success')
        
    return redirect(url_for('plans'))


# Rota para remover usuário
@app.route('/remove_waiting_user', methods=['POST'])
def remove_waiting_user():
    plan = request.form['plan']
    user_id = request.form['user_id']

    if plan == 'basic':
        user = WaitingBasicPlan.query.get(user_id)
    elif plan == 'gold':
        user = WaitingGoldPlan.query.get(user_id)
    elif plan == 'diamond':
        user = WaitingDiamondPlan.query.get(user_id)
    else:
        flash('Invalid plan specified.', 'error')
        return redirect(url_for('waiting_users'))

    if not user:
        flash('User not found.', 'error')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')

    return redirect(url_for('WaitingUsers'))



@app.route('/user_popup_login', methods=['POST'])
def user_popup_login():
    print("Login request received from client.")
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        session['logged_in'] = True
        session['username'] = username  # Armazenar o nome de usuário na sessão
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Invalid username or password'})

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username').lower()  # Convertendo para minúsculas
    password = request.json.get('password')
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'success': False, 'message': 'Username already exists'})
    else:
        try:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Registration successful'})
        except Exception as e:
            print(f"Error occurred during registration: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Error occurred during registration. Please try again.'})

@app.route('/shop')
def index_shop():
    return render_template('shop.html')

@app.route('/grillzs')
def grillzs():
    return render_template('products/grillzs.html')

@app.route('/logo')
def logo():
    return render_template('products/logo.html')

@app.route('/gallery')  
def gallery():
    return render_template('gallery.html')

@app.route('/drop')
def drop():
    return render_template('drop.html')

@app.route('/security')
def security():
    return render_template('security.html')

@app.route('/resources')
def resources():
    return render_template('resources.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/docs')
def docs():
    return render_template('docs.html')

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')


@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')


@app.route('/feedbacks')
def feedbacks():
    if 'logged_in' in session and session['logged_in'] and session['username'] == 'admin':
        return render_template('feedbacks.html')
    else:
        flash('Access denied. Admins only.')
        return redirect(url_for('main'))


@app.route('/get_feedbacks', methods=['GET'])
def get_feedbacks():
    feedbacks = Feedback.query.all()
    feedbacks_data = [
        {
            'id': feedback.id,
            'user': {'username': feedback.user.username if feedback.user else 'Unknown'},
            'message': feedback.message
        }
        for feedback in feedbacks
    ]
    return jsonify(feedbacks_data)


@app.route('/delete_feedback/<int:feedback_id>', methods=['DELETE'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get(feedback_id)
    if feedback:
        db.session.delete(feedback)
        db.session.commit()
        return '', 204
    return jsonify({'error': 'Feedback not found'}), 404


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('main'))

    if request.method == 'POST':
        message_content = request.form.get('message')
        if message_content:
            username = session['username']
            user = User.query.filter_by(username=username).first()
            if user:
                new_message = ChatMessage(user_id=user.id, message=message_content)
                db.session.add(new_message)
                db.session.commit()

    messages = ChatMessage.query.order_by(ChatMessage.timestamp.asc()).all()
    is_admin = session.get('username') == 'admin'
    current_user = User.query.filter_by(username=session['username']).first()
    return render_template('chat.html', messages=messages, is_admin=is_admin, current_user=current_user)



@app.route('/vipchat', methods=['GET', 'POST'])
def vipchat():
    if 'logged_in' not in session or not session['logged_in']:
        return redirect(url_for('main'))

    current_username = session.get('username')
    current_user = User.query.filter_by(username=current_username).first()

    if not current_user:
        flash('User not found.')
        return redirect(url_for('main'))

    is_authorized = (
        current_username == 'admin' or
        GoldPlanUser.query.filter_by(username=current_username).first() is not None or
        DiamondPlanUser.query.filter_by(username=current_username).first() is not None or
        BasicPlanUser.query.filter_by(username=current_username).first() is not None
    )

    if not is_authorized:
        flash('Access denied. Only authorized users can access the VIP chat.')
        return redirect(url_for('main'))

    if request.method == 'POST':
        message_content = request.form.get('message')
        image = request.files.get('image')
        gift = request.files.get('gift')
        image_filename = None
        gift_filename = None

        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_VIPFOLDER'], image_filename)
            image.save(image_path)

        if gift and allowed_file(gift.filename):
            gift_filename = secure_filename(gift.filename)
            gift_path = os.path.join(app.config['UPLOAD_VIPFOLDER'], gift_filename)
            gift.save(gift_path)

        if message_content or image_filename or gift_filename:
            new_message = VipChat(user_id=current_user.id, message=message_content, image_filename=image_filename, gift_filename=gift_filename)
            db.session.add(new_message)
            db.session.commit()
            flash('Message sent successfully.')

        # Redirecionar após o processamento do formulário para evitar envios duplicados ao atualizar a página
        return redirect(url_for('vipchat'))

    # Buscar todas as mensagens e outros dados necessários para exibir na página
    messages = VipChat.query.order_by(VipChat.timestamp.asc()).all()
    is_admin = current_username == 'admin'

    # Renderizar o template 'vipchat.html' com os dados necessários
    return render_template('vipchat.html', messages=messages, is_admin=is_admin, current_user=current_user, is_authorized=is_authorized)


# Rota para remover mensagens (novo endpoint)
@app.route('/remove_vipmessages', methods=['POST'])
def remove_vipmessages():
    data = request.json
    message_ids = data.get('messages', [])

    try:
        # Remover as mensagens do banco de dados
        for message_id in message_ids:
            message = VipChat.query.get(message_id)
            if message:
                db.session.delete(message)
                db.session.commit()

        return jsonify({'success': True})
    except Exception as e:
        print(str(e))
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete_messages', methods=['POST'])
def delete_messages():
    message_ids = request.json.get('messages', [])
    for message_id in message_ids:
        # Excluir as mensagens do banco de dados
        message = ChatMessage.query.get(message_id)
        if message:
            db.session.delete(message)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/save_project', methods=['POST'])
def save_project():
    data = request.json
    username = session.get('username')  # Obter o nome de usuário da sessão

    # Verificar se o usuário está logado
    if not username:
        return jsonify({'success': False, 'message': 'User not logged in'}), 401

    # Verificar se o usuário existe no banco de dados
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    file_id = data.get('file_id')  # Obter o ID do arquivo do JSON
    destination = data.get('destination')  # Obter a fonte de onde o arquivo foi salvo ('index1', 'index2', 'index3', 'index4' , 'index5')

    # Verificar se o arquivo existe no banco de dados
    file = File.query.filter_by(id=file_id).first()
    if not file:
        return jsonify({'success': False, 'message': 'File not found'}), 404

    try:
        # Verificar se o projeto já está salvo pelo usuário
        if UserFavoriteProjects.query.filter_by(user_id=user.id, file_id=file_id).first():
            return jsonify({'success': False, 'message': 'File already saved.'}), 400

        # Salvar o projeto favorito na tabela user_favorite_projects
        user_favorite_project = UserFavoriteProjects(user_id=user.id, file_id=file_id)
        db.session.add(user_favorite_project)
        
        # Definir o campo saved_by no objeto File
        file.saved_by = destination
        db.session.commit()

        return jsonify({'success': True, 'message': 'File saved successfully.'}), 200
    except Exception as e:
        print(f"Error saving project: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error saving project. Please try again.'}), 500

    

@app.route('/get_saved_projects', methods=['GET'])
def get_saved_projects():
    if 'logged_in' not in session or not session['logged_in']:
        saved_files = File.query.filter_by(saved_by=current_user.username).all()
        return jsonify({
            "success": True,
            "saved_projects": [file.id for file in saved_files]
        })
    else:
        return jsonify({
            "success": False,
            "message": "User not authenticated"
        }), 401



def retrieve_saved_files(user):
    print("retrieve_saved_files called with user:", user)
    if user:
        saved_project_ids = [fp.file_id for fp in user.favorite_projects_association]
        saved_files = File.query.filter(File.id.in_(saved_project_ids)).all()
        return saved_files
    return []

@app.route('/saved', methods=['GET'])
def saved():
    if 'logged_in' not in session or not session['logged_in']:
        flash('You need to be logged in to view saved files.')
        return redirect ('main')

    # Obter o usuário atualmente logado
    username = session['username']
    user = User.query.filter_by(username=username).first()

    if not user:
        flash('User not found.')
        return redirect ('main_page')

    # Recuperar os IDs dos arquivos que o usuário salvou
    saved_project_ids = [fp.file_id for fp in user.favorite_projects_association]

    # Consultar os objetos File correspondentes aos IDs salvos
    saved_files = File.query.filter(File.id.in_(saved_project_ids)).all()

    return render_template('saved.html', files=saved_files, current_user=user)



# Adicione o roteamento para servir as imagens estáticas
@app.route('/uploads/<path:filename>')
def uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/get_username')
def get_username():
    if 'username' in session:
        return jsonify(username=session['username'])
    else:
        return jsonify(username=None)


@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'User not logged in'})

    username = session.get('username')
    feedback_message = request.json.get('message')

    user = User.query.filter_by(username=username).first()

    if user and feedback_message:
        try:
            new_feedback = Feedback(user_id=user.id, message=feedback_message)
            db.session.add(new_feedback)
            db.session.commit()
            return jsonify({'success': True})
        except Exception as e:
            print(f"Error submitting feedback: {e}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Error submitting feedback. Please try again later.'})
    else:
        return jsonify({'success': False, 'message': 'Missing username or feedback message'})



@app.route('/index1')
def index1():
    files = File.query.filter_by(destination='index1').all()
    logged_in = 'logged_in' in session and session['logged_in']
    return render_template('index1.html', files=files, logged_in=logged_in, current_user=current_user)



@app.route('/index2')
def index2():
    files = File.query.filter_by(destination='index2').all()
    logged_in = 'logged_in' in session and session['logged_in']
    return render_template('index2.html', files=files, logged_in=logged_in, current_user=current_user)

@app.route('/index3')
def index3():
    files = File.query.filter_by(destination='index3').all()
    logged_in = 'logged_in' in session and session['logged_in']
    return render_template('index3.html', files=files, logged_in=logged_in, current_user=current_user)

@app.route('/index4')
def index4():
    files = File.query.filter_by(destination='index4').all()
    logged_in = 'logged_in' in session and session['logged_in']
    current_username = session.get('username')
    
    # Verifica se o usuário está nas tabelas de planos
    is_authorized = (
        current_username == 'admin' or
        GoldPlanUser.query.filter_by(username=current_username).first() is not None or
        DiamondPlanUser.query.filter_by(username=current_username).first() is not None or
        BasicPlanUser.query.filter_by(username=current_username).first() is not None
    )

    if not logged_in or not is_authorized:
        flash('Access denied. Only authorized users can access this page.')
        
        return redirect(url_for('choose_index'))
    
    return render_template('index4.html', files=files, logged_in=logged_in, current_user=current_user)


@app.route('/index5')
def index5():
    files = File.query.filter_by(destination='index5').all()
    logged_in = 'logged_in' in session and session['logged_in']
    current_username = session.get('username')
    
    # Verifica se o usuário está logado e se está na tabela diamondplanusers
    is_authorized = (
        current_username == 'admin' or
        DiamondPlanUser.query.filter_by(username=current_username).first() is not None
    )

    if not is_authorized:
        flash('Access denied. Only Diamond Plan users can access this page.')
        return redirect(url_for('choose_index'))
    
    return render_template('index5.html', files=files, logged_in=logged_in, current_user=current_user)


# Rota para a página de escolha entre index4 e index5
@app.route('/choose_index')
def choose_index():
    return render_template('choose_index.html')

@app.route('/download_file', methods=['GET'])
def download_file():
    filename = request.args.get('filename')
    destination = request.args.get('destination')

    if not filename or not destination:
        return jsonify({'error': 'Filename or destination not provided'}), 400

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], destination, filename)

    if os.path.isfile(file_path):
        return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], destination), filename, as_attachment=True)
    else:
        app.logger.error(f"File not found: {file_path}")
        return jsonify({'error': 'File not found'}), 404



def can_modify_username(user):
    return True


@app.route('/details/<filename>')
def details(filename):
    return render_template(f'details/{filename}.html')

# Função para verificar se a extensão do arquivo é válida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session.get('logged_in') and session.get('username') == 'admin':
        
        if request.method == 'POST':
            file = request.files['file']
            title = request.form['title']
            description = request.form['description']
            destination = request.form['destination']
            photo = request.files['photo']
            details = request.form['details']  # Novo campo adicionado

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                destination_folder = os.path.join(app.config['UPLOAD_FOLDER'], destination)
                os.makedirs(destination_folder, exist_ok=True)
                file.save(os.path.join(destination_folder, filename))

                if photo and allowed_file(photo.filename):
                    photo_filename = secure_filename(photo.filename)
                    photos_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'photos')
                    os.makedirs(photos_folder, exist_ok=True)
                    photo.save(os.path.join(photos_folder, photo_filename))
                else:
                    photo_filename = None

                details_filename = secure_filename(details) + ".html"
                new_file = File(
                    title=title, 
                    description=description, 
                    filename=filename, 
                    destination=destination, 
                    photo_filename=photo_filename, 
                    details=details_filename
                )
                db.session.add(new_file)
                db.session.commit()

                # Criação do arquivo HTML com base no campo 'details'
                html_content = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>{title}</title>
                </head>
                <body>
                    <h1>{title}</h1>
                    <p>{description}</p>
                    <p><strong>Details:</strong> {details}</p>
                </body>
                </html>
                """
                details_path = os.path.join(DETAILS_DIR, details_filename)
                with open(details_path, 'w') as f:
                    f.write(html_content)

                flash('Arquivo adicionado com sucesso!', 'success')
                return redirect(url_for('admin'))

        files = File.query.all()
        return render_template('admin.html', files=files)

    flash('You need to be logged in to join the session', 'error')
    return redirect(url_for('login'))




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Verificar se o nome de usuário e senha estão corretos
        if username == 'admin' and password == '12345':
            session['logged_in'] = True
            session['username'] = username  # Armazena o nome de usuário na sessão
            return redirect(url_for('admin'))  # Redireciona para a página admin após o login bem-sucedido
        else:
            flash('Credenciais inválidas. Tente novamente.', 'error')
    
    return render_template('login.html')  # Renderize a página de login

@app.route('/block')
def block():
    return render_template('block.html')

# Rota para remover um projeto favorito do usuário
@app.route('/remove_project', methods=['POST'])
def remove_project():
    data = request.json
    file_id = data.get('file_id')

    if not file_id:
        return jsonify({'success': False, 'message': 'File ID not provided'}), 400

    try:
        # Procurar e remover o projeto favorito pelo file_id
        favorite_project = UserFavoriteProjects.query.filter_by(file_id=file_id).first()

        if favorite_project:
            db.session.delete(favorite_project)
            db.session.commit()
            return jsonify({'success': True}), 200
        else:
            return jsonify({'success': False, 'message': 'Favorite project not found'}), 404

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/logout', methods=['POST'])
def logout():
    print("Logging out...")
    try:
        if session.get('logged_in'):
            session.pop('logged_in')
            session.pop('username')
            print("User logged out successfully.")
            return jsonify({'success': True, 'message': 'Logout successful'})
        else:
            print("User not logged in.")
            return jsonify({'success': False, 'message': 'User not logged in'})
    except Exception as e:
        print(f"Error during logout: {str(e)}")
        return jsonify({'success': False, 'message': 'Error during logout'})

@app.route('/update_user_settings', methods=['POST'])
def update_user_settings():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': 'User not logged in'})

    new_username = request.json.get('newUsername')
    new_password = request.json.get('newPassword')

    username = session['username']
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'success': False, 'message': 'User not found'})

    try:
        if not can_modify_username(user):
            return jsonify({'success': False, 'message': 'You can only modify username every 15 days'})

        user.username = new_username
        user.password = generate_password_hash(new_password)
        db.session.commit()
        session['username'] = new_username  # Atualizar o nome de usuário na sessão

        return jsonify({'success': True, 'message': 'User settings updated successfully'})
    except Exception as e:
        print(f"Error occurred during updating user settings: {e}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Error occurred during updating user settings. Please try again.'})
    

@app.route('/update/<int:id>', methods=['POST'])
def update_file(id):
    try:
        file_to_update = File.query.get(id)

        if file_to_update:
            data = request.form
            new_title = data.get('title')
            new_description = data.get('description')
            new_destination = data.get('destination')
            new_details = data.get('details')

            # Atualizar apenas se houver novos dados
            if new_title:
                file_to_update.title = new_title

            if new_description:
                file_to_update.description = new_description

            if new_destination:
                file_to_update.destination = new_destination

            if new_details:
                file_to_update.details = new_details

            # Verifica se foi enviado um arquivo de foto
            if 'photo' in request.files:
                photo = request.files['photo']
                if photo.filename != '':
                    # Salvar a nova foto
                    filename = secure_filename(photo.filename)
                    photo.save(os.path.join(app.config['UPLOAD_FOLDER'], 'photos', filename))
                    file_to_update.photo_filename = filename

            db.session.commit()

            response = make_response(jsonify({'message': 'File updated successfully'}))
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

            return response
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        print(f"Error updating file: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'logged_in' not in session or not session['logged_in']:
        return jsonify({'success': False, 'message': 'User not logged in'})

    username = session['username']
    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')

    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'success': False, 'message': 'User not found'})

    if not check_password_hash(user.password, old_password):
        return jsonify({'success': False, 'message': 'Invalid old password'})

    user.password = generate_password_hash(new_password)
    db.session.commit()

    return jsonify({'success': True, 'message': 'Password changed successfully'})

@app.route('/delete/<int:id>', methods=['POST'])
def delete_file(id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    file_to_delete = File.query.get(id)

    if file_to_delete:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_to_delete.destination, file_to_delete.filename)
        photo_path = None  # Inicializa a variável photo_path
        details_path = None  # Inicializa a variável details_path

        # Verifica se há um nome de arquivo de foto definido
        if file_to_delete.photo_filename:
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], 'photos', file_to_delete.photo_filename)

        # Verifica se há um arquivo de detalhes definido
        if file_to_delete.details:
            details_path = os.path.join(app.config['TEMPLATE_FOLDER'], file_to_delete.details)

        try:
            if os.path.exists(file_path):
                os.remove(file_path)  # Remove o arquivo principal

                # Remove a foto associada, se existir
                if photo_path and os.path.exists(photo_path):
                    os.remove(photo_path)

                # Remove o arquivo de detalhes, se existir
                if details_path and os.path.exists(details_path):
                    os.remove(details_path)

                db.session.delete(file_to_delete)
                db.session.commit()
                
                flash('Arquivo e detalhes excluídos com sucesso!', 'success')
                return redirect(url_for('admin'))
            else:
                return jsonify({'error': 'File not found on the server'}), 404
        except Exception as e:
            print(f"Exception: {e}")
            db.session.rollback()
            flash(f'Erro ao excluir arquivo: {e}', 'error')
            return redirect(url_for('admin'))
    else:
        return jsonify({'error': 'File not found in the database'}), 404



if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)